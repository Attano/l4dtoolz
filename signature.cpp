#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "signature.h"

#ifdef WIN32
#include <windows.h>
#include <TlHelp32.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#endif

#define SIGN_HEADER_LEN		2
#define SIGN_LEN_BYTE		0
#define SIGN_OFFSET_BYTE	1

#define SKIP_BYTE		'\xC3'
#define METAMOD_NAME		"metamod"

#ifndef WIN32
static int lock_region(const void *addr, unsigned int sign_len, unsigned int sign_off, bool lock)
{
	unsigned int u_addr = (unsigned int)addr;
	unsigned int p_size = sysconf(_SC_PAGESIZE);
	unsigned int all_adr = (u_addr + sign_off) & ~(p_size-1);
	unsigned int all_size = u_addr - all_adr + sign_len;
	int ret = 0;

	if(!addr)
		ret = -1;

	if(!ret) {
		if(lock) {
			ret = mlock((void *)all_adr, all_size);
			if(!ret)
				ret = mprotect((void *)all_adr, all_size, PROT_READ|PROT_WRITE|PROT_EXEC);
		} else
			ret = munlock((void *)all_adr, all_size);
	}
	return ret;
}
#endif

static int memcmp_sign(const char* mask, char *base_ptr, unsigned int len, bool pure)
{
	unsigned int i;
	int ret = 0;

	for(i = 0; i < len; ++i) {
		if(!pure && mask[i] == SKIP_BYTE){
			base_ptr++;
			continue;
		}
		if(mask[i] != *base_ptr ) {
			ret = -1;
			break;
		}
		base_ptr++;
	}
	return ret;
}

void *find_signature(const char* mask, struct base_addr_t *base_addr, int pure)
{
	char *base_ptr = (char *)base_addr->addr;
	unsigned int len = (unsigned int)mask[SIGN_LEN_BYTE];
	char *base_end_ptr = base_ptr+base_addr->len-len;
#ifndef WIN32
	unsigned int p_size = sysconf(_SC_PAGESIZE);
	char *all_adr = (char *)((unsigned int)base_ptr & ~(p_size-1));
	unsigned int size = base_end_ptr - all_adr;
#endif
	void *ret_ptr = NULL;
	int ret = 0;

	if(!base_addr || !mask)
		ret = -1;

#ifndef WIN32
	if(!ret)
		ret = mlock(all_adr, size);
#endif

	if(!ret && len <= 0)
		ret = -1;

	if(!ret) {
		for(;base_ptr < base_end_ptr; base_ptr++) {
			if(!memcmp_sign(mask+1, base_end_ptr, len, pure)){
				ret_ptr = base_ptr;
				break;
			}
		}
	}
#ifndef WIN32
	if(!ret)
		ret = munlock(all_adr, size);
#endif
	return ret_ptr;
}

#ifndef WIN32
struct v_data{
	const char *fname;
	void *baddr;
	unsigned int blen;
};

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int i;
	struct v_data *data_ptr;
	int ret = 0;

	if (!info->dlpi_name || !info->dlpi_name[0])
		ret = -1;

	data_ptr = (struct v_data *)data;

	if(!ret && strstr(info->dlpi_name, data_ptr->fname) && !strstr(info->dlpi_name, METAMOD_NAME)) {
		data_ptr->baddr = (void*)info->dlpi_addr;
		data_ptr->blen = 0;
		for(i=0; i < info->dlpi_phnum; ++i) {
			data_ptr->blen+=info->dlpi_phdr[i].p_filesz;
			ret = 0;
			break;
		}
	}
	return ret;
}
#endif

int find_base(const char* name, struct base_addr_t *base_addr)
{
#ifdef WIN32
	HANDLE hModuleSnap;
	MODULEENTRY32 modent;
	int ret = 0;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	if(hModuleSnap == INVALID_HANDLE_VALUE)
		ret = -1;

	modent.dwSize = sizeof(MODULEENTRY32);
	if(!ret) {
		while(Module32Next(hModuleSnap, &modent)) {
			if(strstr(modent.szExePath, name) && !strstr(modent.szExePath, METAMOD_NAME)) {
				base_addr->addr = modent.modBaseAddr;
				base_addr->len = modent.modBaseSize;
				ret = 0;
				break;
			}
		}
	}
	CloseHandle(hModuleSnap);
#else
	struct v_data vdata;
	int ret = 0;

	vdata.fname = name;

	if(dl_iterate_phdr(callback, &vdata)){
		base_addr->addr = vdata.baddr;
		base_addr->len = vdata.blen;
	} else
		ret = -1;
#endif
	return ret;

}

int write_signature(const void* addr, const void* signature)
{
	unsigned int u_addr_sign = (unsigned int)signature;
	unsigned int sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	unsigned int sign_off = ((unsigned char *)signature)[SIGN_OFFSET_BYTE];
	unsigned int u_addr = (unsigned int)addr;
#ifdef WIN32
	HANDLE h_process;
#endif
	int ret = 0;

	if(!addr || !signature)
		ret = -1;

#ifdef WIN32
	if(!ret && !(h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId())) {
		ret = -1;
	}

	if(!ret) {
		if(!WriteProcessMemory(h_process, (void *)(u_addr+sign_off), (void *)(u_addr_sign+SIGN_HEADER_LEN), sign_len, NULL))
			ret = -1;
		CloseHandle(h_process);
	}
#else
	if(!ret)
		ret = lock_region(addr, sign_len, sign_off, true);

	if(!ret) {
		memcpy((void *)(u_addr+sign_off), (void *)(u_addr_sign+SIGN_HEADER_LEN), sign_len);
		ret = lock_region(addr, sign_len, sign_off, false);
	}
#endif
	return ret;
}

int read_signature(const void *addr, void *signature)
{
	unsigned int u_addr_sign = (unsigned int)signature;
	unsigned int sign_len = ((unsigned char *)signature)[SIGN_LEN_BYTE];
	unsigned int sign_off = ((unsigned char *)signature)[SIGN_OFFSET_BYTE];
	unsigned int u_addr = (unsigned int)addr;
#ifdef WIN32
	HANDLE h_process;
#endif
	int ret = 0;

	if(!addr || !signature)
		ret = -1;

#ifdef WIN32
	if(!ret && !(h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId())) {
		ret = -1;
	}

	if(!ret){
		if(!ReadProcessMemory(h_process, (void *)(u_addr+sign_off), (void *)(u_addr_sign+SIGN_HEADER_LEN), sign_len, NULL))
			ret = -1;
		CloseHandle(h_process);
	}
#else
	if(!ret) {
		ret = lock_region(addr, sign_len, sign_off, true);
	}

	if(!ret) {
		memcpy((void *)(u_addr_sign+SIGN_HEADER_LEN), (void *)(u_addr+sign_off), sign_len);
		ret = lock_region(addr, sign_len, sign_off, false);
	}
#endif
	return ret;
}

int get_original_signature(const void *offset, const void *new_sig, void *&org_sig)
{
	unsigned int sign_len;
	int ret = 0;

	if(!offset || !new_sig)
		ret = -1;

	if(!ret) {
		sign_len = ((unsigned char *)new_sig)[SIGN_LEN_BYTE];
		if((org_sig = malloc(sign_len+SIGN_HEADER_LEN)) == NULL)
			ret = -1;
	}

	if(!ret) {
		memcpy(org_sig, new_sig, SIGN_HEADER_LEN);
		ret = read_signature(offset, org_sig);
	}

	return ret;
}

