#include <ISmmPlugin.h>
#include "sign_humanlimit.h"
#include "game_signature.h"

void* human_limit_org = NULL;
void* chuman_limit = NULL;

static void onchange_humanlimit(IConVar *var, const char *pOldValue, float flOldValue)
{
	int new_value = ((ConVar*)var)->GetInt();
	int old_value = atoi(pOldValue);

	if(chuman_limit == NULL) {
		Msg( "sv_removehumanlimit init error\n");
		return;
	}

	if(new_value != old_value) {
		if(new_value == 1)
			write_signature(chuman_limit, human_limit_new);
		else
			write_signature(chuman_limit, human_limit_org);
	}
}

ConVar sv_removehumanlimit("sv_removehumanlimit", "0", 0, "Remove Human limit reached kick", true, 0, true, 1, onchange_humanlimit);

int init_humanlimit(struct base_addr_t *base_addr)
{
	int ret = 0;
	if(!chuman_limit) {
		chuman_limit = find_signature(human_limit, base_addr, 0);
		if(chuman_limit)
			ret = -1;
	}
	if(!ret)
		ret = get_original_signature(chuman_limit, human_limit_new, human_limit_org);
	return ret;
}

int deinit_humanlimit()
{
	int ret = 0;

	write_signature(chuman_limit, human_limit_org);
	free(human_limit_org);
	human_limit_org = NULL;

	return ret;
}
