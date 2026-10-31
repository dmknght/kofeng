/*
 * kv_cfgdlg.h - the state of the CFG dialog (kv_cfgdlg.c): the body (kv_cfgbody.h: the Overview and the Graph), the Disasm rows (kv_disasm.c), the tab shown and the
 * dialog frame's place and scroll (kv_form.h, the frame the Syndromes and Pathogens dialogs use).
 */
#ifndef KV_CFGDLG_H
#define KV_CFGDLG_H

#include "kv_form.h"
#include "kv_cfgbody.h"

struct kv_cfg_ui {
	int open;
	struct kv_main m;               /* the frame: place (dragged by its title), scroll, geometry */
	struct kv_cover cv;
	struct kv_cfg_body body;        /* the Overview and Graph rows (the engine's answer for the function) */
	uint32_t tab;                   /* the tab shown: enum kv_cfg_tab; it opens on the Overview */
	uint32_t off[KV_CFG_TABS], hoff[KV_CFG_TABS];   /* the scroll each tab was left at */
	uint64_t func_off, func_len;    /* the function (the request's) the Disasm tab lists */
	struct dis_func_rows dis;       /* the Disasm rows: made when the tab is first shown (a second decode of the function), not at open */
	int dis_made;
};

#endif /* KV_CFGDLG_H */
