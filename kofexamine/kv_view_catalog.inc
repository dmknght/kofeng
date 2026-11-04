/*
 * kv_view_catalog.inc - THE CATALOG DIALOGS: Pathogens (fam), Syndromes (tag) and the CFG dialog (cfgd).
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P8 (fam, tag), P4 (cfgd). Main users (Inference, by unit names): kv_families.c, kv_tags.c, kv_cfgdlg.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_chooser.c, kv_decl.c, kv_main.c, kofeditor.c, kofexaminer_unpack.c.
 * Source lines of the old kv_view.h: 1169-1173.
 */
	/* Manage > Pathogens: the session's catalog and its dialogs (kv_families.h); NULL until first opened. */
	struct kv_fam_ui *fam;
	/* Manage > Syndromes: the session's tag catalog and its dialogs (kv_tags.h); NULL until first opened. */
	struct kv_tag_ui *tag;
	struct kv_cfg_ui *cfgd;         /* the CFG dialog of a function (kv_cfgdlg.c), made when a function's name is pressed */
