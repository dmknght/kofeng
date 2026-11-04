/*
 * kv_view_filter.inc - THE FULL TEXT OF A MULTI-CLICK SELECTION (`dlg_full*`, used by kv_dlgsel.c), THE SYMBOL FILTER, the Find/Go to fields and the size field.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P8. Main users (Inference, by unit names): kv_find.c, kv_dialogs.c, kv_dlgsel.c, kv_props_tab.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_dialogs.c, kv_props_tab.c, kv_find.c, kv_decl.c, kv_dlgsel.c.
 * Source lines of the old kv_view.h: 1092-1168.
 */
	/*
	 * A double or triple click selects text that is NOT all on the screen (a cell scrolled out of view): its
	 * full text is kept here with the selection's ends it was made for, and the copy takes it while they still
	 * match. A selection made any other way has other ends and copies what was recorded.
	 */
	char       *dlg_full;
	size_t      dlg_full_n;
	int         dlg_full_end[4];
	int         dlg_click_n;    /* presses in a row on one place: 1, 2, 3 */
	int         sy_fy;              /* the screen row of the filter line, -1 when not drawn */
	/*
	 * THE SYMBOL FILTER, and why it replaced the line that was there.
	 *
	 * The tab row used to end with ".symtab, 1662 records, TRUNCATED" - the
	 * origin section, a count and a flag. The count is already on both
	 * tabs, the origin is the same for every row in the dialog and never
	 * changes while it is open, and TRUNCATED is a property of the block
	 * the tree row already reports. Three facts, none of them the question
	 * a reader with 1662 symbols in front of them is asking, sitting in the
	 * one place wide enough for the thing they ARE asking: which of these
	 * is called what.
	 *
	 * `sy_filt` is the text, `sy_ficase` folds case, `sy_frx` reads it as a
	 * regular expression. The regex is compiled by the engine -
	 * kof_regex_compile - and walked by kof_hex_walk_flags, which is the
	 * same pair the matcher uses, so a pattern that filters here means the
	 * same thing written into a rule. `sy_frx_bad` is set when the compile
	 * refuses, and then NOTHING MATCHES and the compiler's words are on the
	 * page: passing everything looked like a search that found everything.
	 */
	char        sy_filt[64];
	uint32_t    sy_foff;            /* how far the field is scrolled */
	int         sy_ficase, sy_frx, sy_frx_bad;
	char        sy_rx_err[96];
	uint8_t     sy_prog[512];
	uint32_t    sy_prog_n;
	int         sy_fbox[2];         /* the text field: columns of a line of the page, then screen columns */
	int         sy_ic_box[2];       /* [ ] ignore case */
	int         sy_rx_box[2];       /* [ ] regex */
	int         goto_file;      /* 1 file offset, 0 offset in this region */
	char        gotobuf[20];
	int         find_hex;       /* the text is hex digits, not bytes */
	int         find_icase;     /* letters compare either way; text only */
	/*
	 * READ THE TEXT AS A REGULAR EXPRESSION.
	 *
	 * The program the engine compiles it to and whether it compiled at all,
	 * beside the flag - a pattern half typed has to leave the search doing
	 * something honest, and what it does is nothing.
	 */
	int         find_regex;
	uint8_t     find_prog[512];
	uint32_t    find_prog_n;
	int         find_rx_bad;
	char        find_rx_err[96];
	int         find_scope;     /* 0 this region, 1 the whole object */
	uint64_t    find_at;        /* the last hit, in file offsets */
	uint32_t    find_i, find_n; /* which hit it is, and how many there are */
	uint32_t    find_off;       /* how far the field is scrolled */
	uint32_t    goto_off;       /* the same, for the Go to field */
	int         g_txt[2], g_mode[2], g_go[2], g_cancel[2];
	/* One offset per field that can hold more than it shows. Separate
	 * because they scroll independently: a caret in one says nothing about
	 * where another is being read from. */
	uint32_t    num_off;
	uint32_t    cnd_eoff[MAX_GROUP];
	/* The search's own message. Shared with the draft panel's it produced
	 * a bare "not found" beside the Generate button, which is an answer to
	 * a question that panel never asked. */
	char        find_msg[128];   /* a regex compiler message is longer than "No match" */
	/* Where each control landed, recorded as it is drawn. */
	int         f_txt[2], f_mode[2], f_rx[2], f_ic[2], f_all[2];
	int         f_next[2], f_back[2], f_cancel[2];

	char        num[24];        /* the size being typed */
	int         num_fresh;      /* nothing typed into it yet */
	int         row_cnd, row_str;
