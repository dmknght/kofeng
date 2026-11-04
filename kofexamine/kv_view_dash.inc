/*
 * kv_view_dash.inc - THE DASHBOARD DIALOG: page, geometry and the table slots, and what the screen kept for the next frame.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P7. Main users (Inference, by unit names): kv_page.c, kv_props_table.c, kv_props_tab.c, kv_screen.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_page.c, kv_props_table.c, kv_props_tab.c, kv_props.c, kv_screen.c.
 * Source lines of the old kv_view.h: 1054-1091.
 */
	/*
	 * THE DASHBOARD DIALOG'S STATE AND THE GEOMETRY IT WAS DRAWN WITH.
	 *
	 * `prop_pg` is the page showing (enum prop_page). The dialog is drawn by the pure functions of
	 * kv_dash_dialog.c and its tables by kv_table.c; what they RETURN is kept here as it is drawn and is
	 * all a click, the wheel, a drag and the copy read: `prop_geo` (strip, close button, body, scrollbar,
	 * count) and one slot per table of the page. A table has no scroll state: the page's offsets are
	 * `prop_off` (the first scrolling line) and `prop_hoff` (sideways, for every table; clamped to
	 * `prop_hmax`, the widest pan any table on the page has).
	 *
	 * The page is `prop_fixed` lines that stay (the filter line, a table's heading) and then scrolling lines:
	 * `prop_total` of them, of which the builder produced the window starting at `prop_vfirst` (a table page
	 * produces only the rows it draws; the overview produces every line and `prop_vfirst` is 0).
	 */
	uint8_t     prop_pg;
	uint8_t     prop_inf;           /* 1: the dialog is the Infection one (its book has the two PROP_PG_INF_* pages) */
	struct dlg_off prop_move;       /* where the reader dragged the dashboard dialog; reset when it opens */
	/* What is on the terminal, kept for the next frame (kv_screen.c): the last frame written (a frame that is byte for byte the same is
	 * not written again), which full-cover dialog it showed and the dashboard's offset it was drawn with. They describe the TERMINAL, so
	 * file_open and proc_open carry them across the clear with the rest of the session. */
	char           *scr_last;
	size_t          scr_last_n;
	int             scr_modal;
	struct dlg_off  scr_prop;
	struct kv_dd_geo prop_geo;
	struct kv_dd_in  prop_in;       /* what the dialog was drawn from: the scrollbar is read with its numbers */
	int         prop_bar_drag;      /* the scrollbar is held */
	uint32_t    prop_hoff, prop_hmax;
	uint32_t    prop_fixed, prop_total, prop_vfirst;
	int         prop_room_rows, prop_room_cols;   /* the body's size, from the dialog's layout, for the builders */
#define PROP_TABS 6u
	struct kv_tab_slot {
		struct kv_tab_geo geo;
		struct kv_tab_rec rec;
		int      abs_head;  /* the page line of the table's heading (-1: none was produced) */
		int      abs_row;   /* the page line of the first row it produced; page lines count the fixed ones, then every scrolling one */
	} prop_tab[PROP_TABS];
	uint32_t    prop_n_tab;
