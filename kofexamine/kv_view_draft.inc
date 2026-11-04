/*
 * kv_view_draft.inc - THE DRAFT PANEL: scroll offsets, strings being edited, the module declaration, the conditions, the recorded controls and the hit table, the block-table window, then the panel divider, drag and size state.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P2. Main users (Inference, by unit names): kv_decl.c, kv_draft.c, kv_field.c, kv_click.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_decl.c, kv_click.c, kv_events.c, kv_actions.c, kv_field.c.
 * Source lines of the old kv_view.h: 514-761.
 */
	/*
	 * How far each list is scrolled sideways.
	 *
	 * A deep tree spends its width on indentation and a signature name is
	 * as long as its author made it, so on a narrow terminal both get cut
	 * before they get useful. Vertical scrolling does not help with that -
	 * the row is there, it is the row that is too wide - so the panes that
	 * hold text keep a horizontal offset too. The hex pane has none by
	 * design: it reflows, fitting fewer bytes per row rather than running
	 * off the edge.
	 */
	uint32_t    tree_hoff, decl_hoff;

	/* The region column's width for this frame - see draw_decl. */
	int         rgn_w;




	/*
	 * A string being edited, as text.
	 *
	 * The declaration holds bytes, and bytes are not what somebody types. A
	 * literal is typed as the characters it is - not as the escaped spelling
	 * the generated source carries, because the escaping is the file
	 * format's business and typing \x41 to mean A is asking the reader to
	 * be a compiler. A hex pattern is typed as spaced pairs, the way the
	 * source reads, which is also what leaves room for the things bytes
	 * cannot express: ?? for a wildcard, [n-m] for a gap, (a|b) for a
	 * choice.
	 *
	 * So the text lives here while it is being edited and is parsed back
	 * into the declaration when the field closes. `sedit_ok` is cleared when
	 * the text cannot be parsed, so the row can say so without the panel
	 * having to guess.
	 */

     /* how far the field is scrolled */


	uint32_t     n_rng, cur_rng;

       /* matchers */




     /* why the last add was refused */
	/*
	 * What the last ACTION did, wherever it was asked for.
	 *
	 * Its own slot rather than `warn`, which is scoped to the draft panel
	 * having focus. A copy is almost always made from the hex pane and a
	 * dump is asked for from the menu bar, so put in `warn` the one message
	 * that exists to prove something happened was itself invisible.
	 *
	 * One slot for both because they are one thing to a reader - the last
	 * thing I asked for, and how it went - and two would mean deciding which
	 * of them wins on a screen that can only show one.
	 */
	char         act_msg[160];
	int          act_ok;        /* whether it did what was asked */
      /* 1 it failed, 0 it is only worth knowing */

	/*
	 * What the finished module will declare about itself.
	 *
	 * The type is cycled rather than typed because it is an enum the build
	 * checks - ksigbuilder refuses a word that is not in its table, and a
	 * text box that can produce a build error is a text box that should have
	 * been a list. The other two are free text and belong to whoever is
	 * writing the signature.
	 */





	char        basedir[256];
	/* Manage > Pathogens: where the family files are kept (<bases>/pathogens or --pathogens); empty = not known, Save refuses. */
	char        pathdir[256];
	/* Manage > Syndromes: where the tag files are kept (<bases>/syndromes or --syndromes); empty = not known, Save refuses. */
	char        syndir[256];

	/*
	 * How the conditions combine, written the way ClamAV writes it: numbers
	 * for conditions, & and |, parentheses. Free text because the shapes
	 * people want are not a menu - "1&2", "(1&2)|3" - and because an empty
	 * one has an obvious meaning worth keeping as the default: every
	 * condition, joined by &.
	 */


	int         edit;           /* 0 none, else the code of the box open (see ED_*) */




	/* Where the header's controls landed, recorded as they are drawn. */
	int         g_c0, g_c1;
	int         n_c0, n_c1;     /* the "+ condition" button */
	int         nw_c0, nw_c1;   /* "New" - empty the panel */
	int         nt_c0, nt_c1;   /* the module's own note */
	int         nt_len, nt_room;/* its length and the width it is shown in */
	int         grp_len[MAX_GROUP], grp_room[MAX_GROUP];
	int         rng_c0, rng_c1, m_c0, m_c1, s_c0, s_c1, e_c0, e_c1;
	/*
	 * WHERE EACH RANGE NAME IS ON THE SCAN RANGES ROW.
	 *
	 * The row used to carry one [Update scan range] button that acted on
	 * "a range" and then asked which. Now the NAME is the control: clicking
	 * one opens a menu whose subject is that range, so the question "which"
	 * is answered by where the reader pressed instead of by another list.
	 * Parallel to the order rng_all produces, which is the order they are
	 * drawn in.
	 */
	int         rng_hs[2 * MAX_GROUP][2];
	uint32_t    n_rng_hs;
	int         rga_c0, rga_c1; /* "[+ Add scan range]" at the row's end */
	int         rgf_c0, rgf_c1; /* "Update string regions" - where they are */
	int         adds_c0, adds_c1; /* "[+ str]" - see BTN_ADDSTR */
	/* The target formats on their row: each name's columns, and the button
	 * that adds one. Recorded where they are drawn, read where they are
	 * clicked - the arrangement every other control here uses. */
	int         fmt_hs[KOF_FMT_COUNT][2];
	uint32_t    n_fmt_hs;
	int         fma_c0, fma_c1;
       /* the region the range menu was built on */
	/*
	 * Ranges the draft declares that no matcher names yet.
	 *
	 * A range normally has no existence apart from a matcher naming one,
	 * which is why the summary row derives itself. "Add CODE to scan
	 * ranges" breaks that for as long as it takes to give the range a
	 * matcher - so it is held here, listed as unused, and refused at save
	 * time rather than turned into an empty matcher nobody asked for.
	 */


	/*
	 * The list a submenu came out of, kept so it can stay on screen.
	 *
	 * A submenu that replaces its parent is not beside it, it is instead of
	 * it - and the reader loses the line they were acting on at the moment
	 * they are asked to qualify it.
	 */
	struct chooser ch_up;
	int         a_c0, a_c1, b_c0, b_c1;
	/*
	 * "[+ String]" - ONE PAIR PER MATCHER, because its column depends on
	 * how many marker ids that matcher's row already printed. A single
	 * shared pair was overwritten by every row in turn, so only the last
	 * matcher's button answered a click and the earlier rows' buttons were
	 * dead while blank space at the last row's column was live.
	 */
	/*
	 * WHERE EVERY CLICKABLE THING IS, RECORDED WHILE IT IS DRAWN.
	 *
	 * The panel's clicks used to be a second walk over the same rows -
	 * click_panel_rows, 390 lines - counting rows in the order the draw
	 * emits them and reaching the controls by a field the draw had left
	 * behind. Two walks of one shape, and nothing making them agree: adding
	 * the Format and [+ Options] rows to the draw and not to the other walk
	 * shifted every click below them by two, and the same drift in
	 * prow_build cost the panel its Conditions rows outright.
	 *
	 * A span is registered by whoever paints it, at the moment it knows
	 * where it landed, and a click is a lookup. The draw becomes the only
	 * place that knows the layout, which is the property the two walks
	 * could not have.
	 *
	 * Last match wins on overlap: rows are painted top down and a later
	 * span is drawn over an earlier one, so the reader is pointing at the
	 * later one.
	 */
	struct hit  hit[HIT_MAX];
	uint32_t    n_hit;

	int         p_c0[MAX_GROUP][2];
	/*
	 * WHERE EACH ITEM OF A MATCHER'S LIST ROW WAS DRAWN - see grp_list.
	 * One array for both kinds of matcher, because a matcher is one kind
	 * or the other and never both.
	 */
	int       (*grp_it[MAX_GROUP])[2];   /* each cap_str_col pairs, allocated with the strings' columns */
	int         opt_c0[OPT_COUNT], opt_c1[OPT_COUNT];

	/*
	 * The panel's rows, listed once and used twice.
	 *
	 * Drawing walked this shape and the click router walked it again, and
	 * keeping two copies of one walk in step is a thing that fails quietly:
	 * a row added to one and not the other sends every click below it to
	 * the wrong control. Built once per frame, indexed by both.
	 */
	uint32_t    n_prow, prow_off;
	/* The block table is a WINDOW onto the draft's blocks: its own scroll (rows hidden above the window), where its rows start in the
	 * panel model, how many it draws, and how many rows it has in all (prow_blocks decides them each frame). */
	uint32_t    blk_off, blk_row0, blk_nwin, blk_nshown;
	/*
	 * MUTATION MODE SCROLLS THE BLOCK LIST AND NOTHING ELSE.
	 *
	 * The condition and what the database scored are written BELOW the
	 * list, and a carve produces as many as sixty-four blocks against a
	 * panel a dozen rows tall - so scrolled as one column they went off the
	 * bottom and the author lost the two rows that say what the ticking is
	 * building. They are what a reader looks at WHILE ticking, so they hold
	 * still and the list moves inside them.
	 *
	 * mtn_above is how many rows sit above the list and kgenome_mtn_win how many
	 * the list itself gets; the drawing, the clamp, the wheel and the
	 * scrollbar all read these rather than each deriving them again.
	 */
	uint32_t    mtn_above, kgenome_mtn_win;
	/* The threshold being typed, as text - a percentage is edited the way
	 * every other box here is edited, and committed back to the block on
	 * each key. */
	char        grp_pct_buf[8];
	uint32_t    grp_pct_off;
	/* Whether the row-count check is the one showing in `warn` - see the
	 * foot of draw_decl. */
	int         rowchk;
	/*
	 * How many draft rows the panel is allowed to show, and whether the
	 * divider is being dragged.
	 *
	 * A cap rather than a height, because the panel still shrinks to fit a
	 * short draft: a researcher who drags the divider down is saying how
	 * much room the draft may take, not demanding that much blank space
	 * while it is empty.
	 */
	uint64_t    last_click;     /* the byte a click landed on */
	uint64_t    last_click_ms;  /* and when, so a second one can pair */

	/*
	 * A DRAFT THAT WAS LOADED OPENS AT ITS BEGINNING.
	 *
	 * The panel scrolls to the bottom when it grows, because what grew is
	 * the row the reader just asked for. Replacing the whole draft also
	 * makes it grow - by every row at once - and that read as the same
	 * event, so opening a rule from the database landed at the end of it
	 * and the KOF_TARGET_ rows, which are at the top, were off screen. The
	 * options looked as though the rule had not declared any.
	 */
	int         prow_home;      /* the next frame starts the draft at its top */
     /* what the draft was when it was written */
	uint64_t    obj_held;       /* bytes of recovered objects being kept */
	int         sizing;
