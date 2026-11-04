/*
 * kv_view_chrome.inc - THE FRAME AROUND THE PANES: scrollbar drag, which unpacker filled the tree, the emulate and heuristic stances, the menu bar and the help dialogs.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P9. Main users (Inference, by unit names): kv_bar.c, kv_main.c, kv_help.c.
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_bar.c, kv_click.c, kv_main.c, kv_help.c, kv_actions.c.
 * Source lines of the old kv_view.h: 762-857.
 */
	/*
	 * Which scrollbar the pointer took hold of, so a drag keeps moving that
	 * one after the pointer has left its column. A bar that only responds
	 * while the pointer stays inside a single column is a bar nobody can
	 * drag.
	 */
	int         bar_drag;       /* 0 none, 1 hex, 2 tree, 3 draft */
	/*
	 * WHICH UNPACKER FILLED THE TREE ON SCREEN.
	 *
	 * Zero is the static unpackers, which is what opening a file uses and
	 * what a reader should get without asking: they read structure, they
	 * are fast, and where one applies it is the better answer. One is the
	 * interpreter, in place of them.
	 *
	 * NOT kept when the file changes, unlike basedir and dbdir. It is a
	 * question asked about ONE object - "what does this look like if it is
	 * run instead of read" - and carrying the answer to the next sample
	 * means every step through a directory pays for an interpretation
	 * nobody asked for, which on a large object is tens of seconds. So
	 * stepping to another file starts over on the static unpackers, and the
	 * researcher who wants the other answer asks for it again.
	 */
	int         emu_mode;

	/*
	 * SEPARATE THE CHILDREN ON DEMAND RATHER THAN ON OPEN.
	 *
	 * The engine's own word and the engine's own flag: kof_scan_option
	 * .heur_off is what gates opening a declared entry into an object of
	 * its own - see kof_objtree_may_open - and it is the same flag
	 * kofscanner spells --heur 0. Not a viewer-only setting beside it,
	 * because a second axis here would be this tool disagreeing with the
	 * engine about what a scan of the same file does.
	 *
	 * WHAT IT IS FOR. Opening a document separates every stream the parse
	 * declared, which on a large one is every decompressor in the database
	 * run before the first row is drawn. A reader who wants to see what the
	 * document SAYS about itself - the entry table, which is one row per
	 * stream with its kind, its name and its filter chain - does not need
	 * any of that work done first. So it can be deferred, and the Analysis
	 * menu asks for it when they want it.
	 *
	 * THE ENTRY ROWS ARE THE POINT OF THE MODE, not a consolation for it.
	 * An entry row is dropped when its content is present as an object of
	 * its own - two rows for one stream, see tree_build - so with nothing
	 * separated the table is shown in full, which is exactly the view a
	 * reader checking the parse wants.
	 *
	 * IT ALSO TURNS THE HEURISTICS OFF, because that is what this one flag
	 * means in the engine. Said plainly in the usage text rather than
	 * worked around: the two were made one flag deliberately, and a viewer
	 * that quietly split them again would be where the two definitions of
	 * --heur 0 drifted apart.
	 */
	int         heur_off;

	/* Set while a sub-scan runs: swallow its echo of the object it was
	 * given. See on_object. */
	int         skip_root;
	/*
	 * WHERE THE OBJECT LIST ENDED BEFORE A RERUN, or 0 for an ordinary
	 * collect. See the dedup in on_object: everything below this index was
	 * already in the tree when the rerun started, so a child that matches
	 * one of them is the same child reported twice.
	 */
	uint32_t    dedup_from;

	/* Which top-level item's submenu is showing, -1 for none. */
	int         bar_sub;

	/*
	 * THE MENU ASKED TO LEAVE.
	 *
	 * A flag and not a return value, because bar_run is reached from a
	 * click handler that returns nothing and from a key handler that
	 * returns "handled" - so there is no one code the two could carry, and
	 * giving the click path a return type means threading it through
	 * everything above it to answer one item.
	 *
	 * The loop reads it immediately after handle(), so nothing runs a frame
	 * after it is set.
	 */
	int         quit;
	int         bar_open;       /* which menu is down, -1 for none */
	int         bar_sel;        /* the item under the pointer or the cursor */
	int         help_open;      /* 0 none, 1 keyboard, 2 about */
	/*
	 * Both help dialogs scroll, and both need somewhere to record where
	 * their Close button landed - a click arrives as a screen position and
	 * nothing else knows the box's geometry once draw_help has returned.
	 * Set while drawing, read while clicking; the same shape the menu bar's
	 * hit test already has.
	 */
	int         help_off;
	int         help_btn_y, help_btn_x0, help_btn_x1;
