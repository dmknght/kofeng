/*
 * kv_view_session.inc - THE SESSION: engine, detection pulls, the object table and the tree rows.
 *
 * A fragment of the BODY of `struct view` (kv_view.h includes it between the braces). It is text, not a header: it has no guard, no
 * includes and is not compiled alone. Members keep their names; moving a member between fragments moves its offset.
 * Owner after the P1 split: package P6/P9. Main users (Inference, by unit names): kv_collect.c (objects), kv_tree.c (tree).
 * Units that name these members most (name match, approximate, 2026-11-03 count at the split): kv_collect.c, kv_main.c, kv_actions.c, kv_tree_draw.c, kv_bar.c.
 * Source lines of the old kv_view.h: 84-126.
 */
	/*
	 * WHAT SURVIVES A FILE SWITCH.
	 *
	 * Opening the next file used to re-exec this program, because the view
	 * is full of pointers whose lifetime is one file and unpicking them by
	 * hand is how a stale one gets left behind. Re-execing also threw away
	 * the database, and loading it is most of what starting costs - so
	 * every step through a directory paid for a load nobody asked for.
	 *
	 * These four are the state that belongs to the SESSION rather than to
	 * the file. file_open keeps exactly them and clears everything else, so
	 * a field added to this struct is cleared by default: the failure mode
	 * of forgetting one is a reset panel, not a pointer into a file that is
	 * no longer mapped.
	 *
	 * `pathbuf` exists because `path` used to point into argv, which is
	 * fine for a path that never changes and wrong the moment one does.
	 */
	kof_engine *eng;
	/* The pull of the engine's detection facts (kscan_explain), made when a panel first asks for the root of the selected object and kept until
	 * the file goes: NULL until then. det_root is the index of the root object it was made for. */
	kdet_run   *det;
	uint32_t    det_root;
	/* The same pull for ONE object the root's run does not hold (a child the emulator made on request, emu_here): its own bytes scanned as a root. */
	kdet_run   *det_own;
	uint32_t    det_own_obj;
	/* The engine's one verdict per top-level file (kverdict_filemap_fold, fed by on_object): the verdict of the object that is the file itself
	 * is the first one made anywhere in its tree, and that is not always its own result. Made with the first object, freed with the file. */
	kverdict_filemap *fmap;
	char        dbdir[256];
	char        pathbuf[KOF_DUMP_PATH_ROOM];

	struct object obj[MAX_OBJ];
	uint32_t      n_obj;



	struct node node[MAX_TREE];
	/* Whether a row was refused for want of space. A truncated list that
	 * does not say so is read as a complete one. */
	uint8_t              tree_cut;
	uint32_t    n_node, sel_node, tree_top;
