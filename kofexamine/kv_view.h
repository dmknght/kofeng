/*
 * kv_view.h - struct view, the whole state of one session.
 *
 * One struct, and the one header here over 1000 lines on purpose: the fields are one
 * session and are documented where they are declared (974 of the 1285 lines are the
 * comments that say why a field exists). Cutting it by purpose would mean nesting
 * structs, which renames every v->field in every unit. A part of kv.h.
 */
#ifndef KV_VIEW_H
#define KV_VIEW_H

struct kv_fam_ui;

struct view {
	/* The scanner that is running RIGHT NOW, so on_object can ask it what
	 * the database's blocks scored before it is freed. NULL at every other
	 * moment, which is what stops anything else from reaching for it. */
	kof_scanner     *scan_sc;
	/*
	 * MUTATION MODE: the same pane, asking a different question.
	 *
	 * It replaces the draft panel rather than sitting beside it because the
	 * two are alternatives - a signature is written out of patterns or out
	 * of blocks, and a screen offering both at once would be offering a
	 * choice nobody makes halfway.
	 */
	/*
	 * A POINTER, so ticked blocks can outlive opening the next file.
	 *
	 * Everything else about a view is about the file in front of it and is
	 * cleared when another is opened. These are not: a block ticked on one
	 * sample is the QUESTION being asked of the next one, and clearing it
	 * left the score column with nothing to measure. Held the way ext and
	 * probe are - allocated once in main, carried across the clear.
	 */

	uint32_t         n_plg;
	uint32_t         mtn_sel;          /* the row the keyboard is on */
	/*
	 * What the last scoring pass was about, so a frame that changed
	 * neither does not redo it.
	 *
	 * Scoring walks the object, which is the one thing in this panel that
	 * is not free - and the answer only moves when the blocks change or
	 * the reader moves to another object. Both are captured here.
	 */
	uint32_t         mtn_scored_obj;
	uint32_t         mtn_scored_n;
	int              mtn_scored;
	/* The blocks came from the object's own cached carve, so their scores
	 * are certainties and not measurements - see mtn_segment. */
	int              mtn_scores_known;
	/*
	 * FOLDED TABLES.
	 *
	 * The block table is as long as the object has areas - sixty-four rows
	 * on a large one - and a reader working on the matchers below it should
	 * not have to scroll past all of them to get there. Folding is per
	 * table and per session, not per object: it is a property of what the
	 * reader is doing, and a fold that reopened itself whenever the sample
	 * changed would be a fold that never holds.
	 *
	 * The heading and the column row stay in both states; the column row is
	 * what carries the control, and a table whose handle vanished when it
	 * was folded could not be opened again.
	 */
	int              blk_fold, diag_fold;
	/* Which object the table was carved from, so moving to another one
	 * carves that one instead of showing the last one's blocks. */
	uint32_t         mtn_seg_obj;
	int              mtn_segged;

	/* The signature generator's model - see kofeditor.h. */
	struct kof_editor ed;
	const char *path;
	void       *map;
	uint64_t    map_len;

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
	char        dbdir[256];
	char        pathbuf[KOF_DUMP_PATH_ROOM];

	struct object obj[MAX_OBJ];
	uint32_t      n_obj;



	struct node node[MAX_TREE];
	/* Whether a row was refused for want of space. A truncated list that
	 * does not say so is read as a complete one. */
	uint8_t              tree_cut;
	uint32_t    n_node, sel_node, tree_top;

	/*
	 * AN EVENT LOG, BROWSED AS A WINDOW RATHER THAN LOADED.
	 *
	 * A log holds millions of records and the object array holds MAX_OBJ,
	 * so the objects are a WINDOW over it: LOG_WIN events starting at
	 * log_first, rebuilt when the selection walks off either end. Nothing
	 * of a record is copied - each event object's buf points into the
	 * mapped file at that record's own extent, so the hex pane shows the
	 * real bytes and the memory cost of opening a log is the mapping.
	 *
	 * `log` is a second handle on the same file, used only to ask WHERE a
	 * record is; the bytes come from the mapping. Two handles because the
	 * questions are different and neither wants the other's file position.
	 */
	struct kofevt_log_r *log;
	uint64_t             log_n;      /* records in the file */
	uint64_t             log_first;  /* the window's first record */

	/*
	 * WHICH RECORD EACH ROW STANDS FOR, and where the window stopped.
	 *
	 * Rows are not records any more and the two must not be conflated: the
	 * verb filter hides some, and a continuation is absorbed into the event
	 * in front of it rather than given a row. The paging code used to
	 * recover the last row's record as `log_first + row - 1`, which is only
	 * true when every record in the window got a row - so with a filter on,
	 * turning the page landed somewhere unrelated to where the reader was.
	 */
	uint64_t             log_idx[MAX_OBJ];
	uint64_t             log_next;   /* the first record past the window */

	/*
	 * The tree needs rebuilding before the next frame.
	 *
	 * Set when something learns a fact that changes what rows exist - a
	 * carried image being identified, so its regions can be listed. Acted
	 * on at the top of the frame, because that is the one place where no
	 * caller is holding a node index.
	 */
	int                  tree_dirty;

	/*
	 * WHERE A SCAN'S RESULT FOR ITS OWN ROOT SHOULD GO, or -1.
	 *
	 * A scan reports the object it was given first, and on_object's normal
	 * job is to APPEND what it is told about. That is right when the engine
	 * is walking a file and discovering objects; it is wrong for a row the
	 * tree already has - a carried image, scanned on its own - where the
	 * findings belong to the row a reader is looking at and a second copy
	 * of it would appear beside itself.
	 */
	int                  into_obj;

	/*
	 * HOW MANY OF THOSE RECORDS ARE EVENTS.
	 *
	 * Not the same number as log_n, and the difference is not cosmetic: a
	 * continuation is a record and is not an event, so a log holding one
	 * AMSI submission split over nine chunks has ten records and one event.
	 * Reported as ten, the header told a reader there were nine things in
	 * the file that are not there.
	 *
	 * log_n stays the record count, because that is what indexes the file -
	 * kofevt_log_extent, the window, the paging all count records. This is
	 * only ever shown.
	 */
	uint64_t             log_events;

	/*
	 * WHICH VERBS THIS LOG ACTUALLY CONTAINS, and which of them to show.
	 *
	 * Both are masks of 1u << kof_evt_verb. `log_verbs` is what the file
	 * holds - built once by walking the MAPPING, which costs no I/O - and
	 * it is what the filter submenu offers: a menu listing verbs the log
	 * does not contain is a menu of rows that do nothing.
	 *
	 * `log_keep` is what the object panel shows. It starts equal to
	 * log_verbs, so opening a log shows everything, and Apply narrows it.
	 */
	uint32_t             log_verbs, log_keep;

	/*
	 * HOW MANY OF EACH, counted in the same walk that learns which verbs
	 * the file holds - so it costs nothing beyond the pass already made.
	 *
	 * A mask says a verb is present; a count says whether it is the trace.
	 * "RegSet" and "RegSet 41000" are different facts about a log, and the
	 * second is the one that decides where to look.
	 */
	uint64_t             log_count[32];

	/*
	 * THE SELECTED EVENT, SPELT OUT - the record itself and where the
	 * reader is inside its field list.
	 *
	 * Copied out of the mapping rather than pointed at it, for the reason
	 * log_window already copies: a log written by a build with a different
	 * head has its text at another offset, and a bounded copy into THIS
	 * build's struct is the only read of it that is defined.
	 *
	 * `evt_sel` is a row index, and -1 means the panel is open with
	 * nothing picked - which is the state it starts in, because landing on
	 * a record should show what it says before it starts pointing at one
	 * part of it.
	 */
	struct kof_evt       evt;
	int                  evt_have;   /* the copy above is a real record */
	int                  evt_open;   /* the reader has not closed it */
	int                  evt_n;      /* rows the record yields */
	int                  evt_sel;    /* the row lit in both panes, or -1 */
	int                  evt_scroll; /* first line drawn */
	/*
	 * HOW FAR THE VALUES ARE SHIFTED LEFT.
	 *
	 * The wrap shows the first six lines of a value, which is enough to see
	 * what a thing is and not enough to read a submitted script to its end.
	 * Shifting moves the whole value before it wraps, so the six lines
	 * become a window over it rather than its beginning - and a reader can
	 * reach the tail of an AMSI buffer without the panel eating the pane.
	 */


	/*
	 * THE WHOLE SUBMISSION, gathered from the event and the continuations
	 * behind it.
	 *
	 * The record holds a prefix - four hundred bytes of arena - and the
	 * rest arrives as KOF_EVT_CONT records, which this viewer folds into
	 * the same row. `join` is the raw bytes, in the order they were sent;
	 * `text` is the rendering of them, which is what a pane can show.
	 *
	 * Both are allocated once with the log and reused per selection: a
	 * record's content is bounded by what the collector will send, so a
	 * fixed pair costs the same for every event and there is nothing to
	 * grow or free while walking a log.
	 */
	char                *evt_join;
	size_t               evt_join_len;
	char                *evt_text;
	size_t               evt_text_len;

	/*
	 * The gathered content is UTF-16LE - a NUL above every character.
	 *
	 * Kept because the HEX PANE needs it too, not only the field row: a
	 * dump of a script block is half NUL bytes, and a column of dots
	 * between every letter is the thing that makes it unreadable.
	 */
	int                  evt_wide;

	/*
	 * WHERE THE GATHERED CONTENT SITS IN THE NODE'S BYTES.
	 *
	 * The submission is one string once it is joined, and it is NOT one run
	 * in the file: the record holds the first four hundred bytes of it and
	 * each continuation holds the next, with a seventy-two byte head in
	 * between. So a character in the box maps to a byte in the dump only
	 * through a table of the pieces.
	 *
	 * Without it the sync could only mark a selection inside the FIRST
	 * record, which is the part a reader scrolls past.
	 *
	 * Capped, and the cap is honest: past it the map runs out and the sync
	 * marks nothing rather than marking the wrong bytes.
	 */
	struct { uint32_t at, len; } evt_seg[EVT_SEG_MAX];
	int                  evt_n_seg;

	/*
	 * AN EXECUTABLE CARRIED INSIDE AN EVENT, as a child object.
	 *
	 * Some submissions are a PE image rather than a script. The bytes are
	 * already gathered - kof_evt_join concatenates the raw content and
	 * nothing else, so what comes out is the file, byte for byte, with no
	 * record heads or padding between the pieces. What was missing was
	 * anywhere to LOOK at it: the panel renders text, and a PE rendered as
	 * text is a column of dots.
	 *
	 * So the event grows a child row, and selecting it puts the image in
	 * the hex pane like any other object. `pe_of` is the object index of
	 * the EVENT a child belongs to - zero for every row that is not one -
	 * because the child's bytes are its parent's join, materialised when
	 * the child is picked rather than for every event in the window.
	 */
	uint32_t             pe_of[MAX_OBJ];
	uint32_t             pe_at;   /* where the image starts in the join */

	/*
	 * A RUN OF CHARACTERS PICKED OUT OF ONE ROW'S VALUE.
	 *
	 * The name column and the value column answer different gestures. A
	 * click on the NAME is a question about the record - which bytes is
	 * this - so it lights the field and takes the dump there. A drag across
	 * the VALUE is a question about the text: an AMSI submission is a
	 * script, and what a reader wants from a script is to pull a URL or a
	 * base64 blob out of it and paste it somewhere else.
	 *
	 * Anchored to (row, character), not to screen positions: the value
	 * wraps and the panel scrolls, and a selection anchored to a screen
	 * cell would name a different part of the text after either.
	 */
	int                  evt_txt_a, evt_txt_b;
	int                  evt_txt_drag;

	struct kof_range *ext;
	/*
	 * A SECOND EXTENT BUFFER, for anything that resolves a region that is
	 * not the one on screen.
	 *
	 * `ext` holds the SELECTED region's runs and is what view_map and
	 * view_unmap read - the hex pane's entire sense of where it is. Mutation
	 * mode resolves other regions to carve and to score, and resolving into
	 * `ext` overwrote that: the highlight then mapped through the wrong
	 * runs and landed nowhere, and the pane it was drawn over was reading
	 * the same wreckage.
	 */
	struct kof_range *ext2;
	uint32_t          n_ext;
	/*
	 * A second extent buffer, for asking about a region that is not the one
	 * being looked at.
	 *
	 * `ext` describes the selected node and the hex pane maps every byte
	 * through it. A lookup that resolved some other region into it left the
	 * pane mapping through extents that belonged to nothing it was showing
	 * - every offset came back as the start of the file, so declaring a
	 * string turned the whole pane into byte zero repeated. A question
	 * about another region gets its own paper.
	 */
	struct kof_range *probe;
	uint64_t          rgn_len, rgn_at;

	/*
	 * A selection of BYTES, not of screen text.
	 *
	 * Held as offsets into the region, which is what dissolves both problems
	 * a character selection has: there is no offset column and no ASCII
	 * column in this model, only bytes, so clicking either one names the
	 * same byte and neither can be dragged into the selection by accident.
	 * A press outside the hex pane is not a hex selection at all, so the
	 * tree and the markers line cannot be dragged into it either.
	 *
	 * KGENOME_BROKEN for "nothing selected", which is distinct from a selection
	 * of length zero.
	 */
	uint64_t    sel_a, sel_b;
	/* The process this view is showing, or 0 when it is a file. What makes
	 * next/prev step through pids instead of through a directory. */
	uint32_t    proc_pid;
	/* The mapped files already given a row - see proc_seen_path. */
#define PROC_SEEN_MAX 256u
	char        seen_path[PROC_SEEN_MAX][256];
	uint32_t    n_seen;
	/* Mapped files this view declined to read, and the bytes it did. */
	uint32_t    proc_skipped;
	uint64_t    proc_skipped_bytes;

	/*
	 * THE DISASSEMBLY PANEL.
	 *
	 * `dis_open` is the panel; `dis_bits` is 32 or 64, because raw shellcode
	 * carries no header to say which and the answer changes what the same
	 * bytes mean - a payload unpacked out of a Metasploit encoder is bytes
	 * and nothing else. It is seeded from the object's architecture when
	 * there is one and left for the reader to change when there is not.
	 *
	 * `dis_at`/`dis_len` pin the panel to a RANGE the reader chose, and
	 * KGENOME_BROKEN in dis_len means it is not pinned: it follows the hex
	 * scroll instead. Both are region offsets, like every other position in
	 * this view.
	 */
	int         dis_open;
	int         dis_bits;
	uint64_t    dis_at, dis_len;

	/*
	 * A selection of LINES in the panel, and the text each one printed.
	 *
	 * Lines rather than characters, because an instruction is the unit
	 * somebody copies: half of a MOV pasted into a note is not a smaller
	 * answer, it is a wrong one. Held as row indices from the top of the
	 * panel, and -1 when nothing is selected.
	 *
	 * The text is kept because the panel is redrawn from the bytes every
	 * frame and the copy has to be of what was on screen - decoding it a
	 * second time at copy time would be a second decoder to disagree with
	 * the first, in exactly the case where the reader is looking at the
	 * output of the first.
	 */
	/*
	 * A TEXT SELECTION, character by character, the way one behaves
	 * anywhere else: an anchor where the press landed and a cursor where the
	 * pointer is, each a row and a column into the panel's own rows.
	 *
	 * It was whole lines, and whole lines are wrong for the same reason a
	 * hex selection is not whole rows: the reader picks what they mean to
	 * copy, and an operand or a mnemonic on its own is a thing people take.
	 *
	 * dis_have is 0 when nothing is selected.
	 */
	/*
	 * ANCHORED TO BYTES, NOT TO ROWS.
	 *
	 * Each end is the file offset of the instruction its row starts at, plus
	 * a column within that row's text. Row indices were tried and are wrong
	 * for one reason: they go stale the moment the panel scrolls, so row 3
	 * stayed lit while row 3 became a different instruction - and scrolling
	 * away and back lost the selection entirely. A byte offset means the
	 * highlight belongs to the instruction, which is what the reader picked.
	 */
	uint64_t    dis_a_at, dis_b_at;
	int         dis_ac, dis_bc;
	int         dis_have;           /* anything selected at all */
	int         dis_dragging;


	/*
	 * WHAT THE PANEL IS READING FROM when it is not pinned.
	 *
	 * See dis_follow_hex for the rule that sets it, and dis_seen_* for what
	 * it last saw of the two things that can move it.
	 */
	uint64_t    dis_follow;
	/*
	 * HOW FAR THE PANEL SITS FROM THE HEX SCROLL, and it is a CONSTANT.
	 *
	 * The panel reads from rgn_at + dis_bias, so scrolling the hex moves it
	 * by exactly as much - the two are locked together whatever the bias is.
	 * Selecting bytes is what sets the bias: enough to bring the selected run
	 * onto these rows. Nothing else changes it, so scrolling away and back
	 * puts the selection back where it was.
	 *
	 * This replaced four attempts that each tied the panel's POSITION to the
	 * selection instead of to the scroll. Every one of them broke one of the
	 * two things asked of it - either the panel stopped following the scroll,
	 * or the highlight left the rows and did not come back. A bias is the
	 * thing that was missing: an offset can satisfy both because it is not a
	 * position at all.
	 */
	int64_t     dis_bias;

	/*
	 * WHO SET THE BYTE SELECTION, and it has to be recorded because the
	 * sync runs both ways.
	 *
	 * The panel follows the hex selection, and picking lines in the panel
	 * SETS that selection - so without this the panel followed itself: a
	 * click on a line moved the selection, the selection moved the panel's
	 * start, and the row under the pointer was no longer the row that had
	 * been clicked. The hex pane does not scroll to a selection, so the two
	 * came apart as well.
	 *
	 * One flag, and the rule it encodes: a selection made HERE does not move
	 * this panel. A selection made in the hex pane does.
	 */
	int         sel_from_dis;
	/*
	 * The last instruction that set the flags (a CMP or a TEST) and where the next instruction would start, so a conditional jump read right after
	 * it - or after instructions that leave the flags alone - is explained as the comparison it is. Kept by dis_format as it goes; a row that is not
	 * the next of the last one starts from nothing known.
	 */
	struct kgenome_x86_insn dis_fl;
	uint64_t    dis_fl_rip, dis_next;
	uint8_t     dis_fl_ok;
	char        dis_line[64][DIS_LINE_MAX];
	/*
	 * The bytes each drawn line stands for.
	 *
	 * Kept so that a selection made in the panel can be turned back into a
	 * byte range - which is what lets the hex pane's own menu items work on
	 * it unchanged. Selecting three instructions and declaring them as a
	 * marker is the same act as selecting their bytes, and it should not
	 * need a second implementation to say so.
	 */
	uint64_t    dis_line_at[64], dis_line_len[64];
	uint8_t     dis_line_lbl[64];       /* the row is a label: no bytes, not selectable */
	int         dis_lines;
	int         dragging;
	int         dragged;        /* the pointer moved off the pressed byte */

	/* Which half of the hex pane the menu was opened on. */
	int         menu_ctx;       /* 1 bytes, 2 the offset column,
				     * 4 the disassembly, 8 the event box */
	uint64_t    menu_off;       /* the row offset it was opened on */

	int         menu_open, menu_row, menu_col, menu_sel;
	struct chooser ch;

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

	/*
	 * How the conditions combine, written the way ClamAV writes it: numbers
	 * for conditions, & and |, parentheses. Free text because the shapes
	 * people want are not a menu - "1&2", "(1&2)|3" - and because an empty
	 * one has an obvious meaning worth keeping as the default: every
	 * condition, joined by &.
	 */


	int         edit;           /* 0 none, 1 family, 2 variant */




	/* Where the header's controls landed, recorded as they are drawn. */
	int         f_c0, f_c1, t_c0, t_c1, v_c0, v_c1, g_c0, g_c1;
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
	int         grp_it[MAX_GROUP][GRP_SIM_MAX][2];
	int         opt_c0[OPT_COUNT], opt_c1[OPT_COUNT];

	/*
	 * The panel's rows, listed once and used twice.
	 *
	 * Drawing walked this shape and the click router walked it again, and
	 * keeping two copies of one walk in step is a thing that fails quietly:
	 * a row added to one and not the other sends every click below it to
	 * the wrong control. Built once per frame, indexed by both.
	 */
	uint8_t     prow_kind[MAX_PROW];
	uint32_t    prow_idx[MAX_PROW];
	uint32_t    n_prow, prow_off;
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

	uint32_t    prow_seen;
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
	int         prow_home;      /* how tall the draft was last frame */
     /* what the draft was when it was written */
	uint64_t    obj_held;       /* bytes of recovered objects being kept */
	int         sizing;
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
	/*
	 * THE DECODER, AND IT IS A FORM RATHER THAN A REPORT.
	 *
	 * Text in, a coding chosen, a key when the coding takes one, plaintext
	 * out - the shape of every decoder tab an analyst already knows.
	 *
	 * A FORM AND NOT AN AUTOMATIC TABLE, and the reason is where the text
	 * comes from: usually NOT this file. It is pasted - out of a log, a
	 * pcap, a mail, a screenshot somebody typed back in - and a box that
	 * could only work on bytes already in the object would be closed again
	 * immediately. "Decode selection" fills the field from the hex pane,
	 * which is the convenience; typing or pasting is the normal case.
	 */
	int         enc_open;
	char        enc_in[ENC_IN_MAX];        /* the encoded text */
	char        enc_key[32];               /* for codings that take one */
	uint32_t    enc_in_off, enc_key_off;   /* how far each field scrolled */
	uint32_t    enc_type;                  /* which coding */
	/*
	 * WHICH WAY - 0 decodes, 1 encodes.
	 *
	 * The box was a decoder only, which is half of what a researcher does
	 * with a coding: the pattern that goes into a signature is the ENCODED
	 * form, so "what does cmd.exe look like in hex" is asked as often as
	 * "what does this hex say". One control, because the two directions
	 * share every other field on the form.
	 */
	int         enc_way;
	uint32_t    enc_res_n;                 /* plaintext bytes, 0 for none */
	int         enc_done;                  /* Decode has been pressed */
	/* The controls, recorded where they are drawn and read where they are
	 * clicked - the arrangement every other dialog here uses. */
	int         e_in[2], e_type[2], e_key[2], e_go[2];
	/* The second button - see draw_enc. `e_go` is Decode. */
	int         e_enc[2];
	/*
	 * THE PLAINTEXT WINDOW: how far down and how far across.
	 *
	 * A decoded script is longer than any box and its lines are longer than
	 * any width, so the result is a WINDOW over it rather than a preview of
	 * it. Both offsets are the reader's, moved by the wheel and by dragging
	 * a selection past the edge, and both are clamped where the window is
	 * drawn - which is the only place that knows how much fits.
	 */
	uint32_t    enc_voff, enc_hoff;
	int         enc_txt_y, enc_txt_x, enc_txt_w, enc_txt_h;
	int         prop_open;      /* the properties page is up */
	/*
	 * A SECOND MODAL PAGE STOOD HERE - the call chain the sweep read and
	 * the trace the interpreter produced, as two tabs of one box. Both
	 * went with the chain matcher. The fields are gone rather than left
	 * at zero, because a dialog's state that nothing ever sets is a
	 * dialog the modal id below still counts.
	 */
	uint32_t    prop_off;       /* the first of its lines on screen */
	/*
	 * "[Copy full path]" on the folder row: which row carries it and which
	 * of that row's columns it occupies, or -1 when the page has no such
	 * row at all.
	 *
	 * Recorded per BUILD rather than per frame because the page scrolls -
	 * the row's index in g_prop is fixed, its position on the screen is
	 * not, so the click converts one to the other with prop_off the way the
	 * select path already does.
	 */
	/*
	 * WHAT IS SELECTED ON THE PAGE, WHICH IS NOT THE SAME AS WHAT WAS CLICKED.
	 *
	 * Clicking used to copy outright, and that is the wrong gesture: a reader
	 * clicks to look, and a click that reaches outside the program and changes
	 * the clipboard is a side effect nobody asked for. Selecting shows what
	 * would be taken and lets it be adjusted; Ctrl+C is when they say to take
	 * it. Same two steps the hex pane already uses, for the same reason.
	 *
	 * Columns index the line's PLAIN text - what prop_plain produces - so the
	 * range means the same thing to the painter and to the copier.
	 */
	/*
	 * Where the mouse went DOWN, which is not where the selection starts.
	 *
	 * A click selects the whole word under it, so the selection's ends are
	 * the word's ends. Dragging must grow from the point that was clicked,
	 * not from whichever end the word happened to put there - otherwise
	 * pulling back over the word does nothing until the pointer passes its
	 * far edge, which is what made dragging feel broken.
	 */
	/*
	 * What is being searched for, and where it was last found.
	 *
	 * `scope` is the one thing a terminal cannot give a modifier for:
	 * Ctrl+Shift+F arrives as the same byte as Ctrl+F on every terminal
	 * that does not implement the newer key protocols, so the choice
	 * between this region and the whole object is made inside the prompt
	 * with Tab rather than by a chord that most terminals cannot send.
	 */
	char        find[80];
	int         find_open;      /* the dialog is up */
	/*
	 * GO TO: an offset typed in, and where it is measured from.
	 *
	 * Its own flag and buffer rather than the find dialog's, because the two
	 * take different things - find takes bytes to look for, this takes one
	 * number - and sharing the field meant a half-typed search turning into
	 * an offset. `goto_file` says whether the number is a FILE offset or an
	 * offset into the region being looked at: both are what somebody means
	 * by "offset" depending on what they are reading, and the hex pane shows
	 * region offsets while every report and every finding names file ones.
	 */
	int         goto_open;
	/*
	 * The shellcode dialog: open, and how far down its byte dump is.
	 *
	 * Separate from the symbol tables' fields even though the two look
	 * alike, because they can be open over each other and a shared offset
	 * would move one when the other scrolled.
	 */
	/*
	 * A DIALOG'S TEXT, AND THE CHARACTERS SELECTED IN IT.
	 *
	 * One set of fields for both dialogs, because only one of them can be
	 * selected in at a time - the boxes are modals, and the topmost owns
	 * the mouse. Two sets would be two things to keep in step for no gain.
	 *
	 * dlg_y0/dlg_x0 are where row 0, column 0 of the recorded text sits on
	 * screen, so a click can be turned into a (row, column) in the text
	 * without the click routing knowing how the box is laid out.
	 *
	 * The anchor is where the drag started and is NOT normalised: a
	 * selection dragged upwards has b before a, and normalising on the way
	 * in would make the anchor move as the pointer does. It is ordered when
	 * it is read, in dlg_span.
	 */
	char        dlg_line[DLG_ROWS][DLG_COLS];
	int         dlg_rows;
	/*
	 * WHERE EACH COLUMN OF A RECORDED ROW BEGINS IN ITS BYTES.
	 *
	 * The screen counts GLYPHS and the recording holds BYTES, and the two
	 * stopped agreeing the day these pages grew box rules: G_V is three
	 * bytes and one column, so from the first wall onwards a click at
	 * column N landed on byte N, three or six bytes to the left of what
	 * the reader pointed at. The highlight was drawn from the same wrong
	 * place, which put its edge in the middle of a glyph - a border that
	 * appeared several words away, and a stray character where the reverse
	 * video repainted half of one.
	 *
	 * Folding the glyphs down to ASCII in the recording would have squared
	 * the arithmetic and changed what a selection PAINTS and COPIES, which
	 * is the thing the recording exists to get right. This keeps the real
	 * bytes and adds the translation: dlg_bx[row][col] is the first byte of
	 * that column and dlg_bx[row][cols] is one past the last, so a span in
	 * columns becomes a span in bytes by two lookups.
	 */
	uint16_t    dlg_bx[DLG_ROWS][DLG_COLS + 1];
	uint16_t    dlg_cols[DLG_ROWS];
	/*
	 * WHICH LINE OF THE LIST each recorded row came from, and -1 when the
	 * recorder was not told.
	 *
	 * The recording is of the VISIBLE WINDOW, rebuilt every frame, so a row
	 * number means "third row on screen" and not "third line of the page".
	 * A selection stored as a row number therefore slid onto whatever the
	 * scroll had put there - the text under the highlight changed while the
	 * highlight stayed still. Anchoring on this instead makes a selection
	 * belong to the LINE it was made on, wherever that line goes.
	 */
	int         dlg_src[DLG_ROWS];
	int         dlg_y0, dlg_x0;
	int         dlg_ar, dlg_ac, dlg_br, dlg_bc;
	int         dlg_have;
	int         dlg_drag;
	/*
	 * THE BOX BEING MOVED, and where the grab started.
	 *
	 * A pointer to the frame rather than a code for which dialog: every box
	 * goes through dframe, the frames are static, and a code would be a
	 * second list to keep in step with the first. NULL when nothing is
	 * being moved.
	 */
	struct dlg_off *dlg_move;
	int         dlg_mx, dlg_my;     /* where the pointer took hold */
	int         dlg_mdx, dlg_mdy;   /* the box's offset when it did */
	/*
	 * THE LAST PRESS IN A DIALOG, so a second one on the same place can be
	 * recognised as a double click.
	 *
	 * Timed rather than counted, for the reason the hex pane's is: a
	 * terminal reports two presses and has no notion of a double click to
	 * pass on. Kept apart from last_click because that one is a byte
	 * OFFSET in the file and this is a place in a recorded page - the same
	 * number would mean two different things, and a click in one pane
	 * would arm a double click in the other.
	 */
	int         dlg_click_r, dlg_click_c;
	uint64_t    dlg_click_ms;

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
	uint32_t    fam_off, num_off;
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
	int         cnd_tg[MAX_GROUP][2];   /* the tag of each condition */
	int         grp_tg[MAX_GROUP][2];   /* the tag of a standalone block matcher */
	/*
	 * THE TAG SOURCES AND THE VIEWS OVER THEM, owned by the session: they
	 * outlive the file being looked at, so the clear that opens another one
	 * keeps the pointer (file_open, proc_open).
	 */
	struct kv_syn *syn;
	/* Manage > Pathogens: the session's catalog and its dialogs (kv_families.h); NULL until first opened. */
	struct kv_fam_ui *fam;
	/* Whether the output pane is listed under the tables - what the
	 * Generate button toggles. Nothing is written either way. */
	int         gen_preview;
	/* The comment boxes, and the condition's own "+ matcher". Recorded per
	 * row as they are drawn, because a row that is scrolled out has no
	 * columns and must not answer a click meant for the one in its place. */
	int         grp_nt[MAX_GROUP][2];
	/* Where a string row's word/case block and its bytes were drawn. Read
	 * back rather than assumed: the columns move when a field widens, and
	 * a click routed by a remembered number goes to the wrong control. */
	int         str_wc[MAX_DECL][2], str_by[MAX_DECL][2];
	int         grp_rl[MAX_GROUP][2], grp_rg[MAX_GROUP][2];
	/*
	 * AN AT MATCHER'S PLACE IS THREE CONTROLS, NOT ONE.
	 *
	 * The anchor names where to count from and opens a list; the sign
	 * says which way and is pressed; the step is typed. They were one
	 * span that opened the list, so the only way to change the number was
	 * to pick a different occurrence of the marker.
	 *
	 * -1 for a row that has none: a matcher that is not an AT, a row that
	 * is scrolled out, and the sign of an anchor that has no choice of
	 * one - see grp_at_sign_free.
	 */
	int         grp_sg[MAX_GROUP][2], grp_of[MAX_GROUP][2];
	char        at_buf[24];     /* the step being typed, as written */
	uint32_t    at_buf_off;
	int         grp_th[MAX_GROUP][2];
	int         cnd_op[MAX_GROUP][2];
	/* Two per condition: its matcher row and its tag row. */
	uint8_t     cseq_kind[2 * MAX_GROUP];
	uint32_t    cseq_idx[2 * MAX_GROUP];
	uint32_t    n_cseq;
	/*
	 * WHERE EACH MATCHER ID ON A CONDITION'S ROW WAS DRAWN.
	 *
	 * Recorded while drawing, the way every other clickable span on these
	 * rows is, rather than recomputed by the hit test from a start column
	 * and a stride. The stride version has been wrong twice - once when the
	 * ids grew past one digit, once when the separator stopped being ", " -
	 * and both times the failure was a click that removed a matcher the
	 * author had not pointed at. There is nothing to keep in step here: the
	 * columns come from the same pass that printed them.
	 *
	 * -1 means "not drawn": the condition does not name that matcher, or
	 * the row is showing a typed expression rather than a list.
	 */
	int         cnd_ids[MAX_GROUP][MAX_GROUP][2];
	/*
	 * And where its TYPED EXPRESSION box is, when the condition carries one
	 * that is not a plain list of ids.
	 *
	 * The box was drawn with a focus colour and the keys to edit it were
	 * wired (edit band 103+i), but nothing recorded a click range and
	 * nothing ever set that band - so a rule loaded from source with an
	 * expression like "(1&2)|3" showed a field that could not be focused or
	 * typed into by any means.
	 */
	int         cnd_ex[MAX_GROUP][2];
	int         cnd_mt[MAX_GROUP][2];
	int         row_rng, row_grp;
	int         pane;           /* 0 tree, 1 hex, 2 markers, 3 draft */
	/*
	 * What the module says about itself, beside the family and the type.
	 *
	 * The two that are already there are a name and an enum; this is the
	 * sentence neither can hold - which family this really belongs to, why
	 * the type was chosen, what the sample was. Written into the generated
	 * source above the declarations, where the next reader meets it before
	 * any of the logic.
	 */

	/*
	 * How far the comment is scrolled inside its own box.
	 *
	 * Its own, not the panel's: the box is one field on a row of fields and
	 * sliding the whole row to read the end of it would take the buttons
	 * off the screen. Follows the caret while the field is being typed
	 * into, so what is being written is always the part on show.
	 */
	uint32_t    note_off;
	/*
	 * Where the caret is in whatever field is being typed into, and which
	 * field that was last time round.
	 *
	 * One caret because only one field is ever open. Comparing the field
	 * against last frame's is how it gets placed at the end of the text
	 * when a field is opened, without every place that opens one having to
	 * remember to say so.
	 */
	uint32_t    caret;
	int         edit_prev;
	/*
	 * WHAT IS SELECTED IN THE OPEN FIELD - a RANGE, unordered.
	 *
	 * It was one flag meaning "all of it", which is what Ctrl+A needs and
	 * is not what a text box is. Dragging the pointer through a pattern to
	 * take half of it, which is how anyone copies part of a string
	 * anywhere else, had nothing to express: the box answered a click with
	 * a caret and that was all it did. So the flag became the two ends of a
	 * range, and Ctrl+A is now the case where they are 0 and the length.
	 *
	 * `fld_a` is the anchor and is NOT normalised - a drag leftwards leaves
	 * b before a, and normalising as it moves would pin the anchor to
	 * whichever end the pointer passed last. Read them through fsel_lo and
	 * fsel_hi.
	 *
	 * Only the field that is OPEN can carry one, so they are cleared
	 * wherever the caret is placed afresh.
	 */
	uint32_t    fld_a, fld_b;
	int         fld_drag;       /* the pointer is extending it */
	/*
	 * WHICH FIELD THE RANGE BELONGS TO - `edit` as it was when the range
	 * was made.
	 *
	 * Without it a range outlives the box it was dragged in: open another
	 * field and the old offsets are painted into it, over text they were
	 * never about. Clearing at every place that assigns `edit` would be a
	 * rule thirty call sites have to remember; comparing is a rule kept in
	 * one place - see fsel_range.
	 */
	int         fld_of;
	int         per;            /* bytes a hex row shows, for click mapping */

	/*
	 * THE TEXT PANE, which is this same pane rendered for something meant
	 * to be read - see KV_CAP_TEXT. Same region, same rgn_at, same
	 * selection, same menu; what changes is the layout and what the status
	 * line counts in.
	 *
	 * rgn_at STAYS THE BYTE OFFSET OF THE TOP OF THE PANE, exactly as the
	 * hex view leaves it. That is what lets goto, find, a marker jump and
	 * every scroll key keep working unchanged: they move a byte offset, and
	 * this pane rounds it down to the start of its line to draw.
	 */
	uint32_t    txt_col;        /* horizontal origin, in columns */
	/*
	 * THE LINE NUMBER OF THE TOP ROW, and an anchor to compute it from.
	 *
	 * Counting newlines from the start of the region every frame is one
	 * pass over the whole region per keystroke - three milliseconds on a
	 * ten megabyte script, on every arrow key. So the last answer is kept
	 * and the next one is counted FROM it, which is a few bytes when
	 * scrolling and a full rescan only when something jumps.
	 */
	uint64_t    txt_anchor;     /* a byte offset whose line number is known */
	uint64_t    txt_anchor_ln;  /* that line number, 0 based */
	/*
	 * The longest line the last frame drew, so sideways scrolling can stop
	 * where the text does. Without it the pane scrolls into blank space and
	 * the reader is left pressing a key that empties the screen - which
	 * reads as the key not working rather than as the end of the line.
	 */
	uint32_t    txt_maxlen;
	/*
	 * THE READER ASKED FOR BYTES, on something this would otherwise show
	 * as text.
	 *
	 * Sticky rather than per object: it is a preference about how to read,
	 * not a fact about a file, and a setting that resets when you step to
	 * the next node is one you set again on every node.
	 */
	uint8_t     hex_forced;
};


#endif /* KV_VIEW_H */
