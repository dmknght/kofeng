/*
 * kofeditor_proto_fn.h - the draft model's session struct and the functions that act on a draft.
 *
 * THE DIAGNOSE GENERATOR'S DRAFT, A PROTOTYPE (see kofeditor_proto_types.h): struct kof_editor and
 * every prototype kofeditor.c defines, moved verbatim from kofeditor.h. The object facts
 * (obj_sha256) and the notes (say_err, say_note) sit among them as they did.
 * A part of kofeditor.h, included by it and by nothing else.
 */
#ifndef KOF_KOFEDITOR_PROTO_FN_H
#define KOF_KOFEDITOR_PROTO_FN_H

struct kof_editor {
	struct kof_draft   dr;

	struct object     *obj;      /* the host's array, not owned */
	const uint32_t    *n_obj;    /* live: objects appear as children are found */
	struct kof_engine *eng;
	struct kof_range  *scratch;  /* KOF_SCAN_MAX_EXTENTS, the host's */
	/*
	 * WHICH FIELD THE HOST HAS OPEN, borrowed the way the tables above are.
	 *
	 * The model does not interpret the number - how a host names its boxes
	 * is the host's business. It only CLEARS it, and only when a row that
	 * a box could be open on has just gone: removing a matcher shifts every
	 * one after it, so a caret that was in matcher 3 is now in what used to
	 * be matcher 4, typing into a rule nobody asked to edit.
	 *
	 * Cleared rather than adjusted because after a removal there are two
	 * cases - the row went, or it moved - and "no box open" is the only
	 * answer that is right in both. The same fix as blk_moved, for the same
	 * reason, at the one level that can see every removal.
	 */
	int               *edit;
	/*
	 * WHICH OBJECT THE DRAFT IS BEING WRITTEN ABOUT.
	 *
	 * The one piece of UI state the model genuinely needs: a rule is
	 * written from what the reader is looking at, and two functions ask -
	 * the one that records which sample it came from, and the one that says
	 * what is still missing. Set by the host wherever the selection moves,
	 * which is one place.
	 */
	uint32_t           cur;
};

void say_err(struct kof_editor *e, const char *fmt, ...);
/* ---- what an object IS, worked out once - see the definitions ---- */
void    obj_sha256(struct object *o);

void say_note(struct kof_editor *e, const char *fmt, ...);

void decl_locate(struct kof_editor *e, struct decl *d);
uint32_t decl_free(struct kof_editor *e);
uint32_t grp_mask(struct kof_editor *e, uint32_t g);
uint32_t grp_count(struct kof_editor *e, uint32_t g);
int grp_has_range(struct kof_editor *e, uint32_t g);
void grp_add(struct kof_editor *e);
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap);
void cnd_canon(struct kof_editor *e, uint32_t g, char *out, size_t cap);
void grp_remove(struct kof_editor *e, uint32_t g);
void cnd_add(struct kof_editor *e);
void cnd_set_op(struct kof_editor *e, uint32_t i, int op);
void cnd_remove(struct kof_editor *e, uint32_t i);
uint32_t grp_thresh_eff(struct kof_editor *e, uint32_t g);
void grp_seed_at(struct kof_editor *e, uint32_t g);
uint32_t draft_hash(struct kof_editor *e);

/*
 * THE SAMPLE LINE: its name AND the hash of the bytes it was written from.
 *
 *     Test sample: shell.asp  sha256:9f86d081...
 *
 * A name is what a file was called on one machine. Two researchers comparing
 * rules, or one of them coming back to this a year later, cannot tell from
 * "shell.asp" whether they are holding the same bytes - and the hash is already
 * computed for the object, beside the parse, so recording it costs nothing.
 *
 * IT IS THE HASH OF THE OBJECT THE RULE IS BEING WRITTEN ABOUT, which for a
 * carried payload is the payload and not the dropper around it - see
 * struct object's sha256, which says why that is the useful one.
 *
 * Written as one string because it is one fact about one sample: the reader
 * takes the rest of the line as the entry, so the pair survives a round trip
 * without a second list to keep in step with the first.
 */
int draft_edited(struct kof_editor *e);
void draft_mark_saved(struct kof_editor *e);
/* `near_miss` and not `near`: mingw's headers still #define near and far as the
 * empty macros 16-bit compilers needed, so a parameter with that name compiles
 * everywhere except Windows, where it vanishes and the call site stops parsing. */
void rng_retarget(struct kof_editor *e, uint32_t was, uint32_t now);
uint32_t rng_removable(struct kof_editor *e, uint32_t *mask, int *unused, uint32_t cap);
uint32_t rng_all(struct kof_editor *e, uint32_t *mask, int *unused, uint32_t cap);
void rng_add_drop(struct kof_editor *e, uint32_t mask);
void rng_delete(struct kof_editor *e, uint32_t mask, int unused);
void rng_apply(struct kof_editor *e, int verb, uint32_t target, uint32_t here);
void draft_refresh(struct kof_editor *e);
void decl_sync_ranges(struct kof_editor *e);
void decl_edit_commit(struct kof_editor *e, uint32_t i);
void decl_remove(struct kof_editor *e, uint32_t i);

/*
 * SPELLED OUT, because the table is defined in kofeditor.c and sizeof cannot
 * see across a translation unit. The definition there asserts the two agree, so
 * adding a word without adding one here does not compile.
 */

/*
 * THE WORDS A RULE IS WRITTEN IN.
 *
 * The architecture names, the ELF and PE subtype names, the format names and
 * the malware-type names are the vocabulary of a KOF_TARGET_ declaration, so
 * they belong with the thing that writes and reads those declarations rather
 * than with the pane that happens to show them in a menu.
 *
 * The counts come with them because sizeof cannot see across a translation
 * unit; each is a variable filled by sizeof where the table is defined, so it
 * cannot disagree with the table it counts.
 */

struct kof_arch_word { const char *word; uint32_t val; };

/* The counts are variables, not macros - see the note in kofeditor.c. */
#define ARCH_N       arch_n
#define ELF_SUB_N    elf_sub_n
#define PE_SUB_N     pe_sub_n
#define FMT_WORD_N   fmt_word_n
#define MALTYPE_N    maltype_word_n

extern const struct kof_arch_word arch_word[];
extern const uint32_t arch_n;
extern const char *const elf_sub[];
extern const uint32_t elf_sub_n;
extern const char *const pe_sub[];
extern const uint32_t pe_sub_n;
/* The script kinds, for the same job - see script_sub in kofeditor.c. */
extern const char *const script_sub[];
extern const uint32_t script_sub_n;
/* And the platforms a process record can be from. */
extern const char *const proc_sub[];
extern const uint32_t proc_sub_n;
/* The identifier for a target value - "KOF_FMT_ZIP" - out of the engine's own
 * list rather than a copy here. See fmt_word in kofeditor.c. */
extern const uint32_t fmt_word_n;
extern const char *const maltype_word[];
extern const uint32_t maltype_word_n;

void draft_reset(struct kof_editor *e);

/*
 * Does this draft name a similarity block at all, and which matcher names one.
 *
 * Asked by everything that has to agree about it: where the rule is written,
 * what it includes, which block declarations are emitted, what the matcher menu
 * may offer, and whether a ticked block is still waiting for a matcher.
 */
uint32_t grp_of_block(const struct kof_editor *e, uint32_t blk);
void grp_label(const struct kof_editor *e, uint32_t g, char *out, size_t cap);
int grp_make_sim(struct kof_editor *e, uint32_t g);

/*
 * THE ITEMS OF A SIMILARITY MATCHER - added, removed and asked about through
 * these rather than by reaching into the array.
 *
 * Every one of them takes the pair (what, blk) as the item's IDENTITY: `blk`
 * is read only for SIM_IT_BLOCK, so the whole-object measure is one
 * per matcher and a block is one per block. That is what makes "is this
 * already here" answerable, and a matcher that held the same measure twice
 * would emit the same comparison twice.
 */
int grp_sim_add(struct kof_editor *e, uint32_t g, uint32_t what, uint32_t blk);
void grp_sim_del(struct kof_editor *e, uint32_t g, uint32_t i);
int grp_sim_has(const struct kof_editor *e, uint32_t g, uint32_t what,
		uint32_t blk);
/* Which matcher holds this item, or MAX_GROUP when none does. */
uint32_t grp_sim_of(const struct kof_editor *e, uint32_t what, uint32_t blk);
/* The default threshold for a measure: where each was measured, not one
 * number for all. See the notes on the SIM_IT_* kinds. */
uint32_t sim_pct_default(uint32_t what);
/* What a measure is called on the panel and in a menu. */
void blk_set_picked(struct kof_editor *e, uint32_t i, int on);
int blk_clears(const struct kof_editor *e, uint32_t i);
void blk_moved(struct kof_editor *e, uint32_t from, uint32_t to);
void blk_permute(struct kof_editor *e, const uint32_t *to, uint32_t n);



/*
 * The architectures, as the enum spells them.
 *
 * All of them, not the one this object happens to be: a signature for a family
 * that ships an arm build and an x86 one is written from whichever sample is to
 * hand, and being offered only that sample's architecture is how a signature
 * ends up narrower than the family it names.
 */


/*
 * A condition: what some combination of matchers MEANS - an expression over
 * matcher ids ("1", "1&2", "(1&2)|3") and the diagnose tag it finds.
 */

/*
 * THE THREE TABS OF THE DIAGNOSE PANEL, and what each one writes.
 *
 *   DT_PATTERNS  strings, their matchers (find_str, find_at) and conditions
 *   DT_BLOCKS    similarity blocks, one find_similar matcher per ticked block
 *   DT_GRAPHS    the diagnoses that matched, as a table
 *
 * The type, the family and the options are declared once for the whole draft.
 */
enum draft_tab { DT_PATTERNS = 0, DT_BLOCKS, DT_GRAPHS, DT_COUNT };

/* The tab a matcher belongs to, which follows from its kind alone, and how many
 * matchers a tab holds. Only Patterns has conditions, so a condition is made of
 * DT_PATTERNS matchers. */
uint8_t grp_tab(const struct kof_editor *e, uint32_t g);
uint32_t grp_tab_count(const struct kof_editor *e, uint8_t tab);
/*
 * THE DIAGNOSE UNITS - one list for everything that needs to know which exist and where their Type and
 * Tag cells are: the draw, the hit zones made from what was drawn, the file names, the preview and the
 * writer. THE RULE: a Patterns CONDITION is a unit and a Blocks MATCHER is a unit; nothing else is.
 * draft_units: the output order (conditions, then block matchers). draft_units_on_tab: the ones the tab
 * lists (Patterns: conditions, Blocks: matchers, Graphs: none). draft_unit_find: the position in the
 * output order, -1 for a non-unit (a string matcher). draft_unit_name: its file name ("" for a non-unit).
 */
struct draft_unit {
	uint8_t     is_grp;   /* 0: struct cond cnd[idx] (Patterns), 1: struct group grp[idx] (Blocks) */
	uint32_t    idx;
	uint8_t     utype;    /* a copy of the unit's own */
	const char *tag;      /* points into the draft */
};
#define DRAFT_UNIT_MAX 16u   /* a condition and a matcher each, MAX_GROUP of both (checked in kofeditor.c) */
uint32_t draft_units(const struct kof_editor *e, struct draft_unit *out, uint32_t cap);
uint32_t draft_unit_count(const struct kof_editor *e);
uint32_t draft_units_on_tab(const struct kof_editor *e, uint8_t tab, struct draft_unit *out, uint32_t cap);
int draft_unit_find(const struct kof_editor *e, int is_grp, uint32_t idx);
void draft_unit_name(const struct kof_editor *e, int is_grp, uint32_t idx, char *out, size_t cap);

/*
 * THE FILE NAME a diagnose would have, in the form
 * `<first type>_<family>_<tag>_<id>.c`, every word the tag's own: its first
 * type in the order the tag declares them, its family, its name. Lower case,
 * only [a-z0-9_-]; a type or family a tag does not have is left out, so no
 * underscore is doubled. The id is a running number per prefix, at least two
 * digits, counted over the conditions in order and then the block
 * matchers in order - the order a Save would write them in. A diagnose with no
 * tag has `<tag>` in its place, so the gap is in the name itself. Nothing is
 * written anywhere.
 */
void cnd_file_name(const struct kof_editor *e, uint32_t ci, char *out,
		   size_t cap);
void grp_file_name(const struct kof_editor *e, uint32_t g, char *out,
		   size_t cap);
/* The generator's output: the declarations of one unit (shared by the preview and the writer), and the writer. */
struct kof_dsrc;
void draft_unit_items(const struct kof_editor *e, const char *stem, uint8_t utype,
		      const char *tag, struct kof_dsrc *d);
/*
 * SAVE: what was ADDED is written and what was REMOVED is deleted, both by the LINK between a unit and the diagnose it was loaded
 * from (struct group.link, struct cond.link; the loaded list is kof_draft.loaded). A unit with no link is new; a loaded link that no
 * unit carries any more is removed (its file is deleted); a linked unit that still equals its file is untouched; a linked unit that no
 * longer equals its file is MODIFIED - reported in the status line, neither written nor the cause of a deletion (editing is not done).
 * All or nothing: the plan is made first and a failure part way puts the tree back. Returns the files written, or -1 (msg says why).
 */
int draft_generate(struct kof_editor *e, const char *dir, char *msg, size_t cap);
int draft_generate_with(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form);
/* The file system the Save acts through: the writer's own tests swap it to make a step fail part way. Create is fopen "wbx". */
struct draft_fs {
	void *ud;
	FILE *(*create)(void *ud, const char *path);
	int   (*unlink)(void *ud, const char *path);
};
int draft_generate_fs(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form, const struct draft_fs *fs);
/*
 * THE LINKS. draft_link_unit links unit (is_grp, idx) to the diagnose of db id `id` (kof_diag_report.id, a value) whose name the engine gave as `name`, a file of the tree `dir`, only when the
 * draft regenerates exactly what the file says (1), else nothing changes (0). draft_links_reset forgets every link and the loaded list
 * (a new object, a discarded draft). draft_unit_link is the link of a unit (0 for new); draft_links_loaded how many diagnoses are
 * loaded; draft_links_removed how many of them no unit carries any more (what a Save would delete).
 */
int draft_link_unit(struct kof_editor *e, int is_grp, uint32_t idx, const char *dir, uint32_t id, const char *name);
/* The diagnoses directory the names of new units are numbered against (the viewer's bases/diagnoses): the name the panel shows is the name Save writes. */
void draft_set_tree_dir(struct kof_editor *e, const char *dir);
void draft_links_reset(struct kof_editor *e);
uint32_t draft_unit_link(const struct kof_editor *e, int is_grp, uint32_t idx);
uint32_t draft_links_loaded(const struct kof_editor *e);
uint32_t draft_links_removed(const struct kof_editor *e);
/* The detection declarations of unit (is_grp, idx) appended to `d` (NULL, or why the unit has no source). */
const char *draft_unit_form(const struct kof_editor *e, int is_grp, uint32_t idx, struct kof_dsrc *d);


void draft_clear(struct kof_editor *e);





/* ---- what kofeditor.c answers ------------------------------------------- */

int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags);
int rng_holds(uint32_t rmask, uint32_t region);
/*
 * The matcher numbers of a condition's expression are the numbers of the Patterns
 * tab: grp_loc is the number of matcher `g` on its tab (0 if there is none),
 * cnd_has_id the
 * plain question "is this number written in the expression" and cnd_uses the
 * one the panel asks - is matcher `g` one this condition names. cnd_foreign is
 * 0 for an expression whose every number is a Patterns matcher's, else the
 * first number that is not, plus one: a reference to a block matcher or
 * to none, which is refused rather than read as something else.
 */
uint32_t grp_loc(const struct kof_editor *e, uint32_t g);
int cnd_has_id(const struct cond *c, uint32_t id);
int cnd_uses(const struct kof_editor *e, const struct cond *c, uint32_t g);
unsigned long cnd_foreign(const struct kof_editor *e, const struct cond *c);
void rng_name_of(const struct kof_parser *fmt, uint32_t mask,
			char *out, size_t cap);
int decl_from_hexs(struct decl *d);
int decl_text_editable(const struct decl *d);
/*
 * The three edits a condition's id row can make to one of its matchers, and
 * the question the row asks before drawing it.
 *
 * A negated id is written "!1" in the expression rather than kept in a flag
 * beside it. The expression is also a TEXT BOX the author can type in, so a
 * flag would be a second place the same fact lived - and the two would part
 * company the first time somebody edited the text by hand.
 */
int  cnd_neg(const struct kof_editor *e, const struct cond *c, uint32_t g);
void cnd_drop_matcher(const struct kof_editor *e, struct cond *c, uint32_t g);
void cnd_negate_matcher(const struct kof_editor *e, struct cond *c,
			uint32_t g);
void cnd_swap_matcher(struct kof_editor *e, uint32_t ci, uint32_t g,
		      uint32_t to);


#endif /* KOF_KOFEDITOR_PROTO_FN_H */
