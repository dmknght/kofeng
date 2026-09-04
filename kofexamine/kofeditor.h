/*
 * kofeditor.h - the signature generator's own state, apart from the viewer's.
 *
 * WHY THIS IS A FILE OF ITS OWN.
 *
 * The generator - the draft a researcher builds, the source it writes, the
 * source it reads back - had grown to sixty-nine functions and three thousand
 * lines inside kofviewer.c, where they sat beside the panes, the tree, the
 * input handling and the disassembler. Nothing forced them apart, so nothing
 * kept them apart: a draft function reached into the selection, a drawing
 * function reached into the draft, and "what is the model" had no answer that
 * could be checked.
 *
 * The measurement that decided the boundary: of those sixty-nine, twenty-two
 * touch no viewer state at all and thirty-eight touch only the draft, the
 * object a marker was taken from, and where a generated rule is to be written.
 * Nine are left, and those really are UI - they read the byte selection, the
 * click position, the tree cursor - so they stay with the UI.
 *
 * WHAT IS NOT HERE.
 *
 * Drawing and input. A model that knows how wide a column is, or which row was
 * clicked, is the same tangle under a new name.
 *
 * Anything the engine already answers. Where a marker is and which region that
 * is come from kof_locate_str in kofinspect.h - the same call the status line's
 * marker list makes - because two answers to one question is how the panel came
 * to call a marker absent that the scan finds every time.
 */

#ifndef KOF_KOFEDITOR_H
#define KOF_KOFEDITOR_H

#include <stdint.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include <kofeng.h>
#include "kofinspect.h"


#define MAX_DECL  32

/*
 * THE LARGEST DECLARATION, AND THE TWO BUFFERS THAT MUST AGREE WITH IT.
 *
 * A hex marker is written three characters to the byte ("2E 2E 5C"), so the
 * spelling of a DECL_BYTES_MAX pattern needs 3*N characters and the scratch a
 * person types into must hold the same. They used to be two unrelated numbers -
 * hexs[512] and sedit[600] - and the gap between them was a silent data loss:
 * a hex marker of 171 bytes or more spells out past 512 characters, so the
 * field opened, took keys, and then decl_edit_commit refused the whole thing
 * for being too long. The edit vanished with no mark on the screen. Whatever
 * can be typed must be committable, which means one number, not two.
 */
#define DECL_BYTES_MAX 512u

/* How many occurrences of one marker the pane will light. Past this the
 * highlight stops being information and starts being a background colour. */
#define DECL_HITS_MAX  64u

/*
 * The right hand end of a string row, in columns from the right edge.
 *
 * The two arrows appear ONLY when there is more than one occurrence to step
 * between: a marker that is in the file once has nowhere to go, and a pair of
 * dead buttons on every row is worse than a row that is shorter.
 */
#define STR_BTN_X     4u        /* [x] */
#define STR_BTN_E     8u        /* [e] */
#define STR_BTN_NEXT 12u        /* [>] */
#define STR_CNT      19u        /* "nn/nn", five wide */
#define STR_BTN_PREV 23u        /* [<] */
#define DECL_HEXS_CAP  (3u * DECL_BYTES_MAX + 16u)

#define MAX_GROUP 8

#define MAX_RANGE 8


/* A string that no condition uses yet. Declaring one must not invent a place to
 * put it: the condition is the researcher's decision and making it for them is
 * the kind of help that has to be undone before anything else can be done. */

/*
 * The optional declarations.
 *
 * KOF_TARGET_FORMAT is required and comes from the parse. These three are not,
 * and each one is a precondition the host checks without entering the module -
 * so adding one is a decision about cost as much as about correctness, and it
 * belongs where the other declarations are rather than being inferred.
 *
 * Their values are seeded from the object, because the object is where a true
 * value comes from: the size of the sample, the architecture it was built for,
 * the kind of file it is. A researcher widens them from there; nobody starts
 * from zero.
 */
enum opt_kind {
	OPT_SIZE_MIN = 0,
	OPT_SIZE_MAX,
	OPT_ARCH,
	OPT_SUBTYPE,
	OPT_COUNT
};



struct decl {
	uint8_t *bytes;
	/*
	 * HOW MANY BYTES ARE IN THE ARRAY, WHICH IS NOT HOW LONG THE PATTERN IS.
	 *
	 * They were one number and could be while every marker was a run of
	 * concrete bytes. A hex pattern is not one: "2E ?? 5C" is three bytes
	 * long in a file and has no byte array at all, and "6A 40 [4-6] 8D" is
	 * six to eight. So `len` is what the pattern covers where it matches -
	 * what the size column shows and what the pane highlights - and
	 * `nbytes` bounds the array, which is empty for any pattern the engine
	 * had to compile.
	 */
	uint32_t nbytes;
	uint32_t span_max;          /* len is the minimum; equal when fixed */
	uint32_t len;
	int      hex;               /* KOF_DEFINE_HEXSTR, else KOF_DEFINE_STR */

	/*
	 * A HEX PATTERN AS IT WAS WRITTEN, WHICH `bytes` CANNOT HOLD.
	 *
	 * `bytes` is a byte sequence. A hex pattern is not one: DEAD??BEEF has a
	 * wildcard, 41[4-8]43 has a gap, 41(42|43)44 has a choice, and none of
	 * the three survives being flattened into bytes. So the spelling is kept
	 * beside them, and it is what gets shown and what gets written back.
	 *
	 * Empty for a literal, and empty for a hex pattern declared from a
	 * selection in this session - those really are concrete bytes and
	 * printing them from `bytes` is exact.
	 *
	 * The bug this exists for: a signature opened WITHOUT its source - the
	 * database keeps strings, not logic - arrived through draft_from_touch,
	 * which copied the pack's (bytes, len) verbatim. For a hex marker those
	 * are the COMPILED PROGRAM and its total length, so ZipSlip's three byte
	 * "2E2E5C" showed as 67 bytes of 010001000300... and, far worse,
	 * Generate wrote that program back out as the pattern. Opening a rule
	 * and saving it replaced it with a different rule.
	 */
	char     hexs[DECL_HEXS_CAP];   /* the pattern, when bytes cannot say it */
	uint32_t obj;               /* which object it was taken from */
	/*
	 * WHERE THIS MARKER IS SEARCHED FOR - which is not one fact but two,
	 * and conflating them is what made the column go stale.
	 *
	 * `mask0` is where the BYTES CAME FROM: the region row they were
	 * selected in. It never changes, and it is zero for a marker read out
	 * of a source file, which says where to look but not where it was
	 * found.
	 *
	 * `mask` is where the rule ACTUALLY LOOKS, which is the union of the
	 * ranges of the matchers that use it, falling back to mask0 when no
	 * matcher does. It is derived, so it is recomputed rather than
	 * remembered - it used to be filled once while reading a source file,
	 * with `|=`, so it could only ever grow: dropping a scan range left
	 * the column reading "X&Y" about a rule that by then searched neither.
	 */
	uint32_t mask0;
	uint32_t mask;
	char     rgn[24];           /* that region's short name */
	/*
	 * WHICH MATCHERS USE IT - a bit each, not a number.
	 *
	 * It was one matcher per marker, and that made "at least three of these
	 * five, otherwise at least two" impossible to express: the second
	 * matcher had to search the same markers as the first, and they could
	 * only be owned once. A marker is a thing to look for; how many
	 * matchers ask about it is their business, not its.
	 *
	 * Zero means no matcher uses it - what GRP_NONE used to say.
	 */
	uint32_t grp;
	/*
	 * WHICH ADDRESS SPACE `at` AND `hits` ARE IN.
	 *
	 * Zero for the object's bytes, which is what everything here assumed.
	 * SYMN_IMP or SYMN_EXP for a marker scoped to a symbol half, whose
	 * offsets are into the BUILT block and are not file offsets at all.
	 *
	 * Without this, every consumer read a block offset as a file offset:
	 * clicking the row jumped the pane to whatever region sits at that
	 * distance from the start of the file - UNCLAIMED, on the sample this
	 * was found with - and the highlighter lit unrelated bytes at the same
	 * number in a pane the marker is not even in.
	 */
	/*
	 * WHICH SPACE `at` AND `hits` ARE IN, as the engine's own scan target.
	 *
	 * Zero for the object's bytes; KOF_SCAN_SYM_IMP or KOF_SCAN_SYM_EXP for
	 * the built symbol block. The engine's name for it rather than the
	 * viewer's row tag, because this is the model: whoever draws it maps it
	 * to whatever a row is called there.
	 */
	uint32_t sym;
	/* Where these bytes are in the object, so the row can jump to them and
	 * the pane can light them. KOF_BROKEN when they are not there at all -
	 * a marker taken from one sample and carried to another. */
	uint64_t at;
	/*
	 * AND EVERYWHERE ELSE IT IS, BECAUSE ONE OF THEM IS NOT THE ANSWER.
	 *
	 * `at` is the occurrence the row reports on - the one inside the region
	 * the module searches, when there is one. The pane lit that one and no
	 * other, so a marker that appears eight times looked like a marker that
	 * appears once, and the seven places worth reading were the seven the
	 * highlight did not point at.
	 *
	 * Kept sorted, and capped: a two byte marker occurs everywhere, and a
	 * list of every offset in a 16 MB object is neither drawable nor worth
	 * drawing. `hits_clipped` says the list is a prefix so the row can say
	 * so rather than imply the count is the whole of it.
	 */
	uint64_t hits[DECL_HITS_MAX];
	/*
	 * AND HOW LONG EACH ONE IS, WHICH IS NOT ONE NUMBER.
	 *
	 * `len` is the SHORTEST a match can be. A pattern with a jump has no
	 * single length - "GET /[4-7].tsunami" covers 17 bytes of "arm5" and 20
	 * of "powerpc" - so lighting `len` bytes at every occurrence cut the
	 * tail off the longer ones, by exactly as much as their jump exceeded
	 * its minimum. The row said "17-20" and the pane lit 17 either way.
	 */
	uint32_t hit_len[DECL_HITS_MAX];
	uint32_t n_hits;
	int      hits_clipped;
	/*
	 * WHICH ONE THE ROW IS POINTING AT.
	 *
	 * Clicking the bytes goes to this one, not to the first: after stepping
	 * to the third occurrence and scrolling away, clicking the row is how
	 * you get BACK to the third. Starting it at the occurrence the row
	 * reports on means the first click still lands where the row says it
	 * will.
	 */
	uint32_t cur_hit;

	/*
	 * How a literal is compared. Both are properties of KOF_DEFINE_STR and
	 * neither exists for a hex pattern - kofsig.h says why: folding case on
	 * a byte that may be a wildcard means nothing, and a word boundary is a
	 * notion of text.
	 */
	int      fullword;
	int      icase;

	/*
	 * The bytes are in the object, but not in the range that searches for
	 * them.
	 *
	 * The one fact that explains a signature which cannot fire however
	 * right it looks, and the panel had no way to say it: the region column
	 * showed the range the matcher DECLARES, so a marker declared in DATA
	 * and actually sitting in CODE read as "DATA, found" on both counts.
	 */
	int      off_rgn;
	char     at_rgn[24];        /* the region it is really in */
	uint32_t at_mask;           /* and that region's bits */
};

/*
 * A declared range: KOF_TARGET_RANGE, exactly.
 *
 * Its own entity rather than a property of a condition, because that is what it
 * is in the module language - a NAMED union of region bits that any number of
 * searches can then name. Which is also what makes the one hard constraint
 * workable: a search call takes one range, so a condition over markers from two
 * regions is impossible until the two regions are one range. Merging them is
 * how that is said, and it is a decision with a cost - a marker in a merged
 * range may then match in either half - so it is a thing somebody does on
 * purpose rather than something the tool arranges quietly.
 */
struct range {
	uint32_t mask;              /* an OR of the format's region bits */
	char     name[40];          /* what the source will call it */
};


/*
 * A condition, and the markers it is about.
 *
 * The group is the thing that is created first: somebody decides "any of these"
 * before deciding which these. What is NOT free is the region - kof_find_str_all
 * and its siblings take ONE range for every string in the call, so a group is a
 * condition over markers that share a region. "Two of these three, in the code
 * section" is a sentence the engine can say; "two of these three, wherever they
 * are" is not.
 *
 * So the region is not chosen, it is learnt: it is fixed by the first marker put
 * into the group, and a marker from anywhere else has to go in a different one.
 * Saying that at the moment of adding beats discovering it at build time.
 */
/*
 * A matcher: one search call, and nothing else.
 *
 * find_all / find_any / find_multi over some markers in one range. It says
 * whether those bytes are there and takes no position on what that means - so
 * it carries no verdict, and the same matcher can be used by two different
 * conclusions.
 */
struct group {
	int      rule;              /* 0 ALL, 1 ANY, 2 threshold */
	uint32_t thresh;
	char     note[512];         /* the author's note, emitted as a comment */
	/* How far it is scrolled inside its own box, for the same reason the
	 * module's comment has one: sliding the whole panel to read the end of
	 * a sentence takes the controls beside it off the screen. */
	uint32_t note_off;
	/*
	 * The range this matcher searches, as a mask.
	 *
	 * Not an index into a list of ranges, because there is no list to keep:
	 * a range has no existence apart from a matcher naming it. Zero means
	 * "the narrowest that holds what I have", recomputed as markers come
	 * and go - which is the answer that is right until somebody decides
	 * otherwise, and the only one that cannot go stale.
	 */
	uint32_t mask;
};

struct cond {
	char     expr[64];          /* over matcher ids */
	/*
	 * Two different combinations, and they are not the same question.
	 *
	 * `op` joins the matcher ids INSIDE this condition - "1 and 2" against
	 * "1 or 2". `join` says how the next condition at this level attaches
	 * to this one: as an alternative tried only when this one misses, or as
	 * a separate test made anyway. A join has nothing to combine unless
	 * there is a sibling below, so it exists only when there is one.
	 */
	int      op;                /* 0 and, 1 or - between this one's ids */
	int      join;              /* 0 alternative, 1 checked as well */
	int      level;             /* enum cnd_level */
	int      var_kind;          /* 0 AUTO, 1 GENERIC, 2 custom */
	char     variant[48];
	int      parent;            /* -1 for a top level block */
};

/*
 * THE DRAFT: everything a rule being written consists of.
 *
 * Lifted out of struct view field for field. The point of naming it is that a
 * function taking one of these cannot reach the tree cursor, the byte
 * selection or a column width even by accident - which is what the sixty-nine
 * functions in kofeditor.c now take instead of the whole viewer.
 *
 * `warn` and `warn_bad` are here rather than with the UI because the sentence
 * is the MODEL's: "String 3 would be empty" is a fact about the draft, and the
 * status line only decides where to put it.
 */
struct kof_draft {
	struct decl  decl[MAX_DECL];
	uint32_t     n_decl, sel_decl;
	char         sedit[DECL_HEXS_CAP];
	uint32_t     sedit_off;
	struct range rng[MAX_RANGE];
	struct group grp[MAX_GROUP];
	uint32_t     n_grp, cur_grp;
	struct cond  cnd[MAX_GROUP];
	uint32_t     n_cnd, cur_cnd;
	char         warn[120];
	int          warn_bad;
	int         opt_on[OPT_COUNT];
	uint64_t    opt_val[OPT_COUNT];
	char        family[64];
	uint32_t    maltype;
	char        expr[96];
	int         gen_ok;
	int         from_rule;
	char        gen_path[600];
	uint32_t    rng_mask;
	uint32_t    rng_add[MAX_GROUP];
	uint32_t    n_rng_add;
	uint32_t    decl_cap;
	uint32_t    saved_hash;
	char        note[512];
};


/* ---- reading a signature back out of its source ---------------------------
 *
 * The pack has the strings and the names; it does not have the logic, because
 * the logic is compiled code. So a rule shown in the panel has to come from the
 * file it was written in, and the file has to be found: the family names it,
 * except that a family may name several - bases/signatures/mirai.c and
 * mirai_42bb.c both declare "Mirai" on purpose - so the line each detection
 * carries is what settles it.
 *
 * Read the restricted way ksigbuilder reads them. Anything this cannot parse is
 * left out of the draft rather than guessed at, and the panel says how much of
 * the file it understood.
 */
#define SRC_MAX_LINES  64u
#define SRC_MAX        512u


struct src_ent {
	char     family[80];
	char     path[512];
	uint32_t line[SRC_MAX_LINES];
	uint32_t n_line;
	/*
	 * What this file searches for, independent of how it is written.
	 *
	 * A sum of per-string hashes, so reordering the declarations does not
	 * change it - which is the point: two signatures that look different
	 * only because their KOF_DEFINE_STRs are in another order are one
	 * signature written twice, and the database pays for both.
	 */
	uint32_t pat;
	uint32_t n_pat;

	/*
	 * What this file targets, folded the same way.
	 *
	 * Separate from the patterns because it answers a different question.
	 * Two modules can look for exactly the same bytes and still be two
	 * modules: the rootkit itself is a relocatable object and the thing
	 * that installs it is an executable, so the same five kernel symbol
	 * names mean a different family, a different malware type and a
	 * different subtype. Comparing patterns alone called that pair a
	 * duplicate and greyed out Save As on the second one.
	 */
	uint32_t tgt;
};

extern struct src_ent *g_src;
extern uint32_t g_n_src;
extern int g_src_done;

/* A name the generated source uses for a marker, paired with its index - how a
 * rule read back off disk is matched up with the draft's own strings. */
struct sname { char id[40]; uint32_t idx; };

uint32_t tgt_mix(uint32_t h, const char *tok);


struct object {
	char      name[256];
	uint8_t  *own;              /* the copy, NULL for the mapped top level */
	void     *mapped;           /* or a spill file, mapped instead of copied */
	uint64_t  mapped_len;
	int       too_big;          /* kept nowhere: past the session's budget */
	kof_buf   buf;
	uint32_t  depth;            /* how many "//" its name carries */

	const struct kof_inspect_fmt *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	char            **finding;
	uint32_t          n_finding;
	char              packer[48];   /* the module that opened or unpacked it */
	/*
	 * The interpreter has already been run on this object.
	 *
	 * Asking twice cannot produce a different answer - the bytes have not
	 * changed and the run is deterministic - so a second press appended a
	 * second identical set of children, and a third a third. Recorded per
	 * object because the question is per object.
	 */
	int               emu_done;
	/*
	 * What the scanner's own gate makes of this object, when no module
	 * claimed it: KOF_EMU_UNP_* . Computed once beside the parse rather
	 * than while drawing - it reads every executable segment, and the
	 * status line is repainted on every keystroke.
	 */
	uint8_t           emu_why;
	/*
	 * The version that module read out of the object, or -1 for none.
	 *
	 * Signed and not a flag beside a uint, because 0 is a version a container
	 * can carry and "it never said" has to be a different answer from "it
	 * said zero".
	 *
	 * It is the FORMAT version the module found in the file - UPX's l_info
	 * byte, RAR's archive version - and not the packer's release. The two get
	 * confused, so nothing here pretends to know that a UPX l_info of 13
	 * means UPX 3.9x: the module reported a field called version and this
	 * shows the field.
	 */
	long long         packer_ver;
	/* What the engine said about this object, kept whole. */
	struct kof_result heur;
	/*
	 * Whether the engine got to the end of THIS object, and what stopped it.
	 *
	 * Kept per object rather than for the file, because it is per object: a
	 * container that opened may hold one entry it could not, and the packed
	 * parent being incomplete says nothing about the child that came out of
	 * it. enum kof_broken, KOF_BROKEN_NONE when it finished.
	 */
	uint32_t          broken;
	struct kof_touch *touch;
	uint32_t          n_touch;

	/*
	 * The object's symbol records, in the KSYM layout kofsym.h fixes.
	 *
	 * Built ONCE, when the object is parsed, and right-sized: the cap is
	 * 4096 records and a scratch of that size for each of MAX_OBJ objects
	 * would be thirty megabytes held to show a table nobody may open, while
	 * the real counts are tens to a few thousand. NULL and zero for a file
	 * with no symbols and for every non-ELF - which is a normal answer, not
	 * a failure, so nothing downstream treats it as one.
	 */
	/*
	 * THE OBJECT'S SYMBOL BLOCK - the engine's, one copy, unsplit.
	 *
	 * It used to be two blocks that this file built by copying records out
	 * of the engine's according to their UNDEFINED flag. That was a second
	 * implementation of "which half is this symbol in", and it disagreed
	 * with the engine's: the engine coalesces adjacent records of one half
	 * into runs, so a pattern is never matched across a record of the other
	 * half, while a copied half joins records the engine keeps apart. On
	 * 23.8% of files the halves interleave, so the two really did answer
	 * differently.
	 *
	 * Now the block is whatever kof_syms_build returned and the halves are
	 * kof_sym_extents' answer - the same call kof_find_str makes.
	 */
	uint8_t          *sym;
	uint32_t          sym_n;

	/* The address a heuristic named as a carried payload, and its length, or
	 * zero when none did. Reported through kof_debug - see on_debug. */
	uint64_t          payload_at;
	uint64_t          payload_len;
	/* Set on the CHILD this viewer built from a parent's payload, so the
	 * menu can find it without inferring anything from the name. A name
	 * test alone would also match an unpacker's child that happened to sit
	 * under the same parent. */
	int               payload_of;
	/*
	 * WHICH VARIABLE IT CAME OUT OF, and what was wrapped round it.
	 *
	 * Kept on the child rather than left in its name: the name says what
	 * the object is, and the symbol is a fact about where in the PARENT it
	 * was found. A reader wants both, and only one of them belongs in a
	 * tree row eighteen columns wide.
	 */
	char              payload_sym[KOF_SYM_NAMELEN + 1];
	int               payload_b64;
};
/*
 * WHAT THE EDITOR IS DRIVING: the draft, plus the little of its surroundings a
 * draft actually refers to.
 *
 * Measured rather than guessed. Of the forty-two model functions, three need
 * the object a marker was taken from, two the directory a rule is written to,
 * and one each the sample's path, the engine and whether the file is somebody
 * else's. Nothing else. So those seven are here and the rest of the viewer -
 * the tree, the panes, the selection - is not reachable from a function that
 * takes one of these.
 *
 * The four pointers borrow the host's storage rather than copying it: `n_obj`
 * and `foreign` change while a session runs, and a copy of a number that
 * changes is a number that goes stale.
 */
struct kof_editor {
	struct kof_draft   dr;

	struct object     *obj;      /* the host's array, not owned */
	const uint32_t    *n_obj;    /* live: objects appear as children are found */
	const uint32_t    *foreign;  /* live: set per file that is opened */
	struct kof_engine *eng;
	const char        *basedir;  /* where a generated rule is written */
	const char        *path;     /* the sample the draft is written against */
	/* What a generated rule says about itself: which samples it was written
	 * from and who wrote it. Live, because a session opens more files. */
	/* Written as well as read: recording which sample a rule came from and
	 * who wrote it is the editor's job, not the pane's. */
	char             (*sample)[128];
	uint32_t          *n_sample;
	char             (*who)[48];
	uint32_t          *n_who;
	/*
	 * A POINTER TO THE ARRAY, not to its first byte.
	 *
	 * As `char *` this compiled and `sizeof e->made` silently became eight
	 * - the pointer's size - so the date was written into a 24 byte buffer
	 * through a bound of 8. Pointing at the array keeps the size with it.
	 */
	char             (*made)[24];
	uint32_t          *foreign_w;   /* the same flag, writable */
	struct kof_range  *scratch;  /* KOF_SCAN_MAX_EXTENTS, the host's */
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
void say_note(struct kof_editor *e, const char *fmt, ...);
int meta_has_sample(struct kof_editor *e);
int name_chars_ok(const char *s);

int grp_same_call(struct kof_editor *e, uint32_t a, uint32_t b);
uint32_t grp_lead(struct kof_editor *e, uint32_t g);
const char *draft_missing(struct kof_editor *e);
void decl_locate(struct kof_editor *e, struct decl *d);
uint32_t decl_free(struct kof_editor *e);
uint32_t grp_mask(struct kof_editor *e, uint32_t g);
uint32_t grp_count(struct kof_editor *e, uint32_t g);
int grp_has_range(struct kof_editor *e, uint32_t g);
void grp_add(struct kof_editor *e);
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap);
void cnd_canon(struct kof_editor *e, uint32_t g, char *out, size_t cap);
int cnd_more_siblings(struct kof_editor *e, uint32_t i);
int cnd_depth(struct kof_editor *e, uint32_t i);
void grp_remove(struct kof_editor *e, uint32_t g);
void cnd_add(struct kof_editor *e, int nested);
void cnd_remove(struct kof_editor *e, uint32_t i);
uint32_t cnd_children(struct kof_editor *e, uint32_t i);
uint32_t grp_thresh_eff(struct kof_editor *e, uint32_t g);
int grp_same_set(struct kof_editor *e, uint32_t a, uint32_t b);
int grp_shared(struct kof_editor *e, uint32_t g);
uint32_t draft_hash(struct kof_editor *e);
const char *draft_sample(struct kof_editor *e);
int draft_edited(struct kof_editor *e);
int draft_dirty(struct kof_editor *e);
void src_index(struct kof_editor *e);
const char *src_of(struct kof_editor *e, const struct kof_touch *t);
uint32_t draft_tgt(struct kof_editor *e);
const char *draft_dup(struct kof_editor *e, int *near);
const char *draft_missing_of(struct kof_editor *e, int as_new);
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
 * Sizes spelled out because the tables are defined in kofeditor.c and sizeof
 * cannot see across a translation unit; the definitions assert they agree.
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
extern const char *const fmt_word[];
extern const uint32_t fmt_word_n;
extern const char *const maltype_word[];
extern const uint32_t maltype_word_n;

void emit_call_as(FILE *f, struct kof_editor *e, uint32_t g, int force_multi);
void emit_call(FILE *f, struct kof_editor *e, uint32_t g);
void emit_call_multi(FILE *f, struct kof_editor *e, uint32_t g);
void emit_matcher(FILE *f, struct kof_editor *e, uint32_t g);
void emit_expr(FILE *f, struct kof_editor *e, const char *expr);
void emit_note(FILE *f, const char *note, int depth);
void emit_verdict(FILE *f, const struct cond *c, int depth);
void emit_cond(FILE *f, struct kof_editor *e, uint32_t i, int depth, int chained);
void draft_reset(struct kof_editor *e);
int draft_from_source(struct kof_editor *e, const char *path);
void draft_from_touch(struct kof_editor *e, const struct kof_touch *t);
void generate(struct kof_editor *e, int as_new);

/*
 * How long a scan_range_ identifier can get: the prefix, plus the longest
 * region name rng_name_of produces (a join of every region word - for ELF
 * "headers_code_data_noload" is 24 characters on its own), plus the terminator.
 * Named so the two callers and this function cannot be sized differently -
 * which is how the identifier came to be cut in the first place.
 */
#define RNG_IDENT_MAX 64


/*
 * The architectures, as the enum spells them.
 *
 * All of them, not the one this object happens to be: a signature for a family
 * that ships an arm build and an x86 one is written from whichever sample is to
 * hand, and being offered only that sample's architecture is how a signature
 * ends up narrower than the family it names.
 */


/*
 * A condition: what some combination of matchers MEANS.
 *
 * This is where the flexibility lives, and where bases/signatures already puts
 * it. lkm_rootkit_general.c is the shape: one matcher gates the file as a
 * rootkit at all, and three more each name a different family inside that gate.
 * Neither half of that is expressible if a verdict is welded to a search -
 * the gate concludes nothing on its own, and the three share it.
 *
 * So a condition is an expression over matcher ids ("1", "1&2", "(1&2)|3"), a
 * verdict, and optionally a parent it sits inside. A condition with children
 * concludes nothing itself: it is the gate, and its children are what happens
 * once it holds.
 */
/*
 * What a condition concludes.
 *
 * LV_NONE is not "undecided" - it is a branch that matched and reports nothing
 * on purpose, which is the only way to say "these bytes are here and they are
 * fine" in a chain of alternatives. It also lets a gate stay a gate.
 */
enum cnd_level { LV_INFECT = 0, LV_SUSPECT, LV_NONE, LV_COUNT };

void draft_clear(struct kof_editor *e);
int meta_take(struct kof_editor *e, const char *t);

/*
 * The banner this tool opens its own header block with.
 *
 * One string, tested only against the first line of a block, and it identifies
 * a whole block rather than a line: what the tool generates and what the author
 * wrote are separate comments, so recognising the banner is enough to tell them
 * apart and nothing has to guess at the prose inside either one.
 */
#define HEAD_BANNER "Generated by KOFViewer"

void head_put(char *dst, size_t cap, size_t *n, const char *s, size_t len);

int body_modelled(const char *line);

/* How many samples and authors one rule's history holds. Past this the oldest
 * are dropped rather than the file growing without bound - a rule tested against
 * forty samples is a rule whose first ten no longer say much. */
#define MAX_META  16

/* ---- what kofeditor.c answers ------------------------------------------- */

void decl_put_literal(FILE *f, const uint8_t *b, uint32_t n);
int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags);
int rng_holds(uint32_t rmask, uint32_t region);
int cnd_uses(const struct cond *c, uint32_t g);
void rng_name_of(const struct kof_inspect_fmt *fmt, uint32_t mask,
			char *out, size_t cap);
void rng_ident(const struct kof_inspect_fmt *fmt, uint32_t mask,
		      char *out, size_t cap);
const char *src_ident(const char *p, char *out, size_t cap);
uint32_t decl_pat(const struct decl *d);
void src_forget(void);
int src_read(const char *path, struct src_ent *out);
void src_scan(const char *dir, int depth);
uint32_t src_mask_of(const struct kof_inspect_fmt *fmt, const char *e);
int decl_from_hexs(struct decl *d);
int src_quoted(const char *p, char *out, size_t cap);
uint32_t src_str_idx(struct sname *tab, uint32_t n, const char *id);
int decl_text_editable(const struct decl *d);
void cnd_drop_matcher(struct cond *c, uint32_t g);

#endif /* KOF_KOFEDITOR_H */
