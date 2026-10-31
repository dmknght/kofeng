#ifndef KOFENG_DIAGFORM_H
#define KOFENG_DIAGFORM_H

/*
 * pack/diagform.h - THE DETECTION FORM OF A DIAGNOSE: what a signature used to declare (string markers, a named
 * range, similarity blocks) and to compute in its kof_scan (and / or / not over the answers), as one value.
 *
 * ONE REPRESENTATION for every owner of it: the source reader's resolver (databases/diagsrc_form.c) FILLS a
 * struct kof_form, ksigbuilder writes it as the KDIG_SEC_FORM sections of the record, the pack loader READS it back
 * (kof_diag_load), the engine's evaluator walks it, and the editor's Generate reaches it through the source. The
 * encoder and the decoder are the two functions below and nothing else spells the wire layout.
 *
 * WHAT A FORM ASKS AND WHO ANSWERS. A MATCHER is one question: "FIND" (the markers it names, searched in a region
 * mask - all of them, any of them, at least `thresh` of them - or one marker at an offset counted from the object's
 * start, entry point or end) or "SIM" (every block it names scores at least `pct` percent). The engine answers a
 * FIND with the pattern matcher over the extents of the mask (the search a module's kof_find_str asks) and a SIM
 * with the similarity set's kof_mutation_pct; this layer only says WHAT is asked. An EXPRESSION is a tree of
 * leaf (a matcher), not, and, or over the matchers, in an array whose children come before their parent, the root
 * last: evaluated depth first with the C operators' short circuit, a matcher answered at most once per object.
 *
 * THE WIRE, little endian, a stream of items [tag u8][len u16][body] cut into KDIG_SEC_FORM sections of at most 255
 * bytes (the loader concatenates the bodies; a cut may fall anywhere):
 *
 *   STR   (1)  kind u8 (KOF_STR_LITERAL | KOF_STR_HEX), flags u8 (KOF_STR_*), then the bytes of the literal or the
 *              compiled hex program (what a .ksig pack's string pool holds, so one matcher reads both)
 *   FIND  (2)  rule u8, thresh u8 (MULTI), anchor u8 (AT), nargs u8, mask u32, at i64, then nargs string indices
 *   BLOCK (3)  mask u32, reserved u8 (0; it was the normalizer, removed 2026-10-31: any other value is refused), side u8, n_hash u16, then n_hash u32
 *   SIM   (4)  pct u8, nargs u8, then nargs block indices
 *   EXPR  (5)  n u8, then n x { op u8, a u8, b u8 }
 *
 * Matchers are numbered in the order their FIND and SIM items appear, strings and blocks in the order of theirs. A
 * stream, an index or an expression that does not add up is REFUSED WHOLE by the decoder (a form half read is a
 * diagnose that matches something its author did not write); every bound below is a hard limit that fails with a
 * reason and never cuts (CLAUDE.md rule 4: it bounds the cost of a hostile record, it deletes no evidence).
 */

#include <stddef.h>
#include <stdint.h>

#define KOF_FORM_MAX_STR    64u    /* KOF_MAX_STR_PER_MODULE: a module's own bound, kept so a marker moves between them */
#define KOF_FORM_MAX_MATCH  64u
#define KOF_FORM_MAX_BLOCK  32u
#define KOF_FORM_MAX_ARG    16u    /* names one matcher may list: kof_find_str_any's own bound */
#define KOF_FORM_MAX_NODE   128u
#define KOF_FORM_MAX_WIRE   65536u /* the whole stream of one diagnose */
#define KOF_FORM_HASH_MAX   128u   /* KOF_MUTATION_MAX_HASH */

enum kof_form_item {
	KOF_FORM_I_STR = 1,
	KOF_FORM_I_FIND = 2,
	KOF_FORM_I_BLOCK = 3,
	KOF_FORM_I_SIM = 4,
	KOF_FORM_I_EXPR = 5
};

/* What kind of question a matcher is. */
enum kof_form_match_kind { KOF_FORM_M_FIND = 0, KOF_FORM_M_SIM = 1 };

/* How a FIND combines its markers: kof_find_str_all, _any, _multi (>= thresh), _at. */
enum kof_form_rule {
	KOF_FORM_R_ALL = 0,
	KOF_FORM_R_ANY = 1,
	KOF_FORM_R_MULTI = 2,
	KOF_FORM_R_AT = 3
};

enum kof_form_op { KOF_FORM_OP_LEAF = 0, KOF_FORM_OP_NOT = 1, KOF_FORM_OP_AND = 2, KOF_FORM_OP_OR = 3 };

/* Where an AT matcher counts its offset from: enum kof_anchor (kofsearch.h), written here so the layout does not
 * include a module header. */
#define KOF_FORM_ANCHOR_BOF   0u
#define KOF_FORM_ANCHOR_ENTRY 1u
#define KOF_FORM_ANCHOR_EOF   2u

struct kof_form_str {
	uint32_t off;               /* into `pool`: aligned for a hex program */
	uint16_t len;
	uint8_t  kind;              /* enum kof_pack_str_kind */
	uint8_t  flags;             /* KOF_STR_* */
};

struct kof_form_match {
	uint8_t  kind;              /* enum kof_form_match_kind */
	uint8_t  rule;              /* FIND: enum kof_form_rule */
	uint8_t  thresh;            /* MULTI: how many of the markers; SIM: the percentage */
	uint8_t  anchor;            /* AT: KOF_FORM_ANCHOR_* */
	uint8_t  n;                 /* names listed: strings (FIND) or blocks (SIM) */
	uint8_t  arg[KOF_FORM_MAX_ARG];
	uint32_t mask;              /* FIND, not AT: the regions searched */
	int64_t  at;                /* AT: the step from the anchor */
};

struct kof_form_block {
	uint32_t mask;              /* where the block was cut from */
	uint8_t  side;              /* enum kgenome_mutation_side */
	uint16_t n_hash;
	uint32_t first;             /* into `hash` */
};

struct kof_form_node {
	uint8_t op, a, b;           /* enum kof_form_op; LEAF: a = matcher; NOT: a = node; AND, OR: a, b = nodes */
};

struct kof_form {
	uint16_t n_str, n_match, n_block, n_node;
	struct kof_form_str   str[KOF_FORM_MAX_STR];
	struct kof_form_match match[KOF_FORM_MAX_MATCH];
	struct kof_form_block block[KOF_FORM_MAX_BLOCK];
	struct kof_form_node  node[KOF_FORM_MAX_NODE];
	uint8_t  *pool;             /* the markers' bytes (owned) */
	uint32_t  pool_n, pool_cap;
	uint32_t *hash;             /* every block's hashes, one after the other (owned) */
	uint32_t  n_hash, hash_cap;
	/* The engine's: where block 0 sits in the similarity set (loader writes it, nothing else reads it). */
	uint32_t  blk_base;
	/* How many of the matchers are SIM: a form with any is answered by the similarity stage, one with none by the
	 * detect stage. A form with both is refused (see kof_form_check). */
	uint16_t  n_sim;
};

/* An empty form: the resolver and the decoder start from it. Returns NULL for want of memory. */
struct kof_form *kof_form_new(void);
void kof_form_free(struct kof_form *f);

/* Append a marker and return its index, or -1 when the table is full, the bytes are too long for their kind or memory
 * is refused. `flags` are KOF_STR_*; a hex program is placed at an offset KOF_HEX_PROG_ALIGN divides. */
int kof_form_add_str(struct kof_form *f, uint8_t kind, uint8_t flags, const uint8_t *p, uint32_t n);
/* Append a block and return its index, or -1 (table full, more than KOF_FORM_HASH_MAX hashes, memory). */
int kof_form_add_block(struct kof_form *f, uint32_t mask, uint8_t side, const uint32_t *h, uint32_t n);

/*
 * THE FORM IS WHOLE: every index inside its table, every count in its bound, a tree for an expression, matchers of
 * one stage. The same function the decoder ends with and the resolver asks, so a source the builder accepts is a
 * record the loader reads. Returns NULL when it is, else a reason (a static string).
 */
const char *kof_form_check(const struct kof_form *f);

/*
 * THE WIRE. kof_form_wire_size is the stream's length, kof_form_wire_write puts it at `out` (that many bytes), and
 * kof_form_section_size / kof_form_section_write cut a stream of `n` bytes into [KDIG_SEC_FORM][len][chunk] sections
 * of at most 255 bytes: what a record carries. A form past KOF_FORM_MAX_WIRE answers 0 (a reason the caller reports).
 */
size_t kof_form_wire_size(const struct kof_form *f);
size_t kof_form_wire_write(const struct kof_form *f, uint8_t *out);
size_t kof_form_section_size(size_t wire_n);
size_t kof_form_section_write(const uint8_t *wire, size_t wire_n, uint8_t *out);

/*
 * Read a stream (the concatenated section bodies) into a new form. NULL when the stream does not add up - and
 * `*why`, when given, is the reason. A hex program is checked by kof_hex_prog_valid, a literal by its bound, every
 * index and the expression tree by kof_form_check: a record is a file, and a file can say anything.
 */
struct kof_form *kof_form_decode(const uint8_t *p, size_t n, const char **why);

/* The expression, spelled with matcher numbers ("0 & !1 | (2 & 3)"), for a report and a test: `out` is NUL terminated
 * and cut at `cap`, the return is the length it wanted. */
size_t kof_form_expr_text(const struct kof_form *f, char *out, size_t cap);

#endif /* KOFENG_DIAGFORM_H */
