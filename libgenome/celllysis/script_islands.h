#ifndef KGENOME_CELLLYSIS_SCRIPT_ISLANDS_H
#define KGENOME_CELLLYSIS_SCRIPT_ISLANDS_H

/*
 * script_islands.h - THE ISLANDS OF A SCRIPT: where its code is, at two levels, in two layers, built from ONE lex together with its
 * function table (kgenome_script_parts). The engine keeps the answer as a product of the object and every consumer reads it - the
 * similarity cut, the obfuscation measure, the tools - and none of them lexes again (owner, 2026-11-14: "Island là mảnh code bao gồm
 * nhiều cái chứ không chỉ mảnh <?php>. island lấy từ engine").
 *
 * THE LEVELS (owner: "1. từng mảnh code theo tag ... 2. function là level nhỏ hơn"). Both are built for every text: a signature
 * chooses the level it was made from, and depth is never decided per object (a variant that adds one function must not flip how
 * the whole text is cut).
 *   level 0  a PIECE: the code of a language from where it begins to where it ends - "<?php ... ?>", "<% ... %>", a cf tag, a
 *            <script runat=server> body, the whole text of a language that has no tags. A piece whose syntax block (a brace, php's
 *            `if (...): ... endif;`, a vb `If ... End If`, a paired cf tag) opens in it and closes in a later piece is ONE island
 *            from the first to the last, the markup between included (KGENOME_SCRIPT_ISL_F_JOINED): "Hàm trải qua nhiều mảnh thì
 *            coi cả đoạn là một island bao gồm markup".
 *   level 1  each level-0 island cut in sequence: [run][function][run][function]... A FUNC is one outermost function of the
 *            language's own table (script_funcs.h); a RUN is a maximal stretch between them. A run that holds no code (white
 *            space and comments only) is not an island. No holes but those, no overlaps.
 * THE LAYERS (owner-agreed design point 4). SERVER is the object's own language. CLIENT is the javascript of the markup the server
 * layer leaves - a <script> element's body, an on* attribute's value, a javascript: url - partitioned on its own. The two layers
 * may overlap (a php echo inside a <script> body is in both); one layer never overlaps itself.
 *
 * OFFSETS are the object's own bytes. Every table is allocated to what the text holds: there is no cap on the number of islands
 * (the module ABI's kof_script_info.island keeps its own fixed list and its FULL bit, which is not this table).
 */

#include <stdint.h>

#include <kgenome_status.h>
#include <genotype/image/funcs.h>

enum kgenome_script_isl_layer {
	KGENOME_SCRIPT_ISL_SERVER = 0,
	KGENOME_SCRIPT_ISL_CLIENT = 1,
	KGENOME_SCRIPT_ISL_LAYERS = 2
};

enum kgenome_script_isl_kind {
	KGENOME_SCRIPT_ISL_PIECE = 0,   /* level 0 */
	KGENOME_SCRIPT_ISL_FUNC  = 1,   /* level 1: one outermost function */
	KGENOME_SCRIPT_ISL_RUN   = 2    /* level 1: code outside every function */
};

#define KGENOME_SCRIPT_ISL_F_JOINED  0x01u      /* level 0: a syntax block spans its tags: several pieces and the markup between them */
#define KGENOME_SCRIPT_ISL_F_OPEN    0x02u      /* level 0: the text ended inside it - no closing tag, or a block it opened was never closed */
#define KGENOME_SCRIPT_ISL_F_CLIPPED 0x04u      /* level 1: the function's own extent crosses its level-0 island's edge and is cut there */
#define KGENOME_SCRIPT_ISL_F_ATTR    0x08u      /* client level 0: the value of an on* attribute or a javascript: url, not a <script> body */

struct kgenome_script_island {
	uint64_t off, len;
	uint32_t parent;        /* level 1: the index of its level-0 island in the same layer; level 0: its own index */
	uint32_t func;          /* FUNC: the index of its function in the layer's table (KGENOME_FUNCS_NONE otherwise) */
	uint32_t pieces;        /* level 0: how many tagged pieces it holds (0 for a text with no tags) */
	uint16_t flags;         /* KGENOME_SCRIPT_ISL_F_* */
	uint8_t  kind;          /* enum kgenome_script_isl_kind */
	uint8_t  lang;          /* enum kgenome_textual_lang_id its code is read as */
};

struct kgenome_script_isl_list {
	struct kgenome_script_island *v;
	uint32_t n, cap;
};

struct kgenome_script_islands {
	struct kgenome_script_isl_list lv[KGENOME_SCRIPT_ISL_LAYERS][2];        /* [layer][level] */
	/* The functions of the client layer, in the object's offsets (the server layer's are kgenome_script_parts.funcs). */
	struct kgenome_func_set client_funcs;
	uint32_t n_pieces;              /* tagged pieces of the server layer */
	uint32_t n_joined;              /* of them, pieces that are in a level-0 island with another */
	/* KGENOME_OK, or KGENOME_NOMEM: a table is short for want of memory (said, never silent). */
	enum kgenome_status status;
};

#define KGENOME_SCRIPT_PART_ISLANDS 0x1u        /* build the islands (the function table is always built) */
#define KGENOME_SCRIPT_PART_CLIENT  0x2u        /* and the client layer (needs the islands) */

struct kgenome_script_parts_req {
	uint32_t       lang;            /* enum kgenome_textual_lang_id */
	uint32_t       flags;           /* KGENOME_TEXTUAL_FRAGMENT: the text is code from its first byte */
	uint32_t       want;            /* KGENOME_SCRIPT_PART_* */
	const uint8_t *in;
	uint64_t       n;
};

struct kgenome_script_parts {
	struct kgenome_func_set       funcs;    /* the server layer's functions (script_funcs.h) */
	struct kgenome_script_islands isl;
	uint64_t                      bytes;    /* what the two hold, for the caller's ledger */
};

/* The function table and the islands of a text, from one lex of it. `out` is zeroed first; kgenome_script_parts_free gives back what it holds. */
void kgenome_script_parts(const struct kgenome_script_parts_req *rq, struct kgenome_script_parts *out);
void kgenome_script_parts_free(struct kgenome_script_parts *p);
void kgenome_script_islands_free(struct kgenome_script_islands *s);

#endif /* KGENOME_CELLLYSIS_SCRIPT_ISLANDS_H */
