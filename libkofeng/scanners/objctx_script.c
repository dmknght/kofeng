/*
 * objctx_script.c - the two forms of a script, as a child object.
 *
 * WHAT THIS SERVES: a module that reads a script asks for it twice - once with
 * the lexical noise folded away (kof_scan_script_forms, deep), once with the language
 * normalised to a canonical form (the same call, not deep). Each answer is a CHILD
 * of the object, produced through the same declaration path every other child
 * takes (objctx_child.c); this file decides only what the text becomes.
 *
 * NOT YET PIPELINE-CLEAN, and said so rather than hidden: the fold and the form
 * are two normalisers with their own thresholds, tuned on webshell corpora
 * (`n < 64`, `n*3 < b.n`, `raw - n < 16`). Both now declare the child's language
 * the same way (script_declare). A change to a threshold needs the Shell.Agent
 * corpus and the named shells, detections identical before and after - only 149
 * webshell samples were available when this was last measured.
 */

/* Before any include, and _GNU_SOURCE rather than _POSIX_C_SOURCE, for the
 * reason dbloader.c gives at length: kofplatform.h's POSIX branch has an inline
 * kof_memmem whose body calls memmem, which glibc declares only under this
 * macro - and _POSIX_C_SOURCE actively suppresses it. */
#define _GNU_SOURCE

#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"

/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_forms below. */
#include "../analyzers/parsers/scripts/script_parse.h"
#include "../analyzers/parsers/scripts/script_route.h"
#include <phenotype/diag_scan.h>
#include <textual/textual.h>
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */


#include "objctx_int.h"
#include "../kofcore/kofdebug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * The one setup both passes below need, and the one place their refusals are
 * written down.
 *
 * `b` comes back as the object's bytes.
 * Answers 0 when there is nothing to do, and the reasons are all of the form
 * "this is not a script this build can read", never "this script is clean".
 */
static int script_pass_open(const struct kof_obj_ctx *ctx,
			    struct kof_scanner **psc, kof_buf *b)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_script_info *si;

	if (!sc || !sc->cur.src || !ctx->file_header)
		return 0;
	if (ctx->format != KOF_FMT_SCRIPT || !oc_can_produce(sc))
		return 0;
	/*
	 * A FORM OF A FORM IS THE FORM. Both passes below declare what they
	 * produce as KOF_ENT_NORMALIZED, and running either on its own output
	 * costs a walk over the object to arrive at bytes that are already in
	 * the tree - the normalised form of a normalised form is itself, and
	 * what a folded constant builds its parent already built.
	 */
	if (kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED) {
		KOF_TRACE("[script] gate closed: a form of a form is the form, this is already one\n");
		return 0;
	}
	si = (const struct kof_script_info *)ctx->file_header;
	if (!kof_script_textual_lang(si->kind)) {
		KOF_TRACE("[script] gate closed: no lexer for kind=%d, nothing is guessed\n", (int)si->kind);
		return 0;       /* no lexer for the kind: nothing is guessed */
	}

	*b = kof_src_buf(sc->cur.src);
	/*
	 * A SCRIPT OVER THE OBJECT CAP IS NOT FORMED OR FOLDED, AND THE OBJECT SAYS SO: a webshell
	 * padded past the cap would otherwise hide every decoded layer behind a clean answer
	 * (BE-8; scan_norm.c's norm_fits says the same for a view).
	 */
	if (b->p && b->n && (b->n > sc->ledger.obj_cap || b->n > 0xffffffffu)) {
		KOF_TRACE("[script] gate closed: %llu byte(s) over the object cap, not formed or folded\n",
			  (unsigned long long)b->n);
		oc_scan_limit(sc);
		return 0;
	}
	if (!b->p || !b->n)
		return 0;
	oc_text_page(sc, ctx);
	*psc = sc;
	KOF_TRACE("[script] gate open: %llu byte(s)\n", (unsigned long long)b->n);
	return 1;
}

/*
 * WHAT THE CHILD OF A SCRIPT IS, DECLARED - not left to be sniffed.
 *
 * Both outputs of this unit (the fold and the form) are scripts in the language
 * of the object they came from, and both declare it the same way. The form did,
 * from the measurement that 625 Backdoor.Shell.Agent samples stopped being
 * detected when a view with no declared subtype replaced the one norm_emit made
 * (KOF_TARGET_SUBTYPE(KOF_SCRIPT_SHELL) declines on an object that never said);
 * the fold relied on a re-injected tag and a newline for the sniff to recognise
 * it, which carries the FORMAT and not the subtype. One function, so the next
 * output of this kind cannot forget.
 */
static void script_declare(struct kof_scanner *sc,
			   const struct kof_obj_ctx *ctx)
{
	sc->pend.subtype = ctx->subtype;
	sc->pend.subfam  = ctx->subfamily;
	sc->pend.lang    = 1;
}

/*
 * A LINE NUMBER, FOR THE LABEL ONLY: 1-based, counting the newlines of the OBJECT's own
 * bytes before `at`. A cheap, local count rather than a shared API - nothing else needs a
 * script's line index today (sym_any.c's kof_script_line_of is a different file's private
 * helper for a different caller) and this is best-effort display text, not a fact anything
 * downstream reads back.
 */
static uint64_t island_line_of(const uint8_t *p, uint64_t n, uint64_t at)
{
	uint64_t i, line = 1;

	if (at > n)
		at = n;
	for (i = 0; i < at; i++)
		if (p[i] == '\n')
			line++;
	return line;
}

/*
 * A CODE ISLAND, AS A REAL CHILD (owner, 2026-11-10: "island phải hiện ngang hàng với
 * normalize... phải là child, phải được tokenize và normalize giống như bình thường" -
 * it must show on a par with the normalised view, as a child, tokenized and normalised
 * the same way a real script object already is). Supersedes the scanner-free display
 * adapter (kof_script_island_units, script_route.c, Merge 168): the SAME resolved
 * bytes (diag_text_walk.c's layer_of_call, unchanged - nothing here re-derives what an
 * island IS, only what becomes of it) are declared and emitted exactly the way the
 * view just above is - `script_declare` sets the same subtype/subfamily/lang, and the
 * engine's own child-push (oc_kid_push) does the rest: the child re-enters the whole
 * pipeline on its own pass, so it gets its own function table (script_funcs.c, via
 * objctx_diag.c's funcs_of - the adapter reads the island's entry, byte 0, as code from its
 * first byte: kof_script_from_code, script_route.c) and its own further fold/form (this same function,
 * called again for the child) FOR FREE: nothing here special-cases it.
 *
 * KIND IS KOF_ENT_SCRIPT ("code meant to run when the file is opened"), NOT
 * KOF_ENT_NORMALIZED: an island is not a transform of the parent's own bytes in
 * place (kex_g_decl_view's whole reason to exist, kofexaminer_blocks.c) and must not
 * be read as one - it is code the program itself assembles and runs, the kind this
 * entry already exists to say.
 *
 * NOT A SCAN TARGET OF ITS OWN (owner, 2026-11-10, second correction: "nó không phải
 * một object con để scan... vẫn được sử dụng làm bằng chứng scan giống như 1 region
 * riêng" - oc_child_evidence_only, read by scan_pipeline.c's DETECT/SIMILAR/ANALYSE/
 * VERDICT guards): FACTS and SCRIPT still run on it (the tokenize/normalise this
 * comment opens with), nothing else does.
 *
 * THE LABEL (owner, same date, third correction: "không hiển thị island@... mà là
 * tên biến, dòng, ngôn ngữ"; owner, 2026-11-10, fourth correction: keep the "$" and
 * drop the language word) names the call's OWN argument text - diag_scan.h's
 * `name_off`/`name_len`, the honest source span kgenome_dtx_arg_range already found,
 * read from the OBJECT's own bytes, never the resolved value - and the line it was
 * called from (island_line_of, above). The SIGIL is read the same way: a PHP variable
 * token's own span excludes its "$" by this project's own lexer convention
 * (diag_text_private.h's `sigil` field), so the byte right before name_off IS it when
 * there is one - PHP only, like the rest of this feature (script_route.c's own gate).
 * NO LANGUAGE WORD: kv_tree_label.c's obj_label already composes "Script-PHP" for
 * every script object from ctx->format/ctx->subtype, the island included - a label
 * carrying "PHP" too said it twice next to each other ("$U@L11 PHP Script-PHP"),
 * obj_label's own convention bypassed rather than reused (kofeng/CLAUDE.md #2). A
 * short emit (the ledger refused mid-island) is not silently dropped: oc_scan_limit
 * says so and the object produced so far still becomes the child, exactly as any
 * other producer's short write does (objctx_child_sink.c's oc_emit).
 */
static void script_island_declare(const struct kof_obj_ctx *ctx, struct kof_scanner *sc,
				  kof_buf obj, const struct kgenome_diag_text_island *isl)
{
	char label[64];
	uint64_t line = island_line_of(obj.p, obj.n, isl->at);
	const char *sigil = (isl->name_len && isl->name_off && isl->name_off <= obj.n &&
			     obj.p[isl->name_off - 1u] == '$') ? "$" : "";

	oc_child_kind(ctx, KOF_ENT_SCRIPT);
	oc_child_evidence_only(ctx);
	script_declare(sc, ctx);
	/*
	 * WHAT THE CHILD IS, SAID (owner-agreed island design point 5, 2026-11-14): its language (script_declare) and that it is CODE FROM
	 * ITS FIRST BYTE - its entry is byte 0 (kof_script_from_code reads ctx->entry_off, KOF_NA for every parsed script). Its description
	 * is the honest one of a text with no tag (tag_off/tag_len 0, no islands of its own in the module ABI's table): the parse's
	 * `tag_len == 0` is no longer read as a "fragment" flag anywhere, which is what made it a template. Without a description
	 * ctx->file_header is NULL and ctx->format KOF_FMT_UNKNOWN the moment the island becomes current (ISL-1, 2026-11-10: sx_identify
	 * has no tag to read a tagless text's format from).
	 */
	{
		struct kof_script_info isl_info;

		memset(&isl_info, 0, sizeof isl_info);
		isl_info.kind = ctx->subtype;
		oc_child_desc(ctx, KOF_FMT_SCRIPT, ctx->arch, ctx->subtype, 0u, &isl_info, (uint32_t)sizeof isl_info);
	}
	if (isl->name_len && (uint64_t)isl->name_off + isl->name_len <= obj.n &&
	    isl->name_len < sizeof label - 24u)
		snprintf(label, sizeof label, "%s%.*s@L%llu", sigil, (int)isl->name_len,
			 (const char *)obj.p + isl->name_off, (unsigned long long)line);
	else
		snprintf(label, sizeof label, "eval@L%llu", (unsigned long long)line);
	oc_note_next(ctx, label);
	if (oc_emit_all(ctx, isl->data, isl->len) != isl->len)
		oc_scan_limit(sc);
	oc_child(ctx);
}

/*
 * ONE CHILD PER DISTINCT STRING (owner-agreed island design point 5): two eval sites that run the same text are one program, read once
 * - the child is declared at the FIRST site (its label and line), and the others are counted. Equal is equal bytes: the strings are
 * ordered by a hash of their bytes and their length, and only strings with both equal are compared byte for byte, so n islands cost
 * n log n and not n squared. Survey (2026-11-14): 9 php eval strings in 8 files and 5 vbs in 2, none a duplicate of another in its
 * file - the rule is for the obfuscator that writes one decoder call per line, built from constructed text in tests/unit/script_islands.c.
 * An index table that cannot be had declares every island (no evidence lost, the cost of reading duplicates paid).
 */
struct isl_key {
	uint64_t h;
	uint32_t len, k;
};

static int isl_key_cmp(const void *a, const void *b)
{
	const struct isl_key *x = a, *y = b;

	if (x->h != y->h)
		return x->h < y->h ? -1 : 1;
	if (x->len != y->len)
		return x->len < y->len ? -1 : 1;
	return x->k < y->k ? -1 : x->k > y->k;
}

static void islands_declare(const struct kof_obj_ctx *ctx, struct kof_scanner *sc, kof_buf b,
			    const struct kgenome_diag_text_island_set *isl)
{
	struct isl_key *key = isl->n > 1u ? malloc((size_t)isl->n * sizeof *key) : NULL;
	uint8_t *dup = isl->n > 1u ? calloc(isl->n, 1) : NULL;
	uint32_t k, n_dup = 0;

	if (key && dup) {
		for (k = 0; k < isl->n; k++) {
			key[k].h = kof_hash64_bytes(isl->v[k].data, isl->v[k].len);
			key[k].len = isl->v[k].len;
			key[k].k = k;
		}
		qsort(key, isl->n, sizeof *key, isl_key_cmp);
		for (k = 1; k < isl->n; k++) {
			uint32_t j = k;

			/* the first of a run of equal keys is kept; a later one equal to an earlier kept one is a duplicate */
			while (j > 0 && key[j - 1u].h == key[k].h && key[j - 1u].len == key[k].len) {
				j--;
				if (!dup[key[j].k] && !memcmp(isl->v[key[j].k].data, isl->v[key[k].k].data, key[k].len)) {
					dup[key[k].k] = 1;
					n_dup++;
					break;
				}
			}
		}
	}
	for (k = 0; k < isl->n; k++)
		if (!dup || !dup[k])
			script_island_declare(ctx, sc, b, &isl->v[k]);
	KOF_TRACE("[script] islands: %u declared, %u duplicate string(s) read once\n", (unsigned)(isl->n - n_dup), (unsigned)n_dup);
	free(key);
	free(dup);
}

/*
 * WHAT A DECODE LEFT BEHIND, CLOSED UP.
 *
 * kof_exe_decode rewrites a run where it sits and fills what it vacates with zeros, which a binary's
 * normaliser collapses. A script's view is text, and a run of zeros in the middle of it is a gap in
 * a string - 'https://host/path<zeros>', - that no marker written on the string can match across.
 * They go, so the decoded text sits where the encoded text was. Only after a decode that fired,
 * and only the zeros the decode made: a script that holds a NUL of its own keeps it (the
 * function removed every zero of the view, its own included: L19 of the lexer audit). `own` is
 * a bit for each byte that was zero BEFORE the decode, or NULL when none was.
 */
static uint32_t script_squeeze(uint8_t *p, uint32_t n, const uint8_t *own)
{
	uint32_t i, w = 0;

	for (i = 0; i < n; i++)
		if (p[i] || (own && ((own[i >> 3] >> (i & 7u)) & 1u)))
			p[w++] = p[i];
	return w;
}

/* Give back the text `oc_script_consts` made, and what it was charged. */
static void consts_end(struct kof_scanner *sc, uint8_t *text, uint64_t charged)
{
	free(text);
	oc_scan_release(sc, charged);
}

/*
 * THE SCRIPT IN THE FORM A SIGNATURE SHOULD BE WRITTEN ON - one child, and the
 * last form, not every form on the way to it.
 *
 * Two stages make that form and they compose in one direction (the order is decided HERE, and each stage is the lib's one API for it - docs/textual_pipeline.txt):
 *
 *   constants  what the program BUILDS out of its own literals, written where it was built (deep only: it costs a walk over every assignment). A
 *              generator that cuts a shell into pieces, scatters them over variables and joins them at run time leaves no byte string that
 *              survives two builds - the separator, the names, the cut points and the join order all change. Measured on two builds of one php
 *              obfuscator: not one shared substring in the raw files, and the same 65 bytes after folding. The lib's evaluator
 *              (kgenome_diag_scan_text, on_const) says what each right side comes to and kgenome_textual_subst writes it: oc_script_consts.
 *              Every language the evaluator serves and whose row can write a literal (oc_script_consts_serves) takes this path; it replaced a folder
 *              (script_fold.c) that read only php, perl, powershell and tcl and handed over the one largest value as the file.
 *   form       how the program was TYPED, removed, and every literal under a decoder decoded (kgenome_textual_form with the decode hook,
 *              objctx_script_dec.c). Always run, over the text the constants stage produced.
 *
 * THE CONSTANTS READ THE WHOLE OBJECT. The pieces of a built program are literals wherever they were assigned, and a server page that assigns
 * one in an island and joins it in the next has a join that folding island by island would miss. There is ONE child: the form of the text with
 * its constants written, never the intermediate text.
 */
uint32_t kof_scan_script_forms(const struct kof_obj_ctx *ctx, int deep)
{
	struct kof_scanner *sc = NULL;
	uint8_t *out = NULL;
	kof_buf b;
	uint32_t n = 0, raw = 0, cap, lang, n_dec = 0;
	uint64_t room = 0, charged = 0;
	int decoded = 0;
	/* Islands found below (or NULL): declared AFTER the normalised view, so the view
	 * keeps slot 0 and islands are 1, 2, 3... - owner, 2026-11-10: "script norm phải
	 * là 0 và cái island... là cái 1, 2, 3... vì nó là thông tin bổ sung cho script". */
	const struct kgenome_diag_text_island_set *isl = NULL;
	/* The text the form reads: the object's own, or - for a language the evaluator knows, deep - the object with what it computes written where
	 * it was computed. */
	uint8_t *text2 = NULL;
	const uint8_t *in_p;
	uint64_t in_n, charged2 = 0;
	uint32_t n2 = 0, n_sub = 0;

	if (!script_pass_open(ctx, &sc, &b))
		return 0;
	lang = kof_script_textual_lang(ctx->subtype);
	in_p = b.p;
	in_n = b.n;
	if (deep && oc_script_consts_serves(lang)) {
		n_sub = oc_script_consts(sc, lang, b, &text2, &n2, &charged2);
		KOF_TRACE("[script] constants: lang=%u, %u substitution(s) written\n", (unsigned)lang,
			  (unsigned)n_sub);
		if (n_sub) {
			in_p = text2;
			in_n = n2;
		}
		/*
		 * ISLANDS, found here but DECLARED BELOW, after the normalised view (ordering,
		 * above) - the SAME walk oc_script_consts just ran already resolved every one it
		 * could reach, so asking for them here costs nothing further (oc_text_islands
		 * reuses the cached scan). Found regardless of whether the fold above found
		 * anything to substitute or the form below finds anything worth a view of its
		 * own: an island is evidence in its own right, not a side effect of there being a
		 * normalised view.
		 */
		/*
		 * NESTED EVAL IS BOUNDED BY THE WALK'S OWN BUDGET (design point 5): the walk that finds this object's islands follows every
		 * layer of code it computes (diag_text_walk.c, layer_of_call: LAYER_DEPTH and the walk's room), each island is collected at its
		 * eval site in this file, and a cap is the set's status, said below as a limit. Measured (tests/unit/script_island_parts.c,
		 * IS-2): a create_function run inside an eval'd string arrives once, as this object's child, on the base and on this tree.
		 */
		isl = oc_text_islands(sc, lang, b);
		KOF_TRACE("[script] islands: %u found\n", (unsigned)(isl ? isl->n : 0));
		if (isl && isl->status != KGENOME_OK)
			oc_scan_limit(sc);
	}
	/*
	 * Neither pass can make anything longer than what it was given - every
	 * rule in both removes bytes or leaves them - except the ONE newline
	 * the form pass may put back at each boundary between a copied run and
	 * a formed one. There are at most two boundaries per body extent and
	 * the extents are capped, so the slack is a constant and cannot be
	 * made to grow by a crafted file.
	 */
	/*
	 * IN 64 BITS, BECAUSE THE SUM IS WHAT SIZES THE BUFFER.
	 *
	 * script_pass_open admits any object up to 0xffffffff, and adding the
	 * slack to one near that wraps a uint32 to something small - a malloc
	 * of a few hundred bytes for a pass whose bound is the input length,
	 * which is a heap overflow rather than a short answer. The ceiling that
	 * keeps it from arising today is obj_cap, and obj_cap is a caller's
	 * option; a bound that holds only while nobody raises a setting is not
	 * a bound.
	 */
	{
		uint64_t need = in_n + 2ull * KOF_SCRIPT_MAX_ISLAND + 2ull;
		uint64_t lib = KGENOME_TEXTUAL_FORM_CAP(in_n);

		/* The lib's form may add a line break in front of each closing tag. */
		if (lang && lib > need)
			need = lib;
		if (need > 0xffffffffu)
			{
				KOF_TRACE("[script] refused: needed buffer %llu byte(s) over 32 bits\n",
					  (unsigned long long)need);
				consts_end(sc, text2, charged2);
				return 0;
			}
		/* The buffer is the scanner's memory like any other: it has to fit under the ceiling. */
		if (need > oc_scan_room(sc)) {
			OC_LIMIT(sc, "script pass buffer over the memory ceiling");
			consts_end(sc, text2, charged2);
			return 0;
		}
		/*
		 * AND, WHERE LITERALS ARE DECODED, ROOM FOR WHAT THEY BECOME: the allowance of
		 * oc_script_dec_room, never past what 32 bits can address and never more than half of
		 * what the ceiling has left after the buffer for the text itself.
		 */
		if (lang) {
			uint64_t avail = oc_scan_room(sc) - need;

			room = oc_script_dec_room(sc, in_n);
			if (room > avail / 2u)
				room = avail / 2u;
			if (need + room > 0xffffffffu)
				room = 0xffffffffu - need;
			need += room;
		}
		cap = (uint32_t)need;
	}
	out = malloc((size_t)cap);
	if (!out) {
		OC_LIMIT(sc, "script pass buffer not allocated");
		{
			consts_end(sc, text2, charged2);
			return 0;
		}
	}
	scan_charge(sc, cap);           /* given back wherever `out` is freed */
	charged = cap;

	/* Every kind a script object has is a language the lib lexes (script_pass_open said so): the form is the lib's, whole. */
	{
		struct oc_script_dec *dec = oc_script_dec_new(sc, lang, room);
		/*
		 * CODE FROM ITS FIRST BYTE, THE SAME TEST THE FUNCTION TABLE MAKES (kof_script_from_code, the object's entry - ISL-1,
		 * 2026-11-10): php's lexer reads code only inside a tag's island (.islands = 1, php_lang.c) and everything before the first
		 * tag is markup, which the form never reformats - an island's own body has no tag to open one, so without this its whole
		 * text read as one block of markup and the form was a no-op (n == raw exactly, confirmed).
		 */
		struct oc_script_form_req fq = { .lang = lang, .in = in_p, .n = (uint32_t)in_n, .out = out,
						 .cap = cap, .dec = dec, .fragment = (uint8_t)kof_script_from_code(ctx) };

		n = oc_script_form(&fq, &n_dec);
		oc_script_dec_end(dec);
	}
	/*
	 * ONLY WHEN THE FORM WAS ACTUALLY DIFFERENT, and by more than a byte.
	 *
	 * Over the whole object, because the whole object is what this
	 * produces: a page whose html is most of it and whose few lines of code
	 * were already tight has nothing here for a marker to trip over, and a
	 * copy of it would be a node in the tree that says the same as its
	 * parent.
	 *
	 * Sixteen, because below it there was nothing to gain: a real shell
	 * whose body is almost entirely string literals came out ONE byte
	 * shorter - the blank line under its tag - and a marker taken from the
	 * raw file matches that copy already. The child worth making is the one
	 * where indentation, comments and spacing were there to remove.
	 *
	 * The folded form above is not held to this. It is not a reformatting
	 * of the file, it is a different program.
	 */
	/*
	 * AND WHAT THE BYTES SAY, NOT ONLY HOW THEY ARE SPACED.
	 *
	 * "Say this object plainly" is two halves. Removing the indentation,
	 * the comments and the line breaks is the half this pass was written
	 * for; the other half is the base64, hex and percent spans a script
	 * spells its strings in, and a view that reformats
	 * '7068705f756e616d65' without reading it has not said anything
	 * plainly at all.
	 *
	 * IT USED TO BE A SECOND VIEW. norm_emit was widened to scripts to get
	 * this, and every script then carried two normalised children, each
	 * holding one of the two halves - see the note at norm_emit's format
	 * gate. The decode is here instead, where the script's own view is
	 * produced, so there is one view and it is whole.
	 *
	 * ON THE PRODUCED BUFFER, NOT ON THE FILE: kof_exe_decode rewrites in
	 * place, and `out` is this pass's own copy.
	 */
	decoded = 0;
	if (n) {
		struct kof_exe_decode_res dres;
		uint8_t *own = NULL;
		uint64_t own_bytes = 0;
		int squeeze = 1;
		uint32_t k;

		/* A NUL the script holds is told from the zeros of the decode by where it was before the decode: a bit for each, charged to the scanner for as long as it is held.
		 * Most scripts hold none and pay nothing. When the map cannot be afforded the zeros stay (a gap in a decoded string, which is what a view without the squeeze
		 * had) and the object says a bound fired. */
		if (memchr(out, 0, n)) {
			own_bytes = ((uint64_t)n + 7u) / 8u;
			own = own_bytes > oc_scan_room(sc) ? NULL : calloc((size_t)own_bytes, 1u);
			if (!own) {
				squeeze = 0;
				own_bytes = 0;
				OC_LIMIT(sc, "script view: the map of the script's own NULs over the memory ceiling");
			} else {
				scan_charge(sc, own_bytes);
				for (k = 0; k < n; k++)
					if (!out[k])
						own[k >> 3] = (uint8_t)(own[k >> 3] | (1u << (k & 7u)));
			}
		}
		decoded = kof_exe_decode_ex(out, n, &dres);
		if (decoded && squeeze)
			n = script_squeeze(out, n, own);
		if (own) {
			free(own);
			oc_scan_release(sc, own_bytes);
		}
		if (dres.limit)
			oc_scan_limit(sc);
	}
	/*
	 * A DECODE IS A DIFFERENCE TOO, and the size test cannot see it.
	 *
	 * The floor below asks whether reformatting removed enough to be worth
	 * a node. kof_exe_decode is LENGTH PRESERVING - it zero-fills what it
	 * vacates - so a tightly written file that is nothing but hex literals
	 * comes out the same length and would have been thrown away with its
	 * decode in it. What that floor is really asking is "does this view
	 * say anything the parent did not", and a decode always does.
	 */
	raw = (uint32_t)b.n;
	/* A literal a decoder was put over is a difference as well, and makes the view longer than the object. */
	n_dec += n_sub;                 /* a value written where it was computed is a difference as well */
	/* oc_script_form's own `n_dec` already carries a statement-end line break the file never had (textual.h's
	 * n_stmt, owner, 2026-11-10): a flat chain of obfuscated statements the source never broke onto more than
	 * one line also makes the view longer with no decode in it, and is exactly a case this floor must not
	 * throw away - the whole point of asking for the break. */
	decoded |= n_dec != 0;
	if (n < 32u || (raw < n && !n_dec) || (!decoded && raw - n < 16u)) {
		KOF_TRACE("[script] form discarded: raw=%u formed=%u decoded=%d, below the floor\n", raw,
			  n, decoded);
		n = 0;
	}
	if (n) {
		oc_child_kind(ctx, KOF_ENT_NORMALIZED);
		/*
		 * AN ISLAND'S OWN FURTHER VIEW IS EVIDENCE TOO (owner, 2026-11-10): this
		 * function runs again, recursively, on the island child's own bytes (see
		 * script_island_declare's header comment) - and that further view is no more
		 * an independent scan target than the island itself was. Checked on the
		 * CURRENT object (sc->cur.src is this object's own, not the child's: the
		 * child does not exist yet) - exactly one level of propagation, the only one
		 * this feature produces.
		 */
		if (kof_src_evidence_only_of(sc->cur.src))
			oc_child_evidence_only(ctx);
		/*
		 * AND IT IS STILL THE SAME LANGUAGE, said rather than left to
		 * be re-read - see kof_src_declare_lang.
		 *
		 * This view is the object reformatted and decoded; it is not a
		 * different file and cannot be a different language. The
		 * decode is what makes saying so necessary: it rewrites the
		 * view's own text, and a payload that a shell script carries
		 * base64-encoded inside a quoted string arrives as PHP source
		 * with its quoting no longer balanced. Re-read, the view then
		 * opens with "<?php" at what looks like shell top level and is
		 * typed PHP - so KOF_TARGET_SUBTYPE(KOF_SCRIPT_SHELL) declines
		 * on the one object that finally holds the evidence, and 625
		 * Backdoor.Shell.Agent samples in this corpus stopped being
		 * detected the moment this view replaced the one norm_emit
		 * used to make. norm_emit declares the language for exactly
		 * this reason; so does this.
		 */
		script_declare(sc, ctx);
		if (oc_emit_exact(ctx, out, n)) {
			oc_child(ctx);
		} else {
			n = 0;
		}
	}
	/*
	 * ISLANDS, DECLARED LAST: after the normalised view above, so the view keeps slot
	 * 0 and islands are 1, 2, 3... whether or not this object actually got a view
	 * (`n` may be 0; an island is evidence in its own right either way - see where
	 * `isl` was found, above).
	 */
	if (isl)
		islands_declare(ctx, sc, b, isl);
	free(out);
	oc_scan_release(sc, charged);
	consts_end(sc, text2, charged2);
	KOF_TRACE("[script] forms done: view=%s, %u island(s) declared\n", n ? "made" : "none",
		  (unsigned)(isl ? isl->n : 0));
	return n;
}
