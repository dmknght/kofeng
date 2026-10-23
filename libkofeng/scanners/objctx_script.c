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
	if (kof_src_kind_of(sc->cur.src) == KOF_ENT_NORMALIZED)
		return 0;
	si = (const struct kof_script_info *)ctx->file_header;
	if (!kof_script_textual_lang(si->kind))
		return 0;       /* no lexer for the kind: nothing is guessed */

	*b = kof_src_buf(sc->cur.src);
	if (!b->p || !b->n || b->n > sc->ledger.obj_cap || b->n > 0xffffffffu)
		return 0;
	*psc = sc;
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
		if (n_sub) {
			in_p = text2;
			in_n = n2;
		}
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
		struct oc_script_form_req fq = { .lang = lang, .in = in_p, .n = (uint32_t)in_n, .out = out,
						 .cap = cap, .dec = dec };

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
	decoded |= n_dec != 0;
	if (n < 32u || (raw < n && !n_dec) || (!decoded && raw - n < 16u))
		n = 0;
	if (n) {
		oc_child_kind(ctx, KOF_ENT_NORMALIZED);
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
	free(out);
	oc_scan_release(sc, charged);
	consts_end(sc, text2, charged2);
	return n;
}
