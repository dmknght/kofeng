/*
 * objctx_script.c - the two forms of a script, as a child object.
 *
 * WHAT THIS SERVES: a module that reads a script asks for it twice - once with
 * the lexical noise folded away (kof_scan_script_fold), once with the language
 * normalised to a canonical form (kof_scan_script_form). Each answer is a CHILD
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

#include <kofmod/kofsym.h>
#include <kofmod/heur.h>   /* KOF_ENG_USE_EMU - a module's declaration */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "../analyzers/parsers/binaries/elf/elf_sym.h"
#include <kofmod/kofpathogen.h>
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../disinfect/pzero.h"
#include "../analyzers/normalize/executables.h"
#include "scan.h"
#include <kofmod/elf.h>
#include "../extractors/unpack/emu_unpack.h"
#include "../extractors/unpack/elf_rebuild.h"

#include "../extractors/decomp/ovba.h"
#include "../extractors/decomp/lzma.h"
#include "../extractors/decomp/aplib.h"
#include "../extractors/decomp/aspack.h"
#include "../extractors/decomp/lzmat.h"
#include "../extractors/decomp/bcj.h"
#include "../extractors/decomp/rar3.h"
#include "../extractors/decomp/rar5.h"
#include "../extractors/decomp/bcj2.h"
/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_fold below. */
#include "../analyzers/parsers/scripts/script_norm.h"
#include "../analyzers/parsers/scripts/script_parse.h"
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */
#include <kofmod/sevenzip.h>

#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/pathogen/kofdiag.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "objctx_int.h"


/*
 * The one setup both passes below need, and the one place their refusals are
 * written down.
 *
 * `b` comes back as the object's bytes and `lx` as the table for its language.
 * Answers 0 when there is nothing to do, and the reasons are all of the form
 * "this is not a script this build can read", never "this script is clean".
 */
static int script_pass_open(const struct kof_obj_ctx *ctx,
			    struct kof_scanner **psc, const struct kof_lex **plx,
			    kof_buf *b)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_script_info *si;

	if (!sc || !sc->cur_src || !ctx->file_header)
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
	if (kof_src_kind_of(sc->cur_src) == KOF_ENT_NORMALIZED)
		return 0;
	si = (const struct kof_script_info *)ctx->file_header;
	*plx = kof_lex_for(si->kind);
	if (!*plx)
		return 0;       /* no table for the kind: nothing is guessed */

	*b = kof_src_buf(sc->cur_src);
	if (!b->p || !b->n || b->n > sc->obj_cap || b->n > 0xffffffffu)
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
	sc->pend_subtype = ctx->subtype;
	sc->pend_subfam  = ctx->subfamily;
	sc->pend_lang    = 1;
}

/*
 * THE TAG THE FILE OPENED WITH, IN FRONT OF WHAT THE PASS PRODUCED.
 *
 * A produced form has to be READABLE AS THE LANGUAGE IT IS, and this is not a
 * nicety - it is the difference between the child being scanned and not.
 * kof_script_sniff accepts a script on a shebang at offset zero or on an
 * opening tag, and it has nothing else to go on: a bare "$k="4e4d..." is a
 * fragment that no sniff claims, so the child came out KOF_FMT_UNKNOWN and
 * every rule written about a PHP script was filtered out before it ran. That
 * was measured, not feared - the folded form of a real shell examined as
 * "unrecognised, 160 bytes".
 *
 * THE TAG FROM THE PARSE, NOT THE HEADER REGION. It used to resolve
 * KOF_SCAN_SCRIPT_HEADER, which worked only while php was credited with a
 * header; it has none now - its tag opens a body block - so the region is
 * empty and the wrapper would have been too. tag_off and tag_len are the fact
 * itself and are right for all three shapes: "<?php", a "<%@ ... %>" directive
 * run, and a "#!" line.
 */
static int script_head_emit(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_script_info *si = kof_script(ctx);
	kof_buf b = kof_src_buf(sc->cur_src);
	kof_buf s;

	if (!si || !si->tag_len)
		return 1;               /* nothing named it; nothing to put back */
	s = kof_slice(b, si->tag_off, si->tag_len);
	if (!s.p || !s.n)
		return 1;
	if (!oc_emit_exact(ctx, s.p, s.n))
		return 0;
	/*
	 * AND A NEWLINE AFTER IT, WHICH THE LANGUAGE REQUIRES.
	 *
	 * "<?php" is not a tag php accepts on its own - it has to be followed
	 * by whitespace, and the first thing the form pass removes is the blank
	 * line under it. Joining the two produced "<?php$p='...", which sniffs
	 * as php, parses as php here, and is a syntax error in php.
	 *
	 * Only when the tag did not already end in one, so a shebang - which
	 * carries its line ending with it - does not gain a blank line the pass
	 * would have taken out.
	 */
	if (s.p[s.n - 1u] != '\n' &&
	    !oc_emit_exact(ctx, (const uint8_t *)"\n", 1u))
		return 0;
	return 1;
}

/* Copy bytes the pass must not touch. Answers `held` unchanged when there is no
 * room, which cannot happen while the output is bounded by the input. */
static uint32_t verbatim(uint8_t *out, uint32_t held, uint32_t cap,
			 const uint8_t *p, uint64_t n)
{
	if (!p || !n || held + n > cap)
		return held;
	memcpy(out + held, p, (size_t)n);
	return held + (uint32_t)n;
}

/*
 * HOW THE PROGRAM WAS TYPED, TAKEN OUT OF IT - the form pass, over the WHOLE
 * object.
 *
 * A signature is bytes, and bytes carry the indentation, the blank lines, the
 * comments and the spacing of whichever copy the researcher had. Every one of
 * those is free for an author to change and none of them changes what the
 * program does, so a marker cut from one copy misses the next. This produces
 * the same file with all of that removed, once, and a marker taken from THAT
 * copy matches every way of typing it.
 *
 * THE PASS RUNS ON BODY AND ON NOTHING ELSE, AND THE REST IS COPIED.
 *
 * Those are two rules, not one, and the second is what this used to get wrong.
 * It walked the BODY extents and emitted only those, so a page came out as its
 * code with the html deleted - and the result was no longer the file. It could
 * not be shown as one either: re-parsed it had one BODY and no MARKUP, so the
 * reader lost where the code had been cut into the page, which is the first
 * thing worth seeing about a page.
 *
 * So the walk is over the whole object. What lies between the BODY extents is
 * the complement of them - the header, the markup gaps, the closing tag - and
 * every byte of it is copied exactly as the parse found it. That is not
 * conservatism, it is correctness: the rules here are the LANGUAGE's, and
 * applied to markup they are wrong in both directions - "//" in an unquoted
 * href is not a comment, and closing up the spaces in a sentence changes it.
 *
 * Because the complement is copied, the result re-parses into the same regions
 * the input had, and the viewer draws a page as a page.
 *
 * A NEWLINE AT A BOUNDARY THAT WOULD OTHERWISE GLUE. The first thing the pass
 * removes from a body is the blank line under the tag that opened it, so
 * "<?php" and the first statement ran together into "<?php$u=" - which sniffs
 * as php, parses as php here, and is a syntax error in php. One rule covers it
 * and the closing tag at the other end: at a boundary between a copied run and
 * a formed one, in either direction, put back a newline unless one of the two
 * sides already has one.
 *
 * Writes into `out`, which must hold b.n, and answers how long the result is.
 */
static uint32_t script_form(const struct kof_obj_ctx *ctx,
			    struct kof_scanner *sc, const struct kof_lex *lx,
			    kof_buf b, uint8_t *out, uint32_t cap)
{
	struct kof_range *ext;
	uint32_t n_ext, i, held = 0;
	uint64_t at = 0;

	ext = sc->ext_gather;
	n_ext = kof_scan_resolve_range(ctx, KOF_SCAN_SCRIPT_BODY, ext);
	if (!n_ext)
		return 0;
	/*
	 * Built whole before anything is emitted, because whether to emit at
	 * all is a question about the whole of it: an extent that formed to
	 * itself says nothing about the next one.
	 */
	for (i = 0; i < n_ext; i++) {
		kof_buf s = kof_slice(b, ext[i].off, ext[i].len);
		uint32_t w;

		/* Everything since the last body extent, exactly as it is. */
		if (ext[i].off > at)
			held = verbatim(out, held, cap, b.p + at,
					ext[i].off - at);
		at = ext[i].off + ext[i].len;
		if (!s.p || !s.n || s.n > 0xffffffffu)
			continue;
		if (held + 1u >= cap)
			break;
		/*
		 * FORMED ONE BYTE ALONG, SO THE BOUNDARY IS DECIDED ON WHAT
		 * CAME OUT.
		 *
		 * Whether a separator is needed is a question about the first
		 * byte of the FORMED run, not of the input's - and the two
		 * differ exactly where it matters. A body opens with the
		 * newline under its tag, which reads as "already separated";
		 * the pass then removes that newline as a blank line and the
		 * tag ends up welded to the first statement. Measured as
		 * "<?php$u=" - sniffs as php, parses as php here, and is a
		 * syntax error in php.
		 *
		 * So a byte is reserved, the pass writes past it, and the byte
		 * is either filled in or closed up once there is something to
		 * look at.
		 */
		w = kof_script_norm(lx, s.p, (uint32_t)s.n, out + held + 1u,
				    cap - held - 1u, KOF_NORM_ALL);
		/*
		 * A REFUSAL KEEPS THE BYTES. kof_script_norm answers 0 when it
		 * will not touch an extent - a heredoc in it, no room - and the
		 * contract there is that the caller uses the input as it
		 * stands. Dropping the extent instead would hand over a program
		 * with a hole in it and call it the same program.
		 */
		if (!w) {
			held = verbatim(out, held, cap, s.p, s.n);
			continue;
		}
		/*
		 * AND A BLOCK THAT CAME OUT EMPTY GOES WITH WHAT EMPTIED IT.
		 *
		 * A block holding one comment forms to "<%\n%>" - a code
		 * region with no code in it. The comment was how the file was
		 * typed, the block around it was typed to hold the comment, and
		 * the pass that removes the one removes the other. Dropped
		 * whole: `at` is already past it, so the markup either side
		 * joins up and the partition stays exact.
		 */
		if (kof_script_block_bare(ctx->subtype, out + held + 1u, w))
			continue;
		if (held && out[held - 1] != '\n' && out[held + 1u] != '\n') {
			out[held] = '\n';
			held += w + 1u;
		} else {
			memmove(out + held, out + held + 1u, (size_t)w);
			held += w;
		}
	}
	/* The closing tag, the markup after the last island, or nothing. */
	if (at < b.n) {
		if (held && out[held - 1] != '\n' && b.p[at] != '\n')
			held = verbatim(out, held, cap,
					(const uint8_t *)"\n", 1u);
		held = verbatim(out, held, cap, b.p + at, b.n - at);
	}
	return held;
}

/*
 * THE SCRIPT IN THE FORM A SIGNATURE SHOULD BE WRITTEN ON - one child, and the
 * last form, not every form on the way to it.
 *
 * Two passes make that form and they compose in one direction:
 *
 *   form    how the program was TYPED, removed. Indentation, blank lines,
 *           comment-only lines, spacing outside strings. Always run.
 *   fold    what the program BUILDS out of its own literals, built. A
 *           generator that cuts a shell into pieces, scatters them over
 *           variables and joins them at run time leaves no byte string that
 *           survives two builds - the separator, the names, the cut points and
 *           the join order all change. Measured on two builds of one php
 *           obfuscator: not one shared substring in the raw files, and the
 *           same 65 bytes after folding. Costs a walk over every assignment,
 *           so it is `deep` - level 2 - only.
 *
 * WHEN THE FOLD FIRES, THE FORM OF THE FOLD IS THE ONLY CHILD. Emitting both
 * put two nodes in the viewer's tree for one file and left the reader to work
 * out which one to take a marker from - and the answer was always the same one,
 * the last. So the fold's output goes through the form pass and that is what is
 * handed over; the intermediate never becomes an object.
 *
 * THE FOLD READS THE WHOLE OBJECT, the form pass only its BODY. The pieces of a
 * built program are literals wherever they were assigned, and a server page
 * that assigns one in an island and joins it in the next has a join that
 * folding island by island would miss.
 *
 * A PACKER'S SHAPE, HERE AND NOT IN A DATABASE MODULE. An unpacker in bases/ is
 * a compiled blob that reaches the host through ctx->content, and both passes
 * need the parser's own lexical table - kof_lex_for - which is not in that
 * vocabulary and should not be: adding it would put a language table in the
 * module ABI.
 */
uint32_t kof_scan_script_forms(const struct kof_obj_ctx *ctx, int deep)
{
	struct kof_scanner *sc = NULL;
	const struct kof_lex *lx = NULL;
	uint8_t *out = NULL, *tmp = NULL;
	kof_buf b;
	uint32_t n = 0, raw = 0, cap;
	int decoded = 0;

	if (!script_pass_open(ctx, &sc, &lx, &b))
		return 0;
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
		uint64_t need = b.n + 2ull * KOF_SCRIPT_MAX_ISLAND + 2ull;

		if (need > 0xffffffffu)
			return 0;
		cap = (uint32_t)need;
	}
	out = malloc((size_t)cap);
	if (!out)
		return 0;

	if (deep) {
		n = kof_script_fold(lx, b.p, (uint32_t)b.n, out, (uint32_t)b.n);
		/*
		 * A SHORT CONSTANT IS NOT A PROGRAM. Every script builds small
		 * strings - a path, a message, a separator - and handing each
		 * one over as an object would bury the one that matters under
		 * them. Sixty-four bytes is shorter than the smallest of the
		 * shells this was built against and longer than the strings
		 * ordinary code assembles.
		 */
		/*
		 * AND IT ONLY DISPLACES THE FORMED FILE WHEN IT IS MOST OF THE
		 * FILE.
		 *
		 * The fold answers "what does this script build out of its own
		 * literals", and there are two very different files that
		 * answer it:
		 *
		 *   A BUILDER, whose whole purpose is to assemble a program -
		 *   the pieces ARE the file, and what they build is the thing
		 *   worth signing.
		 *   A PROGRAM THAT HOLDS A CONSTANT - a blob, a page, a config
		 *   string - which is incidental to it.
		 *
		 * Handing the second one over as the object replaced the file
		 * with a scrap of it. Measured on Ani-Shell.php: 87075 bytes of
		 * shell, and the child was the 3144-byte base64 python backdoor
		 * it carries - so all 87 KB of the code a researcher came to
		 * read was not in the tree at all.
		 *
		 * TWO TESTS, AND THE SHARE IS THE WEAKER ONE.
		 *
		 * WAS IT ASSEMBLED AT ALL. The fold hands back the largest
		 * value the script builds, and "builds" is doing no work when
		 * that value is ONE LITERAL copied out of the file - the
		 * generator joined nothing, and what came back is a constant
		 * the program happens to hold. So: if the folded bytes occur
		 * VERBATIM in the object, this is not a build.
		 *
		 * Measured over the sample tree, of the seven scripts whose
		 * fold covers more than a third of the file:
		 *
		 *   hoho.php, hoho_1, hoho_2   assembled - a real generator,
		 *                              and the fold is the shell
		 *   sym403.php, vhost.php,     ONE literal, copied. 99%, 90%,
		 *   b374k-mini, B374k Beta     68% of the file - and handing
		 *                              the literal over deleted the
		 *                              php around it, which is the
		 *                              whole of what those files are
		 *
		 * The share alone called all seven builders. It is kept as the
		 * second test, because an ASSEMBLED value can still be
		 * incidental: itsecteam_shell and alfa assemble something that
		 * is 1% of the file, and handing that over would lose the shell
		 * for the same reason Ani-Shell.php did - 87075 bytes of code
		 * replaced by the 3144-byte blob it carries.
		 *
		 * Over 30 php shells that fold to anything the coverage is
		 * 0-16% for twenty-three and 57-99% for seven, with NOTHING in
		 * between; a third is the middle of that empty band.
		 *
		 * AND NOTHING HERE LOOKS INSIDE THE VALUE. There was a test for
		 * "does this look like html". It is gone: deciding what a value
		 * CONTAINS is parsing data, and a pass that cuts on its own
		 * reading of data is a pass that can corrupt it. "Does this
		 * appear in the file" is not a reading of the bytes - it is the
		 * same question the fold already answered, asked backwards.
		 */
		if (n < 64u || (uint64_t)n * 3u < b.n ||
		    kof_memmem(b.p, (size_t)b.n, out, (size_t)n)) {
			n = 0;
		} else {
			tmp = malloc((size_t)n);
			if (tmp) {
				uint32_t w = kof_script_norm(lx, out, n, tmp, n,
							     KOF_NORM_ALL);

				/* 0 is "I will not touch this", and the
				 * contract there is to keep the input. */
				if (w) {
					free(out);
					out = tmp;
					n = w;
				} else {
					free(tmp);
				}
			}
		}
	}
	if (n) {
		/*
		 * THE FOLD'S OUTPUT IS NOT A FILE, so it is given the tag its
		 * parent opened with. The form pass below needs none of this -
		 * it produces the whole object, header and markup and closing
		 * tag included, because it copied them.
		 */
		oc_child_kind(ctx, KOF_ENT_NORMALIZED);
		/* Said plainly, like the formed view below - see the call
		 * there for why the decode belongs to this pass. */
		kof_exe_decode(out, n);
		script_declare(sc, ctx);
		if (!script_head_emit(ctx) || !oc_emit_exact(ctx, out, n))
			n = 0;
		else
			oc_child(ctx);
		free(out);
		return n;
	}

	n = script_form(ctx, sc, lx, b, out, cap);
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
	decoded = n ? kof_exe_decode(out, n) : 0;
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
	if (n < 32u || raw < n || (!decoded && raw - n < 16u))
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
		if (oc_emit_exact(ctx, out, n))
			oc_child(ctx);
		else
			n = 0;
	}
	free(out);
	return n;
}
