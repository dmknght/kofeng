/*
 * api_engine_verdict.c - <verdictor/verdict.h>: how a verdict is NAMED
 * (kof_verdict_name, kverdict_target, kof_object_label), how a
 * verdict is made of diseases (kof_verdict_make) and how a file's verdict is rolled
 * up from its objects (kverdict_filemap_*).
 *
 * The naming functions write into fixed arrays the host reads back through spans
 * (at, n) into kof_finding.name: the contract is that the name is always
 * terminated, every span lies inside it, and a name that did not fit says so
 * (name_cut) instead of being cut quietly. That is asserted with strings far
 * longer than the array and with absent parts.
 *
 * The file map is the one object a host keeps across a whole scan, so it is also
 * driven with what a long scan produces: thousands of files, names that chain
 * "//" a thousand deep, duplicates.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <stddef.h>

#include <kofmod/kofsig.h>
#include <kofmod/script.h>
#include "../../libkofeng/verdictor/verdict.h"
#include "../../libkofeng/kofcore/kofobjname.h"

static int span_ok(const struct kof_finding *f, const struct kof_name_span *s)
{
	return (size_t)s->at + s->n <= strlen(f->name);
}

static int spans_ok(const struct kof_finding *f)
{
	return span_ok(f, &f->target) && span_ok(f, &f->maltype) && span_ok(f, &f->family) &&
	       span_ok(f, &f->shape) && span_ok(f, &f->reason);
}

static int span_is(const struct kof_finding *f, const struct kof_name_span *s, const char *want)
{
	return s->n == strlen(want) && memcmp(f->name + s->at, want, s->n) == 0;
}

/* ---- the name's bound ---------------------------------------------------------------- */

static void t_name_clip(void)
{
	struct kof_finding f;
	char big[1000];

	memset(big, 'z', sizeof big - 1);
	big[sizeof big - 1] = 0;
	memset(&f, 0, sizeof f);
	f.verdict = KOF_VERDICT_INFECTED;
	f.type = KOF_MALTYPE_TROJAN;
	kof_verdict_name(&f, big, "R");
	CK(strlen(f.name) < sizeof f.name && spans_ok(&f), "a long family: terminated and spans inside");
	CK(f.name_cut, "a family that did not fit says name_cut");
	CK(span_is(&f, &f.maltype, "Trojan") && f.reason.n == 1,
	   "the parts after a long family are kept (room is reserved for them)");
	memset(&f, 0, sizeof f);
	kof_verdict_name(&f, big, big);
	CK(strlen(f.name) < sizeof f.name && spans_ok(&f) && f.name_cut,
	   "everything too long: still terminated, spans inside, cut said");
	memset(&f, 0, sizeof f);
	f.verdict = KOF_VERDICT_INFECTED;
	kof_verdict_name(&f, "F", "R");
	CK(!f.name_cut && strstr(f.name, ":F?R") != NULL, "short stays whole: %s", f.name);
	{
		/* exactly at the limit: name[] holds 223 characters and a terminator */
		char fam[300];

		memset(fam, 'q', sizeof fam - 1);
		fam[sizeof fam - 1] = 0;
		memset(&f, 0, sizeof f);
		kof_verdict_name(&f, fam, NULL);
		CK(strlen(f.name) == sizeof f.name - 1 && f.name_cut, "a family filling the array is cut at 223");
	}
}

/* ---- kof_verdict_name --------------------------------------------------------------- */

static void t_vname(void)
{
	struct kof_finding f;

	memset(&f, 0, sizeof f);
	f.verdict = KOF_VERDICT_INFECTED;
	f.fmt = KOF_FMT_ELF;
	f.arch = KOF_ARCH_X86_64;
	f.type = KOF_MALTYPE_TROJAN;
	f.engine = KOF_ENGINE_DIAGNOSE;
	kof_verdict_name(&f, "cnc.recv", "why");
	CK(strncmp(f.name, kof_verdict_word(KOF_VERDICT_INFECTED), strlen(kof_verdict_word(KOF_VERDICT_INFECTED))) == 0 &&
	   f.name[strlen(kof_verdict_word(KOF_VERDICT_INFECTED))] == '#', "the verdict word leads: %s", f.name);
	CK(strstr(f.name, "/Trojan:cnc.recv!Diagnose?why") != NULL, "target/type:behaviour!engine?reason: %s", f.name);
	CK(spans_ok(&f) && span_is(&f, &f.family, "cnc.recv") &&
	   span_is(&f, &f.shape, "Diagnose") && span_is(&f, &f.reason, "why") &&
	   span_is(&f, &f.maltype, "Trojan"), "spans");
	CK(f.target.n > 0, "the target span is for the scope word only: %s", f.name);

	f.engine = KOF_ENGINE_NONE;
	f.type = KOF_MALTYPE_COUNT;
	kof_verdict_name(&f, "packed", NULL);
	CK(strstr(f.name, "Malware:packed") != NULL && f.shape.n == 0 && f.reason.n == 0,
	   "a type the database does not name reads Malware, no engine means no shape: %s", f.name);

	{
		char big[600];

		memset(big, 'k', sizeof big - 1);
		big[sizeof big - 1] = 0;
		f.engine = KOF_ENGINE_DIAGNOSE;
		f.type = KOF_MALTYPE_TROJAN;
		kof_verdict_name(&f, big, big);
		CK(strlen(f.name) < sizeof f.name && spans_ok(&f) && f.name_cut, "over-long parts: terminated, inside, cut said");
	}
	kof_verdict_name(NULL, "a", "c");
	CK(1, "NULL finding ignored");
}

/* ---- target and label ---------------------------------------------------------------- */

static void t_target(void)
{
	char out[40];

	kverdict_target(out, sizeof out, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(strncmp(out, "ELF-", 4) == 0 && strlen(out) > 4, "format-arch: %s", out);
	kverdict_target(out, sizeof out, KOF_FMT_ELF, KGENOME_ARCH_ANY);
	CK(strcmp(out, "ELF") == 0, "an architecture-less object is the format alone: %s", out);
	kverdict_target(out, sizeof out, KOF_FMT_UNKNOWN, KOF_ARCH_X86_64);
	CK(strcmp(out, kof_format_name(KOF_FMT_UNKNOWN)) == 0, "an unknown format carries no architecture: %s", out);
	kverdict_target(out, 4, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(strlen(out) == 3, "cut to cap-1 and terminated");
	kverdict_target(out, sizeof out, 250, 250);
	CK(out[0] != 0, "values from outside still read as something");
}

static void t_label(void)
{
	char out[32];

	kof_object_label(KOF_ENT_UNKNOWN, "UPX", KOF_FMT_ELF, 0, out, sizeof out);
	CK(strcmp(out, "UPX") == 0, "a packer name wins");
	kof_object_label(KOF_ENT_NORMALIZED, "", KOF_FMT_ELF, 0, out, sizeof out);
	CK(strcmp(out, "Norm") == 0, "a normalised view is Norm");
	kof_object_label(KOF_ENT_NORMALIZED, "UPX", KOF_FMT_ELF, 0, out, sizeof out);
	CK(strcmp(out, "UPX") == 0, "and the packer outranks it");
	kof_object_label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_SCRIPT, 0, out, sizeof out);
	CK(strcmp(out, kof_format_name(KOF_FMT_SCRIPT)) == 0, "a script of no kind is the format word");
	kof_object_label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_SCRIPT, 1, out, sizeof out);
	CK(strcmp(out, kof_script_type_name(1)) == 0, "a script of a kind is the kind word");
	kof_object_label(KOF_ENT_UNKNOWN, NULL, KOF_FMT_ZIP, 0, out, sizeof out);
	CK(strcmp(out, kof_format_name(KOF_FMT_ZIP)) == 0, "otherwise the format name");
	memset(out, 'x', sizeof out);
	kof_object_label(KOF_ENT_UNKNOWN, "AVeryLongPackerNameIndeed", KOF_FMT_ELF, 0, out, 5);
	CK(strcmp(out, "AVer") == 0 && out[5] == 'x', "cut to cap-1");
	kof_object_label(KOF_ENT_UNKNOWN, "UPX", KOF_FMT_ELF, 0, NULL, 10);
	kof_object_label(KOF_ENT_UNKNOWN, "UPX", KOF_FMT_ELF, 0, out, 0);
	CK(1, "NULL out and cap 0 are ignored");
}

/* ---- the verdict made of diseases ----------------------------------------------------------- */

static struct kof_finding vmake(const struct kof_verdict_disease *d, uint32_t n, const uint32_t *diag,
				uint32_t n_diag, uint8_t fmt, uint8_t arch)
{
	struct kof_verdict_in in;
	struct kof_finding f;

	in.dis = d;
	in.n_dis = n;
	in.diag = diag;
	in.n_diag = n_diag;
	in.fmt = fmt;
	in.arch = arch;
	memset(&f, 0xaa, sizeof f);
	kof_verdict_make(&in, &f);
	return f;
}

static void t_verdict(void)
{
	struct kof_verdict_disease d[3];
	struct kof_finding f;
	uint32_t t;

	d[0].id = 1; d[0].type = KOF_MALTYPE_TROJAN; d[0].name = "cnc/recv";
	f = vmake(d, 1, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.verdict == KOF_VERDICT_INFECTED && f.type == KOF_MALTYPE_TROJAN &&
	   f.engine == KOF_ENGINE_NONE, "one disease is Infected of its type, no diagnose no engine word");
	CK(strstr(f.name, "Trojan:cnc.recv") != NULL && f.reason.n == 0, "the behaviour is the family, '/' written '.': %s", f.name);
	CK(f.fmt == KOF_FMT_ELF && f.arch == KOF_ARCH_X86_64, "format and arch are carried");
	CK(f.n_disease == 1 && f.disease_total == 1 && f.disease[0] == 1 && f.n_diag == 0, "and the way back is carried");

	d[1].id = 2; d[1].type = KOF_MALTYPE_BOTNET; d[1].name = "flood/raw";
	f = vmake(d, 2, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.type == KOF_MALTYPE_TROJAN && strstr(f.name, "?Botnet") != NULL,
	   "equal specificity: the lower type leads, the other is the reason: %s", f.name);
	d[2].id = 3; d[2].type = KOF_MALTYPE_MINER; d[2].name = "pool/stratum/login";
	f = vmake(d, 3, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.type == KOF_MALTYPE_MINER && strstr(f.name, "Miner:pool.stratum.login?Trojan+Botnet") != NULL,
	   "the most specific disease leads whatever its type: %s", f.name);
	{
		uint32_t diag[2] = { 77u, 78u };

		f = vmake(d, 1, diag, 2, KOF_FMT_ELF, KOF_ARCH_X86_64);
		CK(f.engine == KOF_ENGINE_DIAGNOSE && f.n_diag == 2 && f.diag[1] == 78u,
		   "a matched diagnose says Diagnose and is listed");
	}

	/* two diseases of one type: either leads, and the type is not repeated as a reason */
	d[0].id = 1; d[0].type = KOF_MALTYPE_MINER; d[0].name = "verdict/alpha";
	d[1].id = 2; d[1].type = KOF_MALTYPE_MINER; d[1].name = "verdict/zeta";
	f = vmake(d, 2, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.type == KOF_MALTYPE_MINER && !strchr(f.name, '?'), "one type twice: no reason: %s", f.name);
	/* the order the diseases come in does not change the name */
	d[0].id = 1; d[0].type = KOF_MALTYPE_MINER; d[0].name = "verdict/alpha";
	d[1].id = 2; d[1].type = KOF_MALTYPE_BOTNET; d[1].name = "verdict/beta";
	f = vmake(d, 2, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	{
		struct kof_verdict_disease r[2];
		struct kof_finding g;

		r[0] = d[1]; r[1] = d[0];
		g = vmake(r, 2, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
		CK(!strcmp(f.name, g.name), "the order of the diseases does not change the name: %s / %s", f.name, g.name);
	}

	d[0].name = NULL; d[0].type = 0xffu;
	f = vmake(d, 1, NULL, 0, KOF_FMT_PE, KGENOME_ARCH_ANY);
	CK(f.type == KOF_MALTYPE_COUNT && strstr(f.name, "Malware:unnamed") != NULL && spans_ok(&f),
	   "a disease the database does not name still makes a verdict: %s", f.name);

	for (t = 0; t < KOF_MALTYPE_COUNT; t++) {
		d[0].id = 1; d[0].type = (uint8_t)t; d[0].name = "a/b";
		f = vmake(d, 1, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
		CK(f.type == t && strstr(f.name, kof_maltype_name(t)) != NULL && spans_ok(&f) && !f.name_cut,
		   "type %u (%s) names itself", t, kof_maltype_name(t));
	}
	{
		struct kof_verdict_disease many[KOF_MALTYPE_COUNT];
		const char *p;
		unsigned listed = 0, k;

		for (k = 0; k < KOF_MALTYPE_COUNT; k++) {
			many[k].id = k + 1u;
			many[k].type = (uint8_t)k;
			many[k].name = "a/b";
		}
		f = vmake(many, KOF_MALTYPE_COUNT, NULL, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
		p = strchr(f.name, '?');
		for (k = 1; k < KOF_MALTYPE_COUNT; k++)
			if (p && strstr(p, kof_maltype_name(k)))
				listed++;
		CK(spans_ok(&f) && strlen(f.name) < sizeof f.name && listed == KOF_MALTYPE_COUNT - 1u,
		   "every other type is in the reason, none dropped (%u): %s", listed, f.name);
	}
	d[0].id = 1; d[0].type = KOF_MALTYPE_BOTNET; d[0].name = "a/b";
	f = vmake(d, 1, NULL, 0, 250, 250);
	CK(spans_ok(&f) && strlen(f.name) < sizeof f.name, "unknown format and arch");
}

/* ---- the file map ---------------------------------------------------------------------------- */

static void mkres(struct kof_result *r, const char *name, int examined, uint32_t broken)
{
	memset(r, 0, sizeof *r);
	if (name) {
		r->has_verdict = 1;
		r->verdict.verdict = KOF_VERDICT_INFECTED;
		r->verdict.type = KOF_MALTYPE_TROJAN;
		kof_verdict_name(&r->verdict, name, NULL);
	}
	r->examined = examined ? 1u : 0u;
	r->broken = broken;
}

static void t_filemap_basic(void)
{
	kverdict_filemap *m = kverdict_filemap_new();
	struct kof_result r;
	struct kverdict_file *e;

	CK(m != NULL && kverdict_filemap_count(m) == 0 && kverdict_filemap_files(m) == 0, "a new map is empty");
	CK(kverdict_filemap_at(m, 0) == NULL && kverdict_filemap_find(m, "x", 1) == NULL, "nothing in it");

	/* a clean object: no entry unless asked, but its root is a file */
	mkres(&r, NULL, 1, 0);
	CK(kverdict_filemap_fold(m, "a.bin", &r, 0) == NULL, "clean and examined: no entry");
	CK(kverdict_filemap_files(m) == 1, "but the file is counted");
	e = kverdict_filemap_fold(m, "a.bin", &r, 1);
	CK(e != NULL && !e->has_verdict && e->examined == 1 && e->name[0] == 0 && e->host == 0 &&
	   strcmp(e->file, "a.bin") == 0, "keep_clean makes an entry with no verdict");
	CK(kverdict_filemap_files(m) == 2, "folding the same root again counts again (it is a count of folds of roots)");

	/* not examined, or broken, is not clean */
	mkres(&r, NULL, 0, 0);
	e = kverdict_filemap_fold(m, "b.bin", &r, 0);
	CK(e && e->examined == 0 && !e->has_verdict, "nothing eligible: an entry even without keep_clean");
	mkres(&r, NULL, 1, KOF_BROKEN_LIMIT);
	e = kverdict_filemap_fold(m, "c.bin", &r, 0);
	CK(e && e->broken == KOF_BROKEN_LIMIT && e->examined == 1, "a broken object makes an entry");
	mkres(&r, NULL, 1, KOF_BROKEN_DAMAGED);
	e = kverdict_filemap_fold(m, "c.bin//0:x", &r, 0);
	CK(e && e->broken == KOF_BROKEN_LIMIT, "the first broken reason stays");
	CK(kverdict_filemap_files(m) == 4, "a child is not a file");

	/* verdicts: the first one made in the tree is the file's */
	mkres(&r, "I", 1, 0);
	e = kverdict_filemap_fold(m, "d.bin", &r, 0);
	CK(e && e->has_verdict && strstr(e->name, ":I") != NULL, "a verdict");
	mkres(&r, "I2", 1, 0);
	e = kverdict_filemap_fold(m, "d.bin//0", &r, 0);
	CK(e && strstr(e->name, ":I") != NULL && strstr(e->name, ":I2") == NULL, "a later verdict does not replace: first wins");
	mkres(&r, NULL, 1, 0);
	(void)kverdict_filemap_fold(m, "d.bin//1", &r, 0);
	e = kverdict_filemap_find(m, "d.bin", 5);
	CK(e && e->has_verdict, "an object without one leaves the file's verdict alone");
	CK(kverdict_filemap_count(m) == 4, "four files have entries (a, b, c, d)");
	CK(kverdict_filemap_at(m, 0) && strcmp(kverdict_filemap_at(m, 0)->file, "a.bin") == 0 &&
	   strcmp(kverdict_filemap_at(m, 3)->file, "d.bin") == 0 && kverdict_filemap_at(m, 4) == NULL,
	   "at() is in the order entries were first made");
	CK(kverdict_filemap_find(m, "c.bin", 5) == kverdict_filemap_at(m, 2), "find by name");
	CK(kverdict_filemap_find(m, "c.bin//0", 8) == NULL && kverdict_filemap_find(m, "c.bi", 4) == NULL &&
	   kverdict_filemap_find(m, "c.bin", 4) == NULL, "find is exact on the length given");

	/* the host's own field is the host's */
	e = kverdict_filemap_find(m, "d.bin", 5);
	e->host = 77;
	mkres(&r, "I", 1, 0);
	kverdict_filemap_fold(m, "d.bin//9", &r, 0);
	CK(e->host == 77, "the engine never touches host");

	/* argument refusals */
	mkres(&r, NULL, 1, 0);
	CK(kverdict_filemap_fold(NULL, "x", &r, 1) == NULL && kverdict_filemap_fold(m, NULL, &r, 1) == NULL &&
	   kverdict_filemap_fold(m, "x", NULL, 1) == NULL, "NULL map, object, result");
	CK(kverdict_filemap_count(NULL) == 0 && kverdict_filemap_files(NULL) == 0 && kverdict_filemap_at(NULL, 0) == NULL &&
	   kverdict_filemap_find(NULL, "x", 1) == NULL, "NULL map on the readers");
	kverdict_filemap_free(NULL);
	kverdict_filemap_free(m);
	CK(1, "free of NULL and of a map");
}

static void t_filemap_scale(void)
{
	kverdict_filemap *m = kverdict_filemap_new();
	struct kof_result r;
	char name[600];
	char deep[4200];
	size_t i, p = 0;
	struct kverdict_file *e;

	/* 20000 files: the index grows past its first size more than once. */
	for (i = 0; i < 20000; i++) {
		mkres(&r, "F", 1, 0);
		snprintf(name, sizeof name, "/path/to/file-%zu.bin", i);
		e = kverdict_filemap_fold(m, name, &r, 0);
		CK(e != NULL, "file %zu", i);
	}
	CK(kverdict_filemap_count(m) == 20000 && kverdict_filemap_files(m) == 20000, "20000 files");
	for (i = 0; i < 20000; i += 97) {
		snprintf(name, sizeof name, "/path/to/file-%zu.bin", i);
		e = kverdict_filemap_find(m, name, strlen(name));
		CK(e && strcmp(e->file, name) == 0 && e == kverdict_filemap_at(m, i), "find %zu agrees with at", i);
	}

	/* names that chain "//" a thousand deep: the file is the part before the first */
	for (i = 0; i < 1000 && p + 8 < sizeof deep; i++) {
		memcpy(deep + p, "x//", 3);
		p += 3;
	}
	deep[p++] = 'z';
	deep[p] = 0;
	mkres(&r, "D", 1, 0);
	e = kverdict_filemap_fold(m, deep, &r, 0);
	CK(e && strcmp(e->file, "x") == 0, "a 1000 deep object name rolls up to its first component");
	CK(kverdict_filemap_files(m) == 20000, "and is not itself a file");
	{
		struct kof_result c;

		mkres(&c, NULL, 1, 0);
		CK(kverdict_filemap_fold(m, "//x", &c, 1) != NULL && kverdict_filemap_find(m, "", 0) != NULL,
		   "an object name that starts with // belongs to the file named ''");
		CK(kverdict_filemap_fold(m, "", &c, 1) == kverdict_filemap_find(m, "", 0), "and so does the empty name");
	}

	/* a name longer than the entry's name array: the verdict's name is what is copied */
	{
		struct kof_result big;

		memset(&big, 0, sizeof big);
		big.has_verdict = 1;
		big.examined = 1;
		memset(big.verdict.name, 'n', sizeof big.verdict.name - 1);
		e = kverdict_filemap_fold(m, "long-finding", &big, 0);
		CK(e && strlen(e->name) == sizeof big.verdict.name - 1 && e->name[sizeof e->name - 1] == 0,
		   "a full-length verdict name fits the entry");
	}
	kverdict_filemap_free(m);
}

/* ---- hostile input to the roll-up ---------------------------------------------------------------- */

static int fold_hostile(void *arg)
{
	kverdict_filemap *m = kverdict_filemap_new();
	struct he_guard g;
	struct kof_result *r;
	struct kverdict_file *e;
	int ok;

	(void)arg;
	/* the result sits at the very end of a mapping: anything read past it faults */
	if (!m || !he_guard_make(&g, NULL, sizeof *r))
		return 9;
	r = (struct kof_result *)g.p;
	memset(r, 0, sizeof *r);
	r->has_verdict = 1;
	r->examined = 1;
	/* a verdict whose name is not terminated within the array */
	memset(r->verdict.name, 'N', sizeof r->verdict.name);
	e = kverdict_filemap_fold(m, "h.bin", r, 0);
	ok = e && strlen(e->name) == sizeof e->name - 1u;
	he_guard_free(&g);
	kverdict_filemap_free(m);
	return ok ? 0 : 1;
}

static void t_hostile_fold(void)
{
	struct he_status st;

	/* kverdict_filemap_fold is a public entry point a host can call with a result it read from
	 * anywhere else: a name that is not terminated is read as far as its array and no further. */
	st = he_child(fold_hostile, NULL, 10);
	CK(he_ok(st), "an unterminated verdict name does not leave the verdict: %s", he_how(st));
}

int main(void)
{
	t_name_clip();
	t_vname();
	t_target();
	t_label();
	t_verdict();
	t_filemap_basic();
	t_filemap_scale();
	t_hostile_fold();
	printf("api_engine_verdict: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
