/*
 * api_engine_verdict.c - <verdictor/verdict.h>: how a finding is NAMED
 * (kverdict_compose, kverdict_name, kof_verdict_name, kverdict_target,
 * kof_object_label), how a syndrome becomes one (kof_verdict_syndrome) and how a
 * file's verdict is rolled up from its objects (kverdict_filemap_*).
 *
 * The naming functions write into fixed arrays the host reads back through spans
 * (at, n) into kof_finding.name: the contract is that the name is always
 * terminated, every span lies inside it, and a name that did not fit says so
 * (name_cut) instead of being cut quietly. That is asserted with strings far
 * longer than the array and with absent parts.
 *
 * The file map is the one object a host keeps across a whole scan, so it is also
 * driven with what a long scan produces: thousands of files, names that chain
 * "//" a thousand deep, duplicates, ranks arriving in every order.
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
	       span_ok(f, &f->variant) && span_ok(f, &f->shape) && span_ok(f, &f->reason);
}

static int span_is(const struct kof_finding *f, const struct kof_name_span *s, const char *want)
{
	return s->n == strlen(want) && memcmp(f->name + s->at, want, s->n) == 0;
}

/* ---- kverdict_compose -------------------------------------------------------------- */

static void t_compose(void)
{
	char out[64];

	kverdict_compose(out, sizeof out, "ELF-x64", "Trojan", "Mirai", "A");
	CK(strcmp(out, "ELF-x64/Trojan:Mirai#A") == 0, "target, type, family, variant: %s", out);
	kverdict_compose(out, sizeof out, "ELF", "Trojan", "Mirai", NULL);
	CK(strcmp(out, "ELF/Trojan:Mirai") == 0, "no variant: %s", out);
	kverdict_compose(out, sizeof out, "ELF", "Trojan", "Mirai", "");
	CK(strcmp(out, "ELF/Trojan:Mirai") == 0, "an empty variant is no variant");
	kverdict_compose(out, sizeof out, NULL, "Trojan", "Mirai", "B");
	CK(strcmp(out, "Trojan:Mirai#B") == 0, "no target: %s", out);
	kverdict_compose(out, sizeof out, "", "Trojan", "Mirai", NULL);
	CK(strcmp(out, "Trojan:Mirai") == 0, "an empty target is no target");

	memset(out, 'x', sizeof out);
	kverdict_compose(out, 8, "ELF", "Trojan", "Mirai", "A");
	CK(out[7] == 0 && strlen(out) == 7 && strncmp(out, "ELF/Tro", 7) == 0, "cut to cap-1 and terminated: %s", out);
	memset(out, 'x', sizeof out);
	kverdict_compose(out, 1, "ELF", "Trojan", "Mirai", "A");
	CK(out[0] == 0 && out[1] == 'x', "cap 1 writes only the terminator");
	memset(out, 'x', sizeof out);
	kverdict_compose(out, 0, "ELF", "Trojan", "Mirai", "A");
	CK(out[0] == 'x', "cap 0 writes nothing");
	kverdict_compose(NULL, 10, "ELF", "Trojan", "Mirai", "A");
	CK(1, "NULL out is ignored");
}

/* ---- kverdict_name ----------------------------------------------------------------- */

static void t_name(void)
{
	struct kof_finding f;
	char big[1000];

	memset(&f, 0xaa, sizeof f);
	kverdict_name(&f, "ELF-x64", "Trojan", "Mirai", "A", "Packed");
	CK(strcmp(f.name, "ELF-x64/Trojan:Mirai#A!Packed") == 0, "composed: %s", f.name);
	CK(span_is(&f, &f.target, "ELF-x64") && span_is(&f, &f.maltype, "Trojan") &&
	   span_is(&f, &f.family, "Mirai") && span_is(&f, &f.variant, "A") && span_is(&f, &f.shape, "Packed"),
	   "every span reads back its part");
	CK(!f.name_cut, "nothing was cut");

	kverdict_name(&f, NULL, "Trojan", "Mirai", NULL, NULL);
	CK(strcmp(f.name, "Trojan:Mirai") == 0 && f.target.n == 0 && f.variant.n == 0 && f.shape.n == 0,
	   "absent parts have empty spans: %s", f.name);
	kverdict_name(&f, "", "Trojan", NULL, NULL, NULL);
	CK(strcmp(f.name, "Trojan:") == 0 && f.family.n == 0, "a NULL family is empty: %s", f.name);
	memset(&f, 0, sizeof f);
	kverdict_name(&f, "ELF", NULL, "F", NULL, NULL);
	CK(strcmp(f.name, "ELF/:F") == 0 && spans_ok(&f), "a NULL maltype is empty, not a crash: %s", f.name);
	kverdict_name(NULL, "ELF", "T", "F", NULL, NULL);
	CK(1, "a NULL finding is ignored");

	/* A finding named once with a reason, then named again without one. */
	memset(&f, 0, sizeof f);
	f.verdict = KOF_VERDICT_HEUR;
	f.engine = KOF_ENGINE_PATTERN;
	kof_verdict_name(&f, "Fam", NULL, "because");
	CK(f.reason.n == 7, "the first naming set a reason span");
	kverdict_name(&f, "ELF", "Trojan", "Mirai", NULL, NULL);
	CK(f.reason.n == 0, "re-naming a finding with kverdict_name leaves no stale reason span");

	memset(big, 'z', sizeof big - 1);
	big[sizeof big - 1] = 0;
	memset(&f, 0, sizeof f);
	kverdict_name(&f, "ELF", "Trojan", big, "V", NULL);
	CK(strlen(f.name) < sizeof f.name && spans_ok(&f), "a long family: terminated and spans inside");
	CK(f.name_cut, "a family that did not fit says name_cut");
	CK(span_is(&f, &f.maltype, "Trojan") && f.variant.n == 1 && f.name[f.variant.at] == 'V',
	   "the parts after a long family are kept (room is reserved for them)");
	memset(&f, 0, sizeof f);
	kverdict_name(&f, big, big, big, big, big);
	CK(strlen(f.name) < sizeof f.name && spans_ok(&f) && f.name_cut, "everything too long: still terminated, spans inside, cut said");
	memset(&f, 0, sizeof f);
	kverdict_name(&f, "T", "M", "F", "V", "S");
	CK(!f.name_cut && strcmp(f.name, "T/M:F#V!S") == 0, "short stays whole");
	{
		/* exactly at the limit: name[] holds 223 characters and a terminator */
		char fam[300];

		memset(fam, 'q', sizeof fam - 1);
		fam[sizeof fam - 1] = 0;
		memset(&f, 0, sizeof f);
		kverdict_name(&f, NULL, "T", fam, NULL, NULL);
		CK(strlen(f.name) == sizeof f.name - 1 && f.name_cut, "a family filling the array is cut at 223");
		fam[220] = 0;
		kverdict_name(&f, NULL, "T", fam, NULL, NULL);
		CK(!f.name_cut && strlen(f.name) == 2u + 220u, "and one that fits is not");
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
	f.type_known = 1;
	f.engine = KOF_ENGINE_PATTERN;
	kof_verdict_name(&f, "Mirai", "A", "why");
	CK(strncmp(f.name, "Infected#", 9) == 0, "the verdict word leads: %s", f.name);
	CK(strstr(f.name, "/Trojan:Mirai.A!Pattern?why") != NULL, "target/type:family.variant!engine?reason: %s", f.name);
	CK(spans_ok(&f) && span_is(&f, &f.family, "Mirai") && span_is(&f, &f.variant, "A") &&
	   span_is(&f, &f.shape, "Pattern") && span_is(&f, &f.reason, "why") &&
	   span_is(&f, &f.maltype, "Trojan"), "spans");
	CK(f.target.n > 0, "the target span is for the scope word only: %s", f.name);

	f.engine = KOF_ENGINE_NONE;
	f.type_known = 0;
	f.verdict = KOF_VERDICT_HEUR;
	kof_verdict_name(&f, "Packed", NULL, NULL);
	CK(strstr(f.name, "Heur:Packed") != NULL && f.variant.n == 0 && f.shape.n == 0 && f.reason.n == 0,
	   "an unknown type reads Heur, no engine means no shape: %s", f.name);
	CK(kverdict_is_heur(&f), "and a finding so named is a heuristic");

	{
		char big[600];

		memset(big, 'k', sizeof big - 1);
		big[sizeof big - 1] = 0;
		f.engine = KOF_ENGINE_PATTERN;
		f.type_known = 1;
		kof_verdict_name(&f, big, big, big);
		CK(strlen(f.name) < sizeof f.name && spans_ok(&f) && f.name_cut, "over-long parts: terminated, inside, cut said");
	}
	kof_verdict_name(NULL, "a", "b", "c");
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

/* ---- the syndrome verdict ---------------------------------------------------------------- */

static struct kof_finding synd(uint32_t g, uint32_t p, uint8_t fmt, uint8_t arch)
{
	struct kof_synd_result r;
	struct kof_verdict_in in;
	struct kof_finding f;

	memset(&r, 0, sizeof r);
	r.guaranteed = g;
	r.possible = p;
	r.n_query = 1;
	in.synd = &r;
	in.fmt = fmt;
	in.arch = arch;
	memset(&f, 0xaa, sizeof f);
	kof_verdict_syndrome(&in, &f);
	return f;
}

static void t_syndrome(void)
{
	struct kof_finding f;
	uint32_t t, all = 0;

	f = synd(1u << KOF_MALTYPE_TROJAN, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.level == KOF_LEVEL_INFECT && f.verdict == KOF_VERDICT_INFECTED && f.type == KOF_MALTYPE_TROJAN &&
	   f.type_known && f.engine == KOF_ENGINE_SYNDROME, "a proven type is Infected of that type");
	CK(strstr(f.name, "Trojan:Agent") != NULL && f.reason.n == 0, "named Agent, nothing to add: %s", f.name);
	CK(f.fmt == KOF_FMT_ELF && f.arch == KOF_ARCH_X86_64, "format and arch are carried");

	f = synd((1u << KOF_MALTYPE_TROJAN) | (1u << KOF_MALTYPE_BOTNET), 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(f.level == KOF_LEVEL_INFECT && f.type == KOF_MALTYPE_TROJAN && strstr(f.name, "?Botnet") != NULL,
	   "several proven types: the first leads, the rest follow: %s", f.name);

	f = synd(0, 1u << KOF_MALTYPE_MINER, KOF_FMT_PE, KGENOME_ARCH_ANY);
	CK(f.level == KOF_LEVEL_SUSPECT && f.verdict == KOF_VERDICT_SUSPECTED && f.type == KOF_MALTYPE_MINER &&
	   f.variant.n > 0 && span_is(&f, &f.variant, "Predict"), "one possible type is a prediction: %s", f.name);

	f = synd(0, (1u << KOF_MALTYPE_MINER) | (1u << KOF_MALTYPE_ADWARE), KOF_FMT_PE, KGENOME_ARCH_ANY);
	CK(f.level == KOF_LEVEL_SUSPECT && f.type == KOF_MALTYPE_COUNT && span_is(&f, &f.family, "Ambiguous") &&
	   strstr(f.name, "Miner,Adware") != NULL, "several possible types are Ambiguous and listed: %s", f.name);

	f = synd(0, 0, KOF_FMT_PE, KGENOME_ARCH_ANY);
	CK(f.level == KOF_LEVEL_INFECT && f.type == KOF_MALTYPE_COUNT && span_is(&f, &f.family, "Unresolved"),
	   "evidence of nothing known is Unresolved: %s", f.name);

	for (t = 0; t < KOF_MALTYPE_COUNT; t++) {
		all |= 1u << t;
		f = synd(1u << t, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
		CK(f.type == t && strstr(f.name, kof_maltype_name(t)) != NULL && spans_ok(&f) && !f.name_cut,
		   "type %u (%s) names itself", t, kof_maltype_name(t));
	}
	f = synd(all, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(spans_ok(&f) && strlen(f.name) < sizeof f.name, "every type proven at once fits the finding");
	f = synd(0, all, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(spans_ok(&f) && strlen(f.name) < sizeof f.name, "every type possible at once fits");
	{
		const char *p = strchr(f.name, '?');
		unsigned listed = 0, k;

		for (k = 0; k < KOF_MALTYPE_COUNT; k++)
			if (p && strstr(p, kof_maltype_name(k)))
				listed++;
		CK(listed == KOF_MALTYPE_COUNT, "the Ambiguous list names all %u types, none dropped (%u): %s",
		   (unsigned)KOF_MALTYPE_COUNT, listed, f.name);
	}
	/* bits no type has */
	f = synd(0x80000000u, 0, KOF_FMT_ELF, KOF_ARCH_X86_64);
	CK(spans_ok(&f) && strlen(f.name) < sizeof f.name && strstr(f.name, "Malware") != NULL,
	   "a proven bit no type owns still names as Malware: %s", f.name);
	f = synd(0xffffffffu, 0xffffffffu, 250, 250);
	CK(spans_ok(&f) && strlen(f.name) < sizeof f.name, "all bits, unknown format and arch");
}

/* ---- the file map ---------------------------------------------------------------------------- */

static void mkres(struct kof_result *r, const char *name, uint32_t level, int examined, uint32_t broken)
{
	memset(r, 0, sizeof *r);
	if (name) {
		r->n = 1;
		r->v[0].level = level;
		kverdict_name(&r->v[0], "ELF", "Trojan", name, NULL, NULL);
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
	mkres(&r, NULL, 0, 1, 0);
	CK(kverdict_filemap_fold(m, "a.bin", &r, 0) == NULL, "clean and examined: no entry");
	CK(kverdict_filemap_files(m) == 1, "but the file is counted");
	e = kverdict_filemap_fold(m, "a.bin", &r, 1);
	CK(e != NULL && e->level == -1 && e->examined == 1 && e->name[0] == 0 && e->host == 0 &&
	   strcmp(e->file, "a.bin") == 0, "keep_clean makes an entry with level -1");
	CK(kverdict_filemap_files(m) == 2, "folding the same root again counts again (it is a count of folds of roots)");

	/* not examined, or broken, is not clean */
	mkres(&r, NULL, 0, 0, 0);
	e = kverdict_filemap_fold(m, "b.bin", &r, 0);
	CK(e && e->examined == 0 && e->level == -1, "nothing eligible: an entry even without keep_clean");
	mkres(&r, NULL, 0, 1, KOF_BROKEN_LIMIT);
	e = kverdict_filemap_fold(m, "c.bin", &r, 0);
	CK(e && e->broken == KOF_BROKEN_LIMIT && e->examined == 1, "a broken object makes an entry");
	mkres(&r, NULL, 0, 1, KOF_BROKEN_DAMAGED);
	e = kverdict_filemap_fold(m, "c.bin//0:x", &r, 0);
	CK(e && e->broken == KOF_BROKEN_LIMIT, "the first broken reason stays");
	CK(kverdict_filemap_files(m) == 4, "a child is not a file");

	/* findings and the rank order */
	mkres(&r, "H", KOF_LEVEL_HEUR, 1, 0);
	e = kverdict_filemap_fold(m, "d.bin", &r, 0);
	CK(e && e->level == KOF_LEVEL_HEUR, "a heuristic finding");
	mkres(&r, "S", KOF_LEVEL_SUSPECT, 1, 0);
	e = kverdict_filemap_fold(m, "d.bin//0", &r, 0);
	CK(e && e->level == KOF_LEVEL_SUSPECT && strstr(e->name, ":S") != NULL, "suspect outranks heuristic");
	mkres(&r, "I", KOF_LEVEL_INFECT, 1, 0);
	e = kverdict_filemap_fold(m, "d.bin//0//1", &r, 0);
	CK(e && e->level == KOF_LEVEL_INFECT && strstr(e->name, ":I") != NULL, "infected outranks suspect");
	mkres(&r, "S2", KOF_LEVEL_SUSPECT, 1, 0);
	e = kverdict_filemap_fold(m, "d.bin//2", &r, 0);
	CK(e && e->level == KOF_LEVEL_INFECT && strstr(e->name, ":I") != NULL, "a lower rank later does not replace");
	mkres(&r, "I2", KOF_LEVEL_INFECT, 1, 0);
	e = kverdict_filemap_fold(m, "d.bin//3", &r, 0);
	CK(e && strstr(e->name, ":I") != NULL && strstr(e->name, ":I2") == NULL, "an equal rank later does not replace: first wins");
	CK(kverdict_filemap_count(m) == 4, "four files have entries (a, b, c, d)");
	CK(kverdict_filemap_at(m, 0) && strcmp(kverdict_filemap_at(m, 0)->file, "a.bin") == 0 &&
	   strcmp(kverdict_filemap_at(m, 3)->file, "d.bin") == 0 && kverdict_filemap_at(m, 4) == NULL,
	   "at() is in the order entries were first made");
	CK(kverdict_filemap_find(m, "c.bin", 5) == kverdict_filemap_at(m, 2), "find by name");
	CK(kverdict_filemap_find(m, "c.bin//0", 8) == NULL && kverdict_filemap_find(m, "c.bi", 4) == NULL &&
	   kverdict_filemap_find(m, "c.bin", 4) == NULL, "find is exact on the length given");

	/* the heuristic's kind word */
	{
		struct kof_result h;

		memset(&h, 0, sizeof h);
		h.n = 1;
		h.examined = 1;
		h.v[0].level = KOF_LEVEL_HEUR;
		kverdict_name(&h.v[0], "ELF", "Heur", "Packed", NULL, "Shellcode");
		e = kverdict_filemap_fold(m, "k.bin", &h, 0);
		CK(e && strcmp(e->kind, "Shellcode") == 0, "kind is the shape when there is one");
		kverdict_name(&h.v[0], "ELF", "Heur", "Truncated", NULL, NULL);
		e = kverdict_filemap_fold(m, "k2.bin", &h, 0);
		CK(e && strcmp(e->kind, "Truncated") == 0, "and the family when there is not");
		mkres(&h, "N", KOF_LEVEL_SUSPECT, 1, 0);
		e = kverdict_filemap_fold(m, "k3.bin", &h, 0);
		CK(e && e->kind[0] == 0, "a non-heuristic finding has no kind");
	}

	/* the host's own field is the host's */
	e = kverdict_filemap_find(m, "d.bin", 5);
	e->host = 77;
	mkres(&r, "I", KOF_LEVEL_INFECT, 1, 0);
	kverdict_filemap_fold(m, "d.bin//9", &r, 0);
	CK(e->host == 77, "the engine never touches host");

	/* argument refusals */
	mkres(&r, NULL, 0, 1, 0);
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
		mkres(&r, "F", KOF_LEVEL_INFECT, 1, 0);
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
	mkres(&r, "D", KOF_LEVEL_INFECT, 1, 0);
	e = kverdict_filemap_fold(m, deep, &r, 0);
	CK(e && strcmp(e->file, "x") == 0, "a 1000 deep object name rolls up to its first component");
	CK(kverdict_filemap_files(m) == 20000, "and is not itself a file");
	{
		struct kof_result c;

		mkres(&c, NULL, 0, 1, 0);
		CK(kverdict_filemap_fold(m, "//x", &c, 1) != NULL && kverdict_filemap_find(m, "", 0) != NULL,
		   "an object name that starts with // belongs to the file named ''");
		CK(kverdict_filemap_fold(m, "", &c, 1) == kverdict_filemap_find(m, "", 0), "and so does the empty name");
	}

	/* a name longer than the entry's name array: the finding's name is what is copied */
	{
		struct kof_result big;

		memset(&big, 0, sizeof big);
		big.n = 1;
		big.examined = 1;
		big.v[0].level = KOF_LEVEL_INFECT;
		memset(big.v[0].name, 'n', sizeof big.v[0].name - 1);
		e = kverdict_filemap_fold(m, "long-finding", &big, 0);
		CK(e && strlen(e->name) == sizeof big.v[0].name - 1 && e->name[sizeof e->name - 1] == 0,
		   "a full-length finding name fits the entry");
	}
	kverdict_filemap_free(m);
}

/* ---- hostile input to the roll-up ---------------------------------------------------------------- */

struct fold_job {
	int variant;
};

static int fold_hostile(void *arg)
{
	struct fold_job *j = (struct fold_job *)arg;
	kverdict_filemap *m = kverdict_filemap_new();
	struct he_guard g;
	struct kof_result *r;
	struct kverdict_file *e;
	size_t sz = sizeof *r;

	/* the result sits at the very end of a mapping: anything read past it faults */
	if (!m || !he_guard_make(&g, NULL, sz))
		return 9;
	r = (struct kof_result *)g.p;
	memset(r, 0, sizeof *r);
	r->n = 1;
	r->examined = 1;
	r->v[0].level = KOF_LEVEL_HEUR;
	memcpy(r->v[0].name, "ELF/Heur:Packed!Shellcode", 26);
	if (j->variant == 0) {
		/* a shape span that points past the finding's name */
		r->v[0].family.at = 0;
		r->v[0].maltype.at = 4;
		r->v[0].maltype.n = 4;
		memcpy(r->v[0].name + 4, "Heur", 5);
		/* the first byte read is 8 past the end of the finding array's mapping */
		r->v[0].shape.at = (uint16_t)(sizeof *r - offsetof(struct kof_finding, name) + 8u);
		r->v[0].shape.n = 100;
	} else {
		/* a finding whose name is not terminated within the array */
		memset(r->v[0].name, 'N', sizeof r->v[0].name);
		r->v[0].maltype.at = 0;
		r->v[0].maltype.n = 4;
		memcpy(r->v[0].name, "Heur", 4);
		r->v[0].shape.n = 0;
		r->v[0].family.at = 0;
		r->v[0].family.n = (uint16_t)sizeof r->v[0].name;
	}
	e = kverdict_filemap_fold(m, "h.bin", r, 0);
	he_guard_free(&g);
	kverdict_filemap_free(m);
	return e ? 0 : 1;
}

static void t_hostile_fold(void)
{
	struct fold_job j;
	struct he_status st;

	/*
	 * kverdict_filemap_fold copies a heuristic's kind with "%.*s" over
	 * name + span.at for span.n bytes, trusting the finding's spans to lie inside
	 * its name. They do when the engine made them. The fold is a public entry
	 * point a host can call with a finding it read from anywhere else, and a span
	 * that does not is a read through memory the finding does not own.
	 */
	j.variant = 0;
	st = he_child(fold_hostile, &j, 10);
	CK(he_ok(st), "kverdict_filemap_fold does not read past a finding whose shape span points outside its name: %s", he_how(st));
	j.variant = 1;
	st = he_child(fold_hostile, &j, 10);
	CK(he_ok(st), "an unterminated finding name does not leave the finding: %s", he_how(st));
}

int main(void)
{
	t_compose();
	t_name();
	t_vname();
	t_target();
	t_label();
	t_syndrome();
	t_filemap_basic();
	t_filemap_scale();
	t_hostile_fold();
	printf("api_engine_verdict: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
