/*
 * precond_api - the rules a TOOL used to keep its own copy of.
 *
 * Every check here is on a function in the engine, called directly. That is the
 * point of the file: each of these rules was fixed once already, on the side
 * that showed it rather than the side that decides it - the architecture mask
 * in a shell script, the eligibility test in a mirror inside kofinspect, the
 * detection name taken apart by whoever wanted a piece of it. A fix in a tool
 * leaves the engine wrong and every other tool wrong with it, and the scan is
 * what ships.
 *
 * So these ask the engine, with no terminal, no database and no file.
 */
#include <stdio.h>
#include <string.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofdb/kofdb.h"

static int fails;

static void ok(int cond, const char *why)
{
	if (!cond) {
		printf("  FAIL %s\n", why);
		fails++;
	}
}

/* ---- architecture: X86 is a PREFIX of X86_64 ------------------------------ */

/*
 * The bug this guards: the build script matched architecture names as
 * substrings, so KOF_TARGET_ARCH(KOF_ARCH_X86_64) set the X86 bit too and every
 * x86-64-only rule also ran on x86 objects. The fix moved into the engine, so
 * the test belongs against the engine.
 */
static void arch_names(void)
{
	uint8_t v;
	unsigned i;
	static const struct { const char *word; uint8_t val; } want[] = {
#define X_W(name, val, sw) { #name, (uint8_t)(val) },
		KOF_ARCH_LIST(X_W)
#undef X_W
	};

	ok(sizeof want / sizeof want[0] == KOF_ARCH_COUNT,
	   "the list and its count disagree");
	for (i = 0; i < sizeof want / sizeof want[0]; i++) {
		ok(kof_arch_from_name(want[i].word, &v) && v == want[i].val,
		   want[i].word);
		ok(kof_arch_name(want[i].val) != 0, "every value has a word");
	}
	/* Whole names only, in both directions. */
	ok(!kof_arch_from_name("KOF_ARCH_X86_6", &v), "prefix must not match");
	ok(!kof_arch_from_name("KOF_ARCH_X86_640", &v), "extension must not match");
	ok(!kof_arch_from_name("KOF_ARCH_ARM6", &v), "ARM6 is not ARM64");
	ok(kof_arch_from_name("KOF_ARCH_X86", &v) && v == KOF_ARCH_X86, "X86");
	ok(kof_arch_from_name("KOF_ARCH_X86_64", &v) && v == KOF_ARCH_X86_64,
	   "X86_64 is not X86");
}

/* ---- what a module may run on -------------------------------------------- */

static struct kof_module mod_of(uint32_t target, uint32_t arch,
				uint32_t subtype, uint64_t size_min)
{
	struct kof_module m;

	memset(&m, 0, sizeof m);
	m.target_mask  = target;
	m.arch_mask    = arch;
	m.subtype_mask = subtype;
	m.size_min     = size_min;
	return m;
}

static struct kof_obj_ctx ctx_of(uint8_t fmt, uint8_t arch, uint8_t sub)
{
	struct kof_obj_ctx c;

	memset(&c, 0, sizeof c);
	c.format  = fmt;
	c.arch    = arch;
	c.subtype = sub;
	return c;
}

static void precond(void)
{
	struct kof_module m;
	struct kof_obj_ctx c;

	/* An x86-64-only module must not run on an x86 object, and the reverse. */
	m = mod_of(1u << KOF_FMT_ELF, 1u << KOF_ARCH_X86_64, 0, 0);
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86_64, KOF_ELF_EXEC);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_OK, "x64 rule on x64");
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86, KOF_ELF_EXEC);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_ARCH,
	   "x64 rule must not run on x86");

	m = mod_of(1u << KOF_FMT_ELF, 1u << KOF_ARCH_X86, 0, 0);
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86_64, KOF_ELF_EXEC);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_ARCH,
	   "x86 rule must not run on x64");

	/* No mask at all means every architecture. */
	m = mod_of(1u << KOF_FMT_ELF, 0, 0, 0);
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_ARM64, KOF_ELF_DYN);
	ok(kof_module_precond(&m, &c, 1) == KOF_PRECOND_OK, "no arch mask, any arch");

	/*
	 * SUBTYPE VALUES COLLIDE BETWEEN FORMATS ON PURPOSE - KOF_ELF_REL and
	 * KOF_PE_DLL are both 1 - and what keeps that safe is that target is
	 * tested first. A module that targets ELF only must be excluded on a PE
	 * BY FORMAT, before its subtype mask is ever compared.
	 */
	m = mod_of(1u << KOF_FMT_ELF, 0, 1u << KOF_ELF_REL, 0);
	/*
	 * KOF_PE_SYS and not KOF_PE_DLL, and the difference is the whole test.
	 * DLL is 1 and so is ELF_REL, so a subtype test would ACCIDENTALLY pass
	 * on that object and fall through to the format test anyway - the check
	 * would hold whatever order the two were applied in, which is to say it
	 * would check nothing. SYS is 2, so a subtype test reached first rejects
	 * it and says so, and only the right order answers TARGET.
	 */
	c = ctx_of(KOF_FMT_PE, KOF_ARCH_X86_64, KOF_PE_SYS);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_TARGET,
	   "ELF subtype rule on a PE is ruled out by format, not by subtype");
	c = ctx_of(KOF_FMT_PE, KOF_ARCH_X86_64, KOF_PE_DLL);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_TARGET,
	   "and the colliding value is still ruled out by format");
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86_64, KOF_ELF_REL);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_OK, "REL rule on a REL");
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86_64, KOF_ELF_DYN);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_SUBTYPE,
	   "REL rule must not run on a DYN");

	/* Size is tested before architecture, so a too-small object says so. */
	m = mod_of(1u << KOF_FMT_ELF, 1u << KOF_ARCH_X86, 0, 8192);
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_X86_64, KOF_ELF_EXEC);
	ok(kof_module_precond(&m, &c, 100) == KOF_PRECOND_SIZE,
	   "below the minimum size, and that is the reason given");

	/* An architecture no mask can name is not covered by a constrained module. */
	m = mod_of(1u << KOF_FMT_ELF, 1u << KOF_ARCH_X86, 0, 0);
	c = ctx_of(KOF_FMT_ELF, KOF_ARCH_OTHER, KOF_ELF_EXEC);
	ok(kof_module_precond(&m, &c, 4096) == KOF_PRECOND_ARCH,
	   "OTHER is outside the mask width");
}

/* ---- the name, and its parts --------------------------------------------- */

static int span_is(const struct kof_finding *f,
		   const struct kof_name_span *sp, const char *word)
{
	return strlen(word) == sp->n && memcmp(f->name + sp->at, word, sp->n) == 0;
}

/*
 * The bug this guards: the parts were found again by whoever wanted one, by
 * searching the composed name for the separator. A separator changed once, '-'
 * to '#', and every such reader broke at the same moment and in silence.
 */
static void name_parts(void)
{
	struct kof_finding f;
	char want[224];

	kof_finding_name(&f, "ELF-x64", "Botnet", "Mirai", "Gen", NULL);
	ok(strcmp(f.name, "ELF-x64/Botnet:Mirai#Gen") == 0, "detector name");
	ok(span_is(&f, &f.target, "ELF-x64"), "target span");
	ok(span_is(&f, &f.maltype, "Botnet"), "maltype span");
	ok(span_is(&f, &f.family, "Mirai"), "family span");
	ok(span_is(&f, &f.variant, "Gen"), "variant span");
	ok(f.shape.n == 0, "a detector has no shape");
	ok(!kof_finding_is_heur(&f), "Botnet is not Heur");

	/* The two must agree: kofinspect builds one with kof_name_compose to
	 * compare against a finding the engine composed. */
	kof_name_compose(want, sizeof want, "ELF-x64", "Botnet", "Mirai", "Gen");
	ok(strcmp(want, f.name) == 0, "compose and finding_name agree");

	kof_finding_name(&f, "ELF-x64", "Heur", "Meterp", "g7q2x", "Shellcode");
	ok(strcmp(f.name, "ELF-x64/Heur:Meterp#g7q2x?Shellcode") == 0,
	   "heuristic name");
	ok(span_is(&f, &f.family, "Meterp"), "the guessed family");
	ok(span_is(&f, &f.shape, "Shellcode"), "the shape actually recognised");
	ok(kof_finding_is_heur(&f), "Heur is Heur");

	/* Absent parts are absent, not empty text in the middle of the name. */
	kof_finding_name(&f, NULL, "Trojan", "Unknown", NULL, NULL);
	ok(strcmp(f.name, "Trojan:Unknown") == 0, "no target, no variant");
	ok(f.target.n == 0 && f.variant.n == 0, "both spans empty");
	ok(span_is(&f, &f.maltype, "Trojan"), "maltype still found");

	/* A family with a hyphen in it: the reason the separator became '#'. */
	kof_finding_name(&f, "ELF-x64", "Trojan", "Some-Family", "v1", NULL);
	ok(span_is(&f, &f.family, "Some-Family"), "hyphen inside a family name");
	ok(span_is(&f, &f.variant, "v1"), "and the variant after it");
}

static void target_word(void)
{
	char w[32];

	kof_name_target(w, sizeof w, KOF_FMT_ELF, KOF_ARCH_X86_64);
	ok(strcmp(w, "ELF-x64") == 0, "ELF-x64");
	kof_name_target(w, sizeof w, KOF_FMT_ELF, KOF_ARCH_ANY);
	ok(strcmp(w, "ELF") == 0, "no architecture, no suffix");
	kof_name_target(w, sizeof w, KOF_FMT_UNKNOWN, KOF_ARCH_X86_64);
	ok(strcmp(w, kof_format_name(KOF_FMT_UNKNOWN)) == 0,
	   "an unidentified object names no architecture");
}

/* ---- verdicts and object paths ------------------------------------------- */

/*
 * The constants are 0, 1, 2 in an order that is not their strength, so anything
 * comparing them as numbers gets it backwards. Two hosts worked the real order
 * out for themselves before this.
 */
static void levels(void)
{
	ok(kof_level_rank(KOF_LEVEL_INFECT) > kof_level_rank(KOF_LEVEL_SUSPECT),
	   "INFECT outranks SUSPECT");
	ok(kof_level_rank(KOF_LEVEL_SUSPECT) > kof_level_rank(KOF_LEVEL_HEUR),
	   "SUSPECT outranks HEUR");
	ok(kof_level_rank(KOF_LEVEL_HEUR) > kof_level_rank(99u),
	   "any verdict outranks none");
	ok(KOF_LEVEL_HEUR > KOF_LEVEL_INFECT,
	   "and the raw values really are in the wrong order");
}

static void obj_paths(void)
{
	const char *a = "file.zip//inner.tar//deep.elf";

	ok(kof_obj_depth("file.elf") == 0, "a file is at depth 0");
	ok(kof_obj_depth(a) == 2, "two separators, two layers");
	ok(kof_obj_toplevel_len("file.elf") == 8, "no separator: the whole name");
	ok(kof_obj_toplevel_len(a) == 8, "up to the first separator");
	ok(strncmp(a, "file.zip", kof_obj_toplevel_len(a)) == 0, "and it is the file");
	/* A single slash is a path, not a separator. */
	ok(kof_obj_depth("/usr/bin/ls") == 0, "single slashes are not separators");
	ok(kof_obj_toplevel_len("/usr/bin/ls") == 11, "an absolute path is one name");
}

int main(void)
{
	arch_names();
	precond();
	name_parts();
	target_word();
	levels();
	obj_paths();
	if (fails)
		printf("precond_api: %d failure(s)\n", fails);
	else
		printf("precond_api: arch, preconditions, name parts, levels, "
		       "object paths - all from the engine\n");
	return fails != 0;
}
