/*
 * diag/tables - the capability vocabulary and the lineage class tables, asked with arguments taken from the bytes (shape S5: tables,
 * the "enumerate or random wide" row of the plan).
 *
 * The input is read as: nr (4 bytes), arch / bits / target selectors, four argument words, a capability id, a lineage class and a
 * name (the rest, cut at the first NUL). Alongside the random questions the row runs the EXHAUSTIVE small domains on every call that
 * has the budget: every syscall number of both bitnesses up to 1100, every capability id up to 1200, every name id of every
 * language up to 4096 (the plan's "enumerate" half).
 *
 * Held:
 *   - ROUND TRIP: a name id turns back into the spelling it came from (kgenome_nucleo_name_of), and the language's table answers that
 *     spelling with the capability the id came with; name_lookup is cap_of_name plus name_id, from one search
 *   - kgenome_nucleo_name_of is NULL outside the ids that exist and non-empty inside; ids are dense from 1
 *   - a syscall the vocabulary names (sys_name) is named by the kernel's table too (sys_name_all) with the same spelling; names are
 *     non-empty; the per-ABI tables are ascending (kgenome_nucleo_sys_ordered)
 *   - kgenome_nucleo_cap_generic ends: following it from any capability reaches NONE within a handful of steps, never a cycle
 *   - every capability an answer carries ends its generic chain (the same check on the answers of the syscall, name and call lookups)
 *   - kgenome_nucleo_name_arg answers 0, DIRECT or OBJECT, with an argument index below the argument registers
 *   - an `@` ends a name: "socket@GLIBC_2.4" is "socket" (kgenome_nucleo_cap_of_name)
 *   - the lineage plan is a subset of the stage bits and is zero for a class with no x86; the next stage of a reason is a stage bit
 *     or zero; the class of an object has only the bits that exist (kgenome_diag_class_of is called in scan_bin.c on the parsed object)
 *   - determinism (the driver runs every call twice) and no allocation (the leak check: these are lookups)
 */
#include "diag_seed.h"

#include <celllysis/nucleo.h>

static const char *const dict[] = { "socket", "socket@GLIBC_2.4", "system", "eval", "execve", "\0", "@", "(dynamic)", "(load)", "cfexecute", "Convert.FromBase64String", NULL };

static void seeds(struct fz_corpus *c)
{
	uint8_t b[96];
	unsigned k;

	for (k = 0; k < 18; k++) {
		memset(b, 0, sizeof b);
		b[0] = (uint8_t)(k * 13u);               /* nr */
		b[4] = (uint8_t)k;                       /* bits selector */
		b[5] = (uint8_t)(k + 1u);                /* target */
		b[16] = 2; b[24] = 1; b[32] = (uint8_t)(k * 3u);
		b[40] = (uint8_t)k;                      /* cap */
		b[44] = (uint8_t)(k & 0xffu);            /* class */
		memcpy(b + 48, k % 2u ? "system" : "socket@GLIBC_2.4", k % 2u ? 7u : 17u);
		fz_corpus_add(c, "t", b, sizeof b);
	}
}

static uint32_t rd32(const uint8_t *p, size_t n, size_t at)
{
	uint32_t v = 0, i;

	for (i = 0; i < 4u; i++)
		v |= (uint32_t)(at + i < n ? p[at + i] : 0u) << (8u * i);
	return v;
}

static void generic_ends(struct fz_ctx *c, uint16_t cap)
{
	unsigned steps = 0;

	while (cap != KGENOME_NUCLEO_NONE && steps < 16u) {
		cap = kgenome_nucleo_cap_generic(cap);
		steps++;
	}
	FZ_CHECK(c, cap == KGENOME_NUCLEO_NONE, "following kgenome_nucleo_cap_generic does not end");
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	uint32_t nr = rd32(in, n, 0), sel = rd32(in, n, 4), tsel = rd32(in, n, 8);
	uint64_t arg[8];
	uint8_t fl = 0, fl2 = 0;
	unsigned bits = sel & 1u ? 64u : 32u, target = 1u + tsel % (KGENOME_NUCLEO_T_CFML + 2u), have = (unsigned)(sel >> 8) % 7u, k;
	uint16_t cap = (uint16_t)rd32(in, n, 40), id = 0;
	unsigned cls = rd32(in, n, 44);
	char name[256];
	size_t nl = 0, i;
	uint16_t a, b2, c3;
	unsigned arg_ix = 0;

	for (k = 0; k < 8; k++)
		arg[k] = ((uint64_t)rd32(in, n, 16u + 4u * (k % 4u)) << (k < 4 ? 0 : 32)) ^ k;
	for (i = 48; i < n && in[i] && nl + 1u < sizeof name; i++)
		name[nl++] = (char)in[i];
	name[nl] = 0;

	/* syscalls */
	a = kgenome_nucleo_cap_of_syscall(bits, nr, arg, &fl);
	b2 = kgenome_nucleo_cap_of_syscall(bits, nr, NULL, NULL);
	fl2 = fl;
	generic_ends(c, a);
	generic_ends(c, b2);
	fz_digest(c, a + ((uint64_t)b2 << 16) + ((uint64_t)fl2 << 32));
	{
		const char *sn = kgenome_nucleo_sys_name(bits, nr), *all = kgenome_nucleo_sys_name_all(bits, nr);

		FZ_CHECK(c, !sn || *sn, "an empty syscall name");
		FZ_CHECK(c, !all || *all, "an empty kernel syscall name");
		FZ_CHECK(c, !sn || (all && !strcmp(sn, all)), "the vocabulary names a syscall the kernel table does not, or by another spelling");
		if (sn)
			fz_digest(c, (uint8_t)sn[0]);
	}
	(void)kgenome_nucleo_arg_is_flags(bits, nr, sel >> 16);
	(void)kgenome_nucleo_sock_nonblock(bits, nr, arg, have);
	(void)kgenome_nucleo_sockcall_nonblock(nr, arg, have);
	c3 = kgenome_nucleo_cap_of_sockcall(nr, arg, have, &fl);
	generic_ends(c, c3);
	/* per ABI */
	{
		unsigned arch;

		for (arch = 0; arch < 40u; arch++) {
			const struct kgenome_nucleo_abi *fx = kgenome_nucleo_abi_of(arch);

			if (!fx)
				continue;
			FZ_CHECK(c, fx->n_arg <= 8u, "an ABI with more than eight argument registers");
			a = kgenome_nucleo_cap_of_syscall_abi(fx, nr, arg, &fl);
			{
				const char *s2 = kgenome_nucleo_sys_name_abi(fx, nr);

				FZ_CHECK(c, !s2 || *s2, "an empty per-ABI syscall name");
				fz_digest(c, (uint64_t)a + (s2 ? (uint8_t)s2[0] : 0u));
			}
		}
	}
	FZ_CHECK(c, kgenome_nucleo_sys_ordered() == 1, "a syscall table is not ascending");
	(void)kgenome_nucleo_sys_zero_on_success(name);
	/* names */
	a = kgenome_nucleo_cap_of_name(target, name);
	b2 = kgenome_nucleo_name_lookup(target, name, &id);
	FZ_CHECK(c, a == b2, "name_lookup and cap_of_name disagree");
	FZ_CHECK(c, kgenome_nucleo_name_id(target, name) == id, "name_lookup and name_id disagree on the id");
	FZ_CHECK(c, kgenome_nucleo_name_lookup(target, name, NULL) == a, "name_lookup with no id pointer answers another capability");
	if (id) {
		const char *sp = kgenome_nucleo_name_of(id);

		FZ_CHECK(c, sp && *sp, "a name id the table gave has no spelling");
		if (sp)
			FZ_CHECK(c, kgenome_nucleo_cap_of_name(target, sp) == a, "the spelling of a name id is not answered with the capability the id came with");
	}
	{
		char at[300];

		snprintf(at, sizeof at, "%s@GLIBC_2.4", name);
		FZ_CHECK(c, kgenome_nucleo_cap_of_name(target, at) == kgenome_nucleo_cap_of_name(target, name) || nl == 0u,
			 "an @ does not end the name");
	}
	{
		uint16_t r = kgenome_nucleo_cap_of_call(target, name, arg, &fl);

		generic_ends(c, r);
		fz_digest(c, r);
	}
	/* capabilities */
	(void)kgenome_nucleo_cap_named(cap);
	generic_ends(c, cap);
	(void)kgenome_nucleo_hands_on(cap, name);
	(void)kgenome_nucleo_hands_on(cap, NULL);
	{
		unsigned kind = kgenome_nucleo_name_arg(cap, &arg_ix);

		FZ_CHECK(c, kind == 0 || kind == KGENOME_NAME_DIRECT || kind == KGENOME_NAME_OBJECT, "name_arg answers a kind that is not one");
		FZ_CHECK(c, !kind || arg_ix < 8u, "name_arg names an argument past the registers");
		fz_digest(c, kind + ((uint64_t)arg_ix << 4));
	}
	/* the lineage class tables */
	{
		unsigned plan = kgenome_diag_lineage_plan(cls), bit;

		FZ_CHECK(c, (plan & ~KGENOME_LINEAGE_S_ALL) == 0, "the plan names a stage that does not exist");
		FZ_CHECK(c, (cls & KGENOME_CLASS_X86) || plan == 0, "a class with no x86 has a plan");
		for (bit = 0; bit < KGENOME_LINEAGE_W_N; bit++) {
			unsigned nx = kgenome_diag_oblig_next_stage(bit);

			FZ_CHECK(c, nx == 0 || (nx & (nx - 1u)) == 0, "a next stage that is not one stage bit");
		}
		fz_digest(c, plan);
	}
	/* the exhaustive small domains, on a share of the calls */
	if ((sel & 31u) == 0) {
		unsigned x;

		for (x = 0; x < 1100u; x++) {
			const char *s1 = kgenome_nucleo_sys_name(64, x), *s2 = kgenome_nucleo_sys_name(32, x);

			FZ_CHECK(c, !s1 || *s1, "an empty name (64)");
			FZ_CHECK(c, !s2 || *s2, "an empty name (32)");
			fz_step(&c->steps, 1);
		}
		for (x = 0; x < 1200u; x++) {
			generic_ends(c, (uint16_t)x);
			(void)kgenome_nucleo_cap_named((uint16_t)x);
		}
		for (x = 1; x < 4096u; x++) {
			const char *s = kgenome_nucleo_name_of((uint16_t)x);

			if (!s) {
				/* ids are dense from 1: the first hole ends the table */
				for (; x < 4096u; x++)
					FZ_CHECK(c, kgenome_nucleo_name_of((uint16_t)x) == NULL, "name ids are not dense: a hole, then an id");
				break;
			}
			FZ_CHECK(c, *s != 0, "a name id with an empty spelling");
		}
	}
	return 0;
}

FZ_ADAPTER(tables, .name = "kgenome/diag_tables",
	   .covers = "kgenome_nucleo_abi_of kgenome_nucleo_sys_ordered kgenome_nucleo_cap_of_syscall_abi kgenome_nucleo_sys_name_abi "
		     "kgenome_nucleo_sys_zero_on_success kgenome_nucleo_arg_is_flags kgenome_nucleo_sock_nonblock kgenome_nucleo_sockcall_nonblock "
		     "kgenome_nucleo_cap_of_sockcall kgenome_nucleo_sys_name kgenome_nucleo_sys_name_all kgenome_nucleo_cap_of_syscall "
		     "kgenome_nucleo_cap_of_name kgenome_nucleo_cap_named kgenome_nucleo_cap_generic kgenome_nucleo_hands_on kgenome_nucleo_name_arg "
		     "kgenome_nucleo_name_id kgenome_nucleo_name_lookup kgenome_nucleo_cap_of_call kgenome_nucleo_name_of "
		     "kgenome_diag_lineage_plan kgenome_diag_oblig_next_stage",
	   .backstop_s = 3000, .shape = FZ_REQ, .seeds = seeds, .dict = dict, .run = run);
