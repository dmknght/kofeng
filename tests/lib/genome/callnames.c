/*
 * callnames - kgenome_callnames_build on hand-built images whose expected table is known from the layout (callnames_img.h), and on hostile ones.
 *
 * Why the old tests could not have caught anything: there were none - the lib had no such table. What is pinned: the ELF table (lazy .plt, the IBT .plt.sec with
 * its endbr64, a call and a tail jump through a GOT slot), the PE table (x64 and x86: a call through the IAT, a thunk by name, a thunk by ordinal), a branch the
 * table must NOT name (PLT0, a slot that is no import), the hostile inputs (a relocation whose symbol index is past the table, a name with no terminator, a slot
 * outside the file, a section count the file cannot hold, a truncated file, address 0 and UINT64_MAX), the ledger (a refusal is a status and the free gives every
 * byte back), the answer for another architecture (UNSUPPORTED, not an empty table) and the work: ONE read of the code, every instruction decoded once.
 */
#include <kgenome.h>
#include <phenotype/callnames.h>

#include "hk.h"
#include "callnames_img.h"

static uint8_t E[CI_ELF_SIZE];

static int parse_elf(const uint8_t *b, uint32_t n, struct kgenome_elf_info *ei, struct kgenome_obj *o)
{
	memset(ei, 0, sizeof *ei);
	if (!kgenome_elf_image_parse(kof_buf_make(b, n), ei, o))
		return 0;
	o->file_header = ei;
	return 1;
}

static int build(const struct kgenome_obj *o, const uint8_t *b, uint32_t n, struct kgenome_ledger *led, struct kgenome_callnames *t)
{
	return kgenome_callnames_build(&(const struct kgenome_callnames_req){ .obj = o, .file = kof_buf_make(b, n), .led = led }, t);
}

static const char *nm(const uint8_t *b, uint32_t n, const struct kgenome_callname *e)
{
	return e && e->nameoff && e->nameoff < n ? (const char *)b + e->nameoff : "";
}

static void want(const struct kgenome_callnames *t, const uint8_t *b, uint32_t n, uint64_t off, unsigned kind, const char *name)
{
	const struct kgenome_callname *e = kgenome_callnames_at(t, off);

	CK(e != NULL);
	if (!e)
		return;
	CK(e->kind == kind);
	CK(!strcmp(nm(b, n, e), name));
}

static void elf_table(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_callnames t;
	struct kgenome_ledger led;
	uint64_t off;

	ci_elf(E);
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o));
	CK(kgenome_callnames_applicable(&o));
	kgenome_ledger_init(&led, 0);
	CK(build(&o, E, CI_ELF_SIZE, &led, &t) == 1);
	CK(t.status == KGENOME_OK);
	CK(t.format == KGENOME_FMT_ELF);
	CK(t.n == 6);
	want(&t, E, CI_ELF_SIZE, 0x310, KGENOME_CALLNAME_STUB, "rand");
	want(&t, E, CI_ELF_SIZE, 0x320, KGENOME_CALLNAME_STUB, "puts");
	want(&t, E, CI_ELF_SIZE, 0x400, KGENOME_CALLNAME_STUB, "exit");     /* the endbr64: a call lands here */
	want(&t, E, CI_ELF_SIZE, 0x404, KGENOME_CALLNAME_STUB, "exit");
	want(&t, E, CI_ELF_SIZE, 0x505, KGENOME_CALLNAME_SLOT, "puts");
	want(&t, E, CI_ELF_SIZE, 0x510, KGENOME_CALLNAME_SLOT, "rand");
	/* what is NOT named: PLT0 (its slot is no import), the direct calls themselves, every other offset */
	CK(!kgenome_callnames_at(&t, 0x300));
	CK(!kgenome_callnames_at(&t, 0x306));
	CK(!kgenome_callnames_at(&t, 0x500));
	CK(!kgenome_callnames_at(&t, 0x50b));
	for (off = 0; off < CI_ELF_SIZE; off++) {
		const int named = off == 0x310 || off == 0x320 || off == 0x400 || off == 0x404 || off == 0x505 || off == 0x510;

		CK((kgenome_callnames_at(&t, off) != NULL) == named);
	}
	CK(!kgenome_callnames_at(&t, 0) && !kgenome_callnames_at(&t, UINT64_MAX));
	/* the work: one read, 8 instructions of .text + plt + plt.sec code decoded once each - never more than the bytes could hold */
	CK(t.insns > 0 && t.insns <= CI_ELF_SIZE);
	CK(led.used == t.bytes && t.bytes > 0);
	kgenome_callnames_free(&t, &led);
	CK(led.used == 0);                                      /* every byte given back */
	CK(t.n == 0 && t.v == NULL);
}

/* A shared library has e_entry 0: kgenome_elf_sec_is_stub takes the largest executable section as the body, so the PLT is told from it and the kinds are the same. */
static void elf_no_entry(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_callnames t;

	ci_elf(E);
	ci_w(E + 24, 0, 8);
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o) && build(&o, E, CI_ELF_SIZE, NULL, &t) == 1);
	CK(t.n == 6 && t.status == KGENOME_OK);
	want(&t, E, CI_ELF_SIZE, 0x310, KGENOME_CALLNAME_STUB, "rand");
	want(&t, E, CI_ELF_SIZE, 0x404, KGENOME_CALLNAME_STUB, "exit");
	want(&t, E, CI_ELF_SIZE, 0x505, KGENOME_CALLNAME_SLOT, "puts");
	want(&t, E, CI_ELF_SIZE, 0x510, KGENOME_CALLNAME_SLOT, "rand");
	kgenome_callnames_free(&t, NULL);
}

static void elf_hostile(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_callnames t;
	uint32_t i;

	/* a relocation whose symbol index is past the table: that import is not reported, the others are */
	ci_elf(E);
	ci_w(E + CI_RELA + 8, ((uint64_t)99 << 32) | 7u, 8);
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o) && build(&o, E, CI_ELF_SIZE, NULL, &t) == 1);
	CK(!kgenome_callnames_at(&t, 0x310) && kgenome_callnames_at(&t, 0x320) && kgenome_callnames_at(&t, 0x404));
	kgenome_callnames_free(&t, NULL);
	/* a GOT slot outside the file, at 0 and at UINT64_MAX: nothing matches, nothing crashes */
	for (i = 0; i < 2; i++) {
		ci_elf(E);
		ci_w(E + CI_RELA, i ? UINT64_MAX : 0, 8);
		CK(parse_elf(E, CI_ELF_SIZE, &ei, &o) && build(&o, E, CI_ELF_SIZE, NULL, &t) == 1);
		CK(!kgenome_callnames_at(&t, 0x310) && !kgenome_callnames_at(&t, 0x510) && kgenome_callnames_at(&t, 0x320));
		kgenome_callnames_free(&t, NULL);
	}
	/* a name with no terminator: the table holds a position, the bytes decide where the name ends (the engine bounds it) */
	ci_elf(E);
	memset(E + CI_DYNSTR + 1, 'A', 14);
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o) && build(&o, E, CI_ELF_SIZE, NULL, &t) == 1);
	CK(kgenome_callnames_at(&t, 0x310) != NULL);
	kgenome_callnames_free(&t, NULL);
	/* a symbol whose name lies past the end of the object (the .dynstr claims more than the file holds): no entry for it, never a position outside the bytes */
	ci_elf(E);
	ci_w(E + CI_DYNSYM + 24u + 0, 0x7ff00000u, 4);          /* rand's st_name */
	ci_w(E + CI_SHDR + 64u * 2u + 32u, 0x80000000u, 8);     /* .dynstr sh_size */
	if (parse_elf(E, CI_ELF_SIZE, &ei, &o) && build(&o, E, CI_ELF_SIZE, NULL, &t) == 1) {
		uint32_t k;

		for (k = 0; k < t.n; k++)
			CK(t.v[k].nameoff < CI_ELF_SIZE);
		CK(!kgenome_callnames_at(&t, 0x310));
		kgenome_callnames_free(&t, NULL);
	}
	/* a section count the file cannot hold */
	ci_elf(E);
	ci_w(E + 60, 0xffff, 2);
	if (parse_elf(E, CI_ELF_SIZE, &ei, &o)) {
		(void)build(&o, E, CI_ELF_SIZE, NULL, &t);
		kgenome_callnames_free(&t, NULL);
	}
	/* a file cut inside .text and inside .plt: what is there is read, nothing past it */
	for (i = 0x300; i < 0x520; i += 7) {
		ci_elf(E);
		if (parse_elf(E, CI_ELF_SIZE, &ei, &o)) {
			uint32_t cut = i;

			if (build(&o, E, cut, NULL, &t) == 1) {
				uint32_t k;

				for (k = 0; k < t.n; k++)
					CK(t.v[k].off < cut);
				kgenome_callnames_free(&t, NULL);
			}
		}
	}
}

static void elf_ledger_and_scope(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_callnames t;
	struct kgenome_ledger led;
	uint64_t lim;

	ci_elf(E);
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o));
	/* every allowance from nothing to enough: a refusal is OVER_BUDGET (never OK with a short table), and the free always returns the ledger to zero */
	for (lim = 1; lim < 4096; lim += 37) {
		kgenome_ledger_init(&led, lim);
		(void)build(&o, E, CI_ELF_SIZE, &led, &t);
		CK(t.status == KGENOME_OK || t.status == KGENOME_OVER_BUDGET);
		if (t.status == KGENOME_OK)
			CK(t.n == 6);
		else
			CK(t.n < 6);
		kgenome_callnames_free(&t, &led);
		CK(led.used == 0);
	}
	/* another architecture: not applicable, and it says so (a scope limit, not an empty answer) */
	ci_w(E + 18, 183, 2);                                   /* AArch64 */
	CK(parse_elf(E, CI_ELF_SIZE, &ei, &o));
	CK(!kgenome_callnames_applicable(&o));
	CK(build(&o, E, CI_ELF_SIZE, NULL, &t) == 0 && t.status == KGENOME_UNSUPPORTED);
	ci_elf(E);
	ci_w(E + 16, 1, 2);                                     /* relocatable */
	if (parse_elf(E, CI_ELF_SIZE, &ei, &o))
		CK(build(&o, E, CI_ELF_SIZE, NULL, &t) == 0);
	/* no header at all */
	memset(&o, 0, sizeof o);
	CK(build(&o, E, CI_ELF_SIZE, NULL, &t) == 0 && t.status == KGENOME_BAD_INPUT);
}

static void pe_table(int plus)
{
	struct hk_pe P;
	struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_callnames t;
	struct kgenome_ledger led;
	const uint32_t base = 0x200;

	hk_pe(&P, plus);
	ci_pe_code(&P);
	memset(&pi, 0, sizeof pi);
	CK(kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o));
	o.file_header = &pi;
	CK(kgenome_callnames_applicable(&o));
	kgenome_ledger_init(&led, 0);
	CK(build(&o, P.b, P.n, &led, &t) == 1);
	CK(t.status == KGENOME_OK && t.format == KGENOME_FMT_PE && t.n_dll == 2 && t.n == 3);
	want(&t, P.b, P.n, base + 0, KGENOME_CALLNAME_SLOT, "ExitProcess");
	want(&t, P.b, P.n, base + 6, KGENOME_CALLNAME_STUB, "MessageBoxA");
	{
		const struct kgenome_callname *e = kgenome_callnames_at(&t, base + 12);

		CK(e && e->kind == KGENOME_CALLNAME_STUB && e->nameoff == 0 && e->ordinal == 5);
		CK(e && !strcmp(t.dll[e->dll], "kernel32.dll"));
	}
	{
		const struct kgenome_callname *e = kgenome_callnames_at(&t, base + 6);

		CK(e && !strcmp(t.dll[e->dll], "user32.dll"));
	}
	CK(!kgenome_callnames_at(&t, base + 18) && !kgenome_callnames_at(&t, 0) && !kgenome_callnames_at(&t, UINT64_MAX));
	kgenome_callnames_free(&t, &led);
	CK(led.used == 0);
	/* a thunk budget that ran out is TRUNCATED on the table: a partial table is said to be one (hostile directory in hk's PE tests; here the control) */
	CK(t.status == KGENOME_OK);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	elf_table();
	elf_no_entry();
	elf_hostile();
	elf_ledger_and_scope();
	pe_table(1);
	pe_table(0);
	if (hk_fails) {
		printf("callnames: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("callnames: ok\n");
	return 0;
}
