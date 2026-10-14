/*
 * names_structural - a name the file spells for itself decides nothing the file's
 * structure already says.
 *
 * The owner's rule: an attacker can rename or patch symbols and sections, so a NAME is
 * advisory unless it is data a researcher declared or the OS fixes (an import the
 * loader resolves, the kernel's own syscall table). Three decisions in the ELF reader
 * were keyed on the linker's SPELLING:
 *
 *   - which string section a symbol table uses (".strtab" / ".dynstr") - now sh_link;
 *   - which section a relocation section applies to (".rela.text" -> ".text") - now
 *     sh_info;
 *   - the string section the library-span tier reads - now the symbol table's own.
 *
 * Each case builds one object in memory, observes what the reader answers, renames
 * (same-length overwrite in the section-name string table, which breaks nothing that
 * runs) and asks again: the answers must be the same. Before the change the renamed
 * object gave strn == 0 and an empty relocation table.
 *
 * The other half: the diagnose routes. A DEFINED symbol called "execve" in a program
 * is not an import and makes no node; a syscall instruction is a node whatever the
 * symbols around it are called, or whether there are any.
 */

#include <kgenome.h>
#include <celllysis/nucleo.h>
#include <celllysis/trueline.h>

#include "hk.h"

static struct hk_elf E;
static struct kgenome_elf_info info;

struct obs {
	int      sym_ok;
	uint64_t strn;
	uint32_t ncode, ndata, ncalls;
	uint64_t call_at[4];
	char     call_name[4][16];
};

static void on_call(void *u, uint64_t at, uint64_t target, const char *name)
{
	struct obs *o = u;

	(void)target;
	if (o->ncalls < 4u) {
		o->call_at[o->ncalls] = at;
		snprintf(o->call_name[o->ncalls], sizeof o->call_name[0], "%s", name);
	}
	o->ncalls++;
}

static struct kgenome_obj parse_E(void)
{
	struct kgenome_obj o;

	memset(&info, 0, sizeof info);
	memset(&o, 0, sizeof o);
	CK(kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &info, &o));
	o.file_header = &info;
	return o;
}

static struct obs observe(void)
{
	struct obs o;
	struct kgenome_elf_symtab t;
	struct kgenome_elf_relocs rc;
	kof_buf f = kof_buf_make(E.b, E.n);

	memset(&o, 0, sizeof o);
	(void)parse_E();
	o.sym_ok = kgenome_elf_symtab_of(f, &info, KGENOME_ELF_SYMTAB_FULL, &t);
	o.strn = t.strn;
	memset(&rc, 0, sizeof rc);
	o.ndata = kgenome_elf_reloc_table(f, &info, KGENOME_ELF_RELOC_DATA, &rc);
	kgenome_elf_reloc_table_free(&rc);
	memset(&rc, 0, sizeof rc);
	o.ncode = kgenome_elf_reloc_table(f, &info, KGENOME_ELF_RELOC_CODE, &rc);
	kgenome_elf_relcalls(f, &info, &rc, on_call, &o, NULL);
	kgenome_elf_reloc_table_free(&rc);
	return o;
}

/* Overwrite `from` with `to` (same length) inside the section-name string table. */
static int rename_sec(const char *from, const char *to)
{
	uint8_t *p = E.b + E.shstr;
	size_t n = strlen(from), i;

	if (strlen(to) != n)
		return 0;
	for (i = 0; i + n < 64u; i++)
		if (!memcmp(p + i, from, n + 1u)) {
			memcpy(p + i, to, n + 1u);
			return 1;
		}
	return 0;
}

static int sec_named(const char *name)
{
	uint32_t i;

	for (i = 0; i < info.sec_count; i++)
		if (!strcmp(info.sec[i].name, name))
			return 1;
	return 0;
}

static void t_rename_sections(void)
{
	struct obs a, b;

	hk_elf(&E, 1, 0, 1);
	a = observe();
	CK(sec_named(".strtab") && sec_named(".rela.text"));
	CK(a.sym_ok && a.strn > 0u);
	CK(a.ncode == 2u && a.ncalls >= 1u);            /* the control: both relocations, the call to puts */
	CK(!strcmp(a.call_name[0], "puts") || !strcmp(a.call_name[1], "puts"));

	/* the same object, its sections called something else */
	CK(rename_sec(".strtab", ".qqqqqq"));
	CK(rename_sec(".symtab", ".wwwwww"));
	CK(rename_sec(".rela.text", ".zzzzzzzzz"));
	CK(rename_sec(".text", ".code"));
	b = observe();
	CK(!sec_named(".strtab") && !sec_named(".rela.text") && !sec_named(".symtab") && !sec_named(".text"));
	CK(b.sym_ok == a.sym_ok);
	CK(b.strn == a.strn);                           /* the strings are the ones sh_link names */
	CK(b.ncode == a.ncode && b.ndata == a.ndata);   /* the target is the one sh_info names */
	CK(b.ncalls == a.ncalls);
	CK(a.ncalls == b.ncalls && !memcmp(a.call_at, b.call_at, sizeof a.call_at) &&
	   !memcmp(a.call_name, b.call_name, sizeof a.call_name));

	/* a decoy: sections that LOOK like the linker's but are not what sh_link/sh_info say */
	hk_elf(&E, 1, 0, 1);
	(void)parse_E();
	{
		/* point the symbol table's sh_link at .text (not a string table): no strings,
		 * whatever any section is called */
		uint8_t *sh = E.b + E.sh + 2u * E.sh_ent;       /* .symtab */
		struct obs c;

		hk_w(sh + 40, 1, 4, 0);
		c = observe();
		CK(c.sym_ok && c.strn == 0u);
	}
	/* sh_info of the relocation section naming no section: no target, no records */
	hk_elf(&E, 1, 0, 1);
	{
		uint8_t *sh = E.b + E.sh + 4u * E.sh_ent;       /* .rela.text */
		struct obs c;

		hk_w(sh + 44, 0, 4, 0);
		c = observe();
		CK(c.ncode == 0u && c.ncalls == 0u);
	}
}

/* ---- the diagnose routes ---------------------------------------------------------------- */

struct hits {
	uint32_t n;
	uint64_t at[16];
	uint16_t cap[16];
};

static struct hits scan(unsigned run)
{
	struct hits h;
	struct kgenome_obj o = parse_E();
	struct kgenome_diag_scan *s = kgenome_diag_scan_with(&o, E.b, E.n, run);
	uint32_t i, n;

	memset(&h, 0, sizeof h);
	CK(s != NULL);
	if (!s)
		return h;
	n = kgenome_diag_scan_count(s);
	for (i = 0; i < n && i < 16u; i++) {
		const struct kgenome_diag_hit *x = kgenome_diag_scan_at(s, i);

		h.at[h.n] = x->at;
		h.cap[h.n++] = x->cap;
	}
	h.n = n < 16u ? n : 16u;
	kgenome_diag_scan_free(s);
	return h;
}

static int same(const struct hits *a, const struct hits *b)
{
	return a->n == b->n && !memcmp(a->at, b->at, sizeof a->at) && !memcmp(a->cap, b->cap, sizeof a->cap);
}

static unsigned count_cap(const struct hits *h, uint16_t cap)
{
	unsigned i, k = 0;

	for (i = 0; i < h->n; i++)
		k += h->cap[i] == cap;
	return k;
}

/* put `s` over the symbol-name string (offset `at` into the string table) */
static void set_sym_name(unsigned at, const char *s)
{
	memcpy(E.b + E.strtab + at, s, strlen(s) + 1u);
}

static void t_symbol_route(void)
{
	struct hits imp, dec, ren;

	/* an import called mmap: a node, the capability the import names */
	hk_elf(&E, 1, 0, 1);
	set_sym_name(6, "mmap");                        /* "puts" -> "mmap", undefined */
	imp = scan(KGENOME_DIAG_RUN_SYMBOL);
	CK(count_cap(&imp, KGENOME_NUCLEO_ALLOC) == 1u);

	/* the same object with every section renamed: the same node */
	CK(rename_sec(".strtab", ".qqqqqq") && rename_sec(".rela.text", ".zzzzzzzzz"));
	ren = scan(KGENOME_DIAG_RUN_SYMBOL);
	CK(same(&imp, &ren));

	/* a DEFINED symbol with an import's name is the program's own function, not an import */
	hk_elf(&E, 1, 0, 1);
	set_sym_name(11, "execve");                     /* "helper", defined in .text */
	set_sym_name(1, "mmap");                        /* "main", defined in .text */
	dec = scan(KGENOME_DIAG_RUN_SYMBOL);
	CK(count_cap(&dec, KGENOME_NUCLEO_EXEC_IMAGE) == 0u);
	CK(count_cap(&dec, KGENOME_NUCLEO_ALLOC) == 0u);
}

static void t_syscall_route(void)
{
	/* mov eax,59 ; syscall ; ret - execve, in an ET_EXEC with a symbol table */
	static const uint8_t code[] = { 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
	struct hits plain, named, stripped;
	unsigned i;

	hk_elf(&E, 1, 0, 0);
	memcpy(E.b + E.text, code, sizeof code);
	plain = scan(KGENOME_DIAG_RUN_SYSCALL);
	CK(count_cap(&plain, KGENOME_NUCLEO_EXEC_IMAGE) == 1u);

	/* symbols that LIE: main is called socket, helper is called mmap */
	set_sym_name(1, "sock");
	set_sym_name(11, "mmap");
	named = scan(KGENOME_DIAG_RUN_SYSCALL);
	CK(same(&plain, &named));

	/* no symbol table at all */
	for (i = 0; i < 6u; i++) {
		uint8_t *sh = E.b + E.sh + i * E.sh_ent;
		uint32_t type = (uint32_t)E.b[E.sh + i * E.sh_ent + 4u];

		if (type == KGENOME_ELF_SHT_SYMTAB)
			hk_w(sh + 4, 0, 4, 0);
	}
	stripped = scan(KGENOME_DIAG_RUN_SYSCALL);
	CK(same(&plain, &stripped));
}

/* the vocabulary's argument rule is one row of the names table, not a second spelling */
static void t_call_refine(void)
{
	uint64_t arg[4] = { 0, 0, 0, 0x40 };
	uint8_t fl = 0;

	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", arg, &fl) == KGENOME_NUCLEO_ALLOC_EXEC);
	CK(fl == KGENOME_NUCLEO_F_WX);
	arg[3] = 0x04;                                  /* PAGE_READWRITE */
	CK(kgenome_nucleo_cap_of_call("VirtualAlloc", arg, &fl) == KGENOME_NUCLEO_ALLOC && fl == 0);
	arg[2] = 0x20;                                  /* VirtualProtect: protection is argument 3 (index 2) */
	CK(kgenome_nucleo_cap_of_call("VirtualProtect", arg, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == 0);
	arg[0] = 2; arg[1] = 3;                         /* socket(AF_INET, SOCK_RAW) */
	CK(kgenome_nucleo_cap_of_call("socket", arg, &fl) == KGENOME_NUCLEO_NET_RAW);
	/* an ELF import carries a version suffix; the row is the same row */
	CK(kgenome_nucleo_cap_of_call("socket@@GLIBC_2.2.5", arg, &fl) == KGENOME_NUCLEO_NET_RAW);
	CK(kgenome_nucleo_cap_of_call("nonexistent_function", arg, &fl) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_cap_of_call(NULL, arg, &fl) == KGENOME_NUCLEO_NONE);
}


/*
 * The library-span tier reads the symbol table's strings. A local function named with a
 * reserved identifier, under an STT_FILE, is the library's: its extent is a span. The
 * string section it reads is the one sh_link names - renamed, the answer is the same.
 */
static uint32_t spans_of(struct kgenome_true_all *t)
{
	struct kgenome_obj o = parse_E();

	memset(t, 0, sizeof *t);
	kgenome_true_find_object(kof_buf_make(E.b, E.n), (const struct kgenome_elf_info *)o.file_header, t);
	return t->n;
}

static void t_trueline_strings(void)
{
	static struct kgenome_true_all a, b;
	uint8_t *s1, *s3;

	hk_elf(&E, 1, 0, 0);
	s1 = E.b + E.symtab + 1u * E.sym_ent;                   /* main -> an STT_FILE */
	s3 = E.b + E.symtab + 3u * E.sym_ent;                   /* helper -> a local FUNC */
	s1[4] = 0x04;
	s3[4] = 0x02;
	set_sym_name(11, "_helpr");                             /* reserved, defined, local */
	CK(spans_of(&a) >= 1u);                                 /* the control: the extent is a span */
	CK(rename_sec(".strtab", ".qqqqqq"));
	CK(spans_of(&b) == a.n);
	CK(!memcmp(a.span, b.span, a.n * sizeof a.span[0]));
	/* the same name, but the symbol is the program's own (no leading underscore): no span */
	hk_elf(&E, 1, 0, 0);
	E.b[E.symtab + 1u * E.sym_ent + 4u] = 0x04;
	E.b[E.symtab + 3u * E.sym_ent + 4u] = 0x02;
	set_sym_name(11, "helper");
	CK(spans_of(&b) == 0u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_rename_sections();
	t_symbol_route();
	t_syscall_route();
	t_call_refine();
	t_trueline_strings();
	printf("names_structural: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
