/*
 * diag_seed.h - the seeds the diag adapters share: hand-assembled x86-64 programs wrapped in an ELF64 / ELF32 / AArch64 image
 * and a PE32+ whose code sits in the builder's .text, a script per language, and the field maps that aim the mutators at
 * the header fields the routes read.
 *
 * The programs are written from the instruction set manual (as in tests/lib/genome/diag_graph_bin.c), so that a decoder
 * defect cannot make a seed agree with itself. Everything here is a plain static function; an adapter file includes it.
 */
#ifndef KOF_TESTS_FUZZ_DIAG_SEED_H
#define KOF_TESTS_FUZZ_DIAG_SEED_H

#include <kgenome.h>
#include <phenotype/diag_scan.h>

#include "../../lib/genome/hk.h"
#include "../../lib/fuzz_drv.h"

#define DS_CODE_MAX 2048u

struct ds_code {
	uint8_t  b[DS_CODE_MAX];
	unsigned n;
};

static void ds_emit(struct ds_code *c, const uint8_t *p, unsigned n) FZ_UNUSED;
static void ds_emit(struct ds_code *c, const uint8_t *p, unsigned n)
{
	if (c->n + n <= DS_CODE_MAX) {
		memcpy(c->b + c->n, p, n);
		c->n += n;
	}
}
#define DS_E(c, ...) do { static const uint8_t b_[] = { __VA_ARGS__ }; ds_emit((c), b_, (unsigned)sizeof b_); } while (0)

static void ds_p32(uint8_t *b, unsigned at, uint32_t v) FZ_UNUSED;
static void ds_p32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void ds_p64(uint8_t *b, unsigned at, uint64_t v) FZ_UNUSED;
static void ds_p64(uint8_t *b, unsigned at, uint64_t v)
{
	ds_p32(b, at, (uint32_t)v);
	ds_p32(b, at + 4u, (uint32_t)(v >> 32));
}

/* socket(2, 1, 0): rax holds the descriptor; rdi, rsi, rdx hold constants afterwards */
static void ds_sock(struct ds_code *c) FZ_UNUSED;
static void ds_sock(struct ds_code *c)
{
	DS_E(c, 0xb8, 41, 0, 0, 0, 0xbf, 2, 0, 0, 0, 0xbe, 1, 0, 0, 0, 0x31, 0xd2, 0x0f, 0x05);
}
static void ds_mov_rdi_rax(struct ds_code *c) FZ_UNUSED;
static void ds_mov_rdi_rax(struct ds_code *c) { DS_E(c, 0x48, 0x89, 0xc7); }
static void ds_write_sys(struct ds_code *c) FZ_UNUSED;
static void ds_write_sys(struct ds_code *c) { DS_E(c, 0xb8, 1, 0, 0, 0, 0x0f, 0x05); }
static void ds_exit_sys(struct ds_code *c) FZ_UNUSED;
static void ds_exit_sys(struct ds_code *c) { DS_E(c, 0xb8, 60, 0, 0, 0, 0x0f, 0x05); }
static void ds_ret(struct ds_code *c) FZ_UNUSED;
static void ds_ret(struct ds_code *c) { DS_E(c, 0xc3); }
static void ds_pad(struct ds_code *c, unsigned n) FZ_UNUSED;
static void ds_pad(struct ds_code *c, unsigned n) { while (n--) DS_E(c, 0x90); }

static void ds_call_to(struct ds_code *c, unsigned target) FZ_UNUSED;
static void ds_call_to(struct ds_code *c, unsigned target)
{
	if (c->n + 5u > DS_CODE_MAX)
		return;
	c->b[c->n] = 0xe8;
	ds_p32(c->b, c->n + 1u, (uint32_t)(target - (c->n + 5u)));
	c->n += 5u;
}
static unsigned ds_jz_fwd(struct ds_code *c) FZ_UNUSED;
static unsigned ds_jz_fwd(struct ds_code *c)
{
	DS_E(c, 0x0f, 0x84, 0, 0, 0, 0);
	return c->n - 4u;
}
static void ds_here(struct ds_code *c, unsigned hole) FZ_UNUSED;
static void ds_here(struct ds_code *c, unsigned hole)
{
	ds_p32(c->b, hole, (uint32_t)(c->n - (hole + 4u)));
}

/* An ELF64 with one RWX PT_LOAD from offset zero; the code is at +0x78, the entry too. Returns the image size. */
static unsigned ds_elf64(uint8_t *b, const struct ds_code *c, unsigned machine) FZ_UNUSED;
static unsigned ds_elf64(uint8_t *b, const struct ds_code *c, unsigned machine)
{
	memset(b, 0, 0x78u + c->n);
	memcpy(b, "\177ELF\2\1\1", 7);
	b[16] = 2; b[18] = (uint8_t)machine; b[19] = (uint8_t)(machine >> 8); b[20] = 1;
	ds_p64(b, 24, 0x400078u);
	ds_p64(b, 32, 64);
	b[52] = 64; b[54] = 56; b[56] = 1;
	ds_p32(b, 64, 1);
	ds_p32(b, 68, 7);
	ds_p64(b, 80, 0x400000u);
	ds_p64(b, 96, 0x78u + c->n);
	ds_p64(b, 104, 0x78u + c->n);
	memcpy(b + 0x78, c->b, c->n);
	return 0x78u + c->n;
}

/* An ELF32 with one RWX PT_LOAD from offset zero (ARM when machine is 40, i386 when 3); the code is at +0x54. */
static unsigned ds_elf32(uint8_t *b, const struct ds_code *c, unsigned machine) FZ_UNUSED;
static unsigned ds_elf32(uint8_t *b, const struct ds_code *c, unsigned machine)
{
	memset(b, 0, 0x54u + c->n);
	memcpy(b, "\177ELF\1\1\1", 7);
	b[16] = 2; b[18] = (uint8_t)machine; b[20] = 1;
	ds_p32(b, 24, 0x10054u);
	ds_p32(b, 28, 52);
	b[40] = 52; b[42] = 32; b[44] = 1;
	ds_p32(b, 52, 1);
	ds_p32(b, 60, 0x10000u);
	ds_p32(b, 64, 0x10000u);
	ds_p32(b, 68, 0x54u + c->n);
	ds_p32(b, 72, 0x54u + c->n);
	ds_p32(b, 76, 7);
	memcpy(b + 0x54, c->b, c->n);
	return 0x54u + c->n;
}

/* The field map of the two ELF layouts above: what the parse and the routes read from the headers. */
static void ds_elf_map(struct fz_map *m, struct fz_field *f, int is64) FZ_UNUSED;
static void ds_elf_map(struct fz_map *m, struct fz_field *f, int is64)
{
	unsigned n = 0;

	m->f = f;
	if (is64) {
		f[n].off = 24; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_RVA;       /* e_entry */
		f[n].off = 32; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_OFFSET;    /* e_phoff */
		f[n].off = 56; f[n].size = 2; f[n].be = 0; f[n++].kind = FZ_COUNT;     /* e_phnum */
		f[n].off = 72; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_OFFSET;    /* p_offset */
		f[n].off = 80; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_RVA;       /* p_vaddr */
		f[n].off = 96; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_LEN;       /* p_filesz */
		f[n].off = 104; f[n].size = 8; f[n].be = 0; f[n++].kind = FZ_LEN;      /* p_memsz */
	} else {
		f[n].off = 24; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_RVA;
		f[n].off = 28; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_OFFSET;
		f[n].off = 44; f[n].size = 2; f[n].be = 0; f[n++].kind = FZ_COUNT;
		f[n].off = 56; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_OFFSET;
		f[n].off = 60; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_RVA;
		f[n].off = 68; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_LEN;
		f[n].off = 72; f[n].size = 4; f[n].be = 0; f[n++].kind = FZ_LEN;
	}
	m->n = n;
	m->rec_off = 0;
	m->rec_size = 0;
	m->rec_n = 0;
}

/*
 * An ET_REL x86-64 object (a kernel module's shape): .text, .symtab, .strtab, .rela.text, .shstrtab. `syms` are undefined global symbols, the
 * entry `init_module` is defined at the start of .text; relocation k is an R_X86_64_PLT32 at text offset roff[k] against undefined symbol rsym[k]
 * (an index into syms). Returns the image size (at most 0x1000 for code up to 512 bytes).
 */
static unsigned ds_elf_rel(uint8_t *b, const uint8_t *code, unsigned codelen, const char *const *syms, unsigned nsym,
			   const unsigned *roff, const unsigned *rsym, unsigned nrel) FZ_UNUSED;
static unsigned ds_elf_rel(uint8_t *b, const uint8_t *code, unsigned codelen, const char *const *syms, unsigned nsym,
			   const unsigned *roff, const unsigned *rsym, unsigned nrel)
{
	static const char shn[] = "\0.text\0.symtab\0.strtab\0.rela.text\0.shstrtab";
	unsigned text = 0x40, symtab, strtab, rela, shstr, sh, strn = 1, i, at, nsyms = nsym + 2u;
	uint32_t *stroff = (uint32_t *)(void *)(b + 0xf00);       /* scratch for the name offsets: the end of the image page */

	if (codelen > 512u)
		codelen = 512u;
	if (nsym > 24u)
		nsym = 24u, nsyms = 26u;
	if (nrel > 24u)
		nrel = 24u;
	memset(b, 0, 0x1000);
	symtab = (text + codelen + 7u) & ~7u;
	strtab = symtab + nsyms * 24u;
	for (i = 0; i < nsym; i++)
		strn += (unsigned)strlen(syms[i]) + 1u;
	strn += 12u;                                              /* "init_module\0" */
	rela = (strtab + strn + 7u) & ~7u;
	shstr = rela + nrel * 24u;
	sh = (shstr + (unsigned)sizeof shn + 7u) & ~7u;
	memcpy(b, "\177ELF\2\1\1", 7);
	b[16] = 1; b[18] = 0x3e; b[20] = 1;
	ds_p64(b, 40, sh);
	b[52] = 64; b[58] = 64; b[60] = 6; b[62] = 5;
	memcpy(b + text, code, codelen);
	at = strtab + 1u;
	for (i = 0; i < nsym; i++) {
		stroff[i] = at - strtab;
		memcpy(b + at, syms[i], strlen(syms[i]) + 1u);
		at += (unsigned)strlen(syms[i]) + 1u;
	}
	memcpy(b + at, "init_module", 12);
	for (i = 0; i < nsym; i++) {
		uint8_t *y = b + symtab + (i + 1u) * 24u;

		ds_p32(y, 0, stroff[i]);
		y[4] = 0x10;                                      /* GLOBAL NOTYPE, undefined */
	}
	{
		uint8_t *y = b + symtab + (nsym + 1u) * 24u;

		ds_p32(y, 0, at - strtab);
		y[4] = 0x12;                                      /* GLOBAL FUNC, .text */
		y[6] = 1;
		ds_p64(y, 16, codelen);
	}
	for (i = 0; i < nrel; i++) {
		uint8_t *r = b + rela + i * 24u;

		ds_p64(r, 0, roff[i]);
		ds_p64(r, 8, ((uint64_t)(rsym[i] + 1u) << 32) | 4u);
		ds_p64(r, 16, (uint64_t)-4);
	}
	memcpy(b + shstr, shn, sizeof shn);
	{
		struct { uint32_t name, type; uint64_t flags; uint32_t off, size, link, info; uint64_t ent; } h[6] = {
			{ 0, 0, 0, 0, 0, 0, 0, 0 },
			{ 1, 1, 6, text, codelen, 0, 0, 0 },
			{ 7, 2, 0, symtab, nsyms * 24u, 3, nsym + 1u, 24 },
			{ 15, 3, 0, strtab, strn, 0, 0, 0 },
			{ 23, 4, 0x40, rela, nrel * 24u, 2, 1, 24 },
			{ 34, 3, 0, shstr, (unsigned)sizeof shn, 0, 0, 0 }
		};

		for (i = 0; i < 6; i++) {
			uint8_t *e = b + sh + i * 64u;

			ds_p32(e, 0, h[i].name);
			ds_p32(e, 4, h[i].type);
			ds_p64(e, 8, h[i].flags);
			ds_p64(e, 24, h[i].off);
			ds_p64(e, 32, h[i].size);
			ds_p32(e, 40, h[i].link);
			ds_p32(e, 44, h[i].info);
			ds_p64(e, 48, h[i].type == 1 ? 16u : 8u);
			ds_p64(e, 56, h[i].ent);
		}
	}
	memset(b + 0xf00, 0, 0x100);
	return sh + 6u * 64u;
}

/* The kernel-module programs, by number: credentials, a cr0 write, a copy from a user buffer, an indirect call, the credential fields and the fields of a kmalloc'd object. */
#define DS_NKO 6u

static unsigned ds_ko(uint8_t *b, unsigned which) FZ_UNUSED;
static unsigned ds_ko(uint8_t *b, unsigned which)
{
	static const char *const syms[] = { "prepare_kernel_cred", "commit_creds", "native_write_cr0", "kmalloc", "_copy_from_user", "printk" };
	struct ds_code c;
	unsigned roff[4], rsym[4], nrel = 0;

	c.n = 0;
	switch (which % DS_NKO) {
	case 0:                                                   /* commit_creds(prepare_kernel_cred(0)) */
		DS_E(&c, 0x31, 0xff);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 0; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x48, 0x89, 0xc7);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 1; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x31, 0xc0, 0xc3);
		break;
	case 1:                                                   /* cr0 &= ~WP via native_write_cr0 */
		DS_E(&c, 0x0f, 0x20, 0xc0, 0x48, 0x25, 0xff, 0xff, 0xfe, 0xff, 0x48, 0x89, 0xc7);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 2; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x0f, 0x22, 0xc0, 0xc3);
		break;
	case 2:                                                   /* buf = kmalloc(); _copy_from_user(buf, ubuf, n) */
		DS_E(&c, 0xbf, 0x40, 0, 0, 0);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 3; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x48, 0x89, 0xc7, 0x48, 0x89, 0xde, 0xba, 0x40, 0, 0, 0);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 4; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0xc3);
		break;
	case 3:                                                   /* an indirect call through a pointer the loader fills, printk after it */
		DS_E(&c, 0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xff, 0xd0);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 5; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0xc3);
		break;
	case 4:                                                   /* the credentials: uid and gid written into what prepare_kernel_cred made */
		DS_E(&c, 0x31, 0xff);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 0; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x48, 0x89, 0xc3, 0xc7, 0x43, 0x04, 0, 0, 0, 0, 0xc7, 0x43, 0x08, 0, 0, 0, 0, 0x48, 0x89, 0xdf);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 1; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x31, 0xc0, 0xc3);
		break;
	default:                                                  /* a field read and a field written of a kmalloc'd object (a directory record edited in place) */
		DS_E(&c, 0xbf, 0x40, 0, 0, 0);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 3; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0x48, 0x89, 0xc3, 0x8b, 0x43, 0x10, 0x89, 0x4b, 0x10, 0x48, 0x89, 0xdf, 0x48, 0x89, 0xde, 0xba, 0x40, 0, 0, 0);
		roff[nrel] = c.n + 1u; rsym[nrel++] = 4; DS_E(&c, 0xe8, 0, 0, 0, 0);
		DS_E(&c, 0xc3);
		break;
	}
	return ds_elf_rel(b, c.b, c.n, syms, 6, roff, rsym, nrel);
}

/* The programs, by number. Each is the smallest shape of one route. */
#define DS_NPROG 9u

static void ds_prog(struct ds_code *c, unsigned which) FZ_UNUSED;
static void ds_prog(struct ds_code *c, unsigned which)
{
	unsigned h, w1, w2;

	c->n = 0;
	switch (which % DS_NPROG) {
	case 0:                                   /* socket -> write in one line, then exit */
		ds_sock(c); ds_mov_rdi_rax(c); ds_write_sys(c); ds_exit_sys(c);
		break;
	case 1:                                   /* a wrapper with one syscall, called from three places */
		DS_E(c, 0x89, 0xf8, 0x0f, 0x05, 0xc3);                   /* mov eax,edi ; syscall ; ret */
		w1 = c->n;
		DS_E(c, 0xbf, 41, 0, 0, 0);       ds_call_to(c, 0);     /* socket via the wrapper */
		DS_E(c, 0xbf, 1, 0, 0, 0);        ds_call_to(c, 0);
		DS_E(c, 0xbf, 60, 0, 0, 0);       ds_call_to(c, 0);
		(void)w1;
		ds_ret(c);
		break;
	case 2:                                   /* two producers on the arms of a branch, joined before the consumer */
		ds_sock(c); DS_E(c, 0x48, 0x85, 0xc9); h = ds_jz_fwd(c);
		DS_E(c, 0x48, 0x89, 0xc7); ds_here(c, h); ds_write_sys(c); ds_ret(c);
		break;
	case 3:                                   /* connect retried in a loop: the run repeats it */
		DS_E(c, 0xb9, 10, 0, 0, 0);                              /* mov ecx,10 */
		w2 = c->n;
		DS_E(c, 0xb8, 42, 0, 0, 0, 0x0f, 0x05, 0xff, 0xc9);      /* mov eax,42 ; syscall ; dec ecx */
		{
			uint8_t jn[2];

			jn[0] = 0x75;
			jn[1] = (uint8_t)(0x100u - (c->n + 2u - w2));      /* jnz loop */
			ds_emit(c, jn, 2);
		}
		ds_exit_sys(c);
		break;
	case 4:                                   /* mmap RWX then a call into the region: the stager shape */
		DS_E(c, 0xb8, 9, 0, 0, 0, 0x31, 0xff, 0xbe, 0, 0x10, 0, 0, 0xba, 7, 0, 0, 0, 0x0f, 0x05);
		DS_E(c, 0xff, 0xd0);                                     /* call rax */
		ds_exit_sys(c);
		break;
	case 5:                                   /* a call whose clobber reaches the argument */
		ds_sock(c); ds_mov_rdi_rax(c); DS_E(c, 0xe8, 6, 0, 0, 0); ds_write_sys(c); ds_ret(c);
		DS_E(c, 0xbf, 0, 0, 0, 0, 0xc3);
		break;
	case 6:                                   /* a stack-derived mprotect and a jump into the stack (the i386 stager) */
		DS_E(c, 0x48, 0x89, 0xe7, 0x48, 0x81, 0xe7, 0, 0xf0, 0xff, 0xff, 0xb8, 10, 0, 0, 0, 0x0f, 0x05, 0xff, 0xe4);
		break;
	case 7:                                   /* a value kept in memory and read back (a stack slot) */
		DS_E(c, 0x48, 0x83, 0xec, 0x10);
		ds_sock(c);
		DS_E(c, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0x8b, 0x7c, 0x24, 0x08);
		ds_write_sys(c);
		DS_E(c, 0x48, 0x83, 0xc4, 0x10, 0xc3);
		break;
	default:                                  /* data in the code: 0f 05 inside an immediate, then padding */
		DS_E(c, 0xb8, 0x0f, 0x05, 0x90, 0x90, 0x0f, 0x05, 0xc3);
		ds_pad(c, 16);
		break;
	}
}

/* A PE32+ whose .text holds `calls` through the import slots and, for the API-hash route, a read of the PEB loader data. */
static void ds_pe(struct hk_pe *p, unsigned variant) FZ_UNUSED;
static void ds_pe(struct hk_pe *p, unsigned variant)
{
	static const uint8_t peb[] = { 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x20 };
	uint8_t *t;
	unsigned at = 0;

	hk_pe(p, 1);
	t = p->b + p->text_off;
	memset(t, 0xcc, 0x200);
	if (variant & 1u) {                       /* call [rip+slot] to ExitProcess, then to MessageBoxA */
		uint32_t slot0 = 0x20a0u, slot2 = 0x20a0u + 3u * 8u;

		t[at++] = 0xb9; ds_p32(t, at, 0); at += 4;                /* mov ecx, 0 */
		t[at++] = 0xff; t[at++] = 0x15; ds_p32(t, at, slot0 - (0x1000u + at + 4u)); at += 4;
		t[at++] = 0xff; t[at++] = 0x15; ds_p32(t, at, slot2 - (0x1000u + at + 4u)); at += 4;
	}
	if (variant & 2u) {                       /* the resolver's start: PEB.Ldr.InMemoryOrderModuleList */
		memcpy(t + at, peb, sizeof peb);
		at += (unsigned)sizeof peb;
	}
	if (variant & 4u) {                       /* a hell's-gate stub: mov eax, 0x3b ; syscall */
		static const uint8_t g[] = { 0xb8, 0x3b, 0, 0, 0, 0x0f, 0x05 };

		memcpy(t + at, g, sizeof g);
		at += (unsigned)sizeof g;
	}
	if (variant & 8u) {                       /* a spin: the run ends only by its budget */
		t[at++] = 0xeb; t[at++] = 0xfe;
	}
	t[at++] = 0xc3;
}

/* scan_bin.c: the whole walk over one parsed object (the graph, its products, the walk, the functions, a code run, the API-hash set). */
void diag_exercise(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n);
void diag_exercise_ex(struct fz_ctx *c, const struct kgenome_obj *obj, const uint8_t *in, size_t n, int lite);

/* scan_bin.c: the invariants every graph holds (nodes, inputs, names, status, products). */
void diag_check_graph(struct fz_ctx *c, const struct kgenome_diag_scan *s, unsigned run);

/* the graph as one number: caps, places, inputs */
static uint64_t ds_graph_sig(const struct kgenome_diag_scan *s) FZ_UNUSED;
static uint64_t ds_graph_sig(const struct kgenome_diag_scan *s)
{
	uint64_t h = 0xcbf29ce484222325ull;
	uint32_t i, k, cnt = kgenome_diag_scan_count(s);

	h = (h ^ cnt) * 0x100000001b3ull;
	for (i = 0; i < cnt; i++) {
		const struct kgenome_diag_hit *x = kgenome_diag_scan_at(s, i);

		h = (h ^ x->cap) * 0x100000001b3ull;
		h = (h ^ x->at) * 0x100000001b3ull;
		h = (h ^ x->bits) * 0x100000001b3ull;
		h = (h ^ x->n_in) * 0x100000001b3ull;
		for (k = 0; k < x->n_in && k < 4u; k++) {
			h = (h ^ ((uint64_t)x->in[k].from | ((uint64_t)x->in[k].role << 16) | ((uint64_t)x->in[k].how << 24) |
				  ((uint64_t)x->in[k].kind << 32))) * 0x100000001b3ull;
		}
	}
	return h;
}


/* scan_bin.c: the image seeds, their dictionary and the parse of an ELF or PE out of the bytes, for the rows that start from a parsed object. */
struct diag_st {
	struct kgenome_obj      obj;
	struct kgenome_elf_info ei;
	struct kgenome_pe_info  pi;
	int                     is_elf, is_pe;
};
void diag_seeds_bin(struct fz_corpus *c);
void *diag_parse_bin(struct fz_ctx *c, const uint8_t *in, size_t n);
void diag_walk_bin(struct fz_ctx *c, void *h, const uint8_t *in, size_t n);
extern const char *const diag_dict_bin[];

/* scan_code.c: code bytes wrapped in an image that always parses (the first byte picks ELF64/ELF32/ARM/AArch64/PE32+), and the seeds of it. */
struct diag_st *diag_wrap_code(struct fz_ctx *c, const uint8_t *in, size_t n, const uint8_t **img_out, size_t *total_out);
void diag_seeds_code(struct fz_corpus *c);
extern const char *const diag_dict_code[];

#endif
