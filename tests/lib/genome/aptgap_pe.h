/*
 * aptgap_pe.h - a PE32+ written field by field for the aptgap_* tests: .text (code the test writes byte by byte from the instruction set
 * manual), .rdata (import directory, lookup tables, IAT, hint/name entries, strings, unwind info, export directory), .pdata (RUNTIME_FUNCTION
 * entries the test names) and .data (globals, RW). Imports are by NAME or by ORDINAL, per DLL. Nothing here is a sample's bytes: the shapes
 * are the ones an MSVC x64 build leaves (rip-relative `call [iat]`, a frame spill, a hidden out-pointer, a chained unwind entry), written by hand.
 * Header only, every function static.
 */
#ifndef KGENOME_TESTS_APTGAP_PE_H
#define KGENOME_TESTS_APTGAP_PE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AP_UNUSED __attribute__((unused))

#define AP_IB      0x180000000ull
#define AP_TEXT    0x1000u      /* rva of .text, file 0x400, 0x1000 bytes */
#define AP_RDATA   0x2000u      /* rva of .rdata, file 0x1400 */
#define AP_PDATA   0x3000u      /* rva of .pdata, file 0x2400 */
#define AP_DATA    0x4000u      /* rva of .data, file 0x2600 */
#define AP_SECSZ   0x1000u
#define AP_PDSZ    0x200u
#define AP_FILE    0x2800u

/* where the .rdata parts live */
#define AP_IDIR    (AP_RDATA + 0x000u)  /* import descriptors (up to 3 DLLs + the null one) */
#define AP_ILT     (AP_RDATA + 0x100u)  /* lookup tables, 0x80 per DLL */
#define AP_IAT     (AP_RDATA + 0x300u)  /* address tables, 0x80 per DLL */
#define AP_HN      (AP_RDATA + 0x500u)  /* hint/name entries, 0x20 each */
#define AP_STR     (AP_RDATA + 0xa00u)  /* strings the code points at, 0x20 each */
#define AP_UNW     (AP_RDATA + 0xc00u)  /* unwind infos, 0x20 each */
#define AP_EXP     (AP_RDATA + 0xe00u)  /* export directory */

#define AP_MAXDLL  3
#define AP_MAXIMP  12

struct ap_imp {
	const char *name;       /* NULL: by ordinal */
	uint16_t ord;
};

struct ap_dll {
	const char *name;
	struct ap_imp imp[AP_MAXIMP];
	int n;
};

struct ap_pe {
	uint8_t b[AP_FILE];
	uint32_t n;
	uint32_t pc;            /* the next code byte's rva */
	struct ap_dll dll[AP_MAXDLL];
	int ndll;
	int nstr, nunw, nrf;
};

static void ap_w(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

static uint32_t ap_off(uint32_t rva)
{
	if (rva >= AP_DATA)
		return 0x2600u + rva - AP_DATA;
	if (rva >= AP_PDATA)
		return 0x2400u + rva - AP_PDATA;
	if (rva >= AP_RDATA)
		return 0x1400u + rva - AP_RDATA;
	return 0x400u + rva - AP_TEXT;
}

static AP_UNUSED uint8_t *ap_at(struct ap_pe *p, uint32_t rva) { return p->b + ap_off(rva); }

static void ap_sec(struct ap_pe *p, unsigned i, const char *nm, uint32_t rva, uint32_t vs, uint32_t raw, uint32_t rs, uint32_t ch)
{
	uint8_t *h = p->b + 0x80u + 24u + 240u + i * 40u;

	memcpy(h, nm, strlen(nm));
	ap_w(h + 8, vs, 4); ap_w(h + 12, rva, 4); ap_w(h + 16, rs, 4); ap_w(h + 20, raw, 4); ap_w(h + 36, ch, 4);
}

static AP_UNUSED void ap_init(struct ap_pe *p)
{
	uint8_t *b = p->b;
	const uint32_t o = 0x80u + 24u;

	memset(p, 0, sizeof *p);
	b[0] = 'M'; b[1] = 'Z';
	ap_w(b + 0x3c, 0x80, 4);
	memcpy(b + 0x80, "PE\0\0", 4);
	ap_w(b + 0x84, 0x8664, 2);
	ap_w(b + 0x86, 4, 2);
	ap_w(b + 0x94, 240, 2);
	ap_w(b + 0x96, 0x2022, 2);                      /* executable, large address aware, DLL */
	ap_w(b + o, 0x20b, 2);
	b[o + 2] = 14;
	ap_w(b + o + 4, AP_SECSZ, 4);
	ap_w(b + o + 16, AP_TEXT, 4);
	ap_w(b + o + 20, AP_TEXT, 4);
	ap_w(b + o + 24, AP_IB, 8);
	ap_w(b + o + 32, 0x1000, 4); ap_w(b + o + 36, 0x200, 4);
	ap_w(b + o + 40, 6, 2); ap_w(b + o + 48, 6, 2);
	ap_w(b + o + 56, 0x5000, 4); ap_w(b + o + 60, 0x400, 4);
	ap_w(b + o + 68, 2, 2);
	ap_w(b + o + 108, 16, 4);
	ap_sec(p, 0, ".text", AP_TEXT, AP_SECSZ, 0x400, AP_SECSZ, 0x60000020u);
	ap_sec(p, 1, ".rdata", AP_RDATA, AP_SECSZ, 0x1400, AP_SECSZ, 0x40000040u);
	ap_sec(p, 2, ".pdata", AP_PDATA, AP_PDSZ, 0x2400, AP_PDSZ, 0x40000040u);
	ap_sec(p, 3, ".data", AP_DATA, AP_PDSZ, 0x2600, AP_PDSZ, 0xc0000040u);
	memset(b + 0x400, 0xcc, AP_SECSZ);              /* int3 fill between functions, as the linker leaves it */
	p->n = AP_FILE;
	p->pc = AP_TEXT;
}

static AP_UNUSED void ap_dir(struct ap_pe *p, unsigned i, uint32_t rva, uint32_t size)
{
	ap_w(p->b + 0x80u + 24u + 112u + i * 8u, rva, 4);
	ap_w(p->b + 0x80u + 24u + 112u + i * 8u + 4u, size, 4);
}

/* An import of DLL `d` (added if new): its IAT slot's rva. By name, or by ordinal when `name` is NULL. Call before ap_imports_done. */
static AP_UNUSED uint32_t ap_import(struct ap_pe *p, const char *dll, const char *name, uint16_t ord)
{
	int d, k;

	for (d = 0; d < p->ndll; d++)
		if (!strcmp(p->dll[d].name, dll))
			break;
	if (d == p->ndll) {
		p->dll[d].name = dll;
		p->ndll++;
	}
	for (k = 0; k < p->dll[d].n; k++)
		if ((name && p->dll[d].imp[k].name && !strcmp(p->dll[d].imp[k].name, name)) || (!name && !p->dll[d].imp[k].name && p->dll[d].imp[k].ord == ord))
			return AP_IAT + 0x80u * (uint32_t)d + 8u * (uint32_t)k;
	p->dll[d].imp[k].name = name;
	p->dll[d].imp[k].ord = ord;
	p->dll[d].n++;
	return AP_IAT + 0x80u * (uint32_t)d + 8u * (uint32_t)k;
}

/* Write the import directory for every import named so far. */
static AP_UNUSED void ap_imports_done(struct ap_pe *p)
{
	int d, k, hn = 0;

	for (d = 0; d < p->ndll; d++) {
		uint32_t desc = AP_IDIR + 20u * (uint32_t)d, ilt = AP_ILT + 0x80u * (uint32_t)d, iat = AP_IAT + 0x80u * (uint32_t)d;
		uint32_t dn = AP_HN + 0x20u * (uint32_t)hn++;

		memcpy(ap_at(p, dn), p->dll[d].name, strlen(p->dll[d].name) + 1u);
		ap_w(ap_at(p, desc), ilt, 4);
		ap_w(ap_at(p, desc + 12u), dn, 4);
		ap_w(ap_at(p, desc + 16u), iat, 4);
		for (k = 0; k < p->dll[d].n; k++) {
			uint64_t e;

			if (p->dll[d].imp[k].name) {
				uint32_t h = AP_HN + 0x20u * (uint32_t)hn++;

				memcpy(ap_at(p, h + 2u), p->dll[d].imp[k].name, strlen(p->dll[d].imp[k].name) + 1u);
				e = h;
			} else {
				e = (1ull << 63) | p->dll[d].imp[k].ord;
			}
			ap_w(ap_at(p, ilt + 8u * (uint32_t)k), e, 8);
			ap_w(ap_at(p, iat + 8u * (uint32_t)k), e, 8);
		}
	}
	ap_dir(p, 1, AP_IDIR, 20u * (uint32_t)(p->ndll + 1));
	ap_dir(p, 12, AP_IAT, 0x80u * (uint32_t)p->ndll);
}

/* A NUL-terminated string in .rdata: its rva. */
static AP_UNUSED uint32_t ap_str(struct ap_pe *p, const char *s)
{
	uint32_t r = AP_STR + 0x20u * (uint32_t)p->nstr++;

	memcpy(ap_at(p, r), s, strlen(s) + 1u);
	return r;
}

/* ---- code ---- */

static AP_UNUSED void ap_org(struct ap_pe *p, uint32_t rva) { p->pc = rva; }

/* raw bytes from hex ("48 83 ec 28") at pc */
static AP_UNUSED uint32_t ap_hex(struct ap_pe *p, const char *hex)
{
	uint32_t at = p->pc;
	unsigned v;

	while (*hex) {
		if (*hex == ' ') {
			hex++;
			continue;
		}
		if (sscanf(hex, "%2x", &v) != 1)
			break;
		*ap_at(p, p->pc++) = (uint8_t)v;
		hex += 2;
	}
	return at;
}

/* an instruction that ends in a rip-relative disp32 to `to`: `hex` is the bytes before the displacement. Returns the instruction's rva. */
static AP_UNUSED uint32_t ap_rip(struct ap_pe *p, const char *hex, uint32_t to)
{
	uint32_t at = ap_hex(p, hex);

	ap_w(ap_at(p, p->pc), (uint32_t)(to - (p->pc + 4u)), 4);
	p->pc += 4u;
	return at;
}

/* `call [rip+slot]`: the rva of the call */
static AP_UNUSED uint32_t ap_call_iat(struct ap_pe *p, uint32_t slot) { return ap_rip(p, "ff 15", slot); }

/* `call rel32` to `to` */
static AP_UNUSED uint32_t ap_call(struct ap_pe *p, uint32_t to) { return ap_rip(p, "e8", to); }

/* ---- unwind and .pdata ---- */

/* An unwind info: version 1, flags, no codes; when `chained`, the parent's RUNTIME_FUNCTION follows. Its rva. */
static AP_UNUSED uint32_t ap_unwind(struct ap_pe *p, int chained, uint32_t pb, uint32_t pe, uint32_t pu)
{
	uint32_t r = AP_UNW + 0x20u * (uint32_t)p->nunw++;
	uint8_t *u = ap_at(p, r);

	u[0] = (uint8_t)(0x01u | (chained ? 4u << 3 : 0u));
	if (chained) {
		ap_w(u + 4, pb, 4);
		ap_w(u + 8, pe, 4);
		ap_w(u + 12, pu, 4);
	}
	return r;
}

static AP_UNUSED void ap_rf(struct ap_pe *p, uint32_t begin, uint32_t end, uint32_t unw)
{
	uint8_t *e = ap_at(p, AP_PDATA + 12u * (uint32_t)p->nrf++);

	ap_w(e, begin, 4);
	ap_w(e + 4, end, 4);
	ap_w(e + 8, unw, 4);
	ap_dir(p, 3, AP_PDATA, 12u * (uint32_t)p->nrf);
}

/* An export directory naming ONE function. */
static AP_UNUSED void ap_export1(struct ap_pe *p, const char *dllname, const char *name, uint32_t rva)
{
	const uint32_t d = AP_EXP, eat = d + 0x40u, ent = d + 0x48u, eot = d + 0x50u, nm = d + 0x60u, dn = d + 0x80u;

	memcpy(ap_at(p, nm), name, strlen(name) + 1u);
	memcpy(ap_at(p, dn), dllname, strlen(dllname) + 1u);
	ap_w(ap_at(p, d + 12u), dn, 4);
	ap_w(ap_at(p, d + 16u), 1, 4);          /* Base */
	ap_w(ap_at(p, d + 20u), 1, 4);          /* NumberOfFunctions */
	ap_w(ap_at(p, d + 24u), 1, 4);          /* NumberOfNames */
	ap_w(ap_at(p, d + 28u), eat, 4);
	ap_w(ap_at(p, d + 32u), ent, 4);
	ap_w(ap_at(p, d + 36u), eot, 4);
	ap_w(ap_at(p, eat), rva, 4);
	ap_w(ap_at(p, ent), nm, 4);
	ap_w(ap_at(p, eot), 0, 2);
	ap_dir(p, 0, d, 0xa0u);
}

#endif /* KGENOME_TESTS_APTGAP_PE_H */
