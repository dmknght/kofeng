/*
 * kofscfind.c - see kofscfind.h. The measurements behind each threshold were taken on
 * the corpora named beside it and are kept with the number they justify.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <genotype/image/obj.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/elf_rebuild.h>
#include <genotype/image/pe_rebuild.h>
#include <kofcore.h>

#include <celllysis/celllysis.h>
#include <celllysis/xref.h>
#include <celllysis/range_facts.h>

#include "kofscfind.h"

/* ELF's own numbering, spelled out because the parse keeps sh_type and
 * sh_flags raw. */
#define SHT_PROGBITS_   1u
#define SHF_EXECINSTR_  0x4u
#define SHF_WRITE_      0x1u
#define PT_INTERP_      3u
#define STT_OBJECT_     1u
#define STB_GLOBAL_     1u

/*
 * THE FILE HAS TO BE MOSTLY DATA, AS A RATIO - not under a fixed size.
 *
 * A loader is a few hundred bytes of code carrying a payload, so its writable
 * data is comparable to its code or larger. A program that does something has
 * far more code than data. Both sides are executable and writable PROGBITS
 * only - .text and .data, not .bss, not the section table, not the strings.
 *
 * A RATIO RATHER THAN A CAP: a cap of 2048 bytes of code worked on every sample
 * and let a bigger loader walk straight past it. The ratio has no ceiling - a
 * twenty kilobyte loader carrying an eight kilobyte payload trips it exactly as
 * a four hundred byte one does - and both numbers are already in the parsed
 * section table.
 *
 * MEASURED, on the corpus the rule was written on:
 *
 *   loaders           data/code 0.41 to 2.40
 *   libbz2            0.06        crypto table in a real library
 *   libmpfr           0.07        decimal tables
 *   frei0r dither.so  1.86        inside the range, excluded by PT_INTERP
 *
 * One fifth is chosen against the 0.41 floor rather than at it - a threshold
 * set at the lowest sample measured is a threshold fitted to the samples. Of
 * the ELF objects under /usr, 34.95% carry PT_INTERP, and with this ratio in
 * front of the symbol walk 3.63% reach it. Expressed as `data * 5 >= code`.
 */
#define SCL_DATA_NUM    5u

/*
 * AND AN ABSOLUTE CEILING ON THE CODE, because the ratio alone does not bound
 * how big the program is: PingPull has 473,137 bytes of code and 100,624 of
 * data (0.21) and sails through a test that only asks about proportion. It is a
 * large program that happens to hold tables, not a small loader carrying a
 * payload. The twelve loaders measured have 409 to 489 bytes of code; the
 * nearest thing that is not one has 24,265 (Reaper CnC). 8192 sits sixteen
 * times above the loaders and three times below that.
 */
#define SCL_CODE_MAX    8192u

/*
 * NO SINGLE BYTE VALUE MAY BE MORE THAN A QUARTER OF THE BLOB.
 *
 * Shannon entropy is the natural measure - payloads run 4.90 to 7.58 bits - and
 * this is the integer stand-in. The first stand-in counted DISTINCT byte values
 * and was wrong about the case that matters: a pointer table has many distinct
 * bytes and almost no entropy (OpenSSL's ssl3_ciphers has 91 distinct values in
 * 2880 bytes and is three quarters zero; Reaper's knownBots is 62% zero).
 *
 *   payloads          top byte  1.5% to 12.0%
 *   ssl3_ciphers      top byte  75.7%
 *   knownBots         top byte  62.5%
 *   char table[256]   top byte  ~99%
 *
 * A quarter sits between them with room on both sides: `top * 4 >= sz`.
 */
#define SCL_TOP_DENOM   4u

/*
 * ---- THE POINTER-SHAPED VARIANT ------------------------------------------
 *
 * `char shellcode[] = "..."` puts the bytes IN the symbol, and the walk measures
 * them. `char *shellcode = "..."` puts an ADDRESS in the symbol and the bytes in
 * .rodata, so the symbol's size is the width of a pointer. Followed ONCE, never
 * recursively. What separates it from `char *message = "..."`:
 *
 *   The target is NOT EXECUTABLE (else every function pointer in .data: 313 of
 *   them in 300 clean binaries). The blob is not mostly printable: SCL_NPR_PCT
 *   of the bytes must be outside printable ASCII (alone this leaves 2 in 300).
 *   It is not a table, by the same top-byte test. And IT MAKES A SYSCALL, which
 *   Linux shellcode has to and a data blob does not - what takes it to 0 in 300
 *   clean binaries while keeping the one real payload.
 *
 * The cost is stated: a cleartext payload that reaches the kernel some other way
 * - through a resolved libc pointer - is not found. The alternative measured
 * worse: eleven false positives, ten of them OpenSSL curve tables in static
 * builds.
 */
#define SCL_PTR_MIN     16u     /* shorter than this is not a payload */
#define SCL_NPR_PCT     15u     /* of the blob must be non-printable */

/*
 * WHAT "CARRIES A PAYLOAD" MEANS: the code EXECUTES the variable - called or
 * jumped to, because a loader may do either and the two are the same statement
 * about the data - or STAGES it, which needs the argument and a region fact
 * together. Neither region fact is usable alone: every dynamically linked
 * binary calls __libc_start_main through the GOT, an indirect call from the
 * entry's region (107 of 107 over /usr/bin). Over three hundred clean binaries,
 * 155 object symbols of 64..8192 bytes: CALL/JUMP 0, RGN_ICALL 22, ARG 33,
 * ARG and (RGN_ICALL or NEAR) 25 - so the gate is an AND with the byte tests
 * and the zero belongs to the combination.
 */
#define SCF_EXECUTED  (KGENOME_XREF_CALL | KGENOME_XREF_JUMP)
#define SCF_IS_STAGED(x) (((x) & KGENOME_XREF_ARG) && \
			  ((x) & (KGENOME_XREF_RGN_ICALL | KGENOME_XREF_RGN_NEAR)))
/*
 * WHERE THE SWEEP CANNOT LOOK, THIS GATE DOES NOT APPLY. The sweep reads x86; on
 * ARM or MIPS it answers PARTIAL and nothing else, which says "not analysed"
 * rather than "not referred to" - and gating on it regardless rejects every
 * candidate on every such file. So where the answer is real, require it; where
 * it is not, fall through to the byte tests.
 */
#define SCF_NO_XREF(x)  (((x) & KGENOME_XREF_PARTIAL) && !((x) & SCF_EXECUTED))

struct scf {
	const struct kofscfind_in *in;
	const struct kgenome_elf_info *e;
};

static uint8_t rd8(const struct scf *c, uint64_t off)
{
	return off < c->in->n ? c->in->data[off] : 0u;
}

/* How the code refers to a variable, or "nothing known" with no sweep. */
static uint32_t xref_of(const struct scf *c, uint64_t va, uint64_t size)
{
	return c->in->xref ? c->in->xref(c->in->xref_user, va, size)
			   : (uint32_t)KGENOME_XREF_PARTIAL;
}

static int xref_passes(uint32_t x)
{
	return SCF_NO_XREF(x) || (x & SCF_EXECUTED) || SCF_IS_STAGED(x);
}

/* Base64, decoded, because that is the one wrapper that can be undone with no
 * guesswork: the alphabet is fixed and the transform is reversible. Returns the
 * bytes written, or 0 when the input is not base64 - which is most payloads,
 * and not a failure. */
/* KNOWN DEFECT D18 (2026-10-24, R) [sev L]: b64 is a second base64 decoder inside the examiner; kuncoat already has
 * KUNCOAT_ALGO_B64 (decoders/codings.h) and a tool shows engine results, it does not decode. Trigger: any
 * payload the finder tries as base64. Effect: two decoders that can drift (padding, whitespace, lax mode).
 * Reproducer: none (read). Fix: call kuncoat_transform with KUNCOAT_ALGO_B64 and delete this function. */
static uint32_t b64(const uint8_t *in, uint32_t n, uint8_t *out, uint32_t cap)
{
	uint32_t i, k = 0, acc = 0, bits = 0;

	/*
	 * Refused on the first byte that is not in the alphabet, rather than
	 * skipped: a payload with a few base64-looking bytes in it is not base64,
	 * and decoding the parts that happen to fit would produce a blob that
	 * means nothing and looks like an answer.
	 */
	if (n < 8u)
		return 0;
	for (i = 0; i < n; i++) {
		uint32_t sixbit;
		uint8_t c = in[i];

		/*
		 * A NUL ENDS THE INPUT, it does not fail it: these blobs are
		 * declared as C string literals, so sizeof includes the
		 * terminator and the symbol's size is one more than the text.
		 * Only at the END, though: a NUL with data after it is not a
		 * string and not base64.
		 */
		if (!c)
			break;
		if (c == '=' || c == '\n' || c == '\r')
			continue;
		if (c >= 'A' && c <= 'Z')      sixbit = (uint32_t)(c - 'A');
		else if (c >= 'a' && c <= 'z') sixbit = (uint32_t)(c - 'a') + 26u;
		else if (c >= '0' && c <= '9') sixbit = (uint32_t)(c - '0') + 52u;
		else if (c == '+')             sixbit = 62u;
		else if (c == '/')             sixbit = 63u;
		else                           return 0;
		acc = (acc << 6) | sixbit;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (k >= cap)
				return 0;
			out[k++] = (uint8_t)(acc >> bits);
		}
	}
	return k;
}

/* Undo a wrapper, if there is one: the payload as it sits is what `at` holds
 * and zero here says so. */
static void decode(const struct scf *c, struct kofscfind *o)
{
	uint8_t enc[KOFSCFIND_SIZE_MAX];
	uint32_t i, n;

	o->dec_n = 0;
	if (o->len > KOFSCFIND_SIZE_MAX)
		return;
	n = (uint32_t)o->len;
	for (i = 0; i < n; i++)
		enc[i] = rd8(c, o->at + i);
	o->dec_n = b64(enc, n, o->dec, (uint32_t)sizeof o->dec);
}

/*
 * Where a symbol's own bytes are in the file, or 0 when the record's numbers do
 * not describe a place in it. The shndx, the value and the section's own
 * addresses are all read out of the file, so every one of them is checked: a
 * forged index or an address below the section it claims must fail the test,
 * not produce an offset.
 *
 * `strict` also requires the bytes to lie inside the section's file extent.
 * The pointer variant asks for it, because the pointer is READ from there; the
 * inline variant never did - a size that runs past the section but not past the
 * object is measured as before, and tightening it here would change which files
 * are found.
 */
static uint64_t sym_off(const struct scf *c, const struct kgenome_elf_symbol *s,
			uint64_t need, int strict)
{
	const struct kgenome_elf_info *e = c->e;
	uint64_t fo;

	if (s->shndx >= e->sec_count || s->shndx >= KGENOME_ELF_MAX_SECTIONS)
		return 0;
	if (e->sec[s->shndx].type != SHT_PROGBITS_)
		return 0;
	if (s->value < e->sec[s->shndx].mem_addr)
		return 0;
	fo = e->sec[s->shndx].file_off + (s->value - e->sec[s->shndx].mem_addr);
	if (fo >= c->in->obj->obj_size || need > c->in->obj->obj_size - fo)
		return 0;
	if (strict &&
	    (fo < e->sec[s->shndx].file_off ||
	     need > e->sec[s->shndx].file_size - (fo - e->sec[s->shndx].file_off)))
		return 0;
	return fo;
}

/* Does this symbol hold a pointer to a cleartext payload. */
static int pointer_variant(const struct scf *c, const struct kgenome_elf_symbol *s,
			   struct kofscfind *out)
{
	const struct kgenome_elf_info *e = c->e;
	uint32_t w = e->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u;
	uint64_t fo = sym_off(c, s, w, 1);
	uint64_t pv = 0, po, len, k;
	uint32_t i, npr = 0, top = 0, freq[256], sys = 0;

	if (!fo)
		return 0;
	for (k = 0; k < w; k++)
		pv |= (uint64_t)rd8(c, fo + k) << (8u * k);
	if (!pv)
		return 0;

	/* The section the address lands in, and it must not be code: without
	 * this the walk finds every function pointer in .data. */
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *sc = &e->sec[i];
		uint64_t osz = c->in->obj->obj_size;

		if (sc->type != SHT_PROGBITS_ || (sc->flags & SHF_EXECINSTR_))
			continue;
		if (pv < sc->mem_addr || pv >= sc->mem_addr + sc->file_size)
			continue;
		po = sc->file_off + (pv - sc->mem_addr);
		if (po >= osz)
			return 0;
		len = sc->file_off + sc->file_size - po;
		if (len > osz - po)
			len = osz - po;
		if (len > KOFSCFIND_SIZE_MAX)
			len = KOFSCFIND_SIZE_MAX;
		/* A `char *` initialiser is a string, so the payload ends where
		 * the compiler put its terminator. */
		for (k = 0; k < len; k++)
			if (rd8(c, po + k) == 0u) {
				len = k;
				break;
			}
		if (len < SCL_PTR_MIN)
			return 0;
		/*
		 * THE SAME QUESTION, ASKED OF THE POINTER. `fo` is where the
		 * pointer variable sits and `po` is what it points at, and it is
		 * the POINTER the code calls: the loader loads the variable and
		 * calls the register. Asking about the target would ask about an
		 * address the code never names.
		 */
		if (!xref_passes(xref_of(c, s->value, w)))
			return 0;
		for (k = 0; k < 256u; k++)
			freq[k] = 0;
		for (k = 0; k < len; k++) {
			uint8_t b = rd8(c, po + k);

			if (++freq[b] > top)
				top = freq[b];
			if (b < 0x20u || b >= 0x7fu)
				npr++;
			/* int 0x80, syscall, sysenter - the whole of how a
			 * payload on Linux reaches the kernel. WHICH one settles
			 * the width, and the width decides how it is
			 * disassembled: int 0x80 and sysenter are 32-bit,
			 * `syscall` is 64-bit. */
			if (k + 1u < len) {
				uint8_t d = rd8(c, po + k + 1u);

				if (b == 0xcdu && d == 0x80u)
					sys = 32u;
				else if (b == 0x0fu && d == 0x34u)
					sys = 32u;
				else if (b == 0x0fu && d == 0x05u)
					sys = 64u;
			}
		}
		if (npr * 100u < (uint32_t)len * SCL_NPR_PCT)
			return 0;
		if (top * SCL_TOP_DENOM >= (uint32_t)len)
			return 0;       /* a table, not a payload */
		if (!sys)
			return 0;
		out->at   = po;
		out->va   = pv;
		out->len  = len;
		out->bits = sys;
		decode(c, out);
		return 1;
	}
	return 0;
}

/* The inline variant: the blob is the symbol's own bytes. */
static int inline_variant(const struct scf *c, const struct kgenome_elf_symbol *s,
			  struct kofscfind *out)
{
	uint64_t sz = s->size, fo;
	uint32_t k, top = 0;
	uint32_t freq[256];

	if (sz < KOFSCFIND_SIZE_MIN || sz > KOFSCFIND_SIZE_MAX)
		return 0;
	/*
	 * PROGBITS, so the blob HAS bytes in the file: `char buffer[512]` is a
	 * GLOBAL OBJECT in a writable section too, and it lands in .bss with
	 * nothing behind it. sym_off checks the section, the value and the room.
	 */
	fo = sym_off(c, s, sz, 0);
	if (!fo)
		return 0;
	/*
	 * IS IT EXECUTED? The question the byte tests below cannot answer: they
	 * ask what the blob LOOKS like, and encoding the payload defeats every
	 * one of them. This asks what the CODE does with the variable, and no
	 * encoding of the data reaches the code. FIRST, because it is the
	 * cheapest and the most selective: a candidate it rejects has not paid
	 * a pass over its whole blob.
	 */
	if (!xref_passes(xref_of(c, s->value, sz)))
		return 0;
	for (k = 0; k < 256u; k++)
		freq[k] = 0;
	for (k = 0; k < (uint32_t)sz; k++) {
		uint8_t b = rd8(c, fo + k);

		if (++freq[b] > top)
			top = freq[b];
	}
	/* A byte that owns a quarter of the blob makes it a table, not a
	 * payload. */
	if (top * SCL_TOP_DENOM >= (uint32_t)sz)
		return 0;
	out->at   = fo;
	out->va   = s->value;
	out->len  = sz;
	out->bits = 0;                  /* nothing here said a width */
	decode(c, out);
	return 1;
}

enum kgenome_status kofscfind_run(const struct kofscfind_in *in,
				       struct kofscfind *out)
{
	struct scf c;
	const struct kgenome_elf_info *e;
	struct kgenome_elf_symtab t;
	kof_buf file;
	uint64_t i;
	uint32_t k, code = 0, data = 0;
	int interp = 0;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	if (!in || !in->obj || !in->data)
		return KGENOME_BAD_INPUT;
	if (in->obj->format != KGENOME_FMT_ELF || !in->obj->file_header)
		return KGENOME_UNSUPPORTED;
	e = kgenome_obj_elf(in->obj);
	if (!e->valid)
		return KGENOME_UNSUPPORTED;
	c.in = in;
	c.e = e;
	file = kof_buf_make(in->data, in->n);

	/*
	 * IT HAS TO BE A PROGRAM, not a library. PT_INTERP is the kernel being
	 * told which dynamic loader to run this with, so only something meant to
	 * be EXECUTED carries one. That is what separates a loader from the one
	 * clean file that otherwise matches everything below: frei0r's dither.so,
	 * a video plugin with 1831 bytes of code carrying nine dither matrices in
	 * .data - lookup tables in a library, the same shape as a payload in a
	 * program and a different thing. Found by scanning /usr/lib in full rather
	 * than the sample the first measurement used.
	 */
	for (k = 0; k < e->seg_count && k < KGENOME_ELF_MAX_SEGMENTS; k++)
		if (e->seg[k].type == PT_INTERP_)
			interp = 1;
	if (!interp)
		return KGENOME_OK;
	/*
	 * The shape of the file first: it is arithmetic over a table already
	 * parsed, it rejects 96% of what reaches here, and it costs nothing.
	 * THE RATIO IS THE FIRST ANCHOR, the ceiling second - the shape is "mostly
	 * data", and the ceiling is a guard on it rather than the thing looked for.
	 */
	for (k = 0; k < e->sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++) {
		if (e->sec[k].type != SHT_PROGBITS_)
			continue;
		if (e->sec[k].flags & SHF_EXECINSTR_)
			code += (uint32_t)e->sec[k].file_size;
		else if (e->sec[k].flags & SHF_WRITE_)
			data += (uint32_t)e->sec[k].file_size;
	}
	if (!code || (uint64_t)data * SCL_DATA_NUM < (uint64_t)code)
		return KGENOME_OK;
	if (code > SCL_CODE_MAX)
		return KGENOME_OK;

	/* The symbol table the file has: .symtab, or .dynsym when stripped. */
	if (!kgenome_elf_symtab_of(file, e, KGENOME_ELF_SYMTAB_BEST, &t) ||
	    !t.n_decl || !t.strn || t.str >= file.n)
		return KGENOME_OK;      /* stripped, or nothing to walk */

	/*
	 * EVERY RECORD, BACKWARDS from the last. The window used to be bounded by
	 * `_start` (where this toolchain emits a program's own globals: 63 records
	 * became 6 or 7) and the bound was not measurable - three interleaved runs
	 * over the corpus, 0.26/0.22/0.22 against 0.24/0.24/0.22 - while its cost
	 * was real: the order is the linker's, not the format's, so -nostartfiles
	 * put a global before `_start` and the payload was never looked at.
	 * Backwards decides WHICH candidate is reported when a file has more than
	 * one - the blob sits at the end of its section in twelve of twelve.
	 */
	for (i = t.n; i-- > 0; ) {
		struct kgenome_elf_symbol s;
		uint32_t shndx;
		uint64_t sec_flags;

		if (!kgenome_elf_symbol_at(file, &t, i, &s))
			continue;
		/* The attributes the symbol block spells as four bytes: a defined,
		 * sized, global, default-visibility OBJECT in a section that is
		 * writable and not executable. */
		if ((s.info & 0xfu) != STT_OBJECT_ || (s.info >> 4) != STB_GLOBAL_ ||
		    (s.other & 0x3u) != 0u || !s.size)
			continue;
		shndx = s.shndx;
		if (!shndx || shndx >= e->sec_count || shndx >= KGENOME_ELF_MAX_SECTIONS)
			continue;
		sec_flags = e->sec[shndx].flags;
		if (!(sec_flags & SHF_WRITE_) || (sec_flags & SHF_EXECINSTR_))
			continue;

		if (s.size == (e->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u) &&
		    e->elf_data == KGENOME_ELFDATA_LE) {
			/* A pointer, followed once. Only little-endian, because
			 * reading an address the wrong way round yields a number
			 * that lands nowhere and the walk would look like it had
			 * simply found nothing. */
			if (pointer_variant(&c, &s, out)) {
				out->found = 1;
				return KGENOME_OK;
			}
			continue;
		}
		if (inline_variant(&c, &s, out)) {
			out->found = 1;
			return KGENOME_OK;
		}
	}
	return KGENOME_OK;
}

/*
 * ---- THE SWEEP: how the code refers to a data address ----------------------
 *
 * One linear decode of every executable section, fed to the genome's xref map.
 * The startup code (the entry, .init_array, every executable section that is not
 * .text) is named to the map first, as the map asks, so what only the compiler's
 * own code mentions is not mistaken for the author's.
 */
struct sweep {
	struct kgenome_xref *map;
	int cut;
	/* The sweep is made on the first question, not before the search: nearly
	 * every object is turned away by the shape of its section table, and an
	 * examiner that decoded all the code of every ELF it opens to answer
	 * nothing would pay for the whole object on each open. */
	const struct kgenome_obj *obj;
	const uint8_t *data;
	uint64_t n;
	int built;
};

static uint32_t sweep_ask(void *user, uint64_t va, uint64_t size)
{
	struct sweep *w = user;
	uint32_t f, part;

	if (!w->built) {
		w->built = 1;
		/* The reference map of the object's own code is the library's (kgenome_range_xref_build); the examiner only asks it. */
		w->cut = kgenome_range_xref_build(w->obj, kof_buf_make(w->data, w->n), NULL, &w->map) != KGENOME_OK;
	}
	if (!w->map)
		return KGENOME_XREF_PARTIAL;
	f = kgenome_xref_in(w->map, va, size);
	part = (kgenome_xref_full(w->map) || w->cut) ? KGENOME_XREF_PARTIAL : 0u;

	return f ? f | part : part;
}

static uint32_t unswept_ask(void *user, uint64_t va, uint64_t size)
{
	(void)user; (void)va; (void)size;
	return KGENOME_XREF_PARTIAL;
}

enum kgenome_status kofscfind_find(const struct kgenome_obj *obj,
				   const uint8_t *data, uint64_t n,
				   struct kofscfind *out)
{
	struct kofscfind_in in;
	struct sweep w;
	enum kgenome_status st;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	if (!obj || !data)
		return KGENOME_BAD_INPUT;
	if (obj->format != KGENOME_FMT_ELF || !obj->file_header)
		return KGENOME_UNSUPPORTED;
	memset(&w, 0, sizeof w);
	in.obj = obj;
	in.data = data;
	in.n = n;
	in.xref_user = &w;
	if (obj->arch == KGENOME_ARCH_X86 || obj->arch == KGENOME_ARCH_X86_64) {
		w.obj = obj;
		w.data = data;
		w.n = n;
		in.xref = sweep_ask;
	} else {
		in.xref = unswept_ask;
	}
	st = kofscfind_run(&in, out);
	kgenome_xref_free(w.map);
	return st;
}

/* ---- the list of where shellcode could sit ------------------------------------------------------------------ */

#define SHF_ALLOC_      0x2u
#define SHT_NOBITS_     8u
#define ET_REL_         1u
#define PE_CNT_CODE_    0x20u

struct lst {
	const struct kofscfind_list_in *in;
	struct kofscfind_list_res      *res;
};

static void lst_name(char *out, size_t cap, const char *s, size_t smax, const char *suffix)
{
	size_t n = 0;

	for (; n + 1u < cap && n < smax && s[n]; n++)
		out[n] = ((unsigned char)s[n] < 0x20u || (unsigned char)s[n] == 0x7fu) ? '?' : s[n];
	out[n] = 0;
	if (suffix && n + 1u < cap)
		snprintf(out + n, cap - n, "%s", suffix);
}

static struct kofscfind_row *lst_row(struct lst *l, enum kofscfind_what what)
{
	struct kofscfind_row *r;

	l->res->total++;
	if (l->res->n >= l->in->cap || !l->in->out)
		return NULL;
	r = &l->in->out[l->res->n++];
	memset(r, 0, sizeof *r);
	r->what = what;
	r->off = KGENOME_NA;
	r->seq = l->res->total;
	return r;
}

static uint32_t perm_of_flags(uint64_t f)
{
	return ((f & SHF_ALLOC_) ? KGENOME_PERM_R : 0u) | ((f & SHF_WRITE_) ? KGENOME_PERM_W : 0u) |
	       ((f & SHF_EXECINSTR_) ? KGENOME_PERM_X : 0u);
}

/* The memory of a variable symbol, when it is executable: its file offset and permission. 0 when it is not. */
static int sym_exec(const struct kgenome_elf_info *e, uint64_t size, const struct kgenome_elf_symbol *s,
		    uint64_t *va, uint64_t *off, uint32_t *perm)
{
	if (!s->shndx || s->shndx >= 0xff00u || !s->size)
		return 0;
	if (e->e_type == ET_REL_) {
		const struct kgenome_elf_sec *c;

		if (s->shndx >= e->sec_count || s->shndx >= KGENOME_ELF_MAX_SECTIONS)
			return 0;
		c = &e->sec[s->shndx];
		if (!(c->flags & SHF_EXECINSTR_) || c->type == SHT_NOBITS_ || c->file_off > size ||
		    s->value > size - c->file_off ||
		    s->size > size - c->file_off - s->value)
			return 0;
		*va = c->mem_addr + s->value;
		*off = c->file_off + s->value;
		*perm = perm_of_flags(c->flags);
		return 1;
	} else {
		const struct kgenome_elf_seg *g;

		/* the segment's file half may be declared past the end of a damaged object: the bytes are not all there */
		if (!kgenome_elf_va_to_off(e, s->value, s->size, off) || *off > size || s->size > size - *off)
			return 0;
		g = kgenome_elf_load_at_off(e, *off);
		if (!g || !(g->perm & KGENOME_PERM_X))
			return 0;
		*va = s->value;
		*perm = g->perm;
		return 1;
	}
}

static void lst_symbols(struct lst *l, const struct kgenome_elf_info *e)
{
	struct kgenome_elf_symtab t;
	uint64_t i;

	if (!kgenome_elf_symtab_of(l->in->file, e, KGENOME_ELF_SYMTAB_BEST, &t))
		return;
	for (i = 0; i < t.n; i++) {
		struct kgenome_elf_symbol s;
		struct kofscfind_row *r;
		uint64_t va, off;
		uint32_t perm;
		char nm[KOFSCFIND_ROW_NAME];

		if (!kgenome_elf_symbol_at(l->in->file, &t, i, &s) || (s.info & 0xfu) != STT_OBJECT_ ||
		    !sym_exec(e, l->in->file.n, &s, &va, &off, &perm))
			continue;
		if (l->in->payload_len && va == l->in->payload_va)
			continue;       /* the finder's own row says it */
		nm[0] = 0;
		if (t.strn && s.nameoff < t.strn && kof_in_range(l->in->file, t.str, t.strn)) {
			uint64_t room = t.strn - s.nameoff, at = t.str + s.nameoff;

			if (room > l->in->file.n - at)
				room = l->in->file.n - at;
			lst_name(nm, sizeof nm, (const char *)l->in->file.p + at, (size_t)room, NULL);
		}
		r = lst_row(l, KOFSCFIND_W_SYMBOL);
		if (!r)
			continue;
		snprintf(r->name, sizeof r->name, "%s", nm[0] ? nm : "unnamed");
		r->va = va;
		r->off = off;
		r->size = s.size;
		r->perm = perm;
	}
}

static void lst_range(struct lst *l, const char *name, size_t nmax, const char *why, uint64_t va, uint64_t off, uint64_t size,
		      uint32_t perm)
{
	struct kofscfind_row *r = lst_row(l, KOFSCFIND_W_RANGE);

	if (!r)
		return;
	lst_name(r->name, sizeof r->name, name, nmax, why);
	r->va = va;
	r->off = off;
	r->size = size;
	r->perm = perm;
}

static void lst_elf_ranges(struct lst *l, const struct kgenome_elf_info *e)
{
	uint32_t i;
	char tag[32];

	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		const struct kgenome_elf_seg *g = &e->seg[i];

		if (kgenome_elf_seg_is_load(g) && (g->perm & KGENOME_PERM_X) && (g->perm & KGENOME_PERM_W)) {
			uint64_t n = kof_clip_len(l->in->file.n, g->file_off, g->file_size);

			snprintf(tag, sizeof tag, "segment #%u", i);
			lst_range(l, tag, sizeof tag, " (writable and executable)", g->mem_addr, n ? g->file_off : KGENOME_NA,
				  n ? n : g->mem_size, g->perm);
		}
	}
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];
		const struct kgenome_elf_seg *g;
		uint64_t n = kof_clip_len(l->in->file.n, s->file_off, s->file_size);

		if (s->type == SHT_NOBITS_ || !n)
			continue;
		if ((s->flags & SHF_EXECINSTR_) && (s->flags & SHF_WRITE_))
			lst_range(l, s->name, sizeof s->name, " (writable code section)", s->mem_addr, s->file_off, n,
				  perm_of_flags(s->flags));
		else if ((s->flags & SHF_ALLOC_) && !(s->flags & SHF_EXECINSTR_) && e->e_type != ET_REL_ &&
			 (g = kgenome_elf_load_at_off(e, s->file_off)) != NULL && (g->perm & KGENOME_PERM_X))
			lst_range(l, s->name, sizeof s->name, " (data in an executable segment)", s->mem_addr, s->file_off, n,
				  g->perm);
	}
}

static void lst_pe_ranges(struct lst *l, const struct kgenome_pe_info *p)
{
	uint32_t i;

	for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &p->sec[i];
		uint64_t n = kof_clip_len(l->in->file.n, s->file_off, s->file_size);

		if (!(s->perm & KGENOME_PE_PERM_X))
			continue;
		if (s->perm & KGENOME_PE_PERM_W)
			lst_range(l, s->name, sizeof s->name, " (writable and executable section)", s->mem_rva,
				  n ? s->file_off : KGENOME_NA, n ? n : s->mem_size, s->perm);
		else if (!(s->characteristics & PE_CNT_CODE_))
			lst_range(l, s->name, sizeof s->name, " (data section with execute permission)", s->mem_rva,
				  n ? s->file_off : KGENOME_NA, n ? n : s->mem_size, s->perm);
	}
}

/*
 * THE RULE FOR `strong`, which is this tool's and not the library's: some CODE of the object REFERS to the range (an instruction
 * counted by the library: a call, a jump, an address taken, a store, an argument; a pointer in a data table is a reference too
 * but not code's, and measured alone it is common - 40 words of an ARM binary's data point into its own .rodata), AND the range
 * DECODES AS CODE (the library's shape is code-like: nearly all of it is instructions of the object's architecture) AND it holds
 * a system-call instruction. Each part alone is common in an ordinary program (a function is referenced and decodes; a table is
 * referenced; a byte string may hold 0f 05); all three together are what a loader's payload is. The finder's own answer is
 * strong by itself. It is a rule about evidence, not a verdict: a flagged row is a row to read first.
 */
static int is_strong(const struct kofscfind_row *r)
{
	const struct kgenome_range_facts *f = &r->facts;
	uint32_t refs = f->refs.call + f->refs.jump + f->refs.read + f->refs.write + f->refs.arg;

	return r->facts_ok && f->refs_known && refs && f->shape == KGENOME_RANGE_CODE_LIKE && f->syscall;
}

/* 0: flagged, 1: some evidence (referenced, or code-like with a system call), 2: a candidate with none. */
static unsigned lst_group(const struct kofscfind_row *r)
{
	const struct kgenome_range_facts *f = &r->facts;

	if (r->flagged)
		return 0;
	if (r->facts_ok && (f->refs.call + f->refs.jump + f->refs.read + f->refs.write + f->refs.arg + f->refs_ptr ||
			    (f->shape == KGENOME_RANGE_CODE_LIKE && f->syscall)))
		return 1;
	return 2;
}

static int lst_cmp(const void *pa, const void *pb)
{
	const struct kofscfind_row *a = pa, *b = pb;
	unsigned ga = lst_group(a), gb = lst_group(b);

	if (ga != gb)
		return ga < gb ? -1 : 1;
	if (a->va != b->va)
		return a->va < b->va ? -1 : 1;
	return a->seq < b->seq ? -1 : a->seq > b->seq;
}

/* Ask the library about every candidate once, apply the rule, and put the rows with evidence first. */
static void lst_context(struct lst *l)
{
	const struct kofscfind_list_in *in = l->in;
	struct kgenome_budget bud;
	struct kgenome_xref *map = NULL;
	enum kgenome_status xs;
	uint32_t i;
	uint64_t base = 0;

	if (!in->out || !in->obj || !in->obj->file_header)
		return;
	memset(&bud, 0, sizeof bud);
	bud.max_steps = KOFSCFIND_LIST_CODE_MAX;
	xs = kgenome_range_xref_build(in->obj, in->file, &bud, &map);
	if (in->obj->format == KGENOME_FMT_PE)
		base = kgenome_obj_pe(in->obj)->image_base;
	for (i = 0; i < l->res->n; i++) {
		struct kofscfind_row *r = &in->out[i];
		struct kgenome_range_req rq;

		if (r->off == KGENOME_NA || !r->size)
			continue;
		memset(&rq, 0, sizeof rq);
		rq.obj = in->obj;
		rq.file = in->file;
		rq.off = r->off;
		rq.size = r->size;
		rq.va = r->va + base;
		rq.xref = map;
		rq.xref_status = xs;
		(void)kgenome_range_facts(&rq, &r->facts);       /* a cut is in facts.analysed < size: the list status is about rows */
		r->facts_ok = r->facts.analysed != 0;
		if (is_strong(r)) {
			r->strong = 1;
			r->flagged = 1;
		}
	}
	kgenome_xref_free(map);
	qsort(in->out, l->res->n, sizeof *in->out, lst_cmp);
}

enum kgenome_status kofscfind_list(const struct kofscfind_list_in *in, struct kofscfind_list_res *res)
{
	struct lst l;
	enum kgenome_status st = KGENOME_OK;
	const struct kgenome_obj *o = in->obj;

	memset(res, 0, sizeof *res);
	l.in = in;
	l.res = res;
	if (in->payload_len) {
		struct kofscfind_row *r = lst_row(&l, KOFSCFIND_W_FINDER);

		if (r) {
			const struct kgenome_elf_seg *g = NULL;
			uint64_t off = KGENOME_NA, fo;

			if (o && o->format == KGENOME_FMT_ELF && o->file_header && kgenome_obj_elf(o)->valid &&
			    kgenome_elf_va_to_off(kgenome_obj_elf(o), in->payload_va, in->payload_len, &fo) && fo <= in->file.n &&
			    in->payload_len <= in->file.n - fo) {
				off = fo;
				g = kgenome_elf_load_at_off(kgenome_obj_elf(o), fo);
			}
			snprintf(r->name, sizeof r->name, "%s", "payload");
			r->va = in->payload_va;
			r->off = off;
			r->size = in->payload_len;
			r->perm = g ? g->perm : 0u;
			r->flagged = 1;
			r->bits = in->payload_bits;
			if (in->payload_bits)
				snprintf(r->verdict, sizeof r->verdict, "shellcode-like payload, %u-bit", in->payload_bits);
			else
				snprintf(r->verdict, sizeof r->verdict, "%s", "shellcode-like payload");
		}
	}
	if (o && o->file_header && o->format == KGENOME_FMT_ELF && kgenome_obj_elf(o)->valid) {
		lst_symbols(&l, kgenome_obj_elf(o));
		lst_elf_ranges(&l, kgenome_obj_elf(o));
	} else if (o && o->file_header && o->format == KGENOME_FMT_PE && kgenome_obj_pe(o)->valid) {
		lst_pe_ranges(&l, kgenome_obj_pe(o));
	} else {
		st = KGENOME_UNSUPPORTED;
	}
	if (st == KGENOME_OK)
		lst_context(&l);
	if (res->total > res->n && st == KGENOME_OK)
		st = KGENOME_TRUNCATED;
	return st;
}

/* ---- the payload as an object ------------------------------------------------ */

#define LOAD_BASE_  0x400000ull

uint64_t kofscfind_image(const struct kofscfind *f, const uint8_t *data,
			 uint64_t n, int parent_is64, uint8_t *out,
			 uint64_t cap)
{
	struct kgenome_sec_decl sec;
	const uint8_t *src;
	uint64_t len;
	int is64;

	if (!f || !f->found || !data || !out)
		return 0;
	/* The decoded bytes when the loader keeps the payload encoded, else the
	 * bytes where they sit - in both cases the payload and not the text. */
	if (f->dec_n) {
		src = f->dec;
		len = f->dec_n;
	} else {
		if (f->at > n || f->len > n - f->at)
			return 0;
		src = data + f->at;
		len = f->len;
	}
	if (!len || len > KOFSCFIND_SIZE_MAX ||
	    KOFSCFIND_HDR_ROOM + len > cap)
		return 0;
	is64 = f->bits ? f->bits == 64u : parent_is64;

	memset(&sec, 0, sizeof sec);
	memcpy(sec.name, ".payload", 8);
	sec.rva = KOFSCFIND_HDR_ROOM;
	sec.vsize = len;
	sec.perm = KGENOME_PE_PERM_R | KGENOME_PE_PERM_W | KGENOME_PE_PERM_X;
	memset(out, 0, (size_t)(KOFSCFIND_HDR_ROOM + len));
	if (!kgenome_elf_write_hdr(out, KOFSCFIND_HDR_ROOM, is64,
				   is64 ? 62u : 3u, LOAD_BASE_, &sec, 1, 0, 0,
				   KOFSCFIND_HDR_ROOM + len))
		return 0;
	memcpy(out + KOFSCFIND_HDR_ROOM, src, (size_t)len);
	return KOFSCFIND_HDR_ROOM + len;
}
