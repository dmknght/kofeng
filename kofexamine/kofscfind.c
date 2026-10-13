/*
 * kofscfind.c - see kofscfind.h. The measurements behind each threshold were taken on
 * the corpora named beside it and are kept with the number they justify.
 */
#include <stdint.h>
#include <string.h>

#include <genotype/image/obj.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/elf_rebuild.h>
#include <genotype/image/pe_rebuild.h>
#include <kofcore.h>

#include <celllysis/celllysis.h>
#include <celllysis/xref.h>

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

static void sweep_startup(struct sweep *w, const struct kgenome_elf_info *e,
			  const uint8_t *data, uint64_t n)
{
	uint32_t i, wd = e->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u;

	if (e->entry_addr)
		kgenome_xref_startup(w->map, e->entry_addr);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *sec = &e->sec[i];
		uint64_t k, have;

		if (kgenome_elf_sec_is_code(sec) && strcmp(sec->name, ".text") != 0)
			kgenome_xref_startup(w->map, sec->mem_addr);
		if (sec->type != 14u && sec->type != 15u)
			continue;           /* INIT_ARRAY, FINI_ARRAY */
		have = kof_clip_len(n, sec->file_off, sec->file_size);
		for (k = 0; k + wd <= have; k += wd) {
			uint64_t v = 0, j;

			for (j = 0; j < wd; j++)
				v |= (uint64_t)data[sec->file_off + k + j] << (8u * j);
			if (!kgenome_xref_startup(w->map, v))
				break;
		}
	}
}

static void sweep_build(struct sweep *w, const struct kgenome_obj *obj,
			const uint8_t *data, uint64_t n)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	uint32_t i, left = KGENOME_XREF_MAX;
	uint64_t total = 0;

	w->map = kgenome_xref_new();
	if (!w->map)
		return;
	sweep_startup(w, e, data, n);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *sec = &e->sec[i];
		uint64_t at, have, pos, end;

		if (!kgenome_elf_sec_is_code(sec))
			continue;
		have = kgenome_elf_sec_extent(sec, n, &at);
		if (!have)
			continue;
		total += have;
		if (have > left) {
			have = left;
			w->cut = 1;
		}
		left -= (uint32_t)have;
		kgenome_xref_begin(w->map, obj->arch);
		for (pos = at, end = at + have; pos < end; ) {
			struct kgenome_cell_insn ci;
			uint64_t rem = end - pos;
			uint32_t len = kgenome_cell_decode(obj->arch, 0, data + pos,
							   rem > UINT32_MAX ? UINT32_MAX : (uint32_t)rem,
							   sec->mem_addr + (pos - at), &ci);

			if (len) {
				ci.at = pos;
				kgenome_xref_feed(w->map, &ci);
				pos += len;
			} else {
				kgenome_xref_feed(w->map, NULL);  /* data in the code */
				pos++;
			}
		}
	}
	if (total > KGENOME_XREF_MAX)
		w->cut = 1;
}

static uint32_t sweep_ask(void *user, uint64_t va, uint64_t size)
{
	struct sweep *w = user;
	uint32_t f, part;

	if (!w->built) {
		w->built = 1;
		sweep_build(w, w->obj, w->data, w->n);
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
