/*
 * pe_rebuild.c - put an unpacked PE image back into the shape of a file.
 *
 * Three steps: find the header the packer kept, work out where each section's bytes
 * are in the image, and write a file with those bytes at the offsets the header
 * says they belong at. The first step is the only one with any judgement in it.
 *
 *
 * FINDING THE HEADER
 *
 * There is no offset to read and no marker to trust: UPX puts the original header
 * near the end of the image, another packer would put it somewhere else, and a
 * hostile file can put the four bytes "PE\0\0" wherever it likes. So every
 * occurrence is tried and each is accepted only if what follows it is a header that
 * could be true - a machine this format defines, a section count in range, an
 * optional header of a size that matches its own magic, and a section table that
 * fits in the image.
 *
 * Measured on unpacked UPX output: three occurrences of the signature per image,
 * two of them inside compressed-looking data with a section count of 3001 and 53811
 * and an optional header magic of 0x0040. One passes. That is the whole reason the
 * check is a list of conditions rather than a search for bytes.
 *
 *
 * WHERE THE BYTES ARE
 *
 * The image is what the loader would have had, starting at the first section's
 * virtual address: image[x] is RVA (first + x). So a section's bytes begin at
 * (VirtualAddress - first) and there is nothing to search for. Confirmed against
 * real output rather than assumed - .rdata at its computed offset held the strings
 * a .rdata holds, and .text at offset zero held code.
 *
 *
 * WHAT IS BOUNDED, AND WHY EACH
 *
 * Every number below comes from a header inside a file that was compressed by
 * somebody who chose what to compress:
 *
 *   - the section count and the optional header size decide how much is read, so
 *     they are checked against the image before anything is read through them.
 *   - PointerToRawData and SizeOfRawData decide where bytes are WRITTEN in the
 *     output, so the output size is computed from them with saturating arithmetic
 *     and refused if it exceeds what the caller allowed.
 *   - a section whose bytes are not entirely inside the image is written short
 *     rather than refused: an image cut off by a budget is the ordinary case, and
 *     what is there is still worth scanning.
 */

#include <stdio.h>
#include <stdlib.h>
#include <kofmod/pe.h>
#include "pe_rebuild.h"

#include <stdlib.h>
#include <string.h>

/*
 * The signature sits in front of the COFF header, and forgetting it is a four byte
 * error that does not look like one.
 *
 * `hdr` points at "PE\0\0", so the COFF header begins at hdr + SIG_LEN and the
 * section table at hdr + SIG_LEN + COFF_LEN + optsz. Written without the signature
 * once, every section field was read four bytes early: the header copied out was
 * still correct - it is copied from hdr directly - so the rebuilt file identified
 * as PE, parsed, and reported sane sections, while the section CONTENT was placed
 * from garbage offsets. A wrong answer that passes every cheap check is the reason
 * the test below compares bytes rather than verdicts.
 */
#define SIG_LEN          4u
#define COFF_LEN        20u
#define SEC_LEN         40u
#define MAX_SECTIONS   96u      /* the loader's own limit */
#define MIN_OPT_LEN     96u
#define DOS_LEN        0x40u    /* the MZ stub this writes: header and nothing else */

/*
 * Is there a header here that could be true?
 *
 * Deliberately not "is this a valid PE" - the image holds a header for a file that
 * no longer exists and some of its fields describe a layout this code is about to
 * change. What is checked is only what has to hold for the rebuild to be bounded.
 */
static int header_plausible(kof_buf img, uint64_t at, uint16_t *nsec_out,
			    uint16_t *optsz_out)
{
	uint16_t machine, nsec, optsz, magic;

	if (!kof_rd_u16(img, at + SIG_LEN + 0, 0, &machine) ||
	    !kof_rd_u16(img, at + SIG_LEN + 2, 0, &nsec) ||
	    !kof_rd_u16(img, at + SIG_LEN + 16, 0, &optsz))
		return 0;
	if (nsec == 0 || nsec > MAX_SECTIONS)
		return 0;
	if (optsz < MIN_OPT_LEN)
		return 0;
	if (!kof_rd_u16(img, at + SIG_LEN + COFF_LEN, 0, &magic))
		return 0;
	/* 0x10b is PE32 and 0x20b is PE32+; anything else is not an optional
	 * header, whatever the bytes before it said. */
	if (magic != 0x010bu && magic != 0x020bu)
		return 0;
	/* Machine 0 is legal in an object file and never in an image. */
	if (machine == 0)
		return 0;
	/* The section table has to be inside the image, or there is nothing to
	 * rebuild from. */
	if (!kof_in_range(img, at + SIG_LEN + COFF_LEN + optsz,
			  (uint64_t)nsec * SEC_LEN))
		return 0;

	*nsec_out = nsec;
	*optsz_out = optsz;
	return 1;
}




/* ---- a header written from a declaration - see pe_rebuild.h ---------------- */

#define PW_PAGE 0x1000u

static void pw_put16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void pw_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void pw_put64(uint8_t *p, uint64_t v)
{
	pw_put32(p, (uint32_t)v);
	pw_put32(p + 4, (uint32_t)(v >> 32));
}

/*
 * The characteristics a declaration implies.
 *
 * READ is forced on for the reason the old hand-written version forced it: a
 * section this child holds bytes for is one a reader may look at, whatever the
 * original said. CNT_CODE and MEM_EXECUTE come from KOF_SECF_CODE rather than
 * from the permissions, because the declaration is what the module MEANT and
 * the permissions are what it copied.
 */
static uint32_t pw_chars(const struct kof_sec_decl *d)
{
	uint32_t c = 0x40000000u;               /* MEM_READ */

	if (d->flags & KOF_SECF_CODE)
		c |= 0x00000020u | 0x20000000u; /* CNT_CODE | MEM_EXECUTE */
	else
		c |= 0x00000040u;               /* CNT_INITIALIZED_DATA */
	if (d->perm & KOF_PE_PERM_W)
		c |= 0x80000000u;
	if (d->perm & KOF_PE_PERM_X)
		c |= 0x20000000u;
	/*
	 * HOLLOW SURVIVES, WHICH IS THE WHOLE REASON THIS FUNCTION EXISTS.
	 *
	 * A section declared with no bytes behind it gets the uninitialised
	 * flag and, below, SizeOfRawData zero. Written the old way it could not:
	 * the header had to claim the span or the file would not read back, so
	 * VMProtect's destinations stopped looking hollow the moment an outer
	 * unpacker had rebuilt the image, and the module had to anchor on a
	 * coincidence in the data instead.
	 */
	if (d->flags & KOF_SECF_HOLLOW)
		c |= 0x00000080u;               /* CNT_UNINITIALIZED_DATA */
	return c;
}

uint64_t kof_pe_write_hdr(uint8_t *out, uint64_t cap,
			  const struct kof_pe_info *tmpl,
			  const struct kof_sec_decl *sec, uint32_t n,
			  uint64_t entry_rva, uint64_t image_end,
			  const struct kof_dir_decl *dir)
{
	unsigned pe_off = 0x80u, opt, nrva, sec_at;
	uint64_t need;
	uint8_t *o;
	uint32_t i, nw, w;
	int plus;

	if (!out || !sec || !n || !tmpl)
		return 0;
	plus = tmpl->pe32_plus ? 1 : 0;
	opt    = plus ? 0xf0u : 0xe0u;
	nrva   = plus ? 108u : 92u;
	sec_at = pe_off + 24u + opt;
	/*
	 * PADDING IS NOT A SECTION AND IS NOT WRITTEN AS ONE.
	 *
	 * Alignment fill belongs to nothing: counted as part of the section in
	 * front of it, the region partition hands it to DATA, and on one sample
	 * that was 3972 bytes of pure zero reported as data. Left out of the
	 * table entirely it falls to UNCLAIMED, which is what it is. The bytes
	 * stay where they are - only the claim on them goes.
	 */
	for (i = 0, nw = 0; i < n; i++)
		if (!(sec[i].flags & KOF_SECF_PAD))
			nw++;
	if (!nw)
		return 0;
	need = (uint64_t)sec_at + (uint64_t)nw * 40u;
	if (need > cap)
		return 0;                       /* no room in front of the
						 * content: say so */
	memset(out, 0, (size_t)cap);

	out[0] = 'M'; out[1] = 'Z';
	pw_put32(out + 0x3c, pe_off);
	out[pe_off] = 'P'; out[pe_off + 1u] = 'E';
	pw_put16(out + pe_off + 4u, tmpl->machine);
	pw_put16(out + pe_off + 6u, nw);
	pw_put16(out + pe_off + 20u, opt);
	pw_put16(out + pe_off + 22u, plus ? 0x0022u : 0x0102u);

	o = out + pe_off + 24u;
	pw_put16(o, plus ? 0x020bu : 0x010bu);
	pw_put32(o + 16u, (uint32_t)entry_rva);
	for (i = 0; i < n && (sec[i].flags & KOF_SECF_PAD); i++)
		;
	pw_put32(o + 20u, (uint32_t)(i < n ? sec[i].rva : sec[0].rva));
	if (plus) {
		pw_put64(o + 24u, tmpl->image_base);
	} else {
		pw_put32(o + 24u, 0);
		pw_put32(o + 28u, (uint32_t)tmpl->image_base);
	}
	pw_put32(o + 32u, PW_PAGE);                     /* SectionAlignment */
	pw_put32(o + 36u, PW_PAGE);                     /* FileAlignment */
	pw_put16(o + 40u, 6u);
	pw_put16(o + 48u, 6u);
	pw_put32(o + 56u, (uint32_t)image_end);         /* SizeOfImage */
	pw_put32(o + 60u, (uint32_t)sec[0].rva);        /* SizeOfHeaders */
	pw_put16(o + 68u, tmpl->subsystem);
	pw_put16(o + 70u, tmpl->dll_characteristics);
	pw_put32(o + nrva, 16u);

	/*
	 * The directories the parent declared, carried where they still point
	 * at something. Sections keep their virtual addresses here, so a
	 * directory RVA means the same in the child as in the parent.
	 *
	 * Three are dropped and each for its own reason: IMPORT because a
	 * module may have rebuilt it and will say so itself; SECURITY because
	 * its "RVA" is a file offset into the original, which this child does
	 * not reproduce; BASERELOC because the packer applied the original
	 * relocations and threw the table away, so what the header names is the
	 * stub's own and is wrong once unpacked.
	 */
	{
		unsigned ddir = pe_off + 24u + (plus ? 112u : 96u);
		unsigned di;

		/* Sixteen is what the header has room for; KOF_PE_DIR_COUNT is
		 * what the parse fills. They are the same today, and the
		 * smaller of the two is what may be read either way. */
		for (di = 0; di < (16u < KOF_PE_DIR_COUNT ? 16u
							 : KOF_PE_DIR_COUNT);
		     di++) {
			uint64_t rva = tmpl->dir[di].rva;
			uint32_t k;

			/* One the module rebuilt wins outright: it names an
			 * address in THIS child, and the parent's named one in
			 * a file laid out differently. */
			if (dir && dir[di].set) {
				pw_put32(out + ddir + di * 8u,
					 (uint32_t)dir[di].rva);
				pw_put32(out + ddir + di * 8u + 4u,
					 (uint32_t)dir[di].size);
				continue;
			}
			if (di == KOF_PE_DIR_IMPORT ||
			    di == KOF_PE_DIR_SECURITY ||
			    di == KOF_PE_DIR_BASERELOC)
				continue;
			if (!rva || !tmpl->dir[di].size)
				continue;
			for (k = 0; k < n; k++)
				if (rva >= sec[k].rva &&
				    rva < sec[k].rva + sec[k].vsize)
					break;
			if (k == n)
				continue;
			pw_put32(out + ddir + di * 8u, (uint32_t)rva);
			pw_put32(out + ddir + di * 8u + 4u,
				 (uint32_t)tmpl->dir[di].size);
		}
	}

	for (i = 0, w = 0; i < n; i++) {
		uint8_t *d;
		unsigned k;

		if (sec[i].flags & KOF_SECF_PAD)
			continue;
		d = out + sec_at + (uint64_t)w * 40u;
		w++;

		for (k = 0; k < 8u; k++)
			d[k] = (uint8_t)sec[i].name[k];
		pw_put32(d + 8u,  (uint32_t)sec[i].vsize);
		pw_put32(d + 12u, (uint32_t)sec[i].rva);
		/*
		 * SizeOfRawData, and the two things the old shape could not
		 * say. A hollow section claims no bytes; alignment padding is
		 * not part of any section and is simply not described here at
		 * all, so it falls to UNCLAIMED instead of being counted as
		 * DATA - which is what put 3972 NULL bytes into one sample's
		 * DATA region.
		 */
		if (sec[i].flags & KOF_SECF_HOLLOW) {
			pw_put32(d + 16u, 0);
			pw_put32(d + 20u, 0);
		} else {
			pw_put32(d + 16u, (uint32_t)sec[i].vsize);
			pw_put32(d + 20u, (uint32_t)sec[i].rva);
		}
		pw_put32(d + 36u, pw_chars(&sec[i]));
	}
	return need;
}


/*
 * ---- THE LAYOUT OF AN IMAGE, READ OUT OF IT -------------------------------
 *
 * The half of kof_pe_rebuild that is worth keeping, said as a declaration
 * instead of as a second buffer.
 *
 * A packer that hands back an IMAGE - UPX does - leaves the original header
 * somewhere inside it, and the section table in that header is the layout. The
 * old path found it, allocated a whole second buffer, and copied every section
 * into it so the engine could parse the result back. The bytes are already
 * where they belong: an image IS flat, so the only thing missing was somebody
 * to say what the ranges are.
 *
 * Fills `out` and returns how many it wrote, or 0 when the image carries no
 * plausible header. `entry` and `base` come from the same header.
 */
uint32_t kof_pe_layout_of(kof_buf img, struct kof_sec_decl *out, uint32_t cap,
			  uint64_t *entry, uint64_t *base,
			  struct kof_dir_decl *dir)
{
	uint64_t at, hdr = 0, sec_tab;
	uint16_t nsec = 0, optsz = 0;
	uint32_t i, n = 0;
	int found = 0;

	if (!img.p || !out || !cap)
		return 0;
	at = 0;
	while (at + 4 <= img.n) {
		const uint8_t *hit = memchr(img.p + at, 'P',
					    (size_t)(img.n - at - 3));

		if (!hit)
			break;
		at = (uint64_t)(hit - img.p);
		if (!memcmp(img.p + at, "PE\0\0", 4) &&
		    header_plausible(img, at, &nsec, &optsz)) {
			hdr = at;
			found = 1;
			break;
		}
		at++;
	}
	if (!found)
		return 0;
	sec_tab = hdr + SIG_LEN + COFF_LEN + optsz;

	if (entry) {
		uint32_t v = 0;

		kof_rd_u32(img, hdr + SIG_LEN + COFF_LEN + 16, 0, &v);
		*entry = v;
	}
	if (base) {
		uint16_t magic = 0;

		kof_rd_u16(img, hdr + SIG_LEN + COFF_LEN, 0, &magic);
		if (magic == 0x020bu) {
			uint32_t lo = 0, hi = 0;

			kof_rd_u32(img, hdr + SIG_LEN + COFF_LEN + 24, 0, &lo);
			kof_rd_u32(img, hdr + SIG_LEN + COFF_LEN + 28, 0, &hi);
			*base = ((uint64_t)hi << 32) | lo;
		} else {
			uint32_t v = 0;

			kof_rd_u32(img, hdr + SIG_LEN + COFF_LEN + 28, 0, &v);
			*base = v;
		}
	}

	/*
	 * AND THE DIRECTORIES, WHICH THE PARENT'S CANNOT STAND IN FOR.
	 *
	 * The engine carries over the directories of the object a child came
	 * out of, and for a packed file those name addresses in the PACKER's
	 * layout - UPX's own .rsrc, not the program's. The header found inside
	 * the image is the program's own and its directories are the ones that
	 * mean something here. Measured without this: a UPX child with a 13154
	 * byte .rsrc section reporting RESOURCE=0.
	 */
	if (dir) {
		uint16_t magic = 0;
		unsigned dd;
		uint32_t nrva = 0;

		kof_rd_u16(img, hdr + SIG_LEN + COFF_LEN, 0, &magic);
		dd = (unsigned)(hdr + SIG_LEN + COFF_LEN +
				(magic == 0x020bu ? 112u : 96u));
		kof_rd_u32(img, hdr + SIG_LEN + COFF_LEN +
			   (magic == 0x020bu ? 108u : 92u), 0, &nrva);
		if (nrva > 16u)
			nrva = 16u;
		for (i = 0; i < nrva; i++) {
			uint32_t rva = 0, size = 0;

			if (!kof_rd_u32(img, dd + (uint64_t)i * 8u, 0, &rva) ||
			    !kof_rd_u32(img, dd + (uint64_t)i * 8u + 4u, 0,
					&size))
				break;
			if (!rva || !size)
				continue;
			/* SECURITY's "RVA" is a file offset into a file this
			 * child is not, and BASERELOC names the packer's own
			 * table. Neither survives the move. */
			if (i == KOF_PE_DIR_SECURITY ||
			    i == KOF_PE_DIR_BASERELOC)
				continue;
			dir[i].rva = rva;
			dir[i].size = size;
			dir[i].set = 1;
		}
	}

	for (i = 0; i < nsec && n < cap; i++) {
		uint64_t e = sec_tab + (uint64_t)i * SEC_LEN;
		uint32_t vsz = 0, rva = 0, chars = 0;
		unsigned k;

		if (!kof_rd_u32(img, e + 8, 0, &vsz) ||
		    !kof_rd_u32(img, e + 12, 0, &rva) ||
		    !kof_rd_u32(img, e + 36, 0, &chars))
			break;
		if (!vsz || !rva)
			continue;
		/* The table is in address order in every image a loader will
		 * take, and the declaration has to be - so one that is not is
		 * where this stops rather than where it starts guessing. */
		if (n && rva < out[n - 1u].rva + out[n - 1u].vsize)
			break;
		for (k = 0; k < 8u; k++)
			out[n].name[k] = (char)img.p[e + k];
		out[n].name[8] = 0;
		out[n].rva = rva;
		out[n].vsize = vsz;
		out[n].perm = ((chars & 0x40000000u) ? KOF_PE_PERM_R : 0u) |
			      ((chars & 0x80000000u) ? KOF_PE_PERM_W : 0u) |
			      ((chars & 0x20000000u) ? KOF_PE_PERM_X : 0u);
		/*
		 * REBUILT, not READ. These ranges were recovered by
		 * decompressing a stub's output; the file on disk declared no
		 * such thing. A reader has to be able to tell the two apart.
		 */
		out[n].flags = ((chars & 0x20000000u) ? KOF_SECF_CODE
						      : KOF_SECF_DATA) |
			       KOF_SECF_REBUILT;
		n++;
	}
	return n;
}

/* ---- an import directory written from declarations ----------------------- */

/*
 * THE LAYOUT, and it is the one every PE uses, laid out in the one order that
 * makes a single pass possible:
 *
 *   base                    (nmod + 1) * 20   the descriptors, NUL terminated
 *   base + ilt              (nfn + nmod) * 4  the lookup entries, one run per
 *                                             descriptor, each NUL terminated
 *   base + str              the names          "kernel32.dll", then per function
 *                                             a 2-byte hint and the name
 *
 * A DESCRIPTOR PER RUN, NOT PER DISTINCT NAME - see `import` in kofsig.h. The
 * caller's order is the table's order, so a container walked in its own order
 * produces the table its own structure describes.
 *
 * The two functions below have to agree about every one of those numbers, so
 * the sizing one is written as the writing one with the stores left out rather
 * than as a formula: a formula is a second statement of the layout and the day
 * it disagrees is the day a table is written past the room reserved for it.
 */

#define PI_DESC 20u     /* sizeof IMAGE_IMPORT_DESCRIPTOR */

/* A pool string, bounded by the pool. NULL when the offset is not inside it or
 * the string does not end before the pool does. */
static const char *pi_str(const char *pool, uint64_t pool_n, uint32_t off)
{
	uint64_t k;

	if (!pool || off >= pool_n)
		return NULL;
	for (k = off; k < pool_n; k++)
		if (!pool[k])
			return pool + off;
	return NULL;
}

static uint64_t pi_len(const char *s)
{
	uint64_t n = 0;

	while (s[n])
		n++;
	return n;
}

/*
 * Walk the declarations once, counting or writing.
 *
 * `img` NULL counts; otherwise every store is bounded by `img_n` and the walk
 * gives up the moment one would not fit, which is why the caller checks the
 * size first and this checks again: the size is computed from the same pool,
 * but the image may be smaller than the layout the caller promised.
 */
static uint64_t pi_walk(uint8_t *img, uint64_t img_n, uint64_t base,
			const struct kof_imp_decl *imp, uint32_t n,
			const char *pool, uint64_t pool_n, int is64)
{
	/*
	 * A LOOKUP ENTRY AND A THUNK ARE POINTER SIZED, and on PE32+ that is
	 * eight bytes with the ordinal flag in bit 63.
	 *
	 * Written as four throughout, the table is self-consistent and no
	 * parser can read it: measured on a PE32+ Go binary, the engine wrote
	 * 150 entries and its own symbol reader came back with the file's ten
	 * exports and nothing else, because a reader stepping eight bytes at a
	 * time through four-byte entries sees the second half of the first
	 * entry as the whole of the second.
	 */
	const uint32_t step = is64 ? 8u : 4u;
	const uint64_t ord_flag = is64 ? 0x8000000000000000ull : 0x80000000ull;
	uint32_t i, nmod = 0, nfn = 0;
	uint64_t strn = 0, ilt, str, w_ilt, w_str;
	const char *prev = NULL;

	if (!imp || !n || !pool)
		return 0;

	/* ---- pass one: how many descriptors, how many entries, how much text */
	for (i = 0; i < n; i++) {
		const char *d = pi_str(pool, pool_n, imp[i].dll_off);

		if (!d || !*d)
			return 0;
		if (!prev || pi_len(d) != pi_len(prev) ||
		    memcmp(d, prev, (size_t)pi_len(d)) != 0) {
			nmod++;
			strn += pi_len(d) + 1u;
			prev = d;
		}
		if (!imp[i].ordinal) {
			const char *f = pi_str(pool, pool_n, imp[i].fn_off);

			if (!f || !*f)
				return 0;
			strn += 2u + pi_len(f) + 1u;   /* the hint, then the name */
		}
		nfn++;
	}

	ilt = (uint64_t)(nmod + 1u) * PI_DESC;
	str = ilt + ((uint64_t)nfn + nmod) * step;
	if (!img)
		return str + strn;

	/* ---- pass two: write it ---- */
	if (base > img_n || str + strn > img_n - base)
		return 0;
	/*
	 * THE TABLE MAY NOT SIT ON THE THUNKS IT FILLS, and this is refused
	 * rather than ordered around.
	 *
	 * A thunk inside [base, base + size) would be written twice - once as
	 * a slot and once as part of the table - and which survived would
	 * depend on which store came last, so the same declarations would
	 * produce different files depending on where in the table the slot
	 * landed. There is no useful reading of a caller that asks for it: the
	 * IAT belongs to the program and the table is somewhere the module
	 * reserved for it.
	 *
	 * Checked before the memset, so a refusal leaves the image untouched -
	 * which is what the caller relies on to hand the child over without
	 * imports instead of with half a table. imports_fuzz holds it to that.
	 */
	for (i = 0; i < n; i++)
		if (imp[i].iat_rva &&
		    imp[i].iat_rva + step > base &&
		    imp[i].iat_rva < base + str + strn)
			return 0;
	memset(img + base, 0, (size_t)(str + strn));

	w_ilt = ilt;
	w_str = str;
	prev = NULL;
	nmod = 0;
	for (i = 0; i < n; i++) {
		const char *d = pi_str(pool, pool_n, imp[i].dll_off);
		uint64_t ent;

		/*
		 * Checked again although pass one checked the same offsets
		 * against the same pool. Nothing can have changed between them
		 * - but nothing in this function SAYS so, and a walk that
		 * trusts an earlier pass is a walk that dereferences NULL the
		 * day the two stop being called in a pair.
		 */
		if (!d || !*d)
			return 0;
		if (!prev || pi_len(d) != pi_len(prev) ||
		    memcmp(d, prev, (size_t)pi_len(d)) != 0) {
			uint64_t desc;

			/*
			 * The run before this one ends with a null lookup
			 * entry, which is already zero from the memset - only
			 * the cursor has to step over it.
			 */
			if (prev)
				w_ilt += step;
			desc = base + (uint64_t)nmod * PI_DESC;
			memcpy(img + base + w_str, d, (size_t)pi_len(d) + 1u);
			pw_put32(img + desc + 0u,  (uint32_t)(base + w_ilt));
			pw_put32(img + desc + 12u, (uint32_t)(base + w_str));
			/*
			 * FirstThunk is the IAT, which is NOT part of this
			 * table: it is wherever the packer put the slots, and
			 * the caller told us per entry. The first entry of the
			 * run is where the run's IAT begins.
			 */
			pw_put32(img + desc + 16u, (uint32_t)imp[i].iat_rva);
			w_str += pi_len(d) + 1u;
			nmod++;
			prev = d;
		}

		if (imp[i].ordinal) {
			ent = ord_flag | imp[i].ordinal;
		} else {
			const char *f = pi_str(pool, pool_n, imp[i].fn_off);

			if (!f || !*f)
				return 0;
			ent = base + w_str;
			/* the two hint bytes stay zero: nothing declared one,
			 * and a hint is an optimisation a loader may ignore */
			memcpy(img + base + w_str + 2u, f,
			       (size_t)pi_len(f) + 1u);
			w_str += 2u + pi_len(f) + 1u;
		}
		if (is64)
			pw_put64(img + base + w_ilt, ent);
		else
			pw_put32(img + base + w_ilt, (uint32_t)ent);

		/*
		 * AND THE SAME VALUE INTO THE THUNK ITSELF.
		 *
		 * The slot is what the stub filled at run time and it is zero
		 * in what the module produced, so a reader of the file finds a
		 * directory pointing at an empty IAT. Before binding, a thunk
		 * holds its own lookup entry - that is what a loader writes
		 * there and what this engine's own IAT filler expects to find.
		 *
		 * Measured when mpress_pe.c did this by hand, against Avast's
		 * unpacked output of the same file: 1264 of 1265 pages already
		 * matched byte for byte, and the one that did not was this
		 * table.
		 */
		if (imp[i].iat_rva && imp[i].iat_rva + step <= img_n) {
			if (is64)
				pw_put64(img + imp[i].iat_rva, ent);
			else
				pw_put32(img + imp[i].iat_rva, (uint32_t)ent);
		}
		w_ilt += step;
	}
	return str + strn;
}

uint64_t kof_pe_imports_size(const struct kof_imp_decl *imp, uint32_t n,
			     const char *pool, uint64_t pool_n, int is64)
{
	return pi_walk(NULL, 0, 0, imp, n, pool, pool_n, is64);
}

uint64_t kof_pe_write_imports(uint8_t *img, uint64_t img_n, uint64_t base,
			      const struct kof_imp_decl *imp, uint32_t n,
			      const char *pool, uint64_t pool_n, int is64)
{
	if (!img)
		return 0;
	return pi_walk(img, img_n, base, imp, n, pool, pool_n, is64);
}
