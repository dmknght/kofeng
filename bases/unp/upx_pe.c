/*
 * upx_pe.c - unpack a UPX packed PE.
 *
 * The same packer as upx_elf.c and a far simpler job, which is worth saying
 * plainly because the two look alike from outside. UPX on ELF writes a chain of
 * independently compressed blocks with no count and no terminator; UPX on PE
 * writes ONE stream, and states its compressed and uncompressed lengths in a
 * header. Everything below follows from that.
 *
 * Measured on 400 UPX packed PE samples drawn from two collections: 389 carry a
 * coding this engine implements, and all 389 decode to exactly the length the
 * file declares, from exactly one place - immediately after the PackHeader. Not
 * "usually" and not "with a fallback": one rule, no exceptions in the sample,
 * which is why this module has no candidate offsets in it.
 *
 * That sentence used to name a different place - the start of the section the
 * entry point is in - and the two are the same number for most of the samples.
 * Where they are not is set out under WHERE THE STREAM IS, along with what
 * believing the weaker of the two cost.
 *
 *
 * WHERE THE STREAM IS, AND WHY NOT BY NAME
 *
 * The compressed data begins IMMEDIATELY AFTER THE PACKHEADER, wherever that is.
 * The section holding the entry point is how the PackHeader is found - every one
 * of those sections is called UPX1, and this does not look at the name, because a
 * section name is a string whoever built the file chose and pe.h says so where it
 * explains why CODE means IMAGE_SCN_MEM_EXECUTE and never ".text". The entry point
 * is what the loader acts on, so it is the fact rather than the label.
 *
 * Checked both ways over the samples: by name resolved 389, by entry point 388 of
 * a larger set that includes files with no UPX1 name at all. The difference is
 * noise; the reason to prefer the entry point is that renaming a section is free
 * and moving the entry point is not.
 *
 * THIS SAID "AT THE RAW OFFSET OF THAT SECTION", WHICH WAS TRUE OF EVERY SAMPLE
 * IT WAS MEASURED ON AND IS NOT A RULE.
 *
 * Over 31 UPX packed PEs in another collection the PackHeader sits 32 bytes
 * before the section in 20 of them - so it ENDS exactly where the section begins,
 * and "the section's offset" and "after the PackHeader" are the same number. In
 * three it sits five bytes INSIDE the section, behind a version string:
 *
 *     0x200  "3.96\0"
 *     0x205  "UPX!" + 32 bytes of PackHeader
 *     0x225  the LZMA stream
 *
 * Those three were not unpacked at all. The search was bounded above by the
 * section's offset, so a header five bytes past it was never found, this module
 * declined, and the emulator then spent its whole instruction ceiling on each -
 * 22.4, 22.3 and 22.2 seconds for three files that decode in milliseconds.
 *
 * One rule covers both arrangements, because it is the arrangement UPX actually
 * writes: the stream follows the header. Verified by decoding - all three of the
 * missed files and lolMiner.exe, which is one of the twenty the old rule already
 * handled, each produce exactly the length their PackHeader declares. The twenty
 * cannot change behaviour, since for them ph + PH_LEN IS the section's offset.
 *
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not reverse the CTO filter - the byte is right there in the header, at
 * offset 28, and 76% of the samples use 0x26. Strings and data come out correct
 * either way; hex patterns written over filtered code would not. Recorded here
 * rather than left for a pattern to fail on mysteriously.
 *
 * It does not rebuild the PE. The output is the original image as UPX compressed
 * it, which is enough to search and usually enough to identify, but its section
 * table and imports are not reconstructed. Whether that is worth doing is a
 * question for measurement - how many children fail to identify - not for
 * assumption.
 *
 * IT DOES HANDLE LZMA, and this said it did not - written when it was true and
 * left standing after upx_lzma_method was added below. Method 14 is 4 of the
 * 400 samples and it is also what all three of the files described above use,
 * so a reader checking whether this module could have unpacked them would have
 * been told by the documentation that it could not.
 *
 * What it does not handle is a coding this engine has no decoder for at all.
 * Those report incomplete rather than clean, which is the whole point of
 * saying so.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

#include <kofunpack/pe_reassemble.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_PE);

/*
 * The PackHeader's magic. Declared, so the host searches with the machinery it
 * already has and this module carries no scan loop.
 *
 * The first occurrence is the one wanted: UPX writes this header into the padding
 * ahead of the packed section, before any copy that may appear later.
 */
KOF_DEFINE_STR(upx_magic, "UPX!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

/*
 * ---- WHICH UPX, IN UPX'S OWN WORDS ----------------------------------------
 *
 * Two places, both in the file, and which one is there says which era the
 * build is from. Neither is inferred: an inferred version is a guess dressed
 * as a fact, and the l_version byte is a FORMAT number that would make a
 * tempting one - measured, adm_atu.exe carries l_version 12 and says 1.07 in
 * its own stub, while 445.exe carries 13 and says 3.94.
 *
 *   BEFORE THE MAGIC. The newer builds write the release as ASCII with a NUL
 *   after it, immediately in front of `UPX!`:
 *
 *       ... 00 00 c0 33 2e 39 36 00 55 50 58 21 0d 24 0e ...
 *                      3  .  9  6 \0  U  P  X  !
 *
 *       445.exe "3.94", 123.exe.1 "3.96". Read backwards from the magic,
 *       which is where it is anchored and where it costs no search.
 *
 *   THE $Id STRING. The older ones carry `$Id: UPX 1.07 Copyright (C)
 *   1996-2001 the UPX Team...` in the stub instead. adm_atu.exe is one.
 *
 * Neither present is an answer too - see `packer_build` in kofsig.h. RetDec
 * reads the same strings for the same reason; see THIRD-PARTY.md.
 */
KOF_DEFINE_STR(upx_id, "$Id: UPX ", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

#define UPX_ID_SKIP  9u         /* past "$Id: UPX " */
#define UPX_VER_MAX  10u        /* "3.96", "1.07" - never near this */

/* A release is digits and dots and nothing else. */
static int upx_ver_byte(uint8_t c)
{
	return c == '.' || (c >= '0' && c <= '9');
}

/*
 * The version written in front of the magic, into `out`, or 0.
 *
 * `magic_at` is where "UPX!" was found. The byte before it must be the NUL
 * that terminates the string, and what runs back from there is the release.
 */
static unsigned upx_ver_before(const struct kof_obj_ctx *ctx, uint64_t magic_at,
			       char *out)
{
	uint64_t start;
	unsigned n = 0;

	if (magic_at < 2u || !kof_in_obj(magic_at - 1u, 1u))
		return 0;
	if (kof_u8(magic_at - 1u) != 0)
		return 0;
	start = magic_at - 1u;
	while (start && n < UPX_VER_MAX &&
	       kof_in_obj(start - 1u, 1u) && upx_ver_byte(kof_u8(start - 1u))) {
		start--;
		n++;
	}
	/*
	 * A single digit is not a version - one zero byte followed by "0" and
	 * a NUL turns up in ordinary data - and neither is a run with no dot
	 * in it. Both are cheap to require and both were the difference
	 * between reading a release and reading padding.
	 */
	if (n < 3u)
		return 0;
	{
		unsigned k, dots = 0;

		for (k = 0; k < n; k++) {
			out[k] = (char)kof_u8(start + k);
			if (out[k] == '.')
				dots++;
		}
		if (!dots)
			return 0;
		out[n] = 0;
	}
	return n;
}

/*
 * Say which build this is, when the file says so. Quietly does nothing when it
 * does not - see `packer_build` in kofsig.h, where a missing version is an
 * answer and an invented one is not.
 */
static void upx_say_build(const struct kof_obj_ctx *ctx, uint64_t magic_at)
{
	char b[7u + UPX_VER_MAX + 1u];
	uint64_t at;
	unsigned k;

	b[0] = 'P'; b[1] = 'E'; b[2] = ':';
	b[3] = 'U'; b[4] = 'P'; b[5] = 'X'; b[6] = ' ';
	if (upx_ver_before(ctx, magic_at, b + 7)) {
		kunp_rcstruct_build(b);
		return;
	}
	at = kof_find_str_where(0, ctx->obj_size, upx_id);
	if (at == KOF_BROKEN)
		return;
	at += UPX_ID_SKIP;
	for (k = 0; k < UPX_VER_MAX; k++) {
		if (!kof_in_obj(at + k, 1u) || !upx_ver_byte(kof_u8(at + k)))
			break;
		b[7u + k] = (char)kof_u8(at + k);
	}
	if (k < 3u)
		return;
	b[7u + k] = 0;
	kunp_rcstruct_build(b);
}


/*
 * ---- THE IMPORTS UPX TOOK APART ------------------------------------------
 *
 * WHY THERE ARE NONE WITHOUT THIS. UPX does not compress the import directory:
 * it REPLACES it. The descriptors, the lookup table and the name strings are
 * thrown away and what goes in the file instead is a compact list its stub
 * walks at load time, calling GetProcAddress and writing each answer into the
 * IAT. So a child that is only the decompressed image has code and data right
 * and no imports at all - measured on 445.exe, `symbols count=0`, against 159
 * on the MPRESS child beside it. Every rule scoped to a symbol misses the
 * whole family.
 *
 *
 * WHERE THE LIST IS. The decompressed payload carries a TRAILER, and its last
 * four bytes are the offset of it:
 *
 *     payload[len - 4]            offset, within the payload, of the trailer
 *     trailer + 0                 the ORIGINAL IMAGE_NT_HEADERS, whole
 *     + sizeof(NT_HEADERS)        the original section headers, one each
 *     then, when the original had imports:
 *     + 0  dword                  where the compact list is, in the payload
 *     + 4  dword                  where the DLL names are to be written, or 0
 *
 * and the list itself, records until a record whose first dword is zero:
 *
 *     dword   offset of the library's NAME - and NOT into the payload: into
 *             the PACKED FILE's own import data directory, which is the one
 *             place UPX keeps the strings, because its stub needs them before
 *             anything is decompressed
 *     dword   where this library's IAT begins, relative to the image base used
 *             for the payload
 *     then entries until a zero byte:
 *             01 <name\0>         by name
 *             FF <word>           by ordinal
 *             xx <dword>          the thunk value as the packed file already
 *                                 holds it, at that offset in the same import
 *                                 directory - UPX's form for an entry it did
 *                                 not have to rewrite
 *
 * Read off XVolkolak's xupx.cpp, which is where this format is written down -
 * see THIRD-PARTY.md.
 *
 *
 * READ BEFORE THE LAYOUT IS ASKED FOR, and that ordering is the whole trick.
 * kunp_rcstruct_layout_of_image cuts the child back to where the image ends,
 * and the trailer lives PAST the last section - so asking for the layout first
 * throws the import list away. Measured: the child's last four bytes were
 * zero, not an offset.
 */

/* The original headers, by the offsets the format fixes. */
#define UI_NT32      248u    /* sizeof IMAGE_NT_HEADERS32 */
#define UI_NT64      264u
#define UI_OPT       24u     /* the optional header, inside NT_HEADERS */
#define UI_NSEC      6u      /* NumberOfSections, inside NT_HEADERS */
#define UI_SECALIGN  (UI_OPT + 32u)
#define UI_SIZEHDR   (UI_OPT + 60u)
/* The IMPORT directory, which is entry ONE of the table and not the table:
 * pointed at entry zero these read the EXPORT directory instead, and a PE32+
 * sample passed the presence test on an export it happened to have. */
#define UI_DIR32     (UI_OPT + 96u + 8u)
#define UI_DIR64     (UI_OPT + 112u + 8u)
#define UI_SECHDR    40u

#define UI_MAX_DLL   64u
#define UI_MAX_FN    2048u
#define UI_NAME      128u

/*
 * Give up, and say WHERE.
 *
 * There are eighteen ways this walk can decide the trailer is not one it
 * knows, and "it found nothing" is the same answer for all of them - which is
 * useless the first time a build does not work. The number is the line of the
 * walk that refused, reported as a debug fact, so a sample that produces no
 * imports says which step turned it away.
 */
static uint32_t ui_no(const struct kof_obj_ctx *ctx, uint32_t where)
{
	kof_debug("UPX.PE.imp_stop", where);
	return 0;
}

/* A dword out of the child being produced. */
static uint32_t ui_u32(const struct kof_obj_ctx *ctx, uint64_t at, int *ok)
{
	uint8_t b[4];

	if (kunp_rcstruct_read(at, b, 4u) != 4u) {
		*ok = 0;
		return 0;
	}
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* A NUL terminated name out of the child. Returns its length, or `cap`. */
static uint32_t ui_str(const struct kof_obj_ctx *ctx, uint64_t at, char *out,
		       uint32_t cap)
{
	uint32_t n = 0;

	while (n + 1u < cap) {
		uint8_t c = 0;

		if (kunp_rcstruct_read(at + n, &c, 1u) != 1u)
			return cap;
		out[n] = (char)c;
		if (!c)
			return n;
		n++;
	}
	return cap;
}

/* And one out of the PARENT, where the library names are. */
static uint32_t ui_str_obj(const struct kof_obj_ctx *ctx, uint64_t at,
			   char *out, uint32_t cap)
{
	uint32_t n = 0;

	while (n + 1u < cap) {
		uint8_t c;

		if (!kof_in_obj(at + n, 1u))
			return cap;
		c = kof_u8(at + n);
		out[n] = (char)c;
		if (!c)
			return n;
		n++;
	}
	return cap;
}

/*
 * Walk the compact list and declare what it says. `payload` is how many bytes
 * were decompressed, and every offset below is checked against it.
 *
 * Returns the number of entries declared, or 0 - which is not a failure: a
 * program with no imports is a program with no imports, and so is a build
 * whose trailer this does not recognise. The child is still the image.
 */
static uint32_t upx_imports(const struct kof_obj_ctx *ctx,
			    const struct kof_pe_info *pe, uint64_t payload)
{
	uint64_t base = PEI_PAGE;      /* where the payload was written */
	uint64_t tr, list, iend;
	uint32_t nt, dir, nsec, off, rvamin, secalign, n = 0, ndll = 0;
	uint32_t step = pe->pe32_plus ? 8u : 4u;
	uint64_t imp_off, imp_len;
	int ok = 1;
	char dll[UI_NAME], fn[UI_NAME];

	if (payload < 8u)
		return ui_no(ctx, 1);
	off = ui_u32(ctx, base + payload - 4u, &ok);
	if (!ok || !off)
		return ui_no(ctx, 2);

	nt = pe->pe32_plus ? UI_NT64 : UI_NT32;
	dir = pe->pe32_plus ? UI_DIR64 : UI_DIR32;
	if ((uint64_t)off + nt > payload)
		return ui_no(ctx, 3);
	tr = base + off;

	/*
	 * THE ORIGINAL HEADER SAYS WHETHER THERE WERE IMPORTS AT ALL, and a
	 * zero there is the answer rather than a reason to look further.
	 */
	if (!ui_u32(ctx, tr + dir, &ok) || !ok)
		return ui_no(ctx, 4);

	{
		uint8_t b[2];

		if (kunp_rcstruct_read(tr + UI_NSEC, b, 2u) != 2u)
			return ui_no(ctx, 5);
		nsec = (uint32_t)b[0] | ((uint32_t)b[1] << 8);
	}
	if (nsec > 96u)
		return ui_no(ctx, 6);
	secalign = ui_u32(ctx, tr + UI_SECALIGN, &ok);
	rvamin = ui_u32(ctx, tr + UI_SIZEHDR, &ok);
	if (!ok)
		return ui_no(ctx, 7);
	if (!secalign)
		secalign = 0x1000u;
	if (secalign & (secalign - 1u))
		return ui_no(ctx, 8);              /* not a power of two: not an alignment */
	rvamin = (rvamin + secalign - 1u) & ~(secalign - 1u);
	/*
	 * WHERE THE PAYLOAD WAS PUT AGAINST WHERE THE ORIGINAL SAID IT WOULD
	 * BE. This module writes it at PEI_PAGE; UPX's own arithmetic puts it
	 * at rvamin. They agree for every sample here and the module's whole
	 * addressing already assumes they do - so a file where they differ is
	 * reported and left alone rather than given imports at addresses that
	 * are wrong by a constant.
	 */
	if (rvamin != base) {
		kof_debug("UPX.PE.rvamin", rvamin);
		return ui_no(ctx, 9);
	}

	iend = (uint64_t)off + nt + (uint64_t)nsec * UI_SECHDR;
	if (iend + 8u > payload)
		return ui_no(ctx, 10);
	list = ui_u32(ctx, base + iend, &ok);
	if (!ok || !list || list >= payload)
		return ui_no(ctx, 11);
	list += base;

	/*
	 * The library names are in the PACKED file, in its own import
	 * directory - see the note above. Without it there is nothing to name
	 * a library with, so this stops rather than declaring ordinals under
	 * no library at all.
	 */
	if (pe->dir[KOF_PE_DIR_IMPORT].rva == 0 ||
	    pe->dir[KOF_PE_DIR_IMPORT].size == 0)
		return ui_no(ctx, 12);
	imp_off = kof_pe_rva_to_off(pe, pe->dir[KOF_PE_DIR_IMPORT].rva);
	imp_len = pe->dir[KOF_PE_DIR_IMPORT].size;
	if (imp_off == KOF_BROKEN)
		return ui_no(ctx, 13);

	while (ndll < UI_MAX_DLL) {
		uint32_t nm_off, iat, k = 0;
		uint64_t at;

		nm_off = ui_u32(ctx, list, &ok);
		if (!ok)
			return ui_no(ctx, 14);
		if (!nm_off)
			break;                  /* the list ends */
		if (nm_off >= imp_len)
			return ui_no(ctx, 15);
		iat = ui_u32(ctx, list + 4u, &ok);
		if (!ok)
			return ui_no(ctx, 16);
		if (ui_str_obj(ctx, imp_off + nm_off, dll, UI_NAME) >= UI_NAME)
			return ui_no(ctx, 17);
		at = list + 8u;

		for (;;) {
			uint8_t tag = 0;
			/*
			 * EVERY ENTRY TAKES A SLOT, AND THE SLOT IS ITS PLACE
			 * IN THE RUN. `k` counts entries in this library, so
			 * the address is the library's IAT plus k pointers -
			 * and the engine's writer builds the lookup table in
			 * the same order, so the two stay aligned. An entry
			 * this walk skipped would put every slot after it one
			 * place out.
			 */
			uint64_t slot = base + iat + (uint64_t)k * step;

			if (kunp_rcstruct_read(at, &tag, 1u) != 1u)
				return ui_no(ctx, 18);
			if (!tag)
				break;
			if (n >= UI_MAX_FN)
				return ui_no(ctx, 19);
			if (tag == 1u) {
				uint32_t len = ui_str(ctx, at + 1u, fn,
						      UI_NAME);

				if (len >= UI_NAME || !len)
					return ui_no(ctx, 20);
				if (!kunp_rcstruct_import(dll, fn, 0, slot))
					return ui_no(ctx, 21);
				at += 1u + len + 1u;
			} else if (tag == 0xffu) {
				uint8_t o2[2] = { 0, 0 };

				if (kunp_rcstruct_read(at + 1u, o2, 2u) != 2u)
					return ui_no(ctx, 22);
				if (!kunp_rcstruct_import(dll, 0,
							  (uint32_t)o2[0] |
							  ((uint32_t)o2[1] << 8),
							  slot))
					return ui_no(ctx, 23);
				at += 3u;
			} else {
				/*
				 * THE THIRD FORM: the thunk as the packed file
				 * already holds it, at that offset in the same
				 * import directory the names came from. UPX
				 * writes it for an entry it did not have to
				 * take apart.
				 *
				 * DECODED RATHER THAN SKIPPED. A skipped entry
				 * still occupies its IAT slot, so passing over
				 * it would leave every later slot in the
				 * library one place out - and the value is a
				 * plain thunk: the high bit set is an ordinal,
				 * and anything else is the RVA of a two-byte
				 * hint followed by the name, which is in the
				 * image this module has just decompressed.
				 */
				uint32_t toff = ui_u32(ctx, at + 1u, &ok);
				uint32_t val;

				if (!ok || (uint64_t)toff + 4u > imp_len ||
				    !kof_in_obj(imp_off + toff, 4u))
					return ui_no(ctx, 24);
				val = kof_u32(imp_off + toff);
				if (val & 0x80000000u) {
					if (!kunp_rcstruct_import(dll, 0,
								  val & 0xffffu,
								  slot))
						return ui_no(ctx, 25);
				} else {
					/* RVA equals child offset here - see
					 * the rvamin check above. */
					uint32_t len = ui_str(ctx,
							      (uint64_t)val + 2u,
							      fn, UI_NAME);

					if (len >= UI_NAME || !len)
						return ui_no(ctx, 26);
					if (!kunp_rcstruct_import(dll, fn, 0,
								  slot))
						return ui_no(ctx, 27);
				}
				at += 5u;
			}
			k++;
			n++;
		}
		list = at + 1u;
		ndll++;
	}
	kof_debug("UPX.PE.imp_dll", ndll);
	return n;
}

/*
 * ---- WHICH UPX LAYOUT THIS IS, BEFORE ANY OF IT IS READ --------------------
 *
 * Every offset below is a position in a header whose shape UPX chose per
 * version and per target. The module cannot tell a header it understands from
 * one it does not by decoding it - a wrong offset yields numbers, and numbers
 * that happen to pass the bounds checks yield a child of garbage. So the shape
 * is asked first and the answer is a row in a table, which is what upx_elf_00.c
 * does for the ELF side and for the same reason.
 *
 * ONE ROW, AND THE ELSE IS WHAT EARNS IT ITS PLACE. A version or format outside
 * it is REPORTED - `UPX.PE.shape` and KOF_UNP_UNSUPPORTED - rather than walked,
 * so the first genuine variant turns up in a scan's statistics instead of
 * quietly producing something wrong. That is the signal that a second row is
 * needed; without it there is no way to know.
 *
 * MEASURED: l_format 9 at l_version 12 (adm_atu.exe, "UPX 1.07") and 13
 * (445.exe, "UPX 3.94"), and l_format 36 at l_version 13 (123.exe.1,
 * "UPX 3.96") - 9 is the 32-bit PE target and 36 the 64-bit one.
 *
 * THE VERSION IS A RANGE AND THE FORMAT IS NOT, and the asymmetry is the whole
 * care this table needs. l_version moves slowly and the b_info layout did not
 * change across the span, so a range there is a statement about a layout. A
 * different l_format is a different TARGET, so widening that would admit
 * exactly the case this exists to catch - and the first attempt did it by
 * accident, writing the mask 32 bits wide, which folded format 36 onto 4 and
 * refused the only x64 sample here.
 */
struct upx_pe_shape {
	uint8_t  ver_min, ver_max;
	/* Bit per l_format, low bit is format 0. Sixty-four wide because the
	 * PE formats are not all small: 9 is Win32 PE and 36 is the 64-bit
	 * one, and a 32-bit mask silently folded the second onto 4. */
	uint64_t formats;
};

static const struct upx_pe_shape upx_pe_shapes[] = {
	{ 10u, 16u, (1ull << 9) | (1ull << 36) }
};

static int upx_pe_known(uint8_t ver, uint8_t fmt)
{
	unsigned k;

	for (k = 0; k < sizeof upx_pe_shapes / sizeof upx_pe_shapes[0]; k++) {
		const struct upx_pe_shape *r = &upx_pe_shapes[k];

		if (ver < r->ver_min || ver > r->ver_max)
			continue;
		if (fmt < 64u && (r->formats & (1ull << fmt)))
			return 1;
	}
	return 0;
}

/*
 * The PackHeader is 32 bytes behind "UPX!", and the search for the magic runs
 * up to a few bytes PAST the section's offset because three of the samples here
 * put it five bytes inside - see the note at the top of this file.
 *
 * SIXTEEN AND NOT EIGHT, and the four bytes of the magic are why. The bound is
 * a LENGTH and a match has to fit inside it: 123.exe.1 has its magic at 0x205
 * with the section at 0x200, so the match ends at 0x209 and a bound of eight
 * stops at 0x208. Measured - that one file went from unpacked to "no unpacker
 * claimed it" and nothing else moved. Sixteen is the five with room for the
 * magic and still far short of anything that could reach a second one.
 */
#define PH_LEN        32u
#define PH_LOOK       16u

#define PH_VERSION     4u
#define PH_FORMAT      5u
#define PH_METHOD      6u
#define PH_U_LEN      16u
#define PH_C_LEN      20u

/*
 * UPX method numbers mapped onto the engine's decoders.
 *
 * Each group of three is one coding at three bit-buffer widths - _LE32, _8, _LE16
 * in that order - not one coding with three filters. Getting that wrong decodes
 * every _LE32 stream correctly and every _8 stream not at all, which is what it
 * did before it was measured.
 */
static uint32_t method_of(unsigned m)
{
	switch (m) {
	case 2:  return KOF_UNP_NRV2B_32;
	case 3:  return KOF_UNP_NRV2B_8;
	case 4:  return KOF_UNP_NRV2B_16;
	case 5:  return KOF_UNP_NRV2D_32;
	case 6:  return KOF_UNP_NRV2D_8;
	case 7:  return KOF_UNP_NRV2D_16;
	case 8:  return KOF_UNP_NRV2E_32;
	case 9:  return KOF_UNP_NRV2E_8;
	case 10: return KOF_UNP_NRV2E_16;
	default: return 0;              /* LZMA, or something newer */
	}
}

#define UPX_M_LZMA 14u

/*
 * UPX's LZMA blocks: the stream starts two bytes in, and those two bytes carry the
 * parameters.
 *
 * Worked out by decoding real blocks with every combination the specification
 * allows and keeping the ones that produced exactly the length the container
 * declared. 330 LZMA blocks across packed ELF and PE, three distinct headers:
 *
 *     18 03  ->  lc=3 pb=0        1a 03  ->  lc=3 pb=2        3c 07  ->  lc=7 pb=4
 *
 * so lc is the top of the first byte and pb the bottom three bits. Every block used
 * lp=0, so where lp lives is still not established and it is taken as zero - if a
 * build using another value appears, this decodes it wrongly.
 *
 * Being wrong about that is safe and deliberately so: the container states the
 * uncompressed length, the host reports what came out, and a mismatch is an object
 * marked not fully examined. A wrong guess costs a sample reported incomplete,
 * never one silently declared clean.
 */
#define UPX_LZMA_SKIP  2u
#define UPX_LZMA_LP    0u

static uint32_t upx_lzma_method(unsigned first_byte)
{
	unsigned lc = first_byte >> 3, pb = first_byte & 7u;

	/* Both come from the file, and both size or shape the decoder's model.
	 * Out of range is refused here so the module can say it did not finish,
	 * rather than being refused inside the host with nothing to report. */
	if (lc > KOF_LZMA_MAX_LC || pb > KOF_LZMA_MAX_PB)
		return 0;
	return KOF_UNP_LZMA_PROPS(lc, UPX_LZMA_LP, pb);
}


void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint64_t ph, sec_off, stream, got, img_end;
	uint32_t u_len, c_len, decoder, n_imp;

	if (!pe->valid || pe->entry_sec >= pe->sec_count)
		return;

	sec_off = pe->sec[pe->entry_sec].file_off;
	if (!sec_off)
		return;                 /* a section with no bytes in the file */

	/*
	 * Bounded to the headers, which is where UPX puts it and is also the only
	 * bound that costs nothing on files that are not packed at all.
	 *
	 * Naming the whole object looks harmless because the search stops at the
	 * first hit - and it is harmless on a packed file, where the hit is a few
	 * hundred bytes in. On an ordinary PE there is no hit, so the search reads
	 * the entire file to find that out. Measured over 1272 PE samples: 703 carry
	 * no UPX marker anywhere, and searching all of them cost 1334MB of reading
	 * to learn nothing.
	 *
	 * The bound is the start of the packed section's raw data, because the
	 * PackHeader lives in the padding ahead of it. Of 564 samples that do carry
	 * the marker, 557 have it there; the 7 that do not are files whose only
	 * occurrence is inside data, and they were not unpackable through it anyway.
	 */
	ph = kof_find_str_where(0, sec_off + PH_LOOK, upx_magic);
	if (ph == KOF_BROKEN || !kof_in_obj(ph, PH_LEN))
		return;
	/*
	 * AND THE STREAM IS WHAT FOLLOWS IT. See the note above for the two
	 * arrangements this covers and for why they are one rule rather than a
	 * rule and an exception.
	 */
	stream = ph + PH_LEN;

	decoder = method_of(kof_u8(ph + PH_METHOD));
	u_len   = kof_u32(ph + PH_U_LEN);
	c_len   = kof_u32(ph + PH_C_LEN);

	/*
	 * What was recognised, before anything is decided about it.
	 *
	 * These are the three numbers that decide whether a sample is one this
	 * module handles, and when it does not the useful question is which
	 * combination it was - so they are reported whatever happens next, and
	 * before the branches below can return.
	 */
	kof_debug("UPX.PE.version", kof_u8(ph + PH_VERSION));
	upx_say_build(ctx, ph);
	kof_debug("UPX.PE.format", kof_u8(ph + PH_FORMAT));
	kof_debug("UPX.PE.method", kof_u8(ph + PH_METHOD));

	/*
	 * AND THE LAYOUT DECIDES WHETHER TO GO ON. Everything read after this
	 * point is at an offset this row vouches for - see upx_pe_shapes. The
	 * pair is reported as one number so a scan's statistics name the
	 * combination that was refused rather than two halves of it.
	 */
	if (!upx_pe_known(kof_u8(ph + PH_VERSION), kof_u8(ph + PH_FORMAT))) {
		kof_debug("UPX.PE.shape",
			  ((uint32_t)kof_u8(ph + PH_VERSION) << 8) |
			  kof_u8(ph + PH_FORMAT));
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
	}

	if (u_len == 0 || c_len == 0 || !kof_in_obj(stream, c_len)) {
		/* The header contradicts the file it is in. */
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	}
	if (decoder == 0) {
		if (kof_u8(ph + PH_METHOD) != UPX_M_LZMA ||
		    c_len <= UPX_LZMA_SKIP) {
			/* A coding this engine does not have. The file is packed,
			 * the payload is in there, and nothing here can reach it -
			 * a verdict of "not examined", never of "clean". */
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
		}
		decoder = upx_lzma_method(kof_u8(stream));
		if (decoder == 0) {
			/* LZMA parameters outside what the format allows. */
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
		}
		stream += UPX_LZMA_SKIP;
		c_len  -= UPX_LZMA_SKIP;
	}

	/*
	 * u_len sizes the buffer and bounds nothing.
	 *
	 * It is a number out of the file, so a wrong one is ordinary rather than
	 * exceptional: too large and the host clamps it to what the memory ceiling
	 * allows, too small and the decode stops early. Either way the comparison
	 * below is what notices, because the container told us what to expect and
	 * we can hold it to that.
	 */
	/*
	 * WHAT COMES OUT IS AN IMAGE, NOT A FILE: sections at their virtual
	 * addresses with the original header kept somewhere inside.
	 *
	 * So: take the room, decompress into it, and then ask the host to read
	 * the layout out of what is there. The span is declared as one range
	 * because that is all that is known before the bytes exist; the real
	 * sections replace it a few lines down.
	 *
	 * This was KOF_FORM_PE_IMAGE, which hid the same search inside the
	 * decoder and then allocated a SECOND buffer the size of the image and
	 * copied every section into it, so that the engine could parse the
	 * result back and recover what the header had said all along.
	 */
	if (kunp_rcstruct_section("", PEI_PAGE, u_len, KUNP_PERM_R,
			    KOF_SECF_DATA | KOF_SECF_REBUILT) < 0)
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	if (!kunp_rcstruct_image() || !kunp_rcstruct_at(PEI_PAGE))
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	got = kunp_static_decode(decoder, stream, c_len, u_len);
	if (got == 0)
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	/*
	 * THE IMPORTS, BEFORE THE LAYOUT - see upx_imports for why the order is
	 * not a preference. The trailer this reads lives past the last section,
	 * and asking for the layout cuts the child back to where the sections
	 * end.
	 */
	n_imp = upx_imports(ctx, pe, got);
	if (n_imp)
		kof_debug("UPX.PE.imports", n_imp);

	/*
	 * AND NOW WHAT IT ACTUALLY IS. Without this the child is a buffer of
	 * machine code that identifies as nothing, and every module that
	 * targets PE is ruled out before it runs.
	 */
	img_end = kunp_rcstruct_layout_of_image();
	if (!img_end)
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);

	/*
	 * AND THE TABLE THE ENGINE WILL WRITE FROM THEM, after the image
	 * because there is nowhere inside it that is free: every address the
	 * original program used is occupied by what it put there. The same
	 * arrangement bases/unp/mpress_pe.c uses, and for the same reason.
	 */
	if (n_imp) {
		uint64_t need = kunp_rcstruct_import_bytes();

		if (need && kunp_rcstruct_at(img_end) &&
		    kunp_rcstruct_section(".kofimp", img_end, need,
					  KUNP_PERM_R,
					  KOF_SECF_DATA | KOF_SECF_SYNTHETIC)
		    >= 0)
			kunp_rcstruct_import_at(img_end);
	}

	/*
	 * The handover is checked, like every container in this directory
	 * checks it.
	 *
	 * A packer's child is not one entry of many - it is the whole of what
	 * the file was hiding. Refused by the host (a ceiling reached, the child
	 * cap spent) and not reported, the module would be saying it unpacked
	 * the object while having produced nothing, which is the one answer a
	 * scan must never give about a packed sample.
	 */
	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);

	/* Short of what the container declared: the stream did not hold what it
	 * said it held. The host records its own reason when a limit was what
	 * stopped it, and the first reason recorded is the one kept. */
	if (got < u_len)
		kunp_rcstruct_broken(KOF_UNP_DAMAGED);
}
