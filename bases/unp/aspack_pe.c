/*
 * aspack_pe.c - take an ASPack 2.x packed PE apart, statically.
 *
 * THE STUB IS THE MAP. ASPack compresses the image block by block and leaves a
 * table in its own section saying where each block goes and how long it comes
 * out; the original entry point is an immediate in the same stub, and so is the
 * marker byte its call/jmp filter used. Everything needed is in the file, and
 * none of it is anywhere a search would find - it is at a FIXED OFFSET from the
 * entry point, and that offset is different in every build.
 *
 * So this module is a table of stub layouts and nothing else clever. The row is
 * chosen by three checks, and the third is the one that matters:
 *
 *   - the entry point's first bytes. Necessary and NOT SUFFICIENT: the 2.12
 *     signature is a known forgery. XVolkolak carries the identical bytes a
 *     second time under the name FAKESIGNATURE, because other packers stamp
 *     them at their own entry points so tools report ASPack and stop looking.
 *   - "68 00 00 00 00 C3" - push 0 / ret - where the row says the stub's
 *     buffer starts. A second landmark the forgeries do not carry.
 *   - THE DECODER TABLE ITSELF, 114 bytes, at the row's own offset. A stub
 *     carrying this table at this distance from this entry point IS the build
 *     the row names; nothing that merely copied a signature has it.
 *
 * Measured over the five files the survey found by section name: three carry
 * the table and unpack, and the two that do not are rejected - one is a
 * re-packed sample whose entry point is an ordinary function prologue, the
 * other has `.adata` and an entry point belonging to something else entirely.
 * Both would have been called ASPack by a section-name detector. See
 * /mnt/games/kofsurvey/packer-coverage.md.
 *
 *
 * WHAT IS NOT HERE
 *
 * 2.11 AND 2.11c, which wrap the part of the stub holding the marker and the
 * original entry point in a per-file polymorphic decryptor. Their layout is
 * known - XVolkolak has the rows - and it is unusable until the head has run,
 * so they need the interpreter to decrypt a few hundred bytes before the static
 * path could take over. No sample here is one, so there is nothing to test that
 * against, and a row that has never decoded a file is a row that says it works.
 * They fall through to the interpreter with the rest.
 *
 * THE IMPORTS. ASPack fills the IAT at run time from a table its stub walks;
 * statically the directory still points where the packer left it. The child
 * therefore has the code and the data right and its imports wrong, and says so
 * - the parse flags what it finds. That is the same position every static
 * unpacker in this engine is in and it is worth being explicit about, because
 * an import-scoped rule will not reach this child.
 *
 *
 * Written against XVolkolak's xaspack.cpp (MIT) - see THIRD-PARTY.md. The coding
 * itself is libkofeng/extractors/decomp/aspack.c, in the host, because a match
 * may reach any byte already produced and a module cannot hold the window.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>
#include <kofmod/aspack_tab.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("ASPack");

/*
 * A STUB LAYOUT.
 *
 * `sig` is at the entry point. Every other offset is measured from the entry
 * point MINUS ONE, which is where the stub's own base pointer lands - ASPack
 * points the entry point one byte into its stub, and the whole layout is
 * relative to the byte before it. `epbuf` is the exception and is measured from
 * the entry point itself, because that is how the builder wrote it.
 *
 * The rows are XVolkolak's, which derived them per generation from a packed
 * corpus this project does not have. Only `2.xx` is measured here.
 */
struct asp_shape {
	uint8_t  sig[8];
	uint8_t  sig_n;
	uint16_t epbuf;      /* "push 0 / ret", entry-point relative */
	uint16_t blocks;     /* the block table */
	uint8_t  stride;     /* bytes per block table entry */
	uint16_t strmlt;     /* the stub's copy of the offset width table */
	uint16_t compb;      /* the stub's copy of the decoder table */
	uint16_t mark;       /* the call/jmp filter's marker byte */
	uint16_t oep;        /* the original entry point, as an RVA */
	/*
	 * WHERE THE PROGRAM'S OWN IMPORT DIRECTORY IS, as an RVA, or 0 for a
	 * row where it has not been measured.
	 *
	 * Not in XVolkolak's table - its ASPack unpacker recovers no imports
	 * at all - and found here the way that table was built, by looking for
	 * a known value at a fixed distance from the stub's base. The original
	 * directory RVA was recovered from the decompressed image of two
	 * samples by walking for a descriptor array, then searched for in
	 * their stubs: both hold it at nEp + 0x265, and the third sample's
	 * dword there points at a descriptor array too. The two files this
	 * module rejects hold 0x22943d83 and 0x30081357 there, which is what
	 * that offset means in something that is not this stub.
	 */
	uint16_t imp;
	char     name[24];
};

static const struct asp_shape asp_shapes[] = {
	{ { 0x60,0xe8,0x03,0x00,0x00,0x00,0xe9,0xeb }, 8,
	  0x3b9, 0x57c,  8, 0x70e, 0x6d6, 0x148, 0x39b, 0, "PE:ASPack 2.12" },
	{ { 0x60,0xe8,0x03,0x00,0x00,0x00,0xe9,0xeb }, 8,
	  0x414, 0x5d0, 12, 0x6ca, 0x692, 0x145, 0x3f6, 0, "PE:ASPack 2.2" },
	{ { 0x60,0xe8,0x03,0x00,0x00,0x00,0xe9,0xeb }, 8,
	  0x41f, 0x5d8, 12, 0x76a, 0x732, 0x13a, 0x401, 0x265,
	  "PE:ASPack 2.12-2.42" },
	{ { 0x60,0xe8,0x03,0x00,0x00,0x00,0xe9,0xeb }, 8,
	  0x42b, 0x5e4, 12, 0x776, 0x73e, 0x148, 0x40d, 0, "PE:ASPack 2.42" },
	{ { 0x60,0xe8,0x70,0x05,0x00,0x00,0xeb,0x00 }, 7,
	  0x4fb, 0x0de,  8, 0x623, 0x5eb, 0x292, 0x0d2, 0, "PE:ASPack 2.00" },
	{ { 0x60,0xe8,0x72,0x05,0x00,0x00,0xeb,0x00 }, 7,
	  0x4fd, 0x0de,  8, 0x625, 0x5ed, 0x294, 0x0d2, 0, "PE:ASPack 2.01" }
};

#define ASP_SHAPES  (sizeof asp_shapes / sizeof asp_shapes[0])
#define ASP_STUB    0x1000u    /* how far past the entry point a row may reach */
#define ASP_MAX_SEC 64u
/* The block table terminator is a zero RVA. A table that never reaches one
 * inside this many entries is not a block table. */
#define ASP_MAX_BLK 64u
/* What the stub writes at `blocks + 4` for a section it does not compress. */
#define ASP_BLK_SKIP 0xfffffef2u
/* A descriptor array longer than this is not one. */
#define ASP_MAX_DESC 256u

/* One stub byte, by its distance from the entry point minus one. */
static uint32_t asp_u8(const struct kof_obj_ctx *ctx, uint64_t stub, uint32_t at)
{
	return kof_in_obj(stub + at, 1u) ? kof_u8(stub + at) : 0x100u;
}

static uint64_t asp_u32(const struct kof_obj_ctx *ctx, uint64_t at)
{
	return kof_in_obj(at, 4u) ? kof_u32(at) : 0;
}

/*
 * Which build this is, or -1.
 *
 * `stub` is the file offset of the entry point minus one; the caller has
 * already established that it is in the file.
 */
static int asp_shape_of(const struct kof_obj_ctx *ctx, uint64_t stub)
{
	static const uint8_t ep_mark[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
	uint32_t r, k;

	for (r = 0; r < ASP_SHAPES; r++) {
		const struct asp_shape *sh = &asp_shapes[r];

		for (k = 0; k < sh->sig_n; k++)
			if (asp_u8(ctx, stub, 1u + k) != sh->sig[k])
				break;
		if (k < sh->sig_n)
			continue;

		for (k = 0; k < sizeof ep_mark; k++)
			if (asp_u8(ctx, stub, 1u + sh->epbuf + k) != ep_mark[k])
				break;
		if (k < sizeof ep_mark)
			continue;

		/*
		 * The decoder table, which is what makes the row an identity
		 * rather than a guess - see the note at the top.
		 */
		for (k = 0; k < KOF_ASPACK_TAB_N; k++)
			if (asp_u8(ctx, stub, sh->compb + k) != kof_aspack_tab[k])
				break;
		if (k < KOF_ASPACK_TAB_N)
			continue;

		/*
		 * AND THE SECOND TABLE, CHECKED AGAINST THE FIRST RATHER THAN
		 * AGAINST A CONSTANT.
		 *
		 * The stub keeps the offset widths separately, and in every
		 * build here they are byte for byte the decoder table from
		 * 0x38 on. The host decoder is compiled with that assumption -
		 * it takes no parameters at all - so the assumption is checked
		 * where it can still be acted on. Comparing the two copies in
		 * the FILE says the same thing as comparing either to the
		 * constant, and says it without a second constant to keep
		 * right.
		 */
		for (k = 0; k < KOF_ASPACK_OFF_N; k++)
			if (asp_u8(ctx, stub, sh->strmlt + k) !=
			    asp_u8(ctx, stub, sh->compb + KOF_ASPACK_OFF_BASE + k))
				break;
		if (k < KOF_ASPACK_OFF_N)
			continue;

		return (int)r;
	}
	return -1;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	const struct asp_shape *sh;
	struct { uint64_t rva, len; } blk[ASP_MAX_BLK];
	uint64_t stub, tab, oep;
	uint32_t n_blk = 0, i, mark;
	uint32_t nsec, made = 0;
	int r;

	if (!pe->valid || pe->pe32_plus || !pe->entry_rva)
		return;

	stub = kof_pe_rva_to_off(pe, pe->entry_rva - 1u);
	if (stub == KOF_BROKEN || !kof_in_obj(stub, ASP_STUB))
		return;

	r = asp_shape_of(ctx, stub);
	if (r < 0)
		return;
	sh = &asp_shapes[r];
	kunp_rcstruct_build(sh->name);
	kof_debug("ASPack.PE.build", (uint32_t)r);

	/*
	 * THE BLOCK TABLE, READ WHOLE BEFORE ANYTHING IS PRODUCED.
	 *
	 * Because a block is decoded straight into the child and the child's
	 * sections have to be declared first: the engine writes the header once
	 * the layout is known, and the layout is what this table says. Reading
	 * it twice - once to declare, once to decode - would be reading a
	 * hostile file twice and hoping it answered the same way.
	 */
	tab = stub + sh->blocks;
	while (n_blk < ASP_MAX_BLK) {
		uint64_t rva = asp_u32(ctx, tab);
		uint64_t len = asp_u32(ctx, tab + 4u);

		if (!rva)
			break;                     /* the terminator */
		/*
		 * A WIDE ENTRY MAY SAY "NOTHING HERE", and the sentinel is not
		 * zero: the stub writes 0xfffffef2, which is -0x10e, because
		 * what it actually stores is the length its own reader will
		 * add the lookahead back onto. Read as a length it is 4 GB and
		 * every bound below would refuse it; read as the skip it is,
		 * the table continues.
		 */
		if (sh->stride != 8u && (uint32_t)len == ASP_BLK_SKIP) {
			tab += sh->stride;
			continue;
		}
		if (!len || len > pe->size_of_image ||
		    rva + len > pe->size_of_image)
			return;
		blk[n_blk].rva = rva;
		blk[n_blk].len = len;
		n_blk++;
		tab += sh->stride;
	}
	if (!n_blk || n_blk >= ASP_MAX_BLK)
		return;
	kof_debug("ASPack.PE.blocks", n_blk);

	oep = asp_u32(ctx, stub + sh->oep);
	mark = asp_u8(ctx, stub, sh->mark);
	if (oep >= pe->size_of_image || mark > 0xffu)
		return;
	kof_debug("ASPack.PE.oep", (uint32_t)oep);

	/*
	 * THE SECTIONS THE PROGRAM HAD, WHICH ARE THE ONES ASPACK DID NOT ADD.
	 *
	 * ASPack appends its stub in a section of its own and a second, empty
	 * one after it - `.aspack` and `.adata` by default, but the names are
	 * the builder's choice and nothing may depend on them. What does not
	 * change is the SHAPE: the entry point is in the second from last, and
	 * the last has no raw data. That is the test, and it is XVolkolak's.
	 *
	 * Declared at their original RVAs with the file laid out to match, so
	 * an address in the child is the address the program was linked at.
	 */
	nsec = pe->sec_count;
	if (nsec > 2u && pe->entry_sec == nsec - 2u &&
	    !pe->sec[nsec - 1u].file_size)
		nsec -= 2u;
	if (!nsec || nsec > ASP_MAX_SEC)
		return;

	for (i = 0; i < nsec; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		if (kunp_rcstruct_section(s->name, s->mem_rva, s->mem_size,
					  kof_pe_perm_decl(s->perm),
					  KOF_SECF_REBUILT |
					  ((s->perm & KOF_PE_PERM_X)
					   ? KOF_SECF_CODE : KOF_SECF_DATA)) < 0)
			return;
	}
	kunp_rcstruct_as(KOF_FMT_PE, KOF_ARCH_X86, pe->image_base);
	if (!kunp_rcstruct_image())
		return;
	kunp_rcstruct_entry(oep);

	/*
	 * EACH BLOCK DECODED WHERE IT BELONGS.
	 *
	 * kunp_rcstruct_at moves the sink to the block's own RVA, so the file
	 * this produces has raw offset equal to RVA throughout. That is what
	 * makes the declared sections above true without a second layout step,
	 * and it is what the engine's header writer expects.
	 *
	 * ONLY THE FIRST BLOCK CARRIES THE CALL/JMP FILTER. The stub applies it
	 * once, to the first block it decompresses that is long enough to hold
	 * an instruction, and the rest are plain. Asking for it on every block
	 * would rewrite four bytes after every E8 in the data sections that
	 * happened to be followed by the marker.
	 */
	for (i = 0; i < n_blk; i++) {
		uint64_t at = kof_pe_rva_to_off(pe, blk[i].rva);
		uint32_t method = (i == 0u && blk[i].len > 7u)
				  ? KOF_UNP_ASPACK_MARK(mark)
				  : (uint32_t)KOF_UNP_ASPACK;

		if (at == KOF_BROKEN || !kof_in_obj(at, 1u))
			return;
		if (!kunp_rcstruct_at(blk[i].rva))
			return;
		if (kunp_static_decode(method, at, blk[i].len, blk[i].len) !=
		    blk[i].len)
			return;
		made++;
	}
	if (!made)
		return;

	/*
	 * ---- AND THE IMPORTS, WHICH WERE NEVER TAKEN APART -----------------
	 *
	 * ASPack compresses the whole image, INCLUDING the import directory,
	 * and rebuilds nothing: the descriptors, the lookup tables and the name
	 * strings all come back out of the blocks exactly as the linker wrote
	 * them. What it does is repoint the PE header's directory at a little
	 * table of its own - one thunk per library, which is all its loader
	 * needs to call LoadLibrary - and keep the real address in its stub.
	 *
	 * So there is nothing to declare entry by entry here. The table is
	 * already in the child; only the pointer to it is missing, and the
	 * stub has it. Measured on the three samples: 375, 44 and 576 imports
	 * come back, against 0 before this.
	 *
	 * The size is worked out by WALKING to the terminator rather than
	 * taken from anywhere, because nothing states it - and walking is also
	 * what checks the address: a row whose offset is wrong points at bytes
	 * that do not end in a null descriptor.
	 */
	if (sh->imp) {
		uint64_t irva = asp_u32(ctx, stub + sh->imp);
		uint32_t d = 0;

		if (irva >= pe->size_of_image)
			irva = 0;
		while (irva && d < ASP_MAX_DESC) {
			uint8_t b[20];
			uint32_t q, zero = 1, nm;

			if (kunp_rcstruct_read(irva + (uint64_t)d * 20u, b,
					       20u) != 20u)
				break;
			for (q = 0; q < 20u; q++)
				if (b[q]) {
					zero = 0;
					break;
				}
			if (zero)
				break;                 /* the terminator */
			nm = (uint32_t)b[12] | ((uint32_t)b[13] << 8) |
			     ((uint32_t)b[14] << 16) | ((uint32_t)b[15] << 24);
			/*
			 * A DESCRIPTOR NAMES A LIBRARY, and the first byte of
			 * that name is printable. One cheap check, and it is
			 * the one that tells a real array from whatever a
			 * wrong offset pointed at.
			 */
			{
				uint8_t c = 0;

				if (!nm || nm >= pe->size_of_image ||
				    kunp_rcstruct_read(nm, &c, 1u) != 1u ||
				    c < 0x21u || c > 0x7eu)
					break;
			}
			d++;
		}
		kof_debug("ASPack.PE.imp_desc", d);
		if (d)
			kunp_rcstruct_dir(KOF_PE_DIR_IMPORT, irva,
					  ((uint64_t)d + 1u) * 20u);
	}

	kunp_rcstruct_done();
}
