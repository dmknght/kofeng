/*
 * themida_pe.c - recover the loader from a Themida/WinLicense protected PE.
 *
 * WHAT THIS RECOVERS, SAID FIRST BECAUSE IT IS NOT THE WHOLE FILE.
 *
 * A Themida protected PE holds two things this module can tell apart: the
 * PROTECTED PROGRAM, whose sections are encrypted and stay that way, and the
 * LOADER that decrypts them, which is aPLib compressed and comes out whole.
 * This recovers the loader and says nothing about the program.
 *
 * That is worth having and it is worth not overstating. The object as it stands
 * is opaque - the program's sections measure 8.00 bits per byte, and the loader
 * is compressed - so nothing in it can be searched, named or described. After
 * this, three to five megabytes of it can be. What the loader is NOT is the
 * malware: recovering it does not unpack the sample, and a verdict about a
 * Themida protected file still rests on what its own bytes say.
 *
 * The program's sections are decrypted at run time with keys the loader derives
 * then, and there is no declared length, no header and no invariant anywhere in
 * the file that points at them. Reaching them is the emulator's problem or
 * nobody's; it is not a container this or any other module can open.
 *
 *
 * THE CONTAINER
 *
 * Two sections at the end of the image, in this order and with this shape:
 *
 *     .themida   VirtualSize large, SizeOfRawData ZERO - it exists only once
 *     or         loaded, and is where the decompressed loader goes. Oreans
 *     .winlice   ship one engine under two product names and the builder
 *                writes whichever it is; both are accepted.
 *     .boot      holds the entry point, and holds the aPLib stream
 *
 * The entry point is a PLAIN aPLib depacker. Not virtualised, not encrypted,
 * the same bytes in every sample of a given width - which is the whole reason
 * this module is possible at all, and it is Themida's own doing: something has
 * to be able to run before anything has been decrypted.
 *
 *     e8 82 01 00 00     call past the depacker, to the setup
 *     41 52 49 89 e2     push r10 / mov r10, rsp
 *     49 8b 72 10        mov rsi, [r10+0x10]      the source
 *     49 8b 7a 20        mov rdi, [r10+0x20]      the destination
 *     fc b2 80           cld / mov dl, 0x80       the bit buffer
 *     8a 06 48 ff c6     the first literal, copied before any bit is read
 *
 * and the setup it calls says where the stream is, in an immediate:
 *
 *     b9 d4 01 00 00     mov ecx, 0x1d4
 *     83 e9 05           sub ecx, 5
 *     48 01 c1           add rcx, rax             rax is the return address
 *
 * so the stream begins 0x1d4 bytes past the entry point. The 32 bit stub is the
 * same shape with 0x197 in place of 0x1d4 - a different prologue, not a
 * different design.
 *
 *
 * HOW IT IS KNOWN TO BE RIGHT
 *
 * The decompressed length is not stated anywhere in the stream. It does not
 * have to be, because the file states it twice: .themida is the section the
 * loader is decompressed INTO, so its VirtualSize is what must come out.
 *
 * Measured on four samples, two of each width:
 *
 *     PE32+   stream at entry+0x1d4   3481600 of 3481600   (.themida 0x352000)
 *     PE32+   stream at entry+0x1d4   3481600 of 3481600   (.themida 0x352000)
 *     PE32    stream at entry+0x197   3276800 of 3276800   (.themida 0x320000)
 *     PE32    stream at entry+0x197   5120000 of 5120000   (.themida 0x4e2000)
 *
 * Four of four, exactly - not "about" and not "most of". An aPLib stream
 * decoded from the wrong offset fails within a few bytes, and one decoded
 * correctly from the wrong place would have no reason to stop on precisely the
 * number a section header states.
 *
 * The four outputs share 0 to 2% of their 64 byte blocks with one another, so
 * what comes out is specific to each build rather than one runtime repeated.
 *
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not recognise Themida by name, by version, or by anything other than
 * the shape above - the section names are read because the arrangement is what
 * identifies the container, and that is a weaker claim than it looks: a name is
 * free to change, and a build that renames these is one this module misses
 * rather than one it gets wrong. The alternative rules are worse. "The last
 * section holds the entry point and the one before it has no raw data" also
 * describes files this does not handle, and trying the decode on every such
 * file to find out costs a decode.
 *
 * It does not handle the layout with no `.boot`. Of six samples in one
 * collection that carry a `.themida` section, five have the pair this module
 * recognises and one does not: its `.themida` holds the entry point and
 * 3,276,800 bytes of its own, there is no `.boot` at all, and the entry is
 *
 *     55              push ebp
 *     e8 ...          call
 *     5d              pop  ebp
 *     81 ed ...       sub  ebp, imm32
 *
 * which is a position-independent prologue and not the aPLib depacker this
 * module reads. A different build of the protector, and one whose container
 * would have to be measured on its own terms - so the module declines rather
 * than forcing the invariant onto a file it was not measured against.
 *
 * It does not follow the loader to the program. See the top.
 */

#include <kofmod/kofsig.h>
#include <kofmod/heur.h>
#include <kofmod/pe.h>
#include <kofunpack/pe_reassemble.h>

/*
 * A PACKER, AND THE CHILD IS WHERE THE INTERPRETER SHOULD START.
 *
 * This was KOF_ANALYZE_CARVE for a while, and the reason was real: a packer's
 * output sets `packed_here`, the emulator's fallback yields to it, and
 * recovering the loader statically then SUPPRESSED the interpreter on the
 * object it is the only way into.
 *
 * What settled it was measuring where the interpreter actually gets to. Run on
 * the PARENT, it spends between 22 and 44 million instructions decompressing
 * .themida before executing a single byte of it. Run on the CHILD this module
 * produces - the same image with .themida already filled - it reaches THE SAME
 * ADDRESS in 28:
 *
 *     vdr.exe           parent 25,501,035    child 28     both -> 0x600e04
 *     kiskis.exe        parent 22,263,798    child 28     both -> 0x925721
 *     telvm.exe         parent 44,158,819    child 28     both -> 0xba70c5
 *     update_v101.exe   parent 26,319,662    child 28     both -> 0x5b8b88
 *
 * and from there both run the same few million instructions and stop for the
 * same reason. The parent run is the child run with the aPLib decompression
 * done again, interpreted, at about a million instructions per kilobyte.
 *
 * So the packer kind is right after all - the object HAS been opened - and the
 * interpreter is asked for on the child instead, with kunp_emu_want. That is
 * the arrangement bases/unp/mpress_pe.c already uses and for the same reason.
 */
KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("Themida");

/* Where the stream is, measured from the entry point, by stub width. */
#define TH_OFF_64   0x1d4u
#define TH_OFF_32   0x197u

/*
 * Below this a VirtualSize is not a statement. The four samples decompress to
 * between 3.1 and 4.9 MB; a megabyte is far under any of them and still far
 * over anything that could agree with a stream by accident.
 */
#define TH_MIN_OUT  (1u << 20)

/*
 * A section's name against a literal, over the PARSED struct rather than the
 * object's bytes - the parser has already copied and terminated the eight name
 * bytes, so this is plain C on memory the host owns and needs none of the
 * content accessors.
 */
static int sec_is(const struct kof_pe_sec *s, const char *want)
{
	uint32_t i;

	for (i = 0; i < KOF_PE_SECNAME_MAX; i++) {
		if (s->name[i] != want[i])
			return 0;
		if (!want[i])
			return 1;
	}
	return 0;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	const struct kof_pe_sec *boot, *themida;
	uint64_t ep_off, stream, want, got;
	uint32_t i, k, i_boot = 0, i_themida = 0;
	int have_boot = 0, have_themida = 0;

	if (!pe->valid || pe->sec_count < 2u ||
	    pe->entry_sec >= pe->sec_count)
		return;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		if (sec_is(&pe->sec[i], ".boot")) {
			i_boot = i;
			have_boot = 1;
		} else if (sec_is(&pe->sec[i], ".themida") ||
			   sec_is(&pe->sec[i], ".winlice")) {
			/*
			 * TWO NAMES FOR ONE SECTION. Oreans ship the same
			 * engine as Themida and as WinLicense, and the builder
			 * names this section after whichever product wrote it.
			 * The four samples measured here are WinLicense - the
			 * decompressed loader carries "WinLicense" six times
			 * and "SecureEngine" once, and no other vendor string -
			 * so a module that knew only ".themida" was reading
			 * one of the two names its own evidence contradicts.
			 *
			 * Learned from Unlicense's version detection; see
			 * THIRD-PARTY.md.
			 */
			i_themida = i;
			have_themida = 1;
		}
	}
	if (!have_boot || !have_themida)
		return;
	if (i_boot != pe->entry_sec)
		return;                 /* the stub is not where it should be */

	boot    = &pe->sec[i_boot];
	themida = &pe->sec[i_themida];

	/*
	 * .themida IS the declared output size, and its having no file bytes is
	 * half of what says so: a section with a VirtualSize and no raw data is
	 * a region a program intends to fill, which is what this one is for.
	 */
	if (themida->file_size != 0 || themida->mem_size < TH_MIN_OUT)
		return;

	/*
	 * The entry point's offset inside .boot, then the stub's own constant.
	 * Both widths are tried in neither order - the file says which it is.
	 */
	if (pe->entry_rva < boot->mem_rva)
		return;
	ep_off = pe->entry_rva - boot->mem_rva;
	stream = boot->file_off + ep_off +
		 (pe->pe32_plus ? TH_OFF_64 : TH_OFF_32);

	if (!kof_in_obj(stream, 1) ||
	    stream >= boot->file_off + boot->file_size)
		return;

	want = themida->mem_size;

	kof_debug("Themida.PE.out", (uint32_t)(want >> 10));
	kof_debug("Themida.PE.bits", pe->pe32_plus ? 64u : 32u);

	/*
	 * THE IMAGE AND NOT THE BLOB, for the reason pe_reassemble.h gives.
	 *
	 * What comes out of .boot is the contents of .themida, which is one
	 * section of an image the file already describes - so handed over on
	 * its own it is 3 to 5 MB that identifies as nothing: measured,
	 * kofexaminer reported "format unrecognised, 3481600 bytes". Put back
	 * where it belongs, beside the sections the parent already has, it is
	 * a PE with regions, an import table and an entry point.
	 *
	 * THE ENTRY POINT IS THE PARENT'S, unchanged. Themida's stub is where
	 * execution starts and the child has it; where the protected program
	 * starts is decided at run time by the loader and is not in the file,
	 * so claiming any other address would be inventing one. The cost is
	 * that running this child repeats the aPLib decompression the module
	 * just did, which is a megabyte and a half of work and no risk of
	 * being wrong.
	 */
	/*
	 * ---- THE LAYOUT, THEN THE IMAGE --------------------------------------
	 *
	 * Addresses and extents, with the alignment tail of each section said to
	 * be padding rather than left inside it - and no tail after the last
	 * one, which would be past the final claim and would read as an overlay
	 * on a file that has none.
	 *
	 * What each section IS is said below, once there is something to look
	 * at. Themida's own answer to that is unusual and worth having: its
	 * program sections stay at 8.00 bits per byte and the loader never
	 * writes into them across 267 M instructions, so what this module can
	 * honestly say about them is that they are still ciphertext.
	 */
	for (k = 0; k < pe->sec_count && k < KOF_PE_MAX_SECTIONS; k++) {
		const struct kof_pe_sec *t = &pe->sec[k];

		if (kunp_rcstruct_section(t->name, t->mem_rva, t->mem_size,
				    kof_pe_perm_decl(t->perm),
				    KOF_SECF_DATA | KOF_SECF_READ) < 0)
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		if (pei_span(t) > t->mem_size && k + 1u < pe->sec_count &&
		    kunp_rcstruct_section("", t->mem_rva + t->mem_size,
				    pei_span(t) - t->mem_size,
				    kof_pe_perm_decl(t->perm),
				    KOF_SECF_PAD | KOF_SECF_READ) < 0)
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
	}
	if (!kunp_rcstruct_image())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	kunp_rcstruct_entry(pe->entry_rva);
	/*
	 * AND THE DIRECTORIES THE PARENT DECLARED, WHICH THIS DOES NOT MOVE.
	 *
	 * Every section keeps its RVA here - the reconstruction differs from
	 * the file only in that `.themida` now HAS its bytes - so the import,
	 * IAT and resource directories point where they always did.
	 *
	 * WITHOUT THIS THE LOADER CANNOT CALL ANYTHING, and the failure is
	 * silent and precise. The host binds a child's import thunks before
	 * the run so the guest's calls resolve, and it finds them through the
	 * import directory; a child with no directory gets `iat filled=0`, the
	 * thunks keep the RVAs an unbound table holds, and the first call
	 * through one jumps to that RVA as if it were an address. Measured on
	 * three samples, the run ended at `.idata` RVA plus thirteen -
	 * 0xfa00d, 0x7600d, 0x40e00d - which is a pointer to an import NAME
	 * being executed.
	 */
	{
		static const uint32_t carry[] = {
			KOF_PE_DIR_IMPORT, KOF_PE_DIR_IAT, KOF_PE_DIR_RESOURCE
		};
		uint32_t d;

		for (d = 0; d < sizeof carry / sizeof carry[0]; d++)
			if (pe->dir[carry[d]].rva)
				kunp_rcstruct_dir(carry[d],
						  pe->dir[carry[d]].rva,
						  pe->dir[carry[d]].size);
	}

	got = 0;
	for (k = 0; k < pe->sec_count && k < KOF_PE_MAX_SECTIONS; k++) {
		const struct kof_pe_sec *t = &pe->sec[k];
		uint64_t span = pei_span(t), wrote;

		if (!kunp_rcstruct_at(t->mem_rva))
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		if (k == i_themida) {
			/*
			 * The fourth argument is the SIZE HINT, and
			 * KOF_FORM_RAW used to be a fifth: the form a
			 * child took was a parameter, and it is now a
			 * declaration - the sections above say what
			 * this is. See `unpack` in kofsig.h.
			 */
			wrote = kunp_static_decode(
				KOF_UNP_APLIB, stream,
				boot->file_off + boot->file_size - stream,
				want);
			got = wrote;
		} else {
			wrote = t->file_size;
			if (wrote > span)
				wrote = span;
			if (wrote && !pei_copy(ctx, t->file_off, wrote))
				kunp_rcstruct_broken(KOF_UNP_LIMIT);
		}
	}

	/*
	 * AND WHAT IS ACTUALLY THERE, read back one section at a time.
	 *
	 * The one thing this module has always known and never been able to
	 * say: the program sections are still ENCIPHERED. Measured on two
	 * samples, they hold 8.00 bits per byte before the run and 8.00 after
	 * it - the loader decrypts them somewhere this engine does not reach.
	 * Reported as data, they look like data nobody found anything in;
	 * reported as ciphertext, they say what is actually the case and why
	 * the object is not finished.
	 */
	for (k = 0; k < pe->sec_count && k < KOF_PE_MAX_SECTIONS; k++) {
		const struct kof_pe_sec *t = &pe->sec[k];
		uint32_t f = (t->perm & KOF_PE_PERM_X) ? KOF_SECF_CODE
						       : KOF_SECF_DATA;

		if (k == i_themida)
			f |= KOF_SECF_REBUILT;
		else if (t->mem_size >= 0x1000u &&
			 kof_entropy_at(t->file_off, t->file_size) >= 63u)
			f |= KOF_SECF_CIPHERTEXT | KOF_SECF_READ;
		else
			f |= KOF_SECF_READ;
		if (kunp_rcstruct_section(t->name, t->mem_rva, t->mem_size,
				    t->perm, f) < 0)
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
	}
	if (got == 0) {
		/*
		 * The arrangement matched and the stream did not decode. That
		 * is a build this module does not reach - a moved stream, or a
		 * coding changed under the same section names - and it is the
		 * one thing here that must not be reported as a clean file.
		 */
		KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
	}

	/*
	 * AND THE CHILD IS WHAT TO RUN. See the kind above for the measurement:
	 * the child starts where the parent arrives after tens of millions of
	 * instructions, so this is the same request made tens of millions of
	 * instructions cheaper.
	 */
	/*
	 * THE RUN IS NOT ASKED FOR, AND THAT IS A MEASUREMENT.
	 *
	 * The child was handed to the interpreter for a long time and the
	 * numbers never justified it. Two real faults were found and fixed on
	 * the way - this reconstruction had no import directory, so the host
	 * could not bind a thunk and the first call jumped to an RVA; and
	 * VirtualAlloc succeeded over a mapped library image, which Windows
	 * refuses and which this protector probes for deliberately. Each fix
	 * bought distance:
	 *
	 *     kiskis    378,361 -> 16,963,436 -> 25,842,536 instructions
	 *     vdr       334,806 -> 14,914,139 -> 22,964,999
	 *
	 * and NOT ONE of them bought a byte of program. The run still ends in
	 * the loader building a pointer out of a table it has not initialised,
	 * every sample's code section stays at 8.00 bits, and what comes back
	 * is one 8 KB page. Seventy times the instructions for the same
	 * nothing: four seconds across the corpus, and the whole of a Themida
	 * file's scan time.
	 *
	 * SO THE STATIC HALF STAYS AND THE RUN GOES. Decompressing `.themida`
	 * recovers the loader, which is real content, costs nothing and is
	 * worth searching - and the object is still reported as not fully
	 * examined, which is the honest answer about the program beside it.
	 *
	 * WHAT WOULD BRING IT BACK is a run that produces a decrypted section.
	 * The walls are recorded in the memory notes and in THIRD-PARTY.md;
	 * the next one is the uninitialised table at rbp+0x21, reached at
	 * rip 0x4b2cef. Until that is answered this is a capability test, not
	 * a scanner feature.
	 */

	/*
	 * AND WHERE THE PROGRAM WILL BE, FOR THE INTERPRETER.
	 *
	 * Everything that is not this protector's own two sections. The loader
	 * decrypts those sections in memory and jumps into one of them, and
	 * that jump is the moment the image is worth taking - so the run is
	 * told to end there rather than to carry on executing the program.
	 *
	 * ONLY A MODULE CAN SAY THIS. The structural rule the host falls back
	 * on - a section the file declares and supplies no bytes for - is the
	 * exact opposite here: `.themida` is the hollow one and it holds the
	 * LOADER, while the program sits in the sections that do have bytes,
	 * encrypted. A host applying that rule to this container stops the run
	 * on the loader's first instruction.
	 *
	 * The idea of watching where the program will be, rather than
	 * following what the loader does, is Unlicense's - see THIRD-PARTY.md.
	 */
	/*
	 * AND NOT THE SECTIONS A LOADER ENTERS ON PURPOSE.
	 *
	 * "Everything that is not the protector's own two" was too much, and
	 * the measurement says exactly how: on kiskis.exe the run ended after
	 * 378,361 instructions, "handed over at 0x40e00d", which is thirteen
	 * bytes into `.idata`. That is an import thunk. Themida's loader binds
	 * imports and jumps through them long before it has finished
	 * decrypting anything, so the watch fired on the loader doing its job
	 * and the program was still ciphertext - measured, its 4 MB code
	 * section sat at 8.00 bits.
	 *
	 * BY DIRECTORY AND NOT BY NAME. `.idata` and `.rsrc` are conventions;
	 * the import, IAT and resource DIRECTORIES are what the file actually
	 * declares, and a protector that renames a section does not move them.
	 * A section holding any of the three is a section a loader reaches into
	 * as a matter of course, so arriving there says nothing about the
	 * program having started.
	 */
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *t = &pe->sec[i];
		int is_loader_furniture = 0;
		uint32_t d;
		static const uint32_t furniture[] = {
			KOF_PE_DIR_IMPORT, KOF_PE_DIR_IAT, KOF_PE_DIR_RESOURCE
		};

		if (i == i_themida || i == i_boot || !t->mem_size)
			continue;
		for (d = 0; d < sizeof furniture / sizeof furniture[0]; d++) {
			uint64_t rva = pe->dir[furniture[d]].rva;

			if (rva && rva >= t->mem_rva &&
			    rva - t->mem_rva < t->mem_size)
				is_loader_furniture = 1;
		}
		if (is_loader_furniture)
			continue;
		kunp_emu_oep_range(t->mem_rva, t->mem_size);
	}


	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);

	/*
	 * SHORT OF THE SECTION'S OWN NUMBER IS A FINDING, and a stronger one
	 * here than in most of this directory: nothing in the stream declares a
	 * length, so this comparison is the only check that the offset was
	 * right at all. A decode that stops early decoded something else.
	 */
	if (got < want)
		kunp_rcstruct_broken(KOF_UNP_DAMAGED);

	/*
	 * AND THE OBJECT IS STILL NOT EXAMINED, WHICH HAS TO BE SAID OUT LOUD.
	 *
	 * What this recovered is the loader. The program the loader exists to
	 * decrypt is in the sections beside it and is still ciphertext - and a
	 * child that identifies as "PE x64 EXE, 5910528 bytes" reads, to
	 * anything and anyone downstream, as a program that was recovered. It
	 * is not one. Its executable sections are the same encrypted bytes the
	 * parent had; only .themida is content this module produced.
	 *
	 * So the object is reported not fully examined, with the reason that is
	 * true of it. A scan then says "encrypted content" about the file
	 * rather than "clean", which is the difference between a finding and a
	 * silence - and the reconstruction stays, because the loader is worth
	 * searching and the regions are worth having.
	 *
	 * RECORDED AND CARRIED ON, not KUNP_RCSTRUCT_BROKEN: the child was produced
	 * and handed over, and this is a statement about what is left rather
	 * than about a failure.
	 */
	kunp_rcstruct_broken(KOF_UNP_ENCRYPTED);
}
