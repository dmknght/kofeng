/*
 * scpayload_00.c - the blob a shellcode loader carries, as an object of its own.
 *
 * WHY THIS EXISTS AT ALL. bases/heur/scloader_00.c finds the payload and says
 * where it is. That was the whole of it for a while, and it left the bytes
 * unscanned by anything: a debug fact is not an object, no module is offered
 * one, and the scanner walked past a cleartext execve("/bin/sh") stub while
 * reporting only the loader around it. kofviewer worked around it by carving
 * the payload out of the debug value for its own pane - which fixed the pane
 * and left the scanner exactly as blind as before.
 *
 * An unpacker, because in this engine only an unpacker yields children. The
 * search is shared with the heuristic rather than repeated - see scfind.h.
 *
 * THE PAYLOAD IS WRAPPED, not emitted bare. A blob is not a file: every rule
 * declares a format and scopes itself to a region, so bare bytes are offered to
 * no module and come back "no module targets this format". The container is
 * what makes the payload reachable.
 *
 *
 * WHAT THE CONTAINER HAS TO BE, and every one of these was paid for once:
 *
 *   - A WRITABLE, NON-EXECUTABLE SEGMENT, so the payload lands in region DATA.
 *     In the PARENT it is in .data, so region DATA, and one DATA-scoped rule
 *     then reaches both - the un-encoded payload sitting in the loader's
 *     variable, and the decoded payload here. Nine of twelve samples measured
 *     are already matchable in the parent that way, with no reconstruction at
 *     all, and the point is that the SAME rule does both.
 *   - NO ENTRY POINT. An entry point inside a non-executable segment raises
 *     KOF_ELF_ANOM_ENTRY_NOT_EXEC, which kof_emu_unp_gate reads as
 *     "unloadable" and would hand every reconstructed child to the interpreter
 *     for nothing. A blob lifted out of a variable HAS no entry point; nothing
 *     ever jumped to its first byte.
 *   - AND THEREFORE ET_DYN. ET_EXEC with e_entry 0 is a contradiction the
 *     parser objects to, correctly, with KOF_ELF_ANOM_ENTRY_ZERO.
 *   - NOT AN RWX SEGMENT WITH THE ENTRY ON IT. That shape lands the payload in
 *     CODE and is byte for byte what bases/heur/shellcode_00.c looks for - no
 *     section table, one program header, one executable PT_LOAD that is the
 *     whole file. Measured: the engine flagged its own reconstruction as an
 *     msfvenom template.
 *   - THE WIDTH FOLLOWS THE PAYLOAD, not the parent. A 64-bit loader routinely
 *     carries 32-bit shellcode, so taking the parent's class would disassemble
 *     an x86 stub as amd64 - and the architecture is a precondition every
 *     signature is filtered by.
 *
 *
 * IT USED TO BUILD THAT HEADER ITSELF, through kof_wrap_elf, and it was the
 * last module in the tree still doing so. The header was handed over with
 * kunp_rcstruct_write like any other content, which is the round trip the
 * declaration mechanism exists to end: nothing in the engine knew those bytes
 * were a header, so the child's first 0x78 were content like the rest and the
 * layout this module knew exactly had to be recovered by parsing back what
 * this module had just written.
 *
 * WHAT HELD IT UP was the second bullet above. The engine's ELF writer wrote
 * ET_EXEC unconditionally, so "no entry point" was not expressible as a
 * declaration at all and a module that needed it had no choice but to write
 * its own bytes. The writer now takes ET_DYN when nothing declared an entry;
 * see the note beside it in elf_rebuild.c. Every property in the list above is
 * now said rather than assembled, and the bytes are the same.
 */
#include <kofmod/kofsig.h>
#include <kofanalyze/scfind.h>

/*
 * A PACKER, not a container.
 *
 * A container holds files that were separately there - a zip, a tar. This
 * produces one object out of one, which is what a packer does, and it is what
 * makes the child count as a layer of packing for the depth limit.
 */
KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);
KOF_TARGET_FORMAT(KOF_FMT_ELF);

KOF_DEFINE_UNPACK
{
	uint8_t dec[SCL_SIZE_MAX];
	struct scf_hit h;
	uint32_t len, done = 0, hdr;

	if (!scf_find(ctx, &h, dec, sizeof dec))
		return;
	/*
	 * The decoded bytes when there were any, the object's own otherwise.
	 * A base64 payload emitted as its text would be a child nothing can
	 * match: the machine code is what a signature is written against.
	 */
	len = h.dec_n ? h.dec_n : (uint32_t)h.len;
	if (!len || len > SCL_SIZE_MAX)
		return;

	hdr = (h.bits == 32u) ? KUNP_HDR_ELF32 : KUNP_HDR_ELF64;
	if (kunp_rcstruct_section(".data", hdr, len,
				  KUNP_PERM_R | KUNP_PERM_W,
				  KOF_SECF_DATA | KOF_SECF_REBUILT) < 0)
		return;
	/*
	 * Base zero, which is not a default but the answer. These bytes were
	 * never loaded anywhere: they sat in a variable inside another program,
	 * and any address put on them here would be invented.
	 *
	 * No kunp_rcstruct_entry, which is what makes this ET_DYN - see the
	 * list at the top.
	 */
	kunp_rcstruct_as(KOF_FMT_ELF,
			 h.bits == 32u ? KOF_ARCH_X86 : KOF_ARCH_X86_64, 0);
	if (!kunp_rcstruct_image() || !kunp_rcstruct_at(hdr))
		return;

	/*
	 * Copied a window at a time rather than in one call: kof_u8 is the only
	 * way to read the object, and the engine may stop accepting at any
	 * point - the budget is its decision, not this module's.
	 */
	if (h.dec_n) {
		if (!kunp_rcstruct_write(dec, h.dec_n))
			return;
	} else {
		while (done < len) {
			uint8_t buf[256];
			uint32_t n = 0;

			while (n < sizeof buf && done + n < len) {
				buf[n] = kof_u8(h.at + done + n);
				n++;
			}
			if (!kunp_rcstruct_write(buf, n))
				return;
			done += n;
		}
	}
	kunp_rcstruct_done();
}
