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
 * no module and come back "no module targets this format". kof_wrap_elf builds
 * the minimal container that makes the payload reachable, and puts it in a
 * writable non-executable segment so it lands in region DATA - the same region
 * it occupies inside the loader, so ONE DATA-scoped signature reaches both.
 * That last point is the reason for the whole file: a signature written for the
 * payload in the parent needs no second signature for the payload here.
 */
#include <kofmod/kofsig.h>
#include <kofmod/wrap.h>
#include "scfind.h"

/*
 * A PACKER, not a container.
 *
 * A container holds files that were separately there - a zip, a tar. This
 * produces one object out of one, which is what a packer does, and it is what
 * makes the child count as a layer of packing for the depth limit.
 */
KOF_UNPACK_KIND(KOF_UNP_PACKER);
KOF_TARGET_FORMAT(KOF_FMT_ELF);

KOF_DEFINE_UNPACK
{
	uint8_t dec[SCL_SIZE_MAX];
	uint8_t hdr[KOF_WRAP_ELF_MAX];
	struct scf_hit h;
	uint32_t hn, len, done = 0;

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

	/*
	 * THE WIDTH FOLLOWS THE PAYLOAD, and 64 only where nothing said
	 * otherwise. A 64-bit loader routinely carries 32-bit shellcode, so
	 * taking the parent's class would disassemble an x86 stub as amd64 and
	 * name the object's architecture wrongly - and the architecture is a
	 * precondition every signature is filtered by.
	 */
	hn = kof_wrap_elf(hdr, len, h.bits ? h.bits : 64u);
	if (!kof_emit(hdr, hn))
		return;
	/*
	 * Copied a window at a time rather than in one call: kof_u8 is the only
	 * way to read the object, and the engine may stop accepting at any
	 * point - the budget is its decision, not this module's.
	 */
	if (h.dec_n) {
		if (!kof_emit(dec, h.dec_n))
			return;
	} else {
		while (done < len) {
			uint8_t buf[256];
			uint32_t n = 0;

			while (n < sizeof buf && done + n < len) {
				buf[n] = kof_u8(h.at + done + n);
				n++;
			}
			if (!kof_emit(buf, n))
				return;
			done += n;
		}
	}
	kof_child();
}
