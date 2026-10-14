/*
 * probe_unpack_00.c - an unpacker that exercises the child-making slots of the
 * module ABI and notes what each one answered.
 *
 * Companion of probe_read_00.c, for the other half of struct kof_content: the slots
 * a module uses to MAKE objects (window, write, done, kind, format, name, note,
 * build, the static decoders, the produced-bytes read and poke, gather, broken).
 * It fires on the eight bytes "KOFPRB02" at offset 0, and the byte at offset 8
 * says which family of slots this scan exercises, so that each scan has one
 * observable outcome and a failure names the slot rather than a mix.
 *
 * What it declares is Raw only, and what it needs is the marker, so it opens
 * nothing else; it names a content so that a child it makes is credited to it
 * ("Probe"). Nothing here is a detection.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);
KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);
KOF_TARGET_CONTENT("Probe");

KOF_DEFINE_STR(magic, "KOFPRB02", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_UNPACK
{
	static const uint8_t abc[3] = { 'A', 'B', 'C' };
	static const uint8_t xy[2] = { 'x', 'y' };
	static const uint8_t zz[2] = { 'z', 'z' };
	uint8_t buf[32];
	uint64_t n = ctx->obj_size, packed = 0, r;
	uint32_t got, i;

	if (!kof_find_str_at(0u, magic))
		return;

	switch (kof_u8(8)) {
	case 1:
		kof_debug("Probe.window.a", kunp_rcstruct_window(16, 20));
		kof_debug("Probe.window.b", kunp_rcstruct_window(40, 8));
		kof_debug("Probe.window.past", kunp_rcstruct_window(n, 4));
		kof_debug("Probe.window.max", kunp_rcstruct_window(0xffffffffffffffffull, 4));
		kof_debug("Probe.window.empty", kunp_rcstruct_window(8, 0));
		kof_debug("Probe.window.wrap", kunp_rcstruct_window(48, 0xffffffffffffffffull));
		break;
	case 2:
		kof_debug("Probe.write.a", kunp_rcstruct_write(abc, 3));
		kof_debug("Probe.write.b", kunp_rcstruct_write(abc, 3));
		kof_debug("Probe.write.zero", kunp_rcstruct_write(abc, 0));
		kunp_rcstruct_kind(KOF_ENT_SCRIPT);
		kunp_rcstruct_format(KOF_FMT_SCRIPT);
		kunp_rcstruct_name(26, 6);
		kunp_rcstruct_build("9.99");
		kof_debug("Probe.done", kunp_rcstruct_done());
		break;
	case 3:
		kof_debug("Probe.write.note", kunp_rcstruct_write(abc, 3));
		kunp_rcstruct_note("noted");
		kof_debug("Probe.done.note", kunp_rcstruct_done());
		break;
	case 4:
		r = kunp_static_decode(KOF_UNP_DEFLATE, 16, 10, 0);
		kof_debug("Probe.decode", r);
		kof_debug("Probe.decode.bad", kunp_static_decode(KOF_UNP_DEFLATE, n, 10, 0));
		kof_debug("Probe.decode.wrap", kunp_static_decode(KOF_UNP_DEFLATE, 16, 0xffffffffffffffffull, 0));
		kof_debug("Probe.decode.unknown", kunp_static_decode(0xffffu, 16, 10, 0));
		kof_debug("Probe.done.decode", kunp_rcstruct_done());
		break;
	case 5:
		/* a stored LZMA2 chunk at 40: control 01, size-1 big endian, data, end 00 */
		got = kunp_static_peek(KOF_UNP_LZMA2, 40, 9, buf, sizeof buf);
		kof_debug("Probe.peek", got);
		kof_debug("Probe.peek.first", buf[0]);
		kof_debug("Probe.peek.short", kunp_static_peek(KOF_UNP_LZMA2, 40, 9, buf, 2));
		kof_debug("Probe.peek.past", kunp_static_peek(KOF_UNP_LZMA2, n, 9, buf, sizeof buf));
		kof_debug("Probe.peek.nocap", kunp_static_peek(KOF_UNP_LZMA2, 40, 9, buf, 0));
		kof_debug("Probe.peek.deflate", kunp_static_peek(KOF_UNP_DEFLATE, 16, 10, buf, sizeof buf));
		kof_debug("Probe.peek.child", kunp_opened_already());
		break;
	case 6:
		kunp_rcstruct_write("ABCDEF", 6);
		kof_debug("Probe.poke.ok", kunp_rcstruct_poke(2, xy, 2));
		kof_debug("Probe.poke.end", kunp_rcstruct_poke(5, zz, 2));
		kof_debug("Probe.poke.zero", kunp_rcstruct_poke(0, xy, 0));
		kof_debug("Probe.poke.past", kunp_rcstruct_poke(6, xy, 1));
		kof_debug("Probe.poke.max", kunp_rcstruct_poke(0xffffffffffffffffull, xy, 2));
		got = kunp_rcstruct_read(0, buf, 6);
		kof_debug("Probe.read", got);
		for (i = 0; i < 6; i++)
			packed |= (uint64_t)buf[i] << (8u * i);
		kof_debug("Probe.read.bytes", packed);
		kof_debug("Probe.read.tail", kunp_rcstruct_read(4, buf, 100));
		kof_debug("Probe.read.end", kunp_rcstruct_read(6, buf, 4));
		kof_debug("Probe.read.max", kunp_rcstruct_read(0xffffffffffffffffull, buf, 4));
		kof_debug("Probe.read.nocap", kunp_rcstruct_read(0, buf, 0));
		kunp_rcstruct_done();
		break;
	case 7:
		kof_debug("Probe.opened.before", kunp_opened_already());
		kunp_rcstruct_window(16, 4);
		kof_debug("Probe.opened.after", kunp_opened_already());
		break;
	case 8:
		kunp_rcstruct_broken(KOF_UNP_DAMAGED);
		break;
	case 9:
		kunp_rcstruct_broken(99);
		break;
	case 10:
		kof_debug("Probe.gather", kunp_static_gather(KOF_SCAN_ALL, 0));
		kof_debug("Probe.gather.nomask", kunp_static_gather(0, 0));
		kof_debug("Probe.done.gather", kunp_rcstruct_done());
		break;
	case 11:
		kunp_rcstruct_write(abc, 3);
		kunp_rcstruct_supersedes();
		kunp_rcstruct_done();
		break;
	case 12:
		kof_debug("Probe.lzma2", kunp_static_decode(KOF_UNP_LZMA2, 40, 9, 5));
		kof_debug("Probe.lzma2.hint0", kunp_static_decode(KOF_UNP_LZMA2, 40, 9, 0));
		kof_debug("Probe.done.lzma2", kunp_rcstruct_done());
		break;
	default:
		break;
	}
}
