/*
 * probe_read_00.c - a detector that reports nothing and notes what the host's
 * read slots answer, so a test can compare each answer with the bytes it put
 * there.
 *
 * It is the module-side half of tests/unit/api_engine_modabi.c: the slots of
 * struct kof_content that read the object (rd8..rd64, memeq, csum, the string
 * searches, the entropy and shape measures, fmt_wanted) are implemented by the
 * engine and reached only through a module, so the only way to exercise one is to
 * be one. The module fires on the eight bytes "KOFPRB01" at offset 0 and then
 * asks the questions; every answer leaves as a note (kof_debug), which the host
 * hands to kscan_on_debug before any finding. Nothing here is a detection: no
 * rule ever reports, so no scan of anything else changes.
 *
 * The questions include the ones an author gets wrong: an offset past the end,
 * a length that would wrap, a read that straddles the end, offsets at 2^63 and
 * 2^64-1. The contract (kofread.h) is that an out of range read is zero and a
 * compare past the end is false - never a read of something else.
 */

#include <kofmod/kofsig.h>

KOF_TARGET_FORMAT(KOF_FMT_ANY);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "ProbeRead");

KOF_DEFINE_STR(magic, "KOFPRB01", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
KOF_DEFINE_STR(needle, "NEEDLE-XYZ", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	static const uint8_t pat_ok[2] = { 0x10, 0x11 };
	static const uint8_t pat_bad[2] = { 0x10, 0x12 };
	struct kof_region_shape sh;
	uint64_t n = ctx->obj_size;
	uint64_t where;

	if (!kof_find_str_at(0u, magic))
		return;

	kof_debug("Probe.size", n);
	kof_debug("Probe.u8", kof_u8(8));
	kof_debug("Probe.u16", kof_u16(8));
	kof_debug("Probe.u32", kof_u32(8));
	kof_debug("Probe.u64", kof_u64(8));
	kof_debug("Probe.u8.last", kof_u8(n - 1u));
	kof_debug("Probe.u8.end", kof_u8(n));
	kof_debug("Probe.u16.straddle", kof_u16(n - 1u));
	kof_debug("Probe.u32.straddle", kof_u32(n - 3u));
	kof_debug("Probe.u64.straddle", kof_u64(n - 7u));
	kof_debug("Probe.u64.last", kof_u64(n - 8u));
	kof_debug("Probe.u8.max", kof_u8(0xffffffffffffffffull));
	kof_debug("Probe.u64.max", kof_u64(0xffffffffffffffffull));
	kof_debug("Probe.u32.wrap", kof_u32(0xfffffffffffffffeull));
	kof_debug("Probe.u8.2p63", kof_u8(0x8000000000000000ull));
	kof_debug("Probe.u8.2p32", kof_u8(0x100000000ull));

	kof_debug("Probe.memeq.ok", kof_memeq(8, pat_ok, 2));
	kof_debug("Probe.memeq.bad", kof_memeq(8, pat_bad, 2));
	kof_debug("Probe.memeq.straddle", kof_memeq(n - 1u, pat_ok, 2));
	kof_debug("Probe.memeq.hugelen", kof_memeq(8, pat_ok, 0xffffffffu));
	kof_debug("Probe.memeq.max", kof_memeq(0xffffffffffffffffull, pat_ok, 1));
	kof_debug("Probe.memeq.wrap", kof_memeq(0xfffffffffffffffeull, pat_ok, 2));
	kof_debug("Probe.memeq.zero", kof_memeq(8, pat_ok, 0));

	kof_debug("Probe.csum.8", kof_csum(8, 8));
	kof_debug("Probe.csum.all", kof_csum(0, n));
	kof_debug("Probe.csum.straddle", kof_csum(n - 2u, 5));
	kof_debug("Probe.csum.hugelen", kof_csum(8, 0xffffffffu));
	kof_debug("Probe.csum.max", kof_csum(0xffffffffffffffffull, 4));
	kof_debug("Probe.csum.zero", kof_csum(8, 0));

	kof_debug("Probe.in.hit", kof_find_str_in(0, 64, needle));
	kof_debug("Probe.in.short", kof_find_str_in(0, 10, needle));
	kof_debug("Probe.in.past", kof_find_str_in(n, 64, needle));
	kof_debug("Probe.in.wrap", kof_find_str_in(8, 0xffffffffffffffffull, needle));
	kof_debug("Probe.in.max", kof_find_str_in(0xffffffffffffffffull, 4, needle));
	kof_debug("Probe.at.hit", kof_find_str_at(24, needle));
	kof_debug("Probe.at.miss", kof_find_str_at(25, needle));
	kof_debug("Probe.at.past", kof_find_str_at(n, needle));
	kof_debug("Probe.at.straddle", kof_find_str_at(n - 3u, needle));
	where = kof_find_str_where(0, n, needle);
	kof_debug("Probe.where.hit", where);
	kof_debug("Probe.where.window", kof_find_str_where(25, 40, needle));
	kof_debug("Probe.where.broken", kof_find_str_where(25, 8, needle) == KOF_BROKEN);
	kof_debug("Probe.where.past", kof_find_str_where(n, 8, needle) == KOF_BROKEN);
	kof_debug("Probe.where.wrap", kof_find_str_where(8, 0xffffffffffffffffull, needle));

	kof_debug("Probe.entropy.flat", kof_entropy_at(40, 16));
	kof_debug("Probe.entropy.zero", kof_entropy_at(n - 32u, 32));
	kof_debug("Probe.entropy.past", kof_entropy_at(n, 16));
	kof_debug("Probe.entropy.wrap", kof_entropy_at(8, 0xffffffffffffffffull));
	kof_debug("Probe.entropy.max", kof_entropy_at(0xffffffffffffffffull, 16));
	kof_debug("Probe.entropy.region", kof_region_entropy(KOF_SCAN_ALL));
	kof_debug("Probe.entropy.nomask", kof_region_entropy(0));

	kof_debug("Probe.shape.ok", kof_region_shape(KOF_SCAN_ALL, &sh));
	kof_debug("Probe.shape.bytes", sh.bytes);
	kof_debug("Probe.shape.runs", sh.runs);
	kof_debug("Probe.shape.widest", sh.widest);
	kof_debug("Probe.shape.widest_off", sh.widest_off);
	kof_debug("Probe.shape.nomask", kof_region_shape(0, &sh));

	kof_debug("Probe.fmt.zip", kof_fmt_wanted(KOF_FMT_ZIP));
	kof_debug("Probe.fmt.elf", kof_fmt_wanted(KOF_FMT_ELF));
	kof_debug("Probe.fmt.bogus", kof_fmt_wanted(250));
}
