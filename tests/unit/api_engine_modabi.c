/*
 * api_engine_modabi.c - the vtable of struct kof_content (the module ABI), driven
 * through probe modules built from tests/sigs/probe_*.c.
 *
 * A module is a freestanding blob that can reach the host through one table of
 * function pointers (kofcontent.h). The host implements every slot; a module is
 * the only caller; so the only way to test a slot is to be a module. Each probe
 * fires on a magic at offset 0 of the object this test builds, asks its questions
 * of the slots, and leaves every answer as a note (kof_debug) that the host
 * delivers to kscan_on_debug. The test compares each answer with the same
 * computation done here, from the bytes it wrote.
 *
 *   probe_read_00     rd8..rd64, memeq, csum, the string searches, entropy_at,
 *                     region_entropy, region_shape, fmt_wanted - and for each the
 *                     hostile argument: past the end, straddling it, 2^63, 2^64-1,
 *                     a length that would wrap
 *   probe_unpack_00   window, emit (write), child (done), child kind/format/name/
 *                     note/build, the static decoders (decode, peek), the produced
 *                     bytes (read, poke), opened_already, incomplete (broken),
 *                     gather, supersede - one family per scan, picked by a byte of
 *                     the object, so a failure names the slot
 *   probe_crypt_00    capsid_apply, decrypt_peek and decrypt for every cipher of
 *                     kofdecode.h, with the descriptors a module may get wrong: key
 *                     length 0, a NULL key with a length, an unknown algorithm
 *   probe_entry_00    unpack_entry and child_entry on a cabinet's parsed entries,
 *                     with an entry that does not exist and a size hint of 2^64-1
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <sys/stat.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../../libkofeng/kofcore/kofentropy.h"
#include "hostile_engine_seeds.h"

#include <kofmod/kofsig.h>

#define DB_SIGS "build/test/databases-sigs"

struct notes {
	char     what[96][40];
	uint64_t val[96];
	unsigned n;
};

static void on_note(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct notes *a = (struct notes *)user;

	/* the engine's own "which diagnose was called" facts (objctx_diag_trace.c) are not
	 * a module's notes; tests/unit/diag_trace.c pins them */
	if (fact == kverdict_fact_id("diag"))
		return;
	if (a->n < 96) {
		snprintf(a->what[a->n], sizeof a->what[0], "%s", what);
		a->val[a->n] = value;
	}
	a->n++;
}

static int has(const struct notes *a, const char *what)
{
	unsigned i;

	for (i = 0; i < a->n && i < 96; i++)
		if (!strcmp(a->what[i], what))
			return 1;
	return 0;
}

static uint64_t get(const struct notes *a, const char *what)
{
	unsigned i;

	for (i = 0; i < a->n && i < 96; i++)
		if (!strcmp(a->what[i], what))
			return a->val[i];
	return 0xdeadbeefdeadbeefull;
}

#define EXPECT(what, want) CK(has(&a, what) && get(&a, what) == (uint64_t)(want), \
	"%s: %llu, expected %llu", what, (unsigned long long)get(&a, what), (unsigned long long)(want))

static void t_probe_read(kof_engine *e)
{
	uint8_t o[128];
	struct notes a;
	kof_scanner *sc = kscan_new(e);
	struct kof_scan_option op;
	unsigned i;
	uint64_t last8 = 0;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	memset(o, 0x41, sizeof o);
	memcpy(o, "KOFPRB01", 8);
	for (i = 0; i < 16; i++)
		o[8 + i] = (uint8_t)(0x10 + i);
	memcpy(o + 24, "NEEDLE-XYZ", 10);
	for (i = 0; i < 16; i++)
		o[40 + i] = (uint8_t)i;
	memset(o + 96, 0, 16);
	for (i = 0; i < 16; i++)
		o[112 + i] = (uint8_t)(0xc0 + i);
	for (i = 0; i < 8; i++)
		last8 |= (uint64_t)o[120 + i] << (8u * i);

	memset(&a, 0, sizeof a);
	memset(&op, 0, sizeof op);
	kscan_on_debug(sc, on_note, &a);
	CK(kscan_bytes(sc, o, sizeof o, "probe", &op, NULL, NULL) == 1, "the object scans");
	CK(a.n >= 55, "the probe answered (%u notes)", a.n);

	EXPECT("Probe.size", 128);
	EXPECT("Probe.u8", 0x10);
	EXPECT("Probe.u16", 0x1110);
	EXPECT("Probe.u32", 0x13121110u);
	EXPECT("Probe.u64", 0x1716151413121110ull);
	EXPECT("Probe.u8.last", 0xcf);
	EXPECT("Probe.u8.end", 0);
	EXPECT("Probe.u16.straddle", 0);
	EXPECT("Probe.u32.straddle", 0);
	EXPECT("Probe.u64.straddle", 0);
	EXPECT("Probe.u64.last", last8);
	EXPECT("Probe.u8.max", 0);
	EXPECT("Probe.u64.max", 0);
	EXPECT("Probe.u32.wrap", 0);
	EXPECT("Probe.u8.2p63", 0);
	EXPECT("Probe.u8.2p32", 0);

	EXPECT("Probe.memeq.ok", 1);
	EXPECT("Probe.memeq.bad", 0);
	EXPECT("Probe.memeq.straddle", 0);
	EXPECT("Probe.memeq.hugelen", 0);
	EXPECT("Probe.memeq.max", 0);
	EXPECT("Probe.memeq.wrap", 0);
	EXPECT("Probe.memeq.zero", 1);

	EXPECT("Probe.csum.8", kof_crc32(o + 8, 8));
	EXPECT("Probe.csum.all", kof_crc32(o, 128));
	EXPECT("Probe.csum.straddle", 0);
	EXPECT("Probe.csum.hugelen", 0);
	EXPECT("Probe.csum.max", 0);
	EXPECT("Probe.csum.zero", 0);

	EXPECT("Probe.in.hit", 1);
	EXPECT("Probe.in.short", 0);
	EXPECT("Probe.in.past", 0);
	EXPECT("Probe.in.wrap", 1);
	EXPECT("Probe.in.max", 0);
	EXPECT("Probe.at.hit", 1);
	EXPECT("Probe.at.miss", 0);
	EXPECT("Probe.at.past", 0);
	EXPECT("Probe.at.straddle", 0);
	EXPECT("Probe.where.hit", 24);
	EXPECT("Probe.where.broken", 1);
	EXPECT("Probe.where.past", 1);
	EXPECT("Probe.where.wrap", 24);
	CK(get(&a, "Probe.where.window") >= 0xfffffffffffffff0ull, "a search that finds nothing answers KOF_BROKEN, not an offset");

	EXPECT("Probe.entropy.flat", kentropy_eighths(o + 40, 16));
	EXPECT("Probe.entropy.zero", kentropy_eighths(o + 96, 32));
	EXPECT("Probe.entropy.past", 0);
	EXPECT("Probe.entropy.wrap", 0);
	EXPECT("Probe.entropy.max", 0);
	EXPECT("Probe.entropy.region", kentropy_eighths(o, 128));
	EXPECT("Probe.entropy.nomask", 0);

	EXPECT("Probe.shape.ok", 1);
	EXPECT("Probe.shape.bytes", 128);
	EXPECT("Probe.shape.runs", 1);
	EXPECT("Probe.shape.widest", 128);
	EXPECT("Probe.shape.widest_off", 0);
	EXPECT("Probe.shape.nomask", 0);

	EXPECT("Probe.fmt.zip", 1);
	EXPECT("Probe.fmt.elf", 1);
	EXPECT("Probe.fmt.bogus", 1);

	/* a different object: the magic is absent, so the probe says nothing */
	o[0] = 'X';
	memset(&a, 0, sizeof a);
	kscan_bytes(sc, o, sizeof o, "probe2", &op, NULL, NULL);
	CK(a.n == 0, "no magic, no notes (%u)", a.n);

	/* the same object once more: the answers are the same (nothing was kept between calls) */
	o[0] = 'K';
	memset(&a, 0, sizeof a);
	kscan_bytes(sc, o, sizeof o, "probe3", &op, NULL, NULL);
	EXPECT("Probe.u32", 0x13121110u);
	EXPECT("Probe.csum.all", kof_crc32(o, 128));
	kscan_free(sc);
}

/* ---- probe_unpack_00 -------------------------------------------------------------------------- */

struct seen_obj {
	char     name[200];
	uint64_t len;
	uint8_t  head[16];
	uint32_t broken, entry_kind, entry_of;
	char     opened_by[64], build[64];
};

struct scan_out {
	struct notes notes;
	struct seen_obj obj[80];
	unsigned n_obj;
};

static void on_note2(uint32_t fact, const char *what, uint64_t value, void *user)
{
	on_note(fact, what, value, &((struct scan_out *)user)->notes);
}

static int on_obj2(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *user)
{
	struct scan_out *o = (struct scan_out *)user;

	if (o->n_obj < 80) {
		struct seen_obj *s = &o->obj[o->n_obj];

		memset(s, 0, sizeof *s);
		snprintf(s->name, sizeof s->name, "%s", name);
		s->len = n;
		memcpy(s->head, b, n < sizeof s->head ? n : sizeof s->head);
		s->broken = r->broken;
		s->entry_kind = r->entry_kind;
		s->entry_of = r->entry_of;
		snprintf(s->opened_by, sizeof s->opened_by, "%s", r->opened_by ? r->opened_by : "");
		snprintf(s->build, sizeof s->build, "%s", r->packer_build ? r->packer_build : "");
	}
	o->n_obj++;
	return 0;
}

static void unpack_object(uint8_t *o, uint8_t mode)
{
	static const uint8_t blk[10] = { 0x01, 0x05, 0x00, 0xfa, 0xff, 'h', 'e', 'l', 'l', 'o' };
	static const uint8_t l2[9] = { 0x01, 0x00, 0x04, 'h', 'e', 'l', 'l', 'o', 0x00 };

	memset(o, 0x51, 64);
	memcpy(o, "KOFPRB02", 8);
	o[8] = mode;
	memset(o + 9, 0, 7);
	memcpy(o + 16, blk, sizeof blk);
	memcpy(o + 26, "lbl-ab", 6);
	memcpy(o + 40, l2, sizeof l2);
}

static unsigned run_mode(kof_scanner *sc, uint8_t mode, struct scan_out *out, uint8_t *o)
{
	struct kof_scan_option op = he_opt();
	int rc;

	memset(out, 0, sizeof *out);
	unpack_object(o, mode);
	kscan_on_debug(sc, on_note2, out);
	rc = kscan_bytes(sc, o, 64, "pu", &op, on_obj2, out);
	kscan_on_debug(sc, NULL, NULL);
	return rc > 0 ? (unsigned)rc : 0u;
}

#define NOTE(what, want) CK(has(&out.notes, what) && get(&out.notes, what) == (uint64_t)(want), \
	"mode %u %s: %llu, expected %llu", mode, what, (unsigned long long)get(&out.notes, what), (unsigned long long)(want))
#define CHILD(i, nm, ln, text) CK(out.n_obj > (i) && !strcmp(out.obj[i].name, nm) && out.obj[i].len == (ln) && \
	memcmp(out.obj[i].head, text, (ln) < 16 ? (ln) : 16) == 0, "mode %u child %u is %s of %llu bytes (got '%s' %llu)", mode, i, nm, \
	(unsigned long long)(ln), out.n_obj > (i) ? out.obj[i].name : "none", out.n_obj > (i) ? (unsigned long long)out.obj[i].len : 0ull)

static void t_probe_unpack(kof_engine *e)
{
	kof_scanner *sc = kscan_new(e);
	static struct scan_out out;
	uint8_t o[64];
	unsigned mode, n;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mode = 1;
	n = run_mode(sc, 1, &out, o);
	CK(n == 4, "mode 1: root and three windows (%u objects)", n);
	NOTE("Probe.window.a", 1); NOTE("Probe.window.b", 1); NOTE("Probe.window.past", 0);
	NOTE("Probe.window.max", 0); NOTE("Probe.window.empty", 0); NOTE("Probe.window.wrap", 1);
	CHILD(1, "pu//0", 20, o + 16);
	CHILD(2, "pu//1", 8, o + 40);
	CHILD(3, "pu//2", 16, o + 48);

	mode = 2;
	n = run_mode(sc, 2, &out, o);
	CK(n == 2, "mode 2: root and one written child (%u)", n);
	NOTE("Probe.write.a", 1); NOTE("Probe.write.b", 1); NOTE("Probe.write.zero", 1); NOTE("Probe.done", 1);
	CHILD(1, "pu//0:lbl-ab", 6, "ABCABC");
	CK(out.n_obj > 1 && out.obj[1].entry_kind == KOF_ENT_SCRIPT, "the declared kind reaches the child");
	CK(out.n_obj > 0 && !strcmp(out.obj[0].build, "9.99"), "the module's build string is reported on the object it opened ('%s')", out.obj[0].build);
	CK(out.n_obj > 0 && !strcmp(out.obj[0].opened_by, "Probe.write"), "and the module is named by its first note's prefix ('%s')", out.obj[0].opened_by);

	mode = 3;
	n = run_mode(sc, 3, &out, o);
	CK(n == 2, "mode 3: root and one child");
	NOTE("Probe.write.note", 1); NOTE("Probe.done.note", 1);
	CHILD(1, "pu//0:noted", 3, "ABC");

	mode = 4;
	n = run_mode(sc, 4, &out, o);
	CK(n == 2, "mode 4: root and one decoded child");
	NOTE("Probe.decode", 5); NOTE("Probe.decode.bad", 0); NOTE("Probe.decode.wrap", 5);
	NOTE("Probe.decode.unknown", 0); NOTE("Probe.done.decode", 1);
	CHILD(1, "pu//0", 10, "hellohello");

	mode = 5;
	n = run_mode(sc, 5, &out, o);
	CK(n == 1, "mode 5: a peek produces nothing");
	NOTE("Probe.peek", 5); NOTE("Probe.peek.first", 'h'); NOTE("Probe.peek.short", 2);
	NOTE("Probe.peek.past", 0); NOTE("Probe.peek.nocap", 0);
	NOTE("Probe.peek.deflate", 0);
	NOTE("Probe.peek.child", 0);

	mode = 6;
	n = run_mode(sc, 6, &out, o);
	CK(n == 2, "mode 6: root and the edited child");
	NOTE("Probe.poke.ok", 1); NOTE("Probe.poke.end", 0); NOTE("Probe.poke.zero", 0);
	NOTE("Probe.poke.past", 0); NOTE("Probe.poke.max", 0);
	NOTE("Probe.read", 6); NOTE("Probe.read.tail", 2); NOTE("Probe.read.end", 0);
	NOTE("Probe.read.max", 0); NOTE("Probe.read.nocap", 0);
	NOTE("Probe.read.bytes", 0x464579784241ull);
	CHILD(1, "pu//0", 6, "ABxyEF");

	mode = 7;
	n = run_mode(sc, 7, &out, o);
	CK(n == 2, "mode 7: root and a window");
	NOTE("Probe.opened.before", 0); NOTE("Probe.opened.after", 1);

	mode = 8;
	n = run_mode(sc, 8, &out, o);
	CK(n == 1 && out.obj[0].broken == KOF_BROKEN_DAMAGED, "mode 8: a reason the module gives is the object's (%u)", out.obj[0].broken);
	mode = 9;
	n = run_mode(sc, 9, &out, o);
	CK(n == 1 && out.obj[0].broken >= KOF_BROKEN_LIMIT && out.obj[0].broken < KOF_BROKEN_COUNT,
	   "mode 9: a reason outside the vocabulary is clamped to one inside it, not stored (%u)", out.obj[0].broken);

	mode = 10;
	n = run_mode(sc, 10, &out, o);
	NOTE("Probe.gather", 64); NOTE("Probe.gather.nomask", 0); NOTE("Probe.done.gather", 1);
	CK(n == 65, "mode 10: a module that gathers its own object re-opens the same bytes at every layer, and the layer allowance ends it at 64 (%u objects)", n);
	CK(out.n_obj == 65 && out.obj[64].broken == KOF_BROKEN_LIMIT, "and the last layer says it was cut (%u)", out.n_obj == 65 ? out.obj[64].broken : 99u);
	CK(out.n_obj == 65 && out.obj[64].len == 64, "every layer is the whole object");

	mode = 11;
	n = run_mode(sc, 11, &out, o);
	CK(n >= 1, "mode 11: supersede does not stop the scan (%u)", n);

	mode = 12;
	n = run_mode(sc, 12, &out, o);
	CK(n == 2, "mode 12: root and a decoded child");
	NOTE("Probe.lzma2", 5); NOTE("Probe.lzma2.hint0", 5); NOTE("Probe.done.lzma2", 1);
	CHILD(1, "pu//0", 10, "hellohello");

	/* a scanner that has run every mode answers mode 1 as it did at the start */
	n = run_mode(sc, 1, &out, o);
	CK(n == 4, "the scanner is unchanged after all of them");
	kscan_free(sc);
}

/* ---- probe_crypt_00 ------------------------------------------------------------------------------------ */

static uint64_t pack8(const uint8_t *b)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < 8; i++)
		v |= (uint64_t)b[i] << (8u * i);
	return v;
}

static void crypt_object(uint8_t *o, uint8_t mode)
{
	static const uint8_t key[3] = { 'A', 'B', 'C' };
	unsigned i;
	uint32_t k = 0x11223344u, p[3] = { 0x01020304u, 0, 0x0a0b0c0du };

	memset(o, 0x51, 64);
	memcpy(o, "KOFPRB05", 8);
	o[8] = mode;
	memset(o + 9, 0, 7);
	for (i = 0; i < 7; i++)
		o[16 + i] = (uint8_t)(i ^ key[i % 3]);
	if (mode == 10)
		for (i = 0; i < 3; i++) {
			uint32_t c = p[i] ^ k;

			k += p[i];
			memcpy(o + 16 + 4 * i, &c, 4);
		}
}

static unsigned run_crypt(kof_scanner *sc, uint8_t mode, struct scan_out *out, uint8_t *o)
{
	struct kof_scan_option op = he_opt();
	int rc;

	memset(out, 0, sizeof *out);
	crypt_object(o, mode);
	kscan_on_debug(sc, on_note2, out);
	rc = kscan_bytes(sc, o, 64, "cr", &op, on_obj2, out);
	kscan_on_debug(sc, NULL, NULL);
	return rc > 0 ? (unsigned)rc : 0u;
}

static void t_probe_crypt(kof_engine *e)
{
	kof_scanner *sc = kscan_new(e);
	static struct scan_out out;
	uint8_t o[64], ref[16];
	unsigned mode, i, n;
	static const uint8_t key[3] = { 'A', 'B', 'C' };
	static const uint8_t in7[7] = { 0, 1, 2, 3, 4, 5, 6 };

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	mode = 1;
	run_crypt(sc, 1, &out, o);
	memset(ref, 0xee, sizeof ref);
	for (i = 0; i < 7; i++)
		ref[i] = (uint8_t)(in7[i] ^ key[i % 3]);
	NOTE("Probe.n", 7); NOTE("Probe.b0", pack8(ref)); NOTE("Probe.guard", 0xee);

	mode = 2;
	run_crypt(sc, 2, &out, o);
	memset(ref, 0xee, sizeof ref);
	for (i = 0; i < 3; i++)
		ref[i] = (uint8_t)(in7[i] ^ key[i % 3]);
	NOTE("Probe.n", 3); NOTE("Probe.b0", pack8(ref)); NOTE("Probe.zero_cap", 0); NOTE("Probe.zero_in", 0); NOTE("Probe.max_out", 2);

	mode = 3;
	run_crypt(sc, 3, &out, o);
	NOTE("Probe.keylen0", 0); NOTE("Probe.nullkey", 0); NOTE("Probe.hugekey", 0); NOTE("Probe.algo99", 0);
	NOTE("Probe.none", 0); NOTE("Probe.algomax", 0);

	mode = 4;
	run_crypt(sc, 4, &out, o);
	memset(ref, 0xee, sizeof ref);
	for (i = 0; i < 7; i++)
		ref[i] = (uint8_t)(in7[i] ^ (uint8_t)(0xfeu + i));
	NOTE("Probe.n", 7); NOTE("Probe.b0", pack8(ref));

	mode = 5;
	run_crypt(sc, 5, &out, o);
	{
		static const uint8_t want[8] = { 0x40, 'x', 0x3f, 'y', 'A', 0xee, 0xee, 0xee };

		NOTE("Probe.n", 5); NOTE("Probe.b0", pack8(want));
		CK(has(&out.notes, "Probe.nosubs") && (get(&out.notes, "Probe.nosubs") == 0 || get(&out.notes, "Probe.nosubs") == 5),
		   "a template with no subtrahends is refused or copied whole (%llu)", (unsigned long long)get(&out.notes, "Probe.nosubs"));
	}

	mode = 6;
	run_crypt(sc, 6, &out, o);
	{
		static const uint8_t v0[8] = { 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a };
		static const uint8_t v1[8] = { 0xd3, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee };

		NOTE("Probe.n", 9); NOTE("Probe.b0", pack8(v0)); NOTE("Probe.b1", pack8(v1)); NOTE("Probe.keylen0", 0);
	}

	mode = 7;
	run_crypt(sc, 7, &out, o);
	{
		static const uint8_t v[8] = { 0xef, 0xbe, 0xad, 0xde, 0xee, 0xee, 0xee, 0xee };

		NOTE("Probe.n", 4); NOTE("Probe.b0", pack8(v));
	}

	mode = 8;
	run_crypt(sc, 8, &out, o);
	memset(ref, 0xee, sizeof ref);
	memcpy(ref, in7, 7);
	NOTE("Probe.n", 7); NOTE("Probe.b0", pack8(ref)); NOTE("Probe.past", 0); NOTE("Probe.max", 0); NOTE("Probe.nocap", 0);
	CK(has(&out.notes, "Probe.wrap") && get(&out.notes, "Probe.wrap") <= 32u, "a range of 2^64-1 is clipped to the buffer (%llu)", (unsigned long long)get(&out.notes, "Probe.wrap"));

	mode = 9;
	n = run_crypt(sc, 9, &out, o);
	CK(n == 2, "mode 9: root and the decrypted child (%u)", n);
	NOTE("Probe.decrypt", 7); NOTE("Probe.past", 0); NOTE("Probe.done", 1);
	CHILD(1, "cr//0", 7, in7);

	mode = 10;
	run_crypt(sc, 10, &out, o);
	NOTE("Probe.n", 8); NOTE("Probe.b0", 0x01020304ull);
	CK(has(&out.notes, "Probe.b1") && get(&out.notes, "Probe.b1") == 0xeeeeeeeeeeeeeeeeull, "the cipher stops after the first zero plaintext dword and writes nothing beyond it");
	kscan_free(sc);
}

/* ---- probe_entry_00 ---------------------------------------------------------------------------------------- */

static void t_probe_entry(kof_engine *e)
{
	kof_scanner *sc = kscan_new(e);
	static struct scan_out out;
	struct kof_scan_option op = he_opt();
	struct he_w w = { 0 };
	unsigned mode = 0, n;

	if (!sc) {
		CK(0, "scanner");
		return;
	}
	hs_cab(&w);
	memset(&out, 0, sizeof out);
	kscan_on_debug(sc, on_note2, &out);
	n = (unsigned)kscan_bytes(sc, w.p, w.n, "c.cab", &op, on_obj2, &out);
	kscan_on_debug(sc, NULL, NULL);
	CK(n == 3, "root and two children (%u)", n);
	NOTE("Probe.entries", 3);
	NOTE("Probe.bad_index", 0); NOTE("Probe.max_index", 0); NOTE("Probe.bad_method", 0);
	NOTE("Probe.hint_huge", 0);
	NOTE("Probe.e1", 16); NOTE("Probe.done1", 1);
	NOTE("Probe.e0", 0); NOTE("Probe.done0", 0);
	CHILD(1, "c.cab//0", 16, "IJKLMNOPABCDEFGH");
	CK(out.n_obj > 1 && out.obj[1].entry_of == 1, "the child made from entry 1 says so (entry_of %u)", out.n_obj > 1 ? out.obj[1].entry_of : 99u);
	CK(out.n_obj > 2 && !strcmp(out.obj[2].name, "c.cab//1:small.txt") && out.obj[2].len == 8 && out.obj[2].entry_of == 0,
	   "an entry that is a window into the cabinet produces no bytes of its own (the call answers 0) and is still opened, by the engine, under its name");
	he_free(&w);
	kscan_free(sc);
}

int main(void)
{
	struct stat sb;
	kof_engine *e;

	if (stat(DB_SIGS, &sb) != 0) {
		printf("api_engine_modabi: no test signature set (make test-sigs) - nothing tested\n");
		return 0;
	}
	e = keng_open(DB_SIGS);
	if (!e) {
		printf("api_engine_modabi: the test set did not load\n");
		return 1;
	}
	t_probe_read(e);
	t_probe_unpack(e);
	t_probe_crypt(e);
	t_probe_entry(e);
	keng_close(e);
	printf("api_engine_modabi: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
