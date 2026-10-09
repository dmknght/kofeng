/*
 * decrypt_layers - an object with several layers of DIFFERENT ciphers, and the
 * step that describes it without opening it.
 *
 * WHAT THE ENGINE HAS TO GET RIGHT is that one decrypt does not end the
 * examination. An object wrapped by one module comes back round as a child, and
 * the next layer is a different module with a different sign and a different key:
 * the three test ciphers (tests/sigs/layer_{a,b,c}_00.c) are nested here in two
 * different orders, so a pipeline that asked the modules in database order and
 * stopped at the first would recover one order and not the other.
 *
 * THE RECOVERING STEP is the second half. tests/sigs/recover_probe_00.c reports
 * only that it was asked, on an object carrying its sign, and it must be asked
 * whether or not a decrypt produced a child from that object and whether or not a
 * rule had already named it. The last is the one an opening step cannot do: a
 * named object is refused by the gate that decides whether it is worth opening,
 * and it is exactly the object whose description a tool shows first.
 *
 * REPEATED, with a scanner of its own each time and with one scanner kept: the
 * answer must not depend on which run it is. The modules of a step are visited in
 * database order and the scanner keeps state between objects, and either of those
 * is a place where a second run could differ from the first.
 *
 * Built in memory and written to one temporary file, because a scan needs a path.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"

#define RUNS 8u

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

/* Binary on purpose: all-printable bytes would be sniffed as text and the layers
 * only target objects with no format. */
static uint8_t payload[96];

#define KEEP 16u                  /* objects whose bytes are kept */
#define KEEP_N 128u               /* ...and how many bytes of each */

struct outcome {
	uint32_t n_obj;
	uint32_t probe;
	uint32_t named;           /* findings that carry the conviction's name */
	uint32_t broken;          /* objects the engine said it did not finish */
	uint64_t last_n;
	uint8_t  last[256];
	uint64_t sum;             /* every object's bytes, folded - order sensitive */
	uint64_t obj_n[KEEP];
	uint8_t  obj[KEEP][KEEP_N];
};

static struct outcome out;

static uint64_t fold(uint64_t h, const uint8_t *b, uint64_t n)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		h = (h ^ b[i]) * 1099511628211ull;
	return h;
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	uint32_t f;

	(void)name;
	(void)user;
	if (out.n_obj < KEEP) {
		out.obj_n[out.n_obj] = len;
		memcpy(out.obj[out.n_obj], bytes, len < KEEP_N ? len : KEEP_N);
	}
	if (res->broken)
		out.broken++;
	out.n_obj++;
	out.last_n = len;
	memcpy(out.last, bytes, len < sizeof out.last ? len : sizeof out.last);
	out.sum = fold(out.sum ^ out.n_obj, bytes, len);
	for (f = 0; f < res->n; f++)
		if (strstr(res->v[f].name, "LayerConvict"))
			out.named++;
	return 0;
}

static void on_debug(uint32_t fact, const char *what, uint64_t value, void *user)
{
	(void)fact;
	(void)user;
	if (what && strstr(what, "Probe") && value)
		out.probe++;
}

/* magic, four bytes in the clear, then the rest XORed with one byte. */
static uint64_t wrap(uint8_t *dst, const char *magic, const char *clear,
		     uint8_t key, const uint8_t *in, uint64_t n)
{
	uint64_t i;

	memcpy(dst, magic, 4);
	memcpy(dst + 4, clear, 4);
	for (i = 0; i < n; i++)
		dst[8 + i] = (uint8_t)(in[i] ^ key);
	return 8 + n;
}

/* twelve bytes of header - the signs of up to three modules - then the cipher. */
static uint64_t wrap12(uint8_t *dst, const char *head, uint8_t key,
		       const uint8_t *in, uint64_t n)
{
	uint64_t i;

	memcpy(dst, head, 12);
	for (i = 0; i < n; i++)
		dst[12 + i] = (uint8_t)(in[i] ^ key);
	return 12 + n;
}

/* Is there an object of exactly these bytes among the ones kept. */
static int has_obj(const struct outcome *o, const uint8_t *b, uint64_t n)
{
	uint32_t i;

	if (n > KEEP_N)
		return 0;
	for (i = 0; i < o->n_obj && i < KEEP; i++)
		if (o->obj_n[i] == n && !memcmp(o->obj[i], b, n))
			return 1;
	return 0;
}

static int scan(kof_scanner *sc, const char *path, const uint8_t *b, uint64_t n)
{
	struct kof_scan_option opt;
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	fwrite(b, 1, n, f);
	fclose(f);
	memset(&opt, 0, sizeof opt);
	opt.heur_level = 2;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 1u << 20;
	memset(&out, 0, sizeof out);
	return kscan_path(sc, path, &opt, on_object, NULL) >= 0;
}

static int same(const struct outcome *a, const struct outcome *b)
{
	return a->n_obj == b->n_obj && a->probe == b->probe &&
	       a->named == b->named && a->broken == b->broken &&
	       a->last_n == b->last_n && a->sum == b->sum;
}

/*
 * One scenario, RUNS times with a fresh scanner and RUNS more with one kept.
 * Returns the first run's outcome in `first`, and fails if any run differs.
 */
static void repeat(kof_engine *eng, const char *label, const char *path,
		   const uint8_t *b, uint64_t n, struct outcome *first)
{
	kof_scanner *kept = kscan_new(eng);
	uint32_t r;

	if (!kept) {
		fail("could not make a scanner");
		return;
	}
	kscan_on_debug(kept, on_debug, NULL);
	for (r = 0; r < 2u * RUNS; r++) {
		kof_scanner *sc = r < RUNS ? kscan_new(eng) : kept;

		if (!sc) {
			fail("could not make a scanner");
			break;
		}
		if (r < RUNS)
			kscan_on_debug(sc, on_debug, NULL);
		if (!scan(sc, path, b, n)) {
			fail("a scan could not run");
		} else if (r == 0) {
			*first = out;
		} else if (!same(first, &out)) {
			printf("  run %u of %s differs: %u objects, probe %u, "
			       "named %u (first: %u, %u, %u)\n", r, label,
			       out.n_obj, out.probe, out.named, first->n_obj,
			       first->probe, first->named);
			fail("the same object gave a different answer");
		}
		if (r < RUNS)
			kscan_free(sc);
	}
	kscan_free(kept);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	const char *path = "build/test/decrypt_layers.tmp";
	static uint8_t c1[512], b1[512], a1[512], c2[512], a2[512], b2[512];
	static uint8_t conv[256], plain[256];
	struct outcome o1, o2, o3, o4;
	uint64_t n, i;
	kof_engine *eng = keng_open(db);

	if (!eng) {
		printf("decrypt layers: cannot open %s\n", db);
		return 2;
	}
	for (i = 0; i < sizeof payload; i++)
		payload[i] = (uint8_t)(0x80u | (i * 37u + 11u));

	/*
	 * A, then B, then C - outermost first. "RCVR" sits in the four clear bytes of
	 * the OUTER layer, where the recovering step looks.
	 */
	n = wrap(c1, "LAYC", "ZZZZ", 0x11, payload, sizeof payload);
	n = wrap(b1, "LAYB", "ZZZZ", 0xa7, c1, n);
	n = wrap(a1, "LAYA", "RCVR", 0x5a, b1, n);
	repeat(eng, "A-B-C", path, a1, n, &o1);
	printf("  A>B>C: %u objects, innermost %llu bytes, probe %u\n",
	       o1.n_obj, (unsigned long long)o1.last_n, o1.probe);
	if (o1.n_obj != 4u)
		fail("three different layers did not come back as three children");
	if (o1.last_n != sizeof payload ||
	    memcmp(o1.last, payload, sizeof payload) != 0)
		fail("the innermost child is not the payload, byte for byte");
	if (o1.probe != 1u)
		fail("the recovering step did not run exactly once, on the outer "
		     "object that carries its sign");

	/*
	 * The other order: C outermost, then A, then B. Database order does not
	 * change what the layers are, so it must not change what comes out.
	 */
	n = wrap(b2, "LAYB", "ZZZZ", 0xa7, payload, sizeof payload);
	n = wrap(a2, "LAYA", "ZZZZ", 0x5a, b2, n);
	n = wrap(c2, "LAYC", "RCVR", 0x11, a2, n);
	repeat(eng, "C-A-B", path, c2, n, &o2);
	printf("  C>A>B: %u objects, innermost %llu bytes, probe %u\n",
	       o2.n_obj, (unsigned long long)o2.last_n, o2.probe);
	if (o2.n_obj != 4u)
		fail("the layers in the other order were not all opened");
	if (o2.last_n != sizeof payload ||
	    memcmp(o2.last, payload, sizeof payload) != 0)
		fail("the other order did not reach the payload");
	if (o2.probe != 1u)
		fail("the recovering step was not asked in the other order");

	/*
	 * A NAMED OBJECT. It carries the first layer's sign and the recovering
	 * step's, and a word a rule names it by. The detect stage convicts it, the
	 * gate then refuses to open it - so no child - and the recovering step still
	 * runs, because a convicted program is the one whose description is wanted.
	 */
	memset(conv, 0x90, sizeof conv);
	memcpy(conv, "LAYA", 4);
	memcpy(conv + 4, "RCVR", 4);
	memcpy(conv + 64, "CONVICT", 7);
	repeat(eng, "named", path, conv, sizeof conv, &o3);
	printf("  named: %u objects, named %u, probe %u\n", o3.n_obj, o3.named,
	       o3.probe);
	if (o3.named == 0u)
		fail("the rule did not name the object");
	if (o3.n_obj != 1u)
		fail("a named object was opened");
	if (o3.probe != 1u)
		fail("the recovering step did not run on a named object");

	/* And nothing: no sign of any step. */
	for (i = 0; i < sizeof plain; i++)
		plain[i] = (uint8_t)(0x80u | (i * 13u + 5u));
	repeat(eng, "plain", path, plain, sizeof plain, &o4);
	printf("  plain: %u objects, probe %u\n", o4.n_obj, o4.probe);
	if (o4.n_obj != 1u || o4.probe != 0u || o4.named != 0u)
		fail("an object with no sign was claimed by something");

	/*
	 * SEVERAL MODULES, THREE STEPS, ONE OBJECT. "LAYP" at 0 is an UNPACK module's
	 * sign, "LAYD" at 4 and "LAYE" at 8 are two DECRYPT modules', and all three
	 * read the same ciphertext with different keys. The steps are a group the
	 * parent goes through whole: a module that produced a child must not stop
	 * the next from being asked about the parent - the engine measured that on
	 * 5 of 38 encoded stagers once - so three children come back, each the
	 * plaintext its own key makes.
	 */
	{
		static uint8_t ct[96], blob[256], pp[96], pd[96], pe[96];
		struct outcome o5;

		for (i = 0; i < sizeof ct; i++)
			ct[i] = (uint8_t)(0x80u | (i * 29u + 3u));
		memcpy(blob, "LAYPLAYDLAYE", 12);
		memcpy(blob + 12, ct, sizeof ct);
		for (i = 0; i < sizeof ct; i++) {
			pp[i] = (uint8_t)(ct[i] ^ 0x77);
			pd[i] = (uint8_t)(ct[i] ^ 0x33);
			pe[i] = (uint8_t)(ct[i] ^ 0x6c);
		}
		repeat(eng, "three modules", path, blob, 12 + sizeof ct, &o5);
		printf("  P+D+E on one object: %u objects\n", o5.n_obj);
		if (o5.n_obj != 4u)
			fail("one object three modules hold for did not give three "
			     "children");
		if (!has_obj(&o5, pp, sizeof pp))
			fail("the unpack step's child is missing");
		if (!has_obj(&o5, pd, sizeof pd))
			fail("the first decrypt module's child is missing");
		if (!has_obj(&o5, pe, sizeof pe))
			fail("the second decrypt module's child is missing");
	}

	/*
	 * A CONTAINER AHEAD OF THE LAYERS. The unwrap step takes two members out;
	 * the first is two cipher layers deep (A over C) and the second one (B). Each
	 * member goes through the steps on its own, so the tree is the container, its
	 * two members, the layer inside the first, and both payloads: six objects.
	 */
	{
		static uint8_t pa[96], pb[96], m1[512], m2[512], t[512], cont[1200];
		struct outcome o6;
		uint64_t n1, n2, nt;

		for (i = 0; i < sizeof pa; i++) {
			pa[i] = (uint8_t)(0x80u | (i * 7u + 1u));
			pb[i] = (uint8_t)(0xc0u | (i * 11u + 2u));
		}
		nt = wrap(t, "LAYC", "ZZZZ", 0x11, pa, sizeof pa);
		n1 = wrap(m1, "LAYA", "ZZZZ", 0x5a, t, nt);
		n2 = wrap(m2, "LAYB", "ZZZZ", 0xa7, pb, sizeof pb);
		memcpy(cont, "LAYU", 4);
		cont[4] = (uint8_t)n1; cont[5] = (uint8_t)(n1 >> 8);
		cont[6] = (uint8_t)n2; cont[7] = (uint8_t)(n2 >> 8);
		memcpy(cont + 8, m1, n1);
		memcpy(cont + 8 + n1, m2, n2);
		repeat(eng, "container", path, cont, 8 + n1 + n2, &o6);
		printf("  container of two cipher stacks: %u objects\n", o6.n_obj);
		if (o6.n_obj != 6u)
			fail("the container's tree is not the six objects it should be");
		if (!has_obj(&o6, pa, sizeof pa))
			fail("the payload under two layers did not come out");
		if (!has_obj(&o6, pb, sizeof pb))
			fail("the payload under one layer did not come out");
	}

	/*
	 * LAYERS, THE RECOVERING STEP AND A CONVICTION TOGETHER. The outer layer and
	 * the one inside it both carry the recovering step's sign in their clear
	 * bytes, and the payload at the bottom is named by a rule. Three objects; the
	 * probe is asked twice - once per object that carries its sign - and the
	 * conviction lands on the innermost alone.
	 */
	{
		static uint8_t pay[160], lb[256], la[256];
		struct outcome o7;
		uint64_t nb, na;

		memset(pay, 0x90, sizeof pay);
		memcpy(pay + 64, "CONVICT", 7);
		nb = wrap(lb, "LAYB", "RCVR", 0xa7, pay, sizeof pay);
		na = wrap(la, "LAYA", "RCVR", 0x5a, lb, nb);
		repeat(eng, "convicted core", path, la, na, &o7);
		printf("  layers over a convicted payload: %u objects, probe %u, "
		       "named %u\n", o7.n_obj, o7.probe, o7.named);
		if (o7.n_obj != 3u)
			fail("the two layers over a convicted payload did not give "
			     "three objects");
		if (o7.probe != 2u)
			fail("the recovering step was not asked once per object "
			     "carrying its sign");
		if (o7.named != 1u)
			fail("the conviction did not land on the innermost object "
			     "alone");
	}

	/*
	 * DEEP. Twelve layers cycling through the three modules. Either the engine
	 * gets to the payload or it SAYS it stopped - an object it did not finish is
	 * reported broken - and either way the answer is the same on every run. What
	 * it must never do is stop quietly short and report the object as examined.
	 */
	{
		static uint8_t cur[2048], nxt[2048];
		static const char *const mag[3] = { "LAYA", "LAYB", "LAYC" };
		static const uint8_t key[3] = { 0x5a, 0xa7, 0x11 };
		struct outcome o8;
		uint64_t m;
		uint32_t d;

		memcpy(cur, payload, sizeof payload);
		m = sizeof payload;
		for (d = 0; d < 12u; d++) {
			m = wrap(nxt, mag[d % 3], "ZZZZ", key[d % 3], cur, m);
			memcpy(cur, nxt, m);
		}
		repeat(eng, "deep", path, cur, m, &o8);
		printf("  twelve layers: %u objects, broken %u, innermost %llu "
		       "bytes\n", o8.n_obj, o8.broken,
		       (unsigned long long)o8.last_n);
		if (o8.last_n == sizeof payload &&
		    !memcmp(o8.last, payload, sizeof payload)) {
			if (o8.n_obj != 13u)
				fail("the payload was reached through the wrong number "
				     "of objects");
		} else if (!o8.broken) {
			fail("the engine stopped short of the payload and did not "
			     "say so");
		}
	}

	remove(path);
	keng_close(eng);
	printf("decrypt layers: orders, shared bytes, a container, a conviction, "
	       "depth; %u runs each%s\n",
	       2u * RUNS, failures ? " - FAILED" : " - ok");
	return failures != 0;
}
