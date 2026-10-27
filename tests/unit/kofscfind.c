/*
 * kofscfind - where a shellcode loader keeps its payload, the examiner's analysis.
 *
 * kofscfind_run is the one search and kofscfind_find the whole analysis, with the
 * tool's own sweep. This builds loaders in memory, byte for byte, and checks the
 * answer both ways: the search on its own (with the sweep answered by the test,
 * so each gate is exercised alone) and the whole analysis (the real sweep over
 * the real code), and the image the viewer derives from the answer.
 *
 * EVERY EXPECTATION IS THE CORRECT BEHAVIOUR. The controls are the shapes that
 * must NOT be found, each differing from a loader in exactly one thing: the
 * variable is only read, the file has no PT_INTERP (a library), the blob is a
 * table, the file is mostly code.
 */

#include "caps_fix.h"
#include <celllysis/celllysis.h>
#include <celllysis/xref.h>
#include "../../kofexamine/kofscfind.h"
#include <uncoat.h>
#include "known_miss.h"

#include "../lib/scf_img.h"

static uint8_t img[1u << 16];

/* ---- the lib on its own: the sweep is the test's answer ---------------------- */

static uint32_t xref_answer;

static uint32_t sweep(void *user, uint64_t va, uint64_t size)
{
	(void)user; (void)va; (void)size;
	return xref_answer;
}

static int run_with(uint64_t len, uint32_t xref, struct kofscfind *out)
{
	struct kof_obj_ctx ctx;
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(img, len);
	struct kofscfind_in in;
	struct kgenome_obj gobj;
	static uint8_t view[1u << 16];
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	CK(ok);
	kof_genome_obj(&ctx, &gobj);
	memset(&in, 0, sizeof in);
	in.obj = &gobj;
	in.data = img;
	in.n = len;
	in.xref = sweep;
	xref_answer = xref;
	return kofscfind_run(&in, out) == KGENOME_OK;
}

static void run_tests(void)
{
	static struct kofscfind f;
	uint64_t len;

	len = build(img, INLINE_CALLED);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.len == BLOB_N);
	CK(f.va == 0x400400ull);
	CK(f.at == 0x400);
	CK(f.bits == 0 && f.dec_n == 0);

	/* The same file, and the code only reads the variable: not a payload. */
	CK(run_with(len, KGENOME_XREF_READ, &f));
	CK(!f.found);
	/* Staged - the argument of a call in the region of an indirect call. */
	CK(run_with(len, KGENOME_XREF_ARG | KGENOME_XREF_RGN_ICALL, &f));
	CK(f.found);
	/* An argument alone is not enough: the control reads a table into a call. */
	CK(run_with(len, KGENOME_XREF_ARG, &f));
	CK(!f.found);
	/* No sweep for this architecture says "not analysed", and the byte tests decide. */
	CK(run_with(len, KGENOME_XREF_PARTIAL, &f));
	CK(f.found);

	len = build(img, INLINE_LIBRARY);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* no PT_INTERP: a library of tables */

	len = build(img, INLINE_TABLE);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* one byte owns the blob */

	len = build(img, INLINE_BIGCODE);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(!f.found);                           /* a program, not a loader */

	len = build(img, INLINE_BASE64);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.len == BLOB_N);
	CK(f.dec_n == BLOB_N * 3u / 4u);        /* what `at` decodes to is in dec */

	len = build(img, POINTER_CALLED);
	CK(run_with(len, KGENOME_XREF_CALL, &f));
	CK(f.found);
	CK(f.at == 0x180);                      /* the blob, not the pointer */
	CK(f.va == 0x400180ull);
	CK(f.len == 64);
	CK(f.bits == 64);                       /* `syscall` */

	/* Not an ELF at all: a status, and nothing found. */
	{
		struct kofscfind_in in;
		struct kgenome_obj gobj;

		memset(&gobj, 0, sizeof gobj);
		memset(&in, 0, sizeof in);
		in.obj = &gobj;
		in.data = img;
		in.n = len;
		CK(kofscfind_run(&in, &f) == KGENOME_UNSUPPORTED);
		CK(!f.found);
	}
}

/* ---- the whole analysis: the sweep is the tool's own ------------------------- */

static int find_run(uint64_t len, struct kofscfind *out)
{
	struct kof_obj_ctx ctx;
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf = kof_buf_make(img, len);
	struct kgenome_obj gobj;
	static uint8_t view[1u << 16];
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	CK(ok);
	kof_genome_obj(&ctx, &gobj);
	return kofscfind_find(&gobj, img, len, out) == KGENOME_OK;
}

static void find_tests(void)
{
	static struct kofscfind f;
	uint64_t len;

	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.len == BLOB_N && f.va == 0x400400ull);

	len = build(img, INLINE_BASE64);
	CK(find_run(len, &f));
	CK(f.found && f.dec_n == BLOB_N * 3u / 4u);

	len = build(img, POINTER_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.at == 0x180 && f.bits == 64);

	/* the controls: read only, and not a program */
	len = build(img, INLINE_READ);
	CK(find_run(len, &f));
	CK(!f.found);
	len = build(img, INLINE_LIBRARY);
	CK(find_run(len, &f));
	CK(!f.found);
	len = build(img, INLINE_BIGCODE);
	CK(find_run(len, &f));
	CK(!f.found);
}



/* ---- the payload as an object (what the viewer derives from the answer) ------ */

/* Parses `n` bytes of `b` as the viewer would an object it was handed, and
 * returns the ELF parse, or NULL. */
static const struct kgenome_elf_info *parse_img(const uint8_t *b, uint64_t n,
						struct kgenome_obj *gobj)
{
	static struct kof_obj_ctx ctx;
	static uint8_t view[1u << 16];
	const struct kof_parser *pl;
	kof_buf buf = kof_buf_make(b, n);
	uint32_t np, i;
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	if (!ok)
		return NULL;
	kof_genome_obj(&ctx, gobj);
	return kgenome_obj_elf(gobj);
}

static void image_tests(void)
{
	static struct kofscfind f;
	static uint8_t out[KOFSCFIND_IMAGE_MAX];
	struct kgenome_obj gobj;
	const struct kgenome_elf_info *e;
	uint64_t len, n;

	/* An inline blob: the image is a header and the blob's own bytes. */
	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(f.found);
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + BLOB_N);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, img + 0x400, BLOB_N));
	e = parse_img(out, n, &gobj);
	CK(e && e->valid);
	CK(e && e->seg_count == 1 && e->sec_count == 0);
	CK(gobj.arch == KGENOME_ARCH_X86_64);

	/* The parent's width is the default where the payload did not say. */
	n = kofscfind_image(&f, img, len, 0, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + BLOB_N);
	e = parse_img(out, n, &gobj);
	CK(e && e->valid && gobj.arch == KGENOME_ARCH_X86);

	/* Base64 text: the image carries what it decodes to, not the text. */
	len = build(img, INLINE_BASE64);
	CK(find_run(len, &f));
	CK(f.found && f.dec_n);
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + f.dec_n);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, f.dec, f.dec_n));

	/* A pointer-shaped loader: the blob in .rodata, and a syscall that says
	 * it is 64-bit even when the caller's default is 32. */
	len = build(img, POINTER_CALLED);
	CK(find_run(len, &f));
	CK(f.found && f.bits == 64);
	n = kofscfind_image(&f, img, len, 0, out, sizeof out);
	CK(n == KOFSCFIND_HDR_ROOM + 64u);
	CK(!memcmp(out + KOFSCFIND_HDR_ROOM, img + 0x180, 64));
	e = parse_img(out, n, &gobj);
	CK(e && e->valid && gobj.arch == KGENOME_ARCH_X86_64);
	/* and the other way round: 32 from the payload beats a 64-bit parent */
	f.bits = 32;
	n = kofscfind_image(&f, img, len, 1, out, sizeof out);
	e = parse_img(out, n, &gobj);
	CK(n && e && e->valid && gobj.arch == KGENOME_ARCH_X86);

	/* The refusals: nothing found, no room, a range outside the object. */
	len = build(img, INLINE_READ);
	CK(find_run(len, &f));
	CK(!f.found);
	CK(kofscfind_image(&f, img, len, 1, out, sizeof out) == 0);
	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f));
	CK(kofscfind_image(&f, img, len, 1, out, KOFSCFIND_HDR_ROOM) == 0);
	CK(kofscfind_image(&f, img, f.at + 4u, 1, out, sizeof out) == 0);
	CK(kofscfind_image(NULL, img, len, 1, out, sizeof out) == 0);
}

/* ---- hostile rows: truncated and corrupt objects, forged answers, caps ------- */

/* The same parse as find_run, but a refusal is an answer here (a truncated object is
 * allowed not to parse). Returns -1 when the object did not parse, else whether the
 * search finished; `out` is always written whole when the search ran. */
static int try_find(const uint8_t *b, uint64_t len, struct kofscfind *out)
{
	static struct kof_obj_ctx ctx;
	static uint8_t view[1u << 16];
	const struct kof_parser *pl;
	kof_buf buf = kof_buf_make(b, len);
	struct kgenome_obj gobj;
	uint32_t np, i;
	int ok = 0;

	memset(&ctx, 0, sizeof ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np && !ok; i++)
		ok = pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		     pl[i].parse(buf, view, &ctx);
	if (!ok)
		return -1;
	kof_genome_obj(&ctx, &gobj);
	memset(out, 0xa5, sizeof *out);
	return kofscfind_find(&gobj, b, len, out) == KGENOME_OK;
}

/* What every answer must satisfy whatever the object looked like. */
static void answer_ok(const struct kofscfind *f, uint64_t len, const char *what)
{
	if (!f->found)
		return;
	if (f->len < 16u || (f->len < KOFSCFIND_SIZE_MIN && !f->bits) || f->len > KOFSCFIND_SIZE_MAX ||
	    f->at > len || f->len > len - f->at || f->dec_n > KOFSCFIND_SIZE_MAX ||
	    (f->dec_n && f->len < 8u) || (f->bits != 0 && f->bits != 32 && f->bits != 64)) {
		printf("  FAIL %s: found=%d at=%llu len=%llu dec_n=%u bits=%u object=%llu\n", what,
		       f->found, (unsigned long long)f->at, (unsigned long long)f->len,
		       f->dec_n, f->bits, (unsigned long long)len);
		fails++;
	}
}

static void hostile_tests(void)
{
	static const enum shape shapes[] = { INLINE_CALLED, INLINE_BASE64, POINTER_CALLED };
	static struct kofscfind f;
	static uint8_t work[1u << 16];
	static uint8_t out[KOFSCFIND_IMAGE_MAX + 64u];
	uint64_t len, p, cap, n;
	unsigned s, v, parsed = 0, found = 0;
	static const uint8_t flip[] = { 0x00, 0xff, 0x55 };

	for (s = 0; s < sizeof shapes / sizeof shapes[0]; s++) {
		len = build(img, shapes[s]);
		/* every prefix: a truncated object is refused or answered inside itself */
		for (p = 0; p <= len; p++) {
			int r = try_find(img, p, &f);

			if (r < 0)
				continue;
			parsed++;
			answer_ok(&f, p, "prefix");
			found += (unsigned)f.found;
		}
		/* every byte of the object set to three hostile values in turn */
		memcpy(work, img, len);
		for (p = 0; p < len; p++) {
			uint8_t keep = work[p];

			for (v = 0; v < 3; v++) {
				int r;

				work[p] = (uint8_t)(flip[v] ^ (v == 2 ? keep : 0));
				r = try_find(work, len, &f);
				if (r >= 0)
					answer_ok(&f, len, "byte flip");
			}
			work[p] = keep;
		}
	}
	CK(parsed > 100);   /* the sweep did reach the search, not only the parse refusal */
	CK(found > 0);      /* and the whole object is among the prefixes */

	/* kofscfind_image: every cap from 0 to one past the need; the bytes after `cap` stay as they were */
	len = build(img, INLINE_CALLED);
	CK(find_run(len, &f) && f.found);
	for (cap = 0; cap <= KOFSCFIND_HDR_ROOM + BLOB_N + 8u; cap++) {
		uint64_t need = KOFSCFIND_HDR_ROOM + BLOB_N;

		memset(out, 0xcc, sizeof out);
		n = kofscfind_image(&f, img, len, 1, out, cap);
		CK(n == (cap >= need ? need : 0));
		for (p = cap; p < sizeof out; p++)
			if (out[p] != 0xcc) {
				CK(!"kofscfind_image wrote past its cap");
				break;
			}
	}
	/* forged answers: a length that wraps, an offset past the object, a decoded count past the buffer */
	{
		struct kofscfind g = f;

		g.len = ~0ull;
		CK(kofscfind_image(&g, img, len, 1, out, sizeof out) == 0);
		g = f; g.at = ~0ull;
		CK(kofscfind_image(&g, img, len, 1, out, sizeof out) == 0);
		g = f; g.at = len; g.len = 1;
		CK(kofscfind_image(&g, img, len, 1, out, sizeof out) == 0);
		g = f; g.dec_n = KOFSCFIND_SIZE_MAX + 1u;
		n = kofscfind_image(&g, img, len, 1, out, sizeof out);
		CK(n == 0 || n <= sizeof out);
		g = f; g.len = KOFSCFIND_SIZE_MAX + 1u;
		CK(kofscfind_image(&g, img, len, 1, out, sizeof out) == 0);
		g = f; g.found = 0;
		CK(kofscfind_image(&g, img, len, 1, out, sizeof out) == 0);
		CK(kofscfind_image(&f, NULL, len, 1, out, sizeof out) == 0);
		CK(kofscfind_image(&f, img, len, 1, NULL, sizeof out) == 0);
	}
	/* kofscfind_run with no object and a non-ELF object */
	{
		struct kofscfind_in in;

		memset(&in, 0, sizeof in);
		memset(&f, 0x5a, sizeof f);
		CK(kofscfind_run(&in, &f) != KGENOME_OK || !f.found);
	}
}

/* KNOWN DEFECTS pinned (green until fixed): D18 and EX-9, both in kofscfind.c's own b64. */
static void b64_defect_rows(void)
{
	static struct kofscfind f;
	uint64_t len;
	uint8_t ref[KOFSCFIND_SIZE_MAX];
	struct kuncoat_step st;
	uint64_t got = 0;
	enum kuncoat_status ks;

	/* EX-9 (2026-10-27, M) [sev L]: kofscfind.c b64() says "a NUL with data after it is not a string and not
	 * base64" and `break`s on the first NUL whatever follows. Trigger: a base64 blob with a NUL at byte 64 and
	 * text after it. Effect: the payload is decoded from its first half and shown as the loader's payload.
	 * Expected (the comment): no decode. Fix: after the NUL, require only NULs to the end of the symbol. */
	len = build(img, INLINE_BASE64);
	img[0x400 + 64] = 0;
	if (find_run(len, &f) && f.found)
		KM_CHECK(f.dec_n == 0, "b64 stops at a NUL in the middle of the text and decodes the first half", "EX-9");
	else
		KM_CHECK(0, "(EX-9 row could not reach the decode: the object is not found with a NUL inside)", "EX-9");

	/* D18: the examiner's decoder and kuncoat's disagree (measured, a space at byte 40 of 128 base64 characters:
	 * kuncoat skips whitespace and decodes 95 bytes, the finder refuses the text; a NUL at byte 40: the finder
	 * decodes 30 bytes, kuncoat answers BAD). */
	len = build(img, INLINE_BASE64);
	img[0x400 + 40] = ' ';
	memset(&st, 0, sizeof st);
	st.algo = KUNCOAT_ALGO_B64;
	st.dir = KUNCOAT_DECODE;
	ks = kuncoat_transform(&st, img + 0x400, BLOB_N, ref, sizeof ref, &got);
	if (find_run(len, &f) && f.found) {
		int agree = ks == KUNCOAT_OK ? (got == f.dec_n && !memcmp(ref, f.dec, f.dec_n)) : f.dec_n == 0;

		KM_CHECK(agree, "kofscfind b64 and kuncoat B64 give different answers for a space inside the text", "D18");
	} else {
		KM_CHECK(0, "(D18 row: the finder did not find the blob with a space inside)", "D18");
	}
}

/* ---- the candidate list with its facts (kofscfind_list calls the library once per candidate and applies the strong rule) ---- */

static struct kofscfind_row lrows[KOFSCFIND_ROWS_MAX];

static uint32_t list_img(uint64_t n, uint64_t pay_va, uint64_t pay_len, struct kofscfind_list_res *rs)
{
	struct kgenome_obj gobj;
	struct kofscfind_list_in in;

	CK(parse_img(img, n, &gobj) != NULL);
	memset(&in, 0, sizeof in);
	in.obj = &gobj;
	in.file = kof_buf_make(img, n);
	in.payload_va = pay_va;
	in.payload_len = pay_len;
	in.out = lrows;
	in.cap = KOFSCFIND_ROWS_MAX;
	(void)kofscfind_list(&in, rs);
	return rs->n;
}

static int row_named(const struct kofscfind_list_res *rs, const char *name)
{
	uint32_t i;

	for (i = 0; i < rs->n; i++)
		if (strcmp(lrows[i].name, name) == 0)
			return (int)i;
	return -1;
}

static void list_tests(void)
{
	static const uint8_t code[] = { 0x48, 0x31, 0xc0, 0xb0, 0x3b, 0x0f, 0x05, 0xc3, 0x90, 0x90, 0x90, 0x90 };
	struct kofscfind_list_res rs;
	uint64_t len;
	int r;
	uint32_t i;

	/* the variable holds instructions with a system call and the code calls it: strong, and first, without the finder's help */
	len = build(img, INLINE_CALLED);
	memcpy(img + 0x400, code, sizeof code);
	memset(img + 0x400 + sizeof code, 0x90, BLOB_N - sizeof code);
	list_img(len, 0, 0, &rs);
	r = row_named(&rs, "payload");
	CK(r == 0 && lrows[0].what == KOFSCFIND_W_SYMBOL);
	CK(lrows[0].facts_ok && lrows[0].facts.refs_known && lrows[0].facts.refs.call >= 1u && lrows[0].facts.syscall &&
	   lrows[0].facts.shape == KGENOME_RANGE_CODE_LIKE && lrows[0].strong && lrows[0].flagged);
	/* another row is strong only when it holds the same bytes (the section the variable is in) */
	for (i = 1; i < rs.n; i++)
		CK(!lrows[i].strong || (lrows[i].off <= 0x400u && lrows[i].off + lrows[i].size > 0x400u));

	/* the same bytes and nobody refers to them (the code is overwritten with nops): the facts say code-like with a system call,
	 * the rule does not fire, and the row is not first of the flagged */
	memset(img + 0x100, 0x90, 16);
	list_img(len, 0, 0, &rs);
	r = row_named(&rs, "payload");
	CK(r >= 0 && lrows[r].facts.refs_known && lrows[r].facts.refs.call == 0u && lrows[r].facts.refs.read == 0u &&
	   lrows[r].facts.syscall && lrows[r].facts.shape == KGENOME_RANGE_CODE_LIKE && !lrows[r].strong && !lrows[r].flagged);

	/* a string that is called: text, no system call, not strong */
	len = build(img, INLINE_CALLED);
	memcpy(img + 0x400, "hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello.", 110);
	list_img(len, 0, 0, &rs);
	r = row_named(&rs, "payload");
	CK(r >= 0 && lrows[r].facts.shape == KGENOME_RANGE_TEXT && !lrows[r].facts.syscall && !lrows[r].strong);

	/* the finder's answer: its row first, flagged, with the facts; the same symbol is not listed twice */
	len = build(img, INLINE_CALLED);
	list_img(len, 0x400400ull, BLOB_N, &rs);
	CK(rs.n >= 1u && lrows[0].what == KOFSCFIND_W_FINDER && lrows[0].flagged && lrows[0].facts_ok && lrows[0].size == BLOB_N);
	CK(lrows[0].facts.refs.call >= 1u && lrows[0].facts.decodes);
	for (i = 1; i < rs.n; i++)
		CK(lrows[i].what != KOFSCFIND_W_SYMBOL);
	/* the rows past the flagged ones are in address order inside each evidence group */
	{
		uint32_t k;

		for (k = 2; k < rs.n; k++)
			CK(lrows[k - 1u].flagged || lrows[k].flagged || lrows[k - 1u].va <= lrows[k].va ||
			   (lrows[k - 1u].facts.refs.read + lrows[k - 1u].facts.refs.call > 0u) != (lrows[k].facts.refs.read + lrows[k].facts.refs.call > 0u));
	}
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	run_tests();
	find_tests();
	image_tests();
	hostile_tests();
	b64_defect_rows();
	list_tests();
	printf("kofscfind: %s\n", fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
