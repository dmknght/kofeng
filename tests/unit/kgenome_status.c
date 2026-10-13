/*
 * kgenome_status - EVERY LIMIT SETS A STATUS, and the status is readable through
 * the public header.
 *
 * The owner's rule is "a cap hit is 'cannot say', never 'none'". The way to keep
 * it is not to review each cap once but to test that each one, when it fires,
 * leaves a value a caller can read: kgenome_diag_scan_status. One check per
 * limit of the diagnose graph (the limits of the PE import walk and of the apihash run are in
 * caps_pe.c, and the wrapper walk's per-path limits in caps_wrap.c, because
 * their fixtures are theirs), each with its INSIDE case beside it - a limit that
 * sets a status while nothing was cut would make the status worthless in the
 * other direction.
 */

#include "caps_fix.h"
#include <phenotype/diag_int.h>

static unsigned char view[1u << 22];
static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

static struct kgenome_diag_scan *scan_with(unsigned n, const struct kgenome_budget *b)
{
	const struct kof_parser *pl;
	struct kof_obj_ctx ctx;
	uint32_t np, i;
	uint64_t len;
	kof_buf buf;

	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	buf.p = img;
	buf.n = len;
	memset(&ctx, 0, sizeof ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		    pl[i].parse(buf, view, &ctx)) {
			struct kgenome_obj gobj;
			struct kgenome_diag_inputs in;

			memset(&in, 0, sizeof in);
			in.budget = b;
			kof_genome_obj(&ctx, &gobj);
			return kgenome_diag_scan_with_inputs(&gobj, img, len,
							     KGENOME_DIAG_RUN_SYSCALL, &in);
		}
	return NULL;
}

/* x86-64: mmap through a generic wrapper at the end, as caps_wrap.c has it */
static const uint8_t caller[] = {
	0xbf, 9, 0, 0, 0, 0xbe, 0, 0, 0, 0, 0xba, 0, 0x10, 0, 0, 0xb9, 7, 0, 0, 0,
	0x41, 0xb8, 0x22, 0, 0, 0, 0x45, 0x31, 0xc9,
	0xe8, 0, 0, 0, 0,
	0x48, 0x89, 0xc6, 0x31, 0xff, 0xba, 0, 0x10, 0, 0, 0x31, 0xc0, 0x0f, 0x05,
	0xff, 0xe6
};
static const uint8_t arm[] = {
	0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca,
	0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x0f, 0x05, 0xc3
};

static unsigned wrapper_object(void)
{
	unsigned n = cf_emit(code, 0, caller, sizeof caller);

	put32(code, 30, n - 34u);
	return cf_emit(code, n, arm, sizeof arm);
}

static void nodes(void)
{
	struct kgenome_budget b;
	struct kgenome_diag_scan *s;
	unsigned n = 0, i;

	for (i = 0; i < 20u; i++)
		n = cf_filler64(code, n, i);
	/* the limit exactly: 20 nodes fit, nothing is cut */
	memset(&b, 0, sizeof b);
	b.max_nodes = 20;
	s = scan_with(n, &b);
	CK(kgenome_diag_scan_count(s) == 20u && kgenome_diag_scan_status(s) == KGENOME_OK);
	kgenome_diag_scan_free(s);
	/* one under it: the 20th is dropped, and the scan says so */
	b.max_nodes = 19;
	s = scan_with(n, &b);
	CK(kgenome_diag_scan_count(s) == 19u && kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	kgenome_diag_scan_free(s);
}

static void names(void)
{
	struct kgenome_budget b;
	struct kgenome_diag_scan *s;
	char nm[KGENOME_DIAG_STR_MAX + 8u];
	unsigned i;

	code[0] = 0xc3;
	memset(&b, 0, sizeof b);
	b.max_names = 3;
	s = scan_with(1, &b);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	for (i = 0; i < 3u; i++) {
		snprintf(nm, sizeof nm, "n%u", i);
		CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 1);
	}
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, "n3") == 0);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	CK(kgenome_diag_scan_refused(s) == 1u);
	kgenome_diag_scan_free(s);

	/* a name past the record */
	s = scan_with(1, NULL);
	memset(nm, 'x', KGENOME_DIAG_STR_MAX + 1u);
	nm[KGENOME_DIAG_STR_MAX + 1u] = 0;
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	CK(kgenome_diag_str_add(s, KGENOME_NUCLEO_MEM_READ, 0, nm) == 0);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED && kgenome_diag_scan_refused(s) == 1u);
	kgenome_diag_scan_free(s);
}

static void links(void)
{
	struct kgenome_diag_scan *s;
	struct kgenome_diag_hit *h;
	uint16_t src[5];
	unsigned j;

	code[0] = 0xc3;
	s = scan_with(1, NULL);
	for (j = 0; j < 5u; j++) {
		CK(kgenome_diag_hit_add(s, 0x80u + j, KGENOME_NUCLEO_ALLOC_EXEC, 0) != NULL);
		src[j] = (uint16_t)(kgenome_diag_scan_count(s) - 1u);
	}
	CK(kgenome_diag_hit_add(s, 0x100, KGENOME_NUCLEO_MEM_READ, 0) != NULL);
	h = kgenome_diag_hit_of(s, kgenome_diag_scan_count(s) - 1u);
	for (j = 0; j < 4u; j++)
		kgenome_diag_note_in(s, h, src[j], KGENOME_DIAG_ROLE_BUFFER,
				 KGENOME_DIAG_KIND_PRODUCED);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	kgenome_diag_note_in(s, h, src[4], KGENOME_DIAG_ROLE_BUFFER, KGENOME_DIAG_KIND_PRODUCED);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	kgenome_diag_scan_free(s);
}

static void steps(void)
{
	struct kgenome_budget b;
	struct kgenome_diag_scan *s;
	unsigned n = wrapper_object();

	/* the wrapper walk's whole-object step budget: whole when it is ample... */
	s = scan_with(n, NULL);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK);
	CK(cf_count_cap(s, KGENOME_NUCLEO_ALLOC_EXEC) == 1u);
	kgenome_diag_scan_free(s);
	/* ...and spent at a single step, it is OVER_BUDGET and the wrapper is not
	 * summarised (the mmap is not an exec allocation any more) - not silent */
	memset(&b, 0, sizeof b);
	b.max_steps = 1;
	s = scan_with(n, &b);
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	kgenome_diag_scan_free(s);
}

static void api(void)
{
	struct kgenome_diag_scan *s;
	struct kgenome_budget b;

	/* the status names, the merge and the thin wrapper agree */
	CK(!strcmp(kgenome_status_name(KGENOME_OK), "ok"));
	CK(!strcmp(kgenome_status_name(KGENOME_OVER_BUDGET), "over-budget"));
	CK(kgenome_status_merge(KGENOME_OK, KGENOME_TRUNCATED) == KGENOME_TRUNCATED);
	CK(kgenome_status_merge(KGENOME_NOMEM, KGENOME_TRUNCATED) == KGENOME_NOMEM);
	CK(kgenome_status_merge(KGENOME_TRUNCATED, KGENOME_OK) == KGENOME_TRUNCATED);
	CK(kgenome_status_complete(KGENOME_OK) && !kgenome_status_complete(KGENOME_TRUNCATED));
	/* a NULL scan is not "ok" - there is no answer - but it is not "full" either */
	CK(kgenome_diag_scan_status(NULL) == KGENOME_BAD_INPUT);
	CK(kgenome_diag_scan_full(NULL) == 0);
	code[0] = 0xc3;
	memset(&b, 0, sizeof b);
	b.max_nodes = 1;
	s = scan_with(1, &b);
	CK(kgenome_diag_scan_full(s) == (kgenome_diag_scan_status(s) != KGENOME_OK));
	CK(kgenome_diag_hit_add(s, 1, KGENOME_NUCLEO_ALLOC_EXEC, 0) != NULL);
	CK(kgenome_diag_hit_add(s, 2, KGENOME_NUCLEO_ALLOC_EXEC, 0) == NULL);
	CK(kgenome_diag_scan_full(s) == 1);
	kgenome_diag_scan_free(s);
}

int main(void)
{
	nodes();
	names();
	links();
	steps();
	api();
	printf("kgenome status: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
