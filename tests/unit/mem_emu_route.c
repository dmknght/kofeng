/*
 * mem_emu_route - the diagnose emulator is charged for the pages it USES, so an allowance does
 * not change what it finds.
 *
 * The run was billed 64 MiB (the most it could own) before it started: any allowance under that
 * plus the scan's own state refused it, and the emulator that was made with what was left mapped
 * less address space - the same relocatable module gave a different graph under a different
 * allowance. Now the bound on the guest's address space is the same under every allowance and the
 * memory is charged as it is taken (tests/lib/genome/emu_borrow_account.c is that charge on the
 * machine itself). Asserted here on the whole scan, the route that runs the emulator
 * (KGENOME_DIAG_RUN_ALL over a relocatable module):
 *
 *   - the graph (node count, the hits, the status) at 64, 128 and 256 MiB is the unlimited one
 *   - what the ledger held at its peak is a few pages' worth, not 64 MiB
 *   - an allowance that really is too small says OVER_BUDGET instead of a smaller graph with
 *     no word
 */

#include "caps_fix.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"

static uint8_t img[1u << 21];

static struct kgenome_diag_scan *scan_with(uint64_t len, uint64_t bytes)
{
	const struct kof_parser *pl;
	struct kof_obj_ctx ctx;
	static unsigned char view[1u << 22];
	uint32_t np, i;
	kof_buf buf;

	buf.p = img;
	buf.n = len;
	memset(view, 0, sizeof view);
	memset(&ctx, 0, sizeof ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) && pl[i].parse && pl[i].parse(buf, view, &ctx)) {
			struct kgenome_obj gobj;
			struct kgenome_diag_inputs in;
			struct kgenome_budget b;

			memset(&in, 0, sizeof in);
			memset(&b, 0, sizeof b);
			b.max_bytes = bytes;
			in.budget = bytes ? &b : NULL;
			kof_genome_obj(&ctx, &gobj);
			return kgenome_diag_scan_with_inputs(&gobj, img, len, KGENOME_DIAG_RUN_ALL, &in);
		}
	return NULL;
}

int main(void)
{
	uint64_t len = cf_kmod(img, sizeof img, 40, 0), peak = 0, held;
	static const uint64_t mib[] = { 64, 128, 256 };
	struct kgenome_diag_scan *ref = scan_with(len, 0), *s;
	unsigned a;

	CK(ref != NULL && kgenome_diag_scan_status(ref) == KGENOME_OK);
	if (!ref)
		return 1;
	held = kgenome_diag_scan_bytes(ref, &peak);
	printf("    unlimited: %u nodes, ledger holds %llu bytes, peak %llu\n",
	       (unsigned)kgenome_diag_scan_count(ref), (unsigned long long)held,
	       (unsigned long long)peak);
	CK(peak < (8u << 20));                  /* not the 64 MiB it used to be billed up front */
	CK(kgenome_diag_scan_count(ref) > 0);
	for (a = 0; a < 3u; a++) {
		s = scan_with(len, mib[a] << 20);
		CK(s != NULL);
		if (!s)
			continue;
		CK(kgenome_diag_scan_status(s) == KGENOME_OK);
		CK(kgenome_diag_scan_count(s) == kgenome_diag_scan_count(ref));
		CK(cf_match_rwx(s) == cf_match_rwx(ref));
		CK(kgenome_diag_scan_bytes(s, &peak) == held);
		kgenome_diag_scan_free(s);
	}
	/* too small for the table the emulator needs at creation: said, not shortened silently */
	s = scan_with(len, 256u << 10);
	CK(s != NULL);
	if (s) {
		CK(kgenome_diag_scan_status(s) != KGENOME_OK);
		kgenome_diag_scan_free(s);
	}
	kgenome_diag_scan_free(ref);
	printf("mem emu route: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
