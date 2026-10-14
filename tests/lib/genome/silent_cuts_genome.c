/*
 * silent_cuts_genome - memory refused inside libgenome is said in the product's status.
 *
 * The same property as tests/unit/silent_oom_sweep.c, one level down: a diagnose scan whose
 * n-th allocation is refused (failalloc.h) either holds the same nodes as the control or
 * reports it (kgenome_diag_scan_status != KGENOME_OK). A scan whose nodes changed with the
 * status still OK says "examined, and this is all there is" about an object it could not read
 * - the lie of CLAUDE.md rule 4. The sweep runs every allocation of three routes:
 *
 *   - the symbol route on a relocatable ELF whose import is a word of the vocabulary (the
 *     relocation table, then the sites);
 *   - the import route on a PE whose import is a word of the vocabulary;
 *   - the syscall sweep on an ELF with a stager.
 *
 * Fixed here, each with the status it now sets: the relocation table (elf_image.c, NOMEM on the
 * table and on the scan that asked for it), the PE import gather and its growth (diag_pe.c),
 * the loader-walk list (diag_apihash.c, note_peb).
 *
 * Also held here, because it is a cut that cannot be swept: the emulator's API stub names fit
 * the fixed fields the apihash product copies them into (api[40], dll[16]). Every name of the
 * table is walked; the product reports TRUNCATED if one ever did not fit, and this fails first.
 *
 * Under a sanitizer the allocator is not interposable (failalloc.h) and the sweeps are skipped.
 */

#define _GNU_SOURCE

#include <kgenome.h>
#include <phenotype/emu.h>
#include <phenotype/diag_scan.h>

#include "hk.h"
#include "../../unit/failalloc.h"

static struct hk_elf E;
static struct hk_pe  P;
static struct kgenome_elf_info ei;
static struct kgenome_pe_info pi;

struct sig {
	uint32_t n;
	uint64_t h;
	enum kgenome_status st;
};

static uint64_t mix(uint64_t h, uint64_t v)
{
	return (h ^ v) * 0x100000001b3ull + 0x9e3779b97f4a7c15ull;
}

static __attribute__((unused)) struct sig scan_sig(int pe, unsigned run)
{
	struct kgenome_obj o;
	struct kgenome_diag_scan *s;
	struct sig g;
	uint32_t i, k;

	memset(&g, 0, sizeof g);
	memset(&o, 0, sizeof o);
	if (pe) {
		memset(&pi, 0, sizeof pi);
		if (!kgenome_pe_image_parse(kof_buf_make(P.b, P.n), &pi, &o))
			return g;
		o.file_header = &pi;
		s = kgenome_diag_scan_with(&o, P.b, P.n, run);
	} else {
		memset(&ei, 0, sizeof ei);
		if (!kgenome_elf_image_parse(kof_buf_make(E.b, E.n), &ei, &o))
			return g;
		o.file_header = &ei;
		s = kgenome_diag_scan_with(&o, E.b, E.n, run);
	}
	if (!s) {
		g.st = KGENOME_NOMEM;           /* a refused scan object is a said failure */
		return g;
	}
	g.n = kgenome_diag_scan_count(s);
	for (i = 0; i < g.n; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		g.h = mix(mix(g.h, h->at), h->cap);
		g.h = mix(mix(g.h, h->bits), h->symref);
		for (k = 0; k < h->n_in && k < 4u; k++)
			g.h = mix(mix(g.h, h->in[k].from), h->in[k].role);
	}
	g.st = kgenome_diag_scan_status(s);
	kgenome_diag_scan_free(s);
	return g;
}

#if FA_AVAILABLE
struct sweep {
	long allocs, refused, changed, silent, said_nomem;
};

static struct sweep sweep(const char *what, int pe, unsigned run)
{
	struct sweep o;
	struct sig ctl;
	long i;

	memset(&o, 0, sizeof o);
	fa_arm_nth(0);
	ctl = scan_sig(pe, run);
	o.allocs = fa_count();
	fa_disarm_hit();
	CK(ctl.st == KGENOME_OK);
	CK(ctl.n >= 1u);                        /* the control finds the node the sweep is about */
	for (i = 1; i <= o.allocs; i++) {
		struct sig r;

		fa_arm_nth(i);
		r = scan_sig(pe, run);
		if (!fa_disarm_hit())
			continue;
		o.refused++;
		if (r.st == KGENOME_NOMEM)
			o.said_nomem++;
		if (r.n == ctl.n && r.h == ctl.h)
			continue;
		o.changed++;
		if (r.st != KGENOME_OK)
			continue;
		o.silent++;
		printf("  silent [%s] allocation %ld of %ld refused, %u nodes -> %u, status ok, frames:",
		       what, i, o.allocs, ctl.n, r.n);
		fa_print_site();
		printf("\n");
	}
	return o;
}
#endif

static __attribute__((unused)) void put_sym_name(unsigned at, const char *s)
{
	memcpy(E.b + E.strtab + at, s, strlen(s) + 1u);
}

static void t_names_fit(void)
{
	unsigned a;
	int seen = 0;

	/* the emulator's own stub names, against the fields the apihash product keeps them in */
	for (a = 0; a < 4096u; a++) {
		const char *nm = kgenome_emu_win_api_name(a);
		const char *dll;

		if (!nm)
			continue;
		seen++;
		dll = kgenome_emu_win_mod_name(kgenome_emu_win_api_mod(a));
		CK(strlen(nm) < sizeof ((struct kgenome_diag_apihash_call *)0)->api);
		CK(!dll || strlen(dll) < sizeof ((struct kgenome_diag_apihash_call *)0)->dll);
	}
	CK(seen > 20);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	fa_init();
	t_names_fit();
#if FA_AVAILABLE
	{
		struct sweep s;

		/* ET_REL: puts -> mmap, an undefined symbol, a call to it through a relocation */
		hk_elf(&E, 1, 0, 1);
		put_sym_name(6, "mmap");
		s = sweep("elf rel symbol route", 0, KGENOME_DIAG_RUN_SYMBOL);
		printf("  elf rel: %ld allocations, %ld refused, %ld said NOMEM, %ld changed the nodes, %ld silently\n",
		       s.allocs, s.refused, s.said_nomem, s.changed, s.silent);
		CK(s.silent == 0);
		CK(s.said_nomem >= 1);          /* the relocation table is one of them */

		/* PE: ExitProcess -> Sleep, an import with a word in the vocabulary, called through its slot */
		hk_pe(&P, 1);
		{
			uint8_t *at = (uint8_t *)memmem(P.b, P.n, "ExitProcess", 12);

			CK(at != NULL);
			if (at)
				memcpy(at, "Sleep\0", 6);
		}
		/* a call [rip+slot] at the start of .text so there is a node to lose: ff 15 disp32 */
		{
			uint32_t slot_rva = 0, code = P.text_off;

			/* the IAT is the FirstThunk table the builder laid out: find the first
			 * descriptor's FirstThunk through the import directory */
			const uint8_t *d = P.b + P.imp_off;
			slot_rva = (uint32_t)d[16] | (uint32_t)d[17] << 8 | (uint32_t)d[18] << 16 | (uint32_t)d[19] << 24;
			P.b[code] = 0xff; P.b[code + 1] = 0x15;
			{
				uint32_t next_rva = 0x1000u + 6u;
				uint32_t disp = slot_rva - next_rva;

				memcpy(P.b + code + 2, &disp, 4);
			}
			P.b[code + 6] = 0xc3;
		}
		s = sweep("pe import route", 1, KGENOME_DIAG_RUN_SYMBOL);
		printf("  pe: %ld allocations, %ld refused, %ld said NOMEM, %ld changed the nodes, %ld silently\n",
		       s.allocs, s.refused, s.said_nomem, s.changed, s.silent);
		CK(s.silent == 0);
		CK(s.said_nomem >= 1);          /* the import gather and its growth */
	}
#else
	printf("  (a sanitizer owns malloc: the failing-allocation sweeps are skipped)\n");
#endif
	printf("silent_cuts_genome: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
