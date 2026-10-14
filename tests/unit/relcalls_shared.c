/*
 * relcalls_shared - the call sites of a relocatable object are derived ONCE per scan.
 *
 * kgenome_elf_relcalls ran twice over the same relocation table: in the symbol route
 * (diag_sym.c: a node per call of a named capability) and in the emulate route's gap walk
 * (diag_emu_seat.c: what to step over). The relocation table was already shared
 * (kgenome_diag_relocs); the call-site derivation was not. Both now read
 * kgenome_diag_relcalls, which builds the list on first use and keeps it for the scan.
 *
 * Held here: the second ask is the same list (same pointer, same count); it is what a
 * direct kgenome_elf_relcalls over the same table says (the same sites, the capability
 * the name stands for); and a scan with BOTH routes on finds exactly the nodes the
 * routes found before the sharing (the cf_kmod object has the two calls of the
 * kmod_give_root shape: two sites).
 */

#include "caps_fix.h"
#include <genotype/image/elf_image.h>
#include <phenotype/diag_private.h>
#include <celllysis/nucleo.h>

static uint8_t img[1u << 16];

struct direct {
	uint64_t at[8];
	uint16_t cap[8];
	uint32_t n;
};

static void direct_cb(void *user, uint64_t at, uint64_t target, const char *name)
{
	struct direct *d = user;

	if (d->n >= 8u)
		return;
	d->at[d->n] = at;
	d->cap[d->n] = (target || !name) ? (uint16_t)KGENOME_NUCLEO_NONE : kgenome_nucleo_cap_of_name(name);
	d->n++;
}

int main(void)
{
	struct kgenome_elf_info ei;
	struct kgenome_obj obj;
	struct kgenome_diag_scan *s;
	const struct kgenome_diag_rcall *a, *b;
	struct kgenome_elf_relocs rt;
	struct direct d;
	uint32_t na = 0, nb = 0, i;
	uint64_t len = cf_kmod(img, sizeof img, 4, 0);

	memset(&ei, 0, sizeof ei);
	CK(kgenome_elf_image_parse(kof_buf_make(img, len), &ei, &obj));
	obj.file_header = &ei;

	s = kgenome_diag_scan_with(&obj, img, len, KGENOME_DIAG_RUN_ALL);
	CK(s != NULL);
	if (!s)
		return 1;
	a = kgenome_diag_relcalls(s, &obj, &na);
	b = kgenome_diag_relcalls(s, &obj, &nb);
	CK(a == b && na == nb);                         /* one derivation, kept */
	CK(na == 2u);

	memset(&d, 0, sizeof d);
	memset(&rt, 0, sizeof rt);
	(void)kgenome_elf_reloc_table(kof_buf_make(img, len), &ei, KGENOME_ELF_RELOC_CODE, &rt);
	(void)kgenome_elf_relcalls(kof_buf_make(img, len), &ei, &rt, direct_cb, &d, NULL);
	CK(d.n == na);
	for (i = 0; i < na && i < d.n; i++) {
		CK(a[i].at == d.at[i]);
		CK(a[i].cap == d.cap[i]);
		CK(a[i].target == 0u);                  /* both are undefined symbols */
	}
	/* the two imports of the shape are capabilities the vocabulary knows */
	CK(na == 2u && a[0].cap != KGENOME_NUCLEO_NONE && a[1].cap != KGENOME_NUCLEO_NONE);
	/* an ELF with no relocation table, and a PE: an empty list, not an error */
	kgenome_elf_reloc_table_free(&rt);
	kgenome_diag_scan_free(s);

	{
		struct kgenome_elf_info e2;
		struct kgenome_obj o2;
		uint8_t plain[64];
		struct kgenome_diag_scan *s2;
		uint32_t n2 = 99;

		memset(plain, 0, sizeof plain);
		memcpy(plain, "\177ELF\2\1\1", 7);
		memset(&e2, 0, sizeof e2);
		memset(&o2, 0, sizeof o2);
		s2 = kgenome_diag_scan_with(&o2, plain, sizeof plain, KGENOME_DIAG_RUN_DEFAULT);
		if (s2) {
			(void)kgenome_diag_relcalls(s2, &o2, &n2);
			CK(n2 == 0u);
			kgenome_diag_scan_free(s2);
		}
	}
	if (fails) {
		printf("relcalls_shared: %d check(s) failed\n", fails);
		return 1;
	}
	printf("relcalls_shared: one list of call sites per scan, the one a direct walk gives\n");
	return 0;
}
