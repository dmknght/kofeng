/*
 * ksb_main.c - The entry point: the options every mode takes, then the mode.
 */

#include "ksb.h"

int main(int argc, char **argv)
{
	struct ksb_ctx *ksb = calloc(1, sizeof *ksb);
	int rc;

	if (!ksb)
		return 2;
	ksb_decl_init(ksb);

	/* Before either mode reads argv - see kof_utf8_init. A signature source
	 * tree under a path with a non-codepage character was unreachable. */
	kof_utf8_init(&argc, &argv);
	/* The toolchain and the paths, taken out of argv wherever they sit,
	 * so each mode below still reads its own arguments positionally. */
	if (!ksb_opt_take(ksb, &argc, argv)) {
		free(ksb);
		return 2;
	}

	if (argc > 1 && strcmp(argv[1], "--tree") == 0)
		rc = ksb_tree_main(ksb, argc, argv);
	else if (argc > 1 && strcmp(argv[1], "--diagnose") == 0)
		rc = ksb_diagnose_main(ksb, argc, argv);
	else if (argc > 1 && strcmp(argv[1], "--catalog") == 0)
		rc = ksb_catalog_main(ksb, argc, argv);
	else
		rc = ksb_pack_main(ksb, argc, argv);
	/* The catalogs the first diagnose that named one opened (ksb_catalog_get): 2.6 MB with the shipped ones, never given back
	 * (audit_mem MEM-5, LeakSanitizer on --tree over the diagnoses). */
	ksb_catalog_close(ksb->diag.cat);
	free(ksb->diseases.ent);        /* the registry ksb_disease_note grew (4608 bytes with the test bases, LeakSanitizer) */
	free(ksb);
	return rc;
}
