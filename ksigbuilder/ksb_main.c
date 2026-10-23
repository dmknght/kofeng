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
	else if (argc > 1 && strcmp(argv[1], "--tags") == 0)
		rc = ksb_tags_main(argc, argv);
	else
		rc = ksb_pack_main(ksb, argc, argv);
	free(ksb);
	return rc;
}
