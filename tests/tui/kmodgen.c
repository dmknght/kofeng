/*
 * kmodgen - writes the relocatable kernel module the diagnose tests open: the one
 * the unit tests scan (cf_kmod), whose imports are linked the way kmod_give_root
 * reads them, so the viewer's diagnose view has a diagnose to list. Compiled on
 * demand by mkfixtures.py, from the repository's own builder of the image.
 */
#include "../unit/caps_fix.h"

int main(int argc, char **argv)
{
	static uint8_t img[1u << 16];
	uint64_t n = cf_kmod(img, sizeof img, 0, 0);
	FILE *f;

	if (argc < 2)
		return 2;
	f = fopen(argv[1], "wb");
	if (!f)
		return 1;
	if (fwrite(img, 1u, (size_t)n, f) != (size_t)n) {
		fclose(f);
		return 1;
	}
	return fclose(f) != 0;
}
