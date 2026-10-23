#define _GNU_SOURCE
/*
 * norm_defect_endian - N9 of the normalise audit: the static library's code of a big-endian object,
 * appended to the end of the view.
 *
 * The view of a big-endian ELF is in the canonical byte order (libgenome/genotype/image/endian.h): its
 * code is swapped by words. The library is cut out of the body and appended under SLIB_CODE, and it was
 * appended from the PARENT's bytes, so that range was the one place the view held big-endian words -
 * a block or a rule cut from the little-endian build could not find the library's code there, and
 * the view was not the canonical form it says it is.
 *
 * The fixture is the endian kit's MIPS32 object with three library markers ("Permission denied", "No such
 * file or directory", "Bad address": a table the marker tier takes for the library's) written at the end
 * of .text, so the span the marker tier cuts lies in CODE. The oracle is the library of the parent
 * (kgenome_true_find_all) and the plan's own range (kgenome_endian_range): the view must hold those
 * bytes as the plan leaves them, and the parent's raw bytes must be nowhere in it.
 */

#define EK_MAX 16384u
#define EK_CODE_UNITS 1500u

#include <sys/stat.h>

#include <kgenome.h>

#include "../lib/genome/endian_kit.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofentry.h"
#include "notes.h"

#define MAXV 16384u

struct seen {
	unsigned objects, views;
	uint8_t view[MAXV];
	uint32_t view_n;
	uint32_t parent_broken, view_broken;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res,
		     void *user)
{
	struct seen *s = user;

	(void)name;
	s->objects++;
	if (!res)
		return 0;
	if (res->entry_kind == KOF_ENT_NORMALIZED) {
		s->views++;
		s->view_broken = res->broken;
		if (len <= MAXV) {
			memcpy(s->view, bytes, (size_t)len);
			s->view_n = (uint32_t)len;
		}
	} else if (s->objects == 1) {
		s->parent_broken = res->broken;
	}
	return 0;
}

static int has(const struct seen *s, const uint8_t *p, uint64_t len)
{
	return len && len <= s->view_n && memmem(s->view, s->view_n, p, (size_t)len) != NULL;
}

int main(int argc, char **argv)
{
	static struct ek_obj be;
	static uint8_t plan_buf[MAXV];
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *eng = keng_open(db);
	kof_scanner *sc;
	struct kof_scan_option opt;
	struct seen s;
	struct kgenome_elf_info info;
	struct kgenome_obj g;
	struct kgenome_endian_plan plan;
	struct kgenome_true_all lib;
	uint32_t i, checked = 0;

	if (!eng || !(sc = kscan_new(eng))) {
		printf("norm_defect_endian: cannot open the test database\n");
		return 2;
	}
	ek_build(&be, &ek_archs[0], 1, 1);               /* mips32, big-endian */
	/* the markers, at the end of .text, one word aligned and well apart */
	memcpy(be.b + be.text + 5000u, "Permission denied", 18);
	memcpy(be.b + be.text + 5040u, "No such file or directory", 26);
	memcpy(be.b + be.text + 5080u, "Bad address", 12);

	memset(&info, 0, sizeof info);
	memset(&g, 0, sizeof g);
	CK(kgenome_elf_image_parse(kof_buf_make(be.b, be.n), &info, &g));
	g.file_header = &info;
	CK(kgenome_endian_plan_build(kof_buf_make(be.b, be.n), &g, &plan) == KGENOME_OK);
	kgenome_true_find_all(kof_buf_make(be.b, be.n), &info, &lib);
	printf("  library spans of the parent: %u\n", lib.n);
	CK(lib.n >= 1u);

	notes_clear();
	memset(&s, 0, sizeof s);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	CK(kscan_bytes(sc, be.b, be.n, "n9", &opt, on_object, &s) > 0);
	CK(s.views == 1);
	CK(s.parent_broken == 0 && s.view_broken == 0);

	for (i = 0; i < lib.n && s.views == 1; i++) {
		uint64_t off = lib.span[i].off, len = lib.span[i].len;

		if (off + len > be.n || len > sizeof plan_buf || len < 16u)
			continue;
		kgenome_endian_range(plan_buf, be.b, be.n, off, len, &plan);
		printf("  span %u: parent [%llu, +%llu): canonical bytes %s in the view, raw bytes %s\n", i,
		       (unsigned long long)off, (unsigned long long)len,
		       has(&s, plan_buf, len) ? "FOUND" : "missing",
		       has(&s, be.b + off, len) ? "PRESENT" : "absent");
		if (!memcmp(plan_buf, be.b + off, len))
			continue;                        /* the plan leaves this range as it is: no oracle */
		CK(has(&s, plan_buf, len));              /* the view holds the library as the plan leaves it */
		CK(!has(&s, be.b + off, len));           /* and the big-endian words are nowhere in it */
		checked++;
	}
	CK(checked >= 1u);                               /* at least one span was a range the plan changes */
	kgenome_endian_plan_free(&plan);
	kscan_free(sc);
	keng_close(eng);
	if (hk_fails) {
		printf("norm_defect_endian: %d check(s) failed\n", hk_fails);
		return 1;
	}
	printf("norm_defect_endian: ok\n");
	return 0;
}
