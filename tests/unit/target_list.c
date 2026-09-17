/*
 * target_list - a module's targets survive the pack, and mean the same thing
 * on the other side.
 *
 * WHY THIS EXISTS. The target used to be a uint32 bitmask; it is now a count
 * and a list of ids - see n_target in kofdb.h. The reason for the change is
 * that a bit per target made the number of formats this engine could ever have
 * equal to the width of a word, and the reason for THIS TEST is what a list
 * can get wrong that a mask could not:
 *
 *   - the count and the ids can disagree. A row that claims more targets than
 *     it holds reads into the next module's row, which is a pack saying
 *     something about a module it does not describe.
 *   - "nothing" and "everything" are both an empty list. KOF_FMT_ANY compiles
 *     to no targets at all, so a loader that read an empty list as "matches
 *     nothing" would silently disable every module that named every format,
 *     and a scan would simply find less.
 *   - the order is not the meaning. Two modules for the same pair of formats
 *     must behave alike whichever order they were written in.
 *
 * None of those is visible in a scan result: each of them makes modules NOT
 * run, and a module that does not run reports nothing, which reads exactly
 * like a clean file.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libkofeng/core/kofplatform.h"
#include "../../libkofeng/kofdb/kofdb.h"
#include "../../libkofeng/kofdb/kofpack.h"
#include "../../libkofeng/kofdb/kofpackw.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static void ok_(int cond, const char *what)
{
	if (!cond)
		fail(what, "the answer was the wrong one");
}

/* ---- the module the pack carries ------------------------------------------ */

/*
 * An entry point and nothing else. The loader marks the arena executable and
 * records the entry; nothing here calls it, because what is under test is the
 * precondition the host reads BEFORE calling.
 */
static const uint8_t code_ret[] = { 0xc3u };

static void put_mod(struct kof_pw_mod *m, const uint8_t *ids, uint8_t n)
{
	memset(m, 0, sizeof *m);
	m->code = code_ret;
	m->code_len = (uint32_t)sizeof code_ret;
	m->n_target = n;
	if (n)
		memcpy(m->target, ids, n);
	m->scan_mask = KOF_SCAN_ALL;
}

static int write_file(const char *path, const uint8_t *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (fwrite(p, 1u, n, f) != n) {
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

int main(void)
{
	/* One target, three targets, and every target - the three shapes a
	 * module can declare. */
	static const uint8_t one[]   = { KOF_FMT_ELF };
	static const uint8_t three[] = { KOF_FMT_ELF, KOF_FMT_PE,
					 KOF_FMT_UNKNOWN };
	/* The same pair, written the other way round: a set, not a sequence. */
	static const uint8_t pair_a[] = { KOF_FMT_ZIP, KOF_FMT_DOCZIP };
	static const uint8_t pair_b[] = { KOF_FMT_DOCZIP, KOF_FMT_ZIP };
	struct kof_pw_mod m[5];
	struct kof_engine *e;
	uint8_t *img;
	size_t len = 0;
	char dir[] = "build/test/target_list_XXXXXX";
	char pack[512];

	put_mod(&m[0], one, 1);
	put_mod(&m[1], three, 3);
	put_mod(&m[2], NULL, 0);            /* KOF_FMT_ANY */
	put_mod(&m[3], pair_a, 2);
	put_mod(&m[4], pair_b, 2);

	img = kof_pack_build(KOF_PACK_DETECT, m, 5, &len);
	if (!img || !len) {
		printf("target list: the pack could not be built\n");
		free(img);
		return 1;
	}
	if (!mkdtemp(dir)) {
		printf("target list: no temporary directory\n");
		free(img);
		return 1;
	}
	snprintf(pack, sizeof pack, "%s/t.ksig", dir);
	if (!write_file(pack, img, len)) {
		printf("target list: the pack could not be written\n");
		free(img);
		rmdir(dir);
		return 1;
	}
	free(img);

	e = kof_db_load(dir);
	if (!e) {
		fail("load", "a pack with target lists in it was refused");
	} else if (e->n_mods != 5) {
		fail("load", "the modules did not all arrive");
	} else {
		const struct kof_module *a = &e->mods[0], *b = &e->mods[1],
					*any = &e->mods[2],
					*p1 = &e->mods[3], *p2 = &e->mods[4];

		/* The counts came back as they went in. */
		ok_(a->n_target == 1 && b->n_target == 3 &&
		    any->n_target == 0, "counts survive the pack");

		/* One target: that one and no other. */
		ok_(kof_module_targets(a, KOF_FMT_ELF), "one target hits");
		ok_(!kof_module_targets(a, KOF_FMT_PE), "one target misses");

		/* Three: every one of them, and nothing else. */
		ok_(kof_module_targets(b, KOF_FMT_ELF) &&
		    kof_module_targets(b, KOF_FMT_PE) &&
		    kof_module_targets(b, KOF_FMT_UNKNOWN),
		    "every named target hits");
		ok_(!kof_module_targets(b, KOF_FMT_SCRIPT),
		    "an unnamed target misses");

		/*
		 * EMPTY IS EVERYTHING. The failure this catches is the quiet
		 * one: read as "nothing", every KOF_FMT_ANY module stops
		 * running and every scan simply finds less.
		 */
		{
			uint32_t f;
			int all = 1;

			for (f = 0; f < KOF_TARGET_COUNT; f++)
				if (!kof_module_targets(any, (uint8_t)f))
					all = 0;
			ok_(all, "an empty list is every target");
		}

		/* Order is not meaning. */
		{
			uint32_t f;
			int same = 1;

			for (f = 0; f < KOF_TARGET_COUNT; f++)
				if (kof_module_targets(p1, (uint8_t)f) !=
				    kof_module_targets(p2, (uint8_t)f))
					same = 0;
			ok_(same, "the same targets in another order are the "
				  "same module");
		}

		/*
		 * AND THE PRECONDITION AGREES WITH THE LIST, because that is
		 * the thing the scan actually asks - kof_module_targets is
		 * only its first line.
		 */
		{
			struct kof_obj_ctx c;

			memset(&c, 0, sizeof c);
			c.format = KOF_FMT_PE;
			ok_(kof_module_precond(a, &c, 4096) == KOF_PRECOND_TARGET,
			    "precond refuses another format");
			ok_(kof_module_precond(b, &c, 4096) == KOF_PRECOND_OK,
			    "precond admits a named one");
			ok_(kof_module_precond(any, &c, 4096) == KOF_PRECOND_OK,
			    "precond admits everything for an empty list");
		}
		kof_db_free(e);
	}

	/*
	 * A ROW THAT LIES ABOUT ITS OWN LENGTH.
	 *
	 * The count is what bounds the read, and the pack is a file - so a
	 * count past the end of the row must be clamped rather than believed.
	 * Believed, it reads the next module's row, and the module then
	 * targets things nobody wrote.
	 */
	{
		uint8_t *bad;
		size_t blen = 0;

		put_mod(&m[0], one, 1);
		bad = kof_pack_build(KOF_PACK_DETECT, m, 2, &blen);
		if (bad && blen) {
			const struct kof_pack_hdr *h = (const void *)bad;
			uint8_t *row = bad + h->sec[KOF_SEC_PRE_TARGET].off;
			struct kof_engine *e2;

			row[0] = 0xffu;          /* claim 255 targets */
			/* The checksum is repaired after the mutation: without
			 * that, this case would only ever be testing the
			 * checksum again - see reseal in pack_load.c. */
			{
				struct kof_pack_hdr *bh = (void *)bad;

				bh->crc32 = kof_crc32(bad + KOF_PACK_CRC_FROM,
						      (uint64_t)blen -
						      KOF_PACK_CRC_FROM);
			}
			snprintf(pack, sizeof pack, "%s/b.ksig", dir);
			if (write_file(pack, bad, blen)) {
				e2 = kof_db_load(dir);
				if (e2) {
					ok_(e2->mods[0].n_target <=
					    KOF_TARGET_LIST_MAX,
					    "a row claiming more targets than "
					    "it holds is clamped");
					kof_db_free(e2);
				}
				unlink(pack);
			}
		}
		free(bad);
	}

	snprintf(pack, sizeof pack, "%s/t.ksig", dir);
	unlink(pack);
	rmdir(dir);

	if (failures) {
		printf("target list: %d check(s) failed\n", failures);
		return 1;
	}
	printf("target list: counts, one, many, any, order, precond, a lying "
	       "row - ok\n");
	return 0;
}
