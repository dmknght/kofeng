/*
 * cure - the repair a rule describes, and the two ways writing it can go wrong.
 *
 * WHAT THIS IS DEFENDING, and it is not the same thing as the rest of the suite.
 * Everywhere else the engine reads. Here the product WRITES to a file somebody
 * already has, which means two properties nothing was checking:
 *
 *   the repair that comes out of a scan is the one the rule asked for, and the
 *   requests the host must refuse really are refused - a clamped repair is a
 *   different repair, and applying a different repair to somebody's binary is
 *   worse than applying none;
 *
 *   the write does not follow a link. The file was identified by scanning THAT
 *   path; if the name now points somewhere else the answer is to fail. On Linux
 *   that is a symlink, on Windows a junction needs no privilege at all - which
 *   is why the opener refuses rather than trusting the filesystem.
 *
 * The applier itself lives in kofscanner.c and is static, so what is checked
 * here is the same five lines through the same two platform helpers it uses:
 * kof_fopen_rw and kof_fseek64. If those five lines are ever changed there,
 * change them here - the point is that the HELPERS behave, and that the repair
 * they are handed is right.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/core/kofplatform.h"

static int fails;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

/*
 * THE OBJECT THE TEST SIGNATURE DESCRIBES.
 *
 * 48 bytes: the marker at 0, four bytes of damage at 16, and a tail past 32 for
 * the truncation to remove. Built here rather than kept as a fixture because a
 * file whose every byte is named in the test is a file whose failure says which
 * byte.
 */
#define OBJ_LEN   48u
#define DAMAGE_AT 16u
#define CUT_TO    32u

static void build_object(uint8_t *b)
{
	unsigned i;

	for (i = 0; i < OBJ_LEN; i++)
		b[i] = (uint8_t)(0x40u + i);
	memcpy(b, "KOFCURETEST!", 12);
	/* What the infection put there, which the cure puts back. */
	b[DAMAGE_AT + 0u] = 0x11;
	b[DAMAGE_AT + 1u] = 0x22;
	b[DAMAGE_AT + 2u] = 0x33;
	b[DAMAGE_AT + 3u] = 0x44;
}


/* ------------------------------------------------------------------ an ELF */

/*
 * A REAL ELF, BUILT HERE, so the last check in this file can be "it runs".
 *
 * Nothing in the suite may execute a sample, and a cured sample is still a
 * sample - so the only honest way to assert that a repair leaves a working
 * program is to infect a program this test wrote itself. Sixty-four bit,
 * static, one PT_LOAD, and the whole of it is exit(42): small enough that
 * every byte below is accounted for, which is what makes a failure readable.
 *
 * WHY 42 AND NOT 0. A file that fails to exec, or execs and dies, also leaves
 * a status - and a status of zero is what a shell gives for several of those.
 * A number nothing else produces is the difference between "it ran" and "it
 * did not fail loudly".
 */
#define ELF_BASE   0x400000u
#define ELF_HDR    64u
#define ELF_PHDR   56u
#define ELF_CODE   (ELF_HDR + ELF_PHDR)          /* 120 */
#define EXIT_CODE  42

static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p+4, (uint32_t)(v>>32)); }

/* mov eax,60 ; mov edi,42 ; syscall  - exit(42) */
static const uint8_t code_ok[] = {
	0xb8, 0x3c, 0x00, 0x00, 0x00,
	0xbf, EXIT_CODE, 0x00, 0x00, 0x00,
	0x0f, 0x05
};
/* The same, exiting 1 - what the infection would run if the cure failed. */
static const uint8_t code_bad[] = {
	0xb8, 0x3c, 0x00, 0x00, 0x00,
	0xbf, 0x01, 0x00, 0x00, 0x00,
	0x0f, 0x05
};

/*
 * The clean program, then the infection appended to it:
 *
 *   e_entry moved to the appended stub;
 *   "KOFINFECT", the original e_entry and the original length behind it;
 *   the stub itself.
 *
 * The PT_LOAD is sized to cover the appended bytes too, because a segment
 * that did not would leave the entry point unmapped and the file would fail
 * to exec for a reason that has nothing to do with the repair.
 */
static size_t build_infected(uint8_t *out, size_t cap, uint64_t *clean_len)
{
	size_t payload = ELF_CODE + sizeof code_ok;   /* the clean length */
	size_t inf = payload;                         /* where the virus starts */
	size_t total = inf + 19u + sizeof code_bad;
	uint8_t *ph = out + ELF_HDR;

	if (cap < total)
		return 0;
	memset(out, 0, total);

	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = 2;            /* ELFCLASS64   */
	out[5] = 1;            /* ELFDATA2LSB  */
	out[6] = 1;            /* EV_CURRENT   */
	put16(out + 16, 2);    /* ET_EXEC      */
	put16(out + 18, 0x3e); /* EM_X86_64    */
	put32(out + 20, 1);
	put64(out + 24, ELF_BASE + inf);        /* e_entry -> the stub */
	put64(out + 32, ELF_HDR);               /* e_phoff */
	put16(out + 52, ELF_HDR);               /* e_ehsize */
	put16(out + 54, ELF_PHDR);              /* e_phentsize */
	put16(out + 56, 1);                     /* e_phnum */

	put32(ph +  0, 1);                      /* PT_LOAD */
	put32(ph +  4, 5);                      /* R+X */
	put64(ph +  8, 0);                      /* p_offset */
	put64(ph + 16, ELF_BASE);               /* p_vaddr */
	put64(ph + 24, ELF_BASE);               /* p_paddr */
	put64(ph + 32, total);                  /* p_filesz */
	put64(ph + 40, total);                  /* p_memsz  */
	put64(ph + 48, 0x1000);                 /* p_align  */

	memcpy(out + ELF_CODE, code_ok, sizeof code_ok);

	/*
	 * A JUMP FIRST, because the entry point is CODE.
	 *
	 * The first version put the marker at the entry and the processor ran
	 * "KOFINFECT" - which decodes, as it happens, into a run of REX
	 * prefixes and a push, and then fell into the saved numbers. A real
	 * appending virus opens with a branch over its own data for exactly
	 * this reason, so the test's payload does too and the rule looks for
	 * the marker two bytes in.
	 *
	 *   +0  eb 11        jmp to +19
	 *   +2  "KOFINFECT"  9
	 *   +11 original e_entry
	 *   +15 original length
	 *   +19 the stub
	 */
	out[inf]      = 0xeb;
	out[inf + 1u] = 0x11;
	memcpy(out + inf + 2u, "KOFINFECT", 9);
	put32(out + inf + 11u, (uint32_t)(ELF_BASE + ELF_CODE)); /* real entry */
	put32(out + inf + 15u, (uint32_t)payload);               /* real length */
	memcpy(out + inf + 19u, code_bad, sizeof code_bad);

	*clean_len = payload;
	return total;
}

static int n_obj;
static struct kof_result seen;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)user;
	if (n_obj == 0)
		seen = *res;
	n_obj++;
	return 1;
}

/* The applier, spelled the way kofscanner.c spells it. */
static int apply_repair(const char *path, const struct kof_repair *rp)
{
	FILE *f = kof_fopen_rw(path);
	uint32_t i;
	int okw = 1;

	if (!f)
		return 0;
	for (i = 0; i < rp->n_fix && okw; i++) {
		if (!kof_fseek64(f, rp->fix[i].off) ||
		    fwrite(rp->fix[i].b, 1, rp->fix[i].n, f) != rp->fix[i].n)
			okw = 0;
	}
	if (fclose(f) != 0)
		okw = 0;
	if (okw && rp->truncate)
		okw = kof_truncate_file(path, rp->truncate);
	return okw;
}

static int read_all(const char *path, uint8_t *out, size_t cap, size_t *got)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return 0;
	*got = fread(out, 1, cap, f);
	fclose(f);
	return 1;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	char dir[] = "build/test/cure_XXXXXX";
	char path[256], link[256], target[256];
	uint8_t obj[OBJ_LEN];
	/* Big enough for the ELF below too, not just the 48 byte object. */
	uint8_t back[1024];
	size_t got = 0;
	kof_engine *e;
	kof_scanner *sc;
	struct kof_scan_option opt;
	FILE *f;
	int rc;

	printf("cure:\n");

	if (!mkdtemp(dir)) {
		printf("cure: cannot make a work directory\n");
		return 1;
	}
	snprintf(path, sizeof path, "%s/infected.bin", dir);
	snprintf(link, sizeof link, "%s/aimed-elsewhere", dir);
	snprintf(target, sizeof target, "%s/do-not-touch", dir);

	build_object(obj);
	f = fopen(path, "wb");
	if (!f) { printf("cure: cannot write the object\n"); return 1; }
	fwrite(obj, 1, OBJ_LEN, f);
	fclose(f);

	/* ---- what the scan describes ---------------------------------- */

	e = kof_engine_open(db);
	if (!e) {
		printf("cure: cannot open %s - run `make databases "
		       "BASEDIR=tests/sigs` first\n", db);
		return 1;
	}
	sc = kof_scanner_new(e);
	if (!sc) {
		printf("cure: cannot make a scanner\n");
		return 1;
	}
	memset(&opt, 0, sizeof opt);
	rc = kof_scan_path(sc, path, &opt, on_object, NULL);
	ok("the object was scanned", rc >= 0 && n_obj > 0);
	ok("and reported infected", seen.n > 0);

	ok("one patch was accepted", seen.repair.n_fix == 1);
	if (seen.repair.n_fix == 1) {
		ok("at the offset the rule named",
		   seen.repair.fix[0].off == DAMAGE_AT);
		ok("of the length the rule named", seen.repair.fix[0].n == 4u);
		ok("with the bytes the rule named",
		   seen.repair.fix[0].b[0] == 0xDE &&
		   seen.repair.fix[0].b[1] == 0xAD &&
		   seen.repair.fix[0].b[2] == 0xBE &&
		   seen.repair.fix[0].b[3] == 0xEF);
	}
	/*
	 * THE REFUSALS. sig_cure asks for four impossible things after the two
	 * real ones - more than sixteen bytes, a patch past the end, a cut to
	 * nothing and a cut to more than there is. None of them may appear.
	 */
	ok("the oversized and out-of-range patches were refused, not clamped",
	   seen.repair.n_fix == 1);
	ok("the impossible truncations did not replace the real one",
	   seen.repair.truncate == CUT_TO);

	/* ---- applying it ---------------------------------------------- */

	ok("the repair applied", apply_repair(path, &seen.repair));
	ok("and the file can be read back", read_all(path, back, sizeof back,
						     &got));
	ok("the tail was cut", got == CUT_TO);
	if (got >= DAMAGE_AT + 4u) {
		ok("the damaged bytes were put back",
		   back[DAMAGE_AT + 0u] == 0xDE &&
		   back[DAMAGE_AT + 1u] == 0xAD &&
		   back[DAMAGE_AT + 2u] == 0xBE &&
		   back[DAMAGE_AT + 3u] == 0xEF);
		ok("and nothing else moved",
		   back[DAMAGE_AT - 1u] == (uint8_t)(0x40u + DAMAGE_AT - 1u) &&
		   back[DAMAGE_AT + 4u] == (uint8_t)(0x40u + DAMAGE_AT + 4u));
	}

	/* ---- and the link ---------------------------------------------- */

	f = fopen(target, "wb");
	if (f) { fwrite("do-not-touch\n", 1, 13, f); fclose(f); }

#ifndef _WIN32
	/*
	 * A SYMLINK HERE, A JUNCTION ON WINDOWS. Only the POSIX half can be
	 * built without a privilege, so only the POSIX half is asserted - the
	 * Windows opener is the one that refuses a reparse point, and saying
	 * "not tested there" is better than a test that silently passes
	 * because it made nothing to refuse.
	 */
	if (symlink("do-not-touch", link) == 0) {
		FILE *g = kof_fopen_rw(link);

		ok("the repair opener refuses a symlink", g == NULL);
		if (g)
			fclose(g);
		ok("and the file it pointed at is untouched",
		   read_all(target, back, sizeof back, &got) && got == 13u &&
		   memcmp(back, "do-not-touch\n", 13) == 0);
		ok("truncating through a symlink is refused too",
		   !kof_truncate_file(link, 1u) ||
		   (read_all(target, back, sizeof back, &got) && got == 13u));
	} else {
		printf("       symlink() failed - the link half is not tested\n");
	}
#else
	printf("       junctions need a Windows host - the link half is not "
	       "tested here\n");
#endif

	/* ---- and the whole point: a cured file still runs --------------- */

	{
		static uint8_t elf[512];
		char epath[256];
		uint64_t clean_len = 0;
		size_t n = build_infected(elf, sizeof elf, &clean_len);
		int st = -1;

		snprintf(epath, sizeof epath, "%s/host.elf", dir);
		f = n ? fopen(epath, "wb") : NULL;
		if (f) { fwrite(elf, 1, n, f); fclose(f); }
		ok("an infected ELF was built", n != 0 && f != NULL);
		if (n && f) {
			chmod(epath, 0700);

			/*
			 * INFECTED FIRST, so the test is not passing because
			 * the stub never ran. exit(1) is what the appended
			 * code does; anything else means this file is not the
			 * thing the repair is about to be judged on.
			 */
			st = system(epath);
			ok("and it runs the appended stub before the cure",
			   st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 1);

			n_obj = 0;
			memset(&seen, 0, sizeof seen);
			rc = kof_scan_path(sc, epath, &opt, on_object, NULL);
			ok("the infection is found", rc >= 0 && seen.n > 0);
			/*
			 * TWO patches, not one: e_entry, and the PT_LOAD the
			 * virus widened. A cure that restored only the entry
			 * left a file that RAN and still came back
			 * Heur:Truncated - see the note in sig_cure_elf.c.
			 */
			ok("and a repair is offered - entry AND segment",
			   seen.repair.n_fix == 2 &&
			   seen.repair.truncate == clean_len);
			ok("the repair applied",
			   apply_repair(epath, &seen.repair));

			/*
			 * THE ONE CHECK THAT SEPARATES A REPAIR FROM A
			 * REBUILD. A file whose structure merely parses is
			 * not a file that works: exec it, and require the
			 * status the ORIGINAL program produced.
			 */
			st = system(epath);
			ok("and the cured file RUNS, with the original's "
			   "exit status",
			   st != -1 && WIFEXITED(st) &&
			   WEXITSTATUS(st) == EXIT_CODE);

			ok("and it is byte for byte the original length",
			   read_all(epath, back, sizeof back, &got) &&
			   (uint64_t)got == clean_len);

			n_obj = 0;
			memset(&seen, 0, sizeof seen);
			kof_scan_path(sc, epath, &opt, on_object, NULL);
			ok("and it no longer reports as infected", seen.n == 0);

			/*
			 * AND THROUGH A PATH WITH A DOUBLED SLASH.
			 *
			 * "//" is what the engine composes a CHILD name with,
			 * so a filesystem path carrying one made the file
			 * itself read as a child - and a child is never
			 * repaired, because its offsets are into bytes the
			 * engine produced in memory. Measured before the fix:
			 * the same infected file reported "repairable"
			 * through dir/x.elf and nothing at all through
			 * dir//x.elf, so the repair silently did not happen. A shell
			 * joining "$dir/" and "/name" writes one by accident.
			 */
			{
				char dpath[512];

				f = fopen(epath, "wb");
				if (f) { fwrite(elf, 1, n, f); fclose(f); }
				chmod(epath, 0700);
				snprintf(dpath, sizeof dpath, "%s//host.elf",
					 dir);
				n_obj = 0;
				memset(&seen, 0, sizeof seen);
				kof_scan_path(sc, dpath, &opt, on_object, NULL);
				ok("a doubled slash still reaches the repair",
				   seen.n > 0 && seen.repair.n_fix == 2);
			}
			unlink(epath);
		}
	}

	kof_scanner_free(sc);
	kof_engine_close(e);

	/* Leave nothing behind; a repair test that litters is a repair test
	 * somebody stops running. */
	unlink(path);
	unlink(link);
	unlink(target);
	rmdir(dir);

	if (fails) {
		printf("cure: %d check(s) failed\n", fails);
		return 1;
	}
	printf("cure: ok\n");
	return 0;
}
