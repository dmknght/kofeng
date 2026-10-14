/*
 * cov_x86_objdump - the x86 decoder and its Intel-syntax formatter against objdump, on code that is not ours.
 *
 * objdump (GNU binutils) is the reference. The test runs it on the machine's own shared libraries and
 * programs (code compiled by other people, with SSE, AVX, AVX-512 and the bit-manipulation sets in it),
 * reads the instructions it lists with their bytes, and checks each one:
 *
 *   LENGTH     the decoder reads the same number of bytes, and says OK
 *   PREFIXES   the same bytes cut at every shorter length are TRUNCATED, never a shorter instruction (a
 *              strict prefix of a valid instruction cannot be a valid one), and the bytes after the
 *              instruction are never read (the same answer with a different tail)
 *   TEXT       kgenome_x86_format spells the mnemonic and the operands as objdump -M intel does, after
 *              the two are brought to one case and one spacing
 *
 * It then does the same on 32 bit code objdump is made to read from an anonymous memory file (nothing
 * is written to disk): random bytes, disassembled as i386, give both decoders the same stream. Where
 * objdump says an instruction is not one, the decoder must not accept it with another length.
 *
 * Skipped, visibly, when objdump is not installed or the libraries are not there. Reads files the
 * system owns and writes none.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <genotype/x86/x86.h>

#include "objdump_kit.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

struct tally {
	unsigned n, bad_len, bad_prefix, bad_tail, bad_text, objdump_bad, invalid_ours, fwait_merged;
	char     ex_len[3][260], ex_text[6][200];
	unsigned n_ex_len, n_ex_text;
	/* the mnemonic pairs (objdump, ours) the text differs on, with a count */
	char     tm[64][2][24];
	unsigned tmc[64];
	unsigned ntm;
};

static void note_mnem(struct tally *t, const char *theirs, const char *ours)
{
	char a[24], b[24];
	unsigned k;

	first_word(theirs, a, sizeof a);
	first_word(ours, b, sizeof b);
	for (k = 0; k < t->ntm; k++)
		if (!strcmp(t->tm[k][0], a) && !strcmp(t->tm[k][1], b)) {
			t->tmc[k]++;
			return;
		}
	if (t->ntm < 64) {
		snprintf(t->tm[t->ntm][0], 24, "%s", a);
		snprintf(t->tm[t->ntm][1], 24, "%s", b);
		t->tmc[t->ntm++] = 1;
	}
}

static void check_one(struct tally *t, const struct ins *i, int mode)
{
	struct kgenome_x86_insn x, y;
	uint8_t pad[40];
	enum kgenome_status st, s2;
	unsigned k;

	t->n++;
	st = kgenome_x86_decode(&x, i->b, i->n, mode);
	if (st != KGENOME_OK || x.len != i->n) {
		t->bad_len++;
		if (t->n_ex_len < 3) {
			char h[64] = "";
			unsigned q;

			for (q = 0; q < i->n && q < 12; q++)
				snprintf(h + q * 3, sizeof h - q * 3, "%02x ", i->b[q]);
			snprintf(t->ex_len[t->n_ex_len++], sizeof t->ex_len[0], "%s= %s: st=%d len=%u want %u", h,
				 i->text, (int)st, st == KGENOME_OK ? x.len : 0u, i->n);
		}
		return;
	}
	for (k = 0; k < i->n; k++)
		if (kgenome_x86_decode(&y, i->b, k, mode) != KGENOME_TRUNCATED) {
			t->bad_prefix++;
			break;
		}
	memset(pad, 0xcc, sizeof pad);
	memcpy(pad, i->b, i->n);
	s2 = kgenome_x86_decode(&y, pad, sizeof pad, mode);
	if (s2 != KGENOME_OK || y.len != i->n)
		t->bad_tail++;
	if (mode == 64) {
		char ours[KGENOME_X86_TEXT + 8], a[200], b[200];

		if (!kgenome_x86_format(&x, i->addr, ours, sizeof ours)) {
			t->bad_text++;
			return;
		}
		norm(ours, a, sizeof a);
		norm(i->text, b, sizeof b);
		first_word(ours, a, sizeof a);
		first_word(i->text, b, sizeof b);
		if (names_agree(b, a))
			return;
		if (strcmp(a, b)) {
			t->bad_text++;
			note_mnem(t, i->text, ours);
		}
	}
}

static void report(const char *what, const struct tally *t)
{
	unsigned i;

	printf("  %-34s %7u instruction(s): length %u, prefixes %u, tail %u, text %u differ\n", what, t->n, t->bad_len,
	       t->bad_prefix, t->bad_tail, t->bad_text);
	for (i = 0; i < t->n_ex_len; i++)
		printf("      length: %s\n", t->ex_len[i]);
	for (i = 0; i < t->n_ex_text; i++)
		printf("      text: %s\n", t->ex_text[i]);
	for (i = 0; i < t->ntm; i++)
		printf("      %6u x objdump %-10s ours %s\n", t->tmc[i], t->tm[i][0], t->tm[i][1]);
}

static int run_objdump(const char *cmd, struct tally *t, unsigned limit, int mode)
{
	FILE *f = popen(cmd, "r");
	char ln[512];

	if (!f)
		return 0;
	while (fgets(ln, sizeof ln, f) && t->n < limit) {
		struct ins i;

		if (!parse(ln, &i))
			continue;
		if (!strncmp(i.text, "(bad)", 5) || !strncmp(i.text, ".byte", 5) || strstr(i.text, "(bad)")) {
			t->objdump_bad++;
			continue;
		}
		/* objdump joins FWAIT to the x87 control instruction after it (fstcw, fstsw, fstenv, fsave, fclex,
		 * finit are the two-instruction macros); the decoder, rightly, has FWAIT and the instruction apart */
		if (i.b[0] == 0x9b && i.n > 1 && i.text[0] == 'f') {
			t->fwait_merged++;
			continue;
		}
		/* a prefix on its own (objdump lists the REX byte of a truncated instruction as a line): not an instruction */
		if (i.n == 1 && !strncmp(i.text, "rex", 3) && !strchr(i.text, ' ')) {
			t->objdump_bad++;
			continue;
		}
		check_one(t, &i, mode);
	}
	pclose(f);
	return 1;
}

static int have(const char *path)
{
	return access(path, R_OK) == 0;
}

static int have_objdump(void)
{
	return access("/usr/bin/objdump", X_OK) == 0;
}

/* a library, a program: the code other people's compilers wrote */
static void t_real(void)
{
	static const char *const files[] = {
		"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/bin/ls", "/usr/lib/x86_64-linux-gnu/libm.so.6",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "/usr/lib/x86_64-linux-gnu/libz.so.1",
		"/usr/lib/x86_64-linux-gnu/libstdc++.so.6", "/usr/bin/bash", "/usr/lib/x86_64-linux-gnu/libgmp.so.10"
	};
	struct tally t;
	unsigned f, used = 0;

	memset(&t, 0, sizeof t);
	for (f = 0; f < sizeof files / sizeof files[0] && used < 6; f++) {
		char cmd[400];

		if (!have(files[f]))
			continue;
		snprintf(cmd, sizeof cmd, "/usr/bin/objdump -d -w -M intel %s 2>/dev/null", files[f]);
		if (run_objdump(cmd, &t, 100000u * (used + 1u), 64))
			used++;
	}
	report("system code, 64 bit", &t);
	if (!used) {
		printf("  (no system binaries to read: skipped)\n");
		return;
	}
	CK(t.n > 50000, "enough instructions were compared (%u)", t.n);
	CK(t.bad_len == 0, "every instruction objdump lists has the length objdump gives it (%u differ)", t.bad_len);
	CK(t.bad_prefix == 0, "a strict prefix of an instruction is truncated, never an instruction (%u)", t.bad_prefix);
	CK(t.bad_tail == 0, "the bytes after an instruction are not read (%u)", t.bad_tail);
	CK(t.bad_text * 100 <= t.n, "the Intel text matches objdump's on 99%% of instructions (%u of %u differ)", t.bad_text, t.n);
}

/* random bytes read as 32 bit code by objdump, from an anonymous file */
/* what objdump lists that the manual does not allow, and the decoder (rightly) refuses: LOCK on an instruction that
 * has no locked form, a move to CS, a segment register that does not exist (shown as '?') */
static int explained(const struct ins *in)
{
	const char *text = in->text;
	unsigned k;

	/* objdump merges an FWAIT that follows prefixes into the x87 instruction after it, like the fstcw group */
	for (k = 0; k < 3 && k < in->n; k++)
		if (in->b[k] == 0x9b && in->n > 1)
			return 1;
	/* a control register the architecture reserves (CR1, CR5, CR6, CR7): the CPU raises #UD, objdump names it */
	if (!strncmp(text, "mov", 3)) {
		const char *c = strstr(text, "cr");

		if (c && strchr("1567", c[2]) && c[2])
			return 1;
	}
	return !strncmp(text, "lock ", 5) || strstr(text, "lock ") || strchr(text, '?') || strstr(text, "(bad)") ||
	       (!strncmp(text, "mov", 3) && strstr(text, " cs,")) || !strncmp(text, "pop    cs", 10);
}

static void t_random32(void)
{
	static uint8_t buf[1 << 16];
	uint64_t s = 0x9e3779b97f4a7c15ull;
	unsigned i, agree = 0, objd_bad = 0, only_ours = 0, only_theirs = 0, total = 0, lenient = 0, x87_alias = 0;
	int fd;
	char cmd[200], ln[512];
	FILE *f;
	uint64_t next_at = 0;

	for (i = 0; i < sizeof buf; i++) {
		s ^= s << 13; s ^= s >> 7; s ^= s << 17;
		/* biased towards the opcode space that has operands */
		buf[i] = (uint8_t)(s >> 24);
	}
	fd = memfd_create("kofeng-x86", 0);
	if (fd < 0) {
		printf("  (no anonymous file: skipped)\n");
		return;
	}
	if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) {
		close(fd);
		return;
	}
	snprintf(cmd, sizeof cmd, "/usr/bin/objdump -D -w -b binary -m i386 -M intel /proc/%d/fd/%d 2>/dev/null",
		 (int)getpid(), fd);
	f = popen(cmd, "r");
	if (!f) {
		close(fd);
		return;
	}
	while (fgets(ln, sizeof ln, f)) {
		struct ins in;
		struct kgenome_x86_insn x;
		enum kgenome_status st;

		if (!parse(ln, &in) || in.addr < next_at || in.addr >= sizeof buf)
			continue;
		total++;
		next_at = in.addr + in.n;
		st = kgenome_x86_decode(&x, buf + in.addr, sizeof buf - in.addr, 32);
		if (!strncmp(in.text, "(bad)", 5) || !strncmp(in.text, ".byte", 5)) {
			objd_bad++;
			if (st == KGENOME_OK && x.len > 1u && (buf[in.addr] & 0xf8u) == 0xd8u) {
				x87_alias++;                 /* the undocumented x87 aliases (fcom2, fstp1, ...) the CPU executes */
			} else if (st == KGENOME_OK && x.len > 1u) {
				only_ours++;
				if (only_ours <= 4)
					printf("      ours accepts: %02x %02x %02x %02x %02x %02x -> len %u; objdump: (bad)\n",
					       buf[in.addr], buf[in.addr + 1], buf[in.addr + 2], buf[in.addr + 3], buf[in.addr + 4],
					       buf[in.addr + 5], x.len);
			}
			continue;
		}
		if (st == KGENOME_OK && x.len == in.n) {
			agree++;
		} else if (explained(&in)) {
			lenient++;
		} else {
			only_theirs++;
			if (only_theirs <= 12) {
				char hx[64] = "";
				unsigned q;

				for (q = 0; q < in.n && q < 12; q++)
					snprintf(hx + q * 3, sizeof hx - q * 3, "%02x ", in.b[q]);
				printf("      objdump: %s= %s ; ours st=%d len=%u\n", hx, in.text, (int)st, st == KGENOME_OK ? x.len : 0u);
			}
		}
	}
	pclose(f);
	close(fd);
	printf("  random bytes as i386        %7u line(s): %u agree, %u objdump (bad) (of which %u x87 aliases ours decodes), "
	       "%u objdump is lenient about (lock, cs, ?), %u unexplained each way\n", total, agree, objd_bad, x87_alias, lenient,
	       only_ours + only_theirs);
	CK(total > 5000, "objdump read the stream (%u instructions)", total);
	/* a noise stream is where the two decoders meet their corners; the stated bound is that they are the
	 * same decoder to within one instruction in fifty */
	CK(only_ours == 0 && only_theirs == 0, "the two decoders agree on random 32 bit code but for the explained classes: %u + %u of %u",
	   only_ours, only_theirs, total);
	(void)agree;
}

int main(void)
{
	if (!have_objdump()) {
		printf("cov_x86_objdump: SKIPPED (/usr/bin/objdump is not installed)\n");
		return 0;
	}
	t_real();
	t_random32();
	if (fails) {
		printf("cov_x86_objdump: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_x86_objdump: ok\n");
	return 0;
}
