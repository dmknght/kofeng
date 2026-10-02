/* See ovlflow.h. */

#include "diagnose.h"

#include <stdlib.h>
#include <string.h>

uint8_t kof_diag_weight(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_FILE_OPEN:                        /* 66.62% */
		return KOF_DIAG_W_COMMON;
	case KOF_CAP_READ:                             /* 14.89% */
	case KOF_CAP_WRITE:                            /* 12.61% */
		return KOF_DIAG_W_ORDINARY;
	case KOF_CAP_EXEC_IMAGE:                       /*  8.36% */
	case KOF_CAP_SLEEP:                            /*  6.74% */
	case KOF_CAP_SPAWN:                            /*  6.19% */
	case KOF_CAP_ALLOC:                            /*  5.29% */
	case KOF_CAP_NET_OPEN:                         /*  3.52% */
	case KOF_CAP_PTRACE:                           /*  2.38% */
	case KOF_CAP_NET_CONNECT:                      /*  1.76% */
	case KOF_CAP_NET_ACCEPT:                       /*  1.07% */
	/*
	 * THE TWO THAT WERE SPLIT OUT OF THE ONES ABOVE, and they keep the
	 * weight they were carrying rather than getting one invented for
	 * them. THREAD came out of SPAWN and NET_RAW out of NET_OPEN, so
	 * either must be at least as rare as its parent - but "at least as
	 * rare" is not a number, and every other row here IS a measured one.
	 *
	 * Leaving them at the parent's weight cannot lose a chain that was
	 * kept before the split, which is the property that matters until
	 * somebody measures them: adding a word to the vocabulary must not
	 * silently delete findings, and it did - 150 objects with a chain
	 * became 75 when these two fell through to `default: 0`.
	 */
	case KOF_CAP_THREAD:                           /*  not measured */
	case KOF_CAP_NET_RAW:                          /*  not measured */
	/*
	 * AND THE WINDOWS SIDE, none of it measured either - there is no
	 * clean PE corpus on hand to measure against, and a weight invented
	 * without one would be a number pretending to be an observation.
	 *
	 * NOTABLE for all of them, which is the weight that cannot LOSE a
	 * chain that would otherwise have been kept. Being generous here
	 * costs a chain that is carried and weighed later; being mean deletes
	 * it before anybody sees it, which is the failure that is silent.
	 */
	case KOF_CAP_PROC_MEM:                         /*  not measured */
	case KOF_CAP_PROC_EXEC:                        /*  not measured */
	case KOF_CAP_RESOLVE:                          /*  not measured */
	case KOF_CAP_REG_SET:                          /*  not measured */
	/*
	 * AND THE THREE READ FROM INSTRUCTIONS RATHER THAN FROM NAMES, which
	 * are here because leaving them out is the same silent deletion the
	 * paragraph above describes, and it happened again: a payload whose
	 * whole readable body is `self-resolve` plus a hash loop scored 0 and
	 * reported "no run of it claims enough to be worth a chain". Not a
	 * missing detection - a missing ROW.
	 *
	 * None of the three is measured, and NOTABLE is the generous choice
	 * for the same reason as above. What each is worth on its own is also
	 * less than usual, because for all three the EVIDENCE IS IN THE LINK
	 * rather than in the word:
	 *
	 *   exec-register   `call rax` where rax came from an earlier step.
	 *                   Fed by alloc-exec that is a stager handing over;
	 *                   fed by a resolve it is every delay-loaded import
	 *                   in ordinary software. Same word, different fact,
	 *                   and only the link tells them apart.
	 *   self-resolve    a read of fs:[0x30] / gs:[0x60]. The OS fixes the
	 *                   offset, so unlike a hash seed the author cannot
	 *                   move it - but inlined IsDebuggerPresent and parts
	 *                   of a CRT read the same field.
	 *   name-hash       a rotate by a small constant inside a loop, which
	 *                   is also what a CRC and half the string hashes in
	 *                   any program look like.
	 */
	case KOF_CAP_EXEC_REG:                         /*  not measured */
	case KOF_CAP_SELF_RESOLVE:                     /*  not measured */
	case KOF_CAP_NAME_HASH:                        /*  not measured */
	case KOF_CAP_CALL_REG:                         /*  not measured */
	/*
	 * AND THE NINE WORDS ADDED WITH THEM, none measured either. They do
	 * NOT all sit in one band, because two of them are known in advance to
	 * keep common company and putting those at NOTABLE would be inventing
	 * a rarity nobody observed:
	 *
	 *   file-delete  every program that writes a temporary file unlinks
	 *                it. This is COMMON by construction, not by
	 *                measurement, and the construction is the argument.
	 *   perm-set     an installer chmods what it installed.
	 *
	 * The other seven name entry points that exist to do one thing a
	 * normal program rarely asks for, and they stay at the generous
	 * NOTABLE until somebody prices them.
	 */
	case KOF_CAP_CRYPTO:                           /*  not measured */
	case KOF_CAP_CAPTURE:                          /*  not measured */
	case KOF_CAP_SVC_INSTALL:                      /*  not measured */
	case KOF_CAP_MOD_LOAD:                         /*  not measured */
	case KOF_CAP_PIPE:                             /*  not measured */
	case KOF_CAP_ANTI_DEBUG:                       /*  not measured */
	case KOF_CAP_JAIL:                             /*  not measured */
	/*
	 * The three measured ones, and the measurement is a PREVALENCE IN
	 * MALWARE and not the rate every other row here is - there is still
	 * no clean corpus for these. 2.1% of 10243 objects import dup2 and
	 * 0.5% a timestamp setter, which says they are uncommon among files
	 * that are already malicious and says nothing yet about clean ones.
	 * NOTABLE for the same reason as the rest of this block.
	 */
	case KOF_CAP_FD_REDIR:                         /*  2.1% of malware */
	case KOF_CAP_TIMESTOMP:                        /*  0.5% of malware */
	case KOF_CAP_PROC_LIST:                        /*  2.0% of malware */
		return KOF_DIAG_W_NOTABLE;
	case KOF_CAP_FILE_DELETE:                      /*  not measured */
		return KOF_DIAG_W_COMMON;
	case KOF_CAP_PERM_SET:                         /*  not measured */
		return KOF_DIAG_W_ORDINARY;
	/*
	 * AND THE KERNEL SIDE, which IS measured - against a different corpus
	 * from every other row here: 1497 loadable modules from two kernels,
	 * not 846 binaries from /usr/bin. Written down because a weight that
	 * came from somewhere else is not comparable to its neighbours, and a
	 * reader who assumes it is will draw the wrong conclusion from it.
	 *
	 * Taking an entry out of a list is what the measurement calls
	 * ordinary: 255 of 1497 clean modules do it, under the kernel's newer
	 * spelling of the check. It weighs what the rate says it weighs.
	 */
	case KOF_CAP_LIST_HIDE:                        /* 17.04% of 1497 */
		return KOF_DIAG_W_ORDINARY;
	case KOF_CAP_MEMFD:                            /*  0.07% */
	case KOF_CAP_ALLOC_EXEC:                       /*  0.10% */
	/*
	 * Neither of these is in ANY of the 1497. Zero is not a rate and is
	 * not written as one - what it supports is "rarer than anything else
	 * measured here", which is the weight below and no more than it.
	 */
	case KOF_CAP_CRED_SET:                         /*  0 of 1497 */
	case KOF_CAP_HOOK:                             /*  0 of 1497 */
	/*
	 * Read from the instruction rather than from a name, and measured on
	 * the same corpus: 3 of 898 loadable modules write a control
	 * register, against 4 of 7 LKM rootkits. The three are the ones that
	 * manage the CPU.
	 */
	case KOF_CAP_PROT_OFF:                         /*  0.33% of 898 */
		return KOF_DIAG_W_RARE;
	/*
	 * AND THE TWO WHOSE FIRST MEASUREMENT WAS WRONG, kept here with what
	 * the second one said because the mistake is worth more than the
	 * numbers.
	 *
	 * The symbol ranking that chose these words put `htons` at 5.2% of
	 * malware against 0.06% of clean, and `inet_addr` at 18.1% against
	 * 0.47%. Both are real - and both are rates within the objects that
	 * HAVE names. Malware here is statically linked and clean software is
	 * not, so that subpopulation is 1772 of some 10800 malware objects
	 * and nearly all of the clean ones.
	 *
	 * Measured the way the engine actually sees a corpus - per object,
	 * chains and all - the order reverses:
	 *
	 *     net-addr    29 of 2416 botnet   176 of 1260 clean
	 *     self-hide   16 of 2416 botnet   235 of 1260 clean
	 *
	 * So these are ORDINARY, and the lesson is in the denominator: a rate
	 * measured over "the files that carry the thing" is not a rate over
	 * the files a scan meets.
	 */
	/*
	 * Reading a socket is rarer than reading, and nothing has measured
	 * how much rarer. ORDINARY is what `read` and `write` carry, and
	 * these two cannot be MORE common than the words they were split
	 * out of - the same argument the THREAD/NET_RAW split used.
	 */
	case KOF_CAP_NET_READ:                         /*  not measured */
	case KOF_CAP_NET_WRITE:                        /*  not measured */
	case KOF_CAP_NET_ADDR:                         /* 14.0% of 1260 */
	case KOF_CAP_SELF_HIDE:                        /* 18.7% of 1260 */
		return KOF_DIAG_W_ORDINARY;
	default:
		return 0;
	}
}

/*
 * WHICH CAPABILITIES ARE NEAR NEIGHBOURS.
 *
 * Not everything that differs differs equally. `read` and `recvfrom` already
 * arrive as one capability, so what is left here is coarser: a variant that
 * maps with mmap where another used mprotect is the same program, and one that
 * opens a socket where another connected one is doing the same kind of thing
 * one step earlier.
 *
 * SMALL AND STATED, rather than a full matrix. Every row is a claim, and a
 * matrix of claims nobody checked is how a "flexible" matcher becomes one that
 * matches everything. Three families, each of which a variant really does move
 * inside.
 */
static uint8_t family(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_ALLOC:
	case KOF_CAP_ALLOC_EXEC:
	case KOF_CAP_EXEC_REG:
	case KOF_CAP_SELF_RESOLVE:
	case KOF_CAP_NAME_HASH:
	case KOF_CAP_CALL_REG:
		return 1;
	case KOF_CAP_NET_OPEN:
	case KOF_CAP_NET_CONNECT:
	case KOF_CAP_NET_ACCEPT:
	/* A raw socket is still a socket: a variant that opens one where
	 * another opened a stream is doing the same thing one step rougher. */
	case KOF_CAP_NET_RAW:
	/* Building the address is the step before opening the socket to it,
	 * and a variant that hardcodes where another resolved is the same
	 * move - so it belongs with the network family. */
	case KOF_CAP_NET_ADDR:
		return 2;
	case KOF_CAP_READ:
	case KOF_CAP_WRITE:
	/* The same move over a socket instead of a file - see
	 * KOF_CAP_NET_READ. A variant that reads its payload off the network
	 * where another read it off disk is the same program. */
	case KOF_CAP_NET_READ:
	case KOF_CAP_NET_WRITE:
	/* Pointing stdin at something is what a program does INSTEAD of
	 * reading it itself, and a variant that redirects where another read
	 * is the same move. */
	case KOF_CAP_FD_REDIR:
	/* Encrypting a buffer in the middle of a read/write loop is the same
	 * move as copying it, one transformation along - a variant that
	 * encrypts where another copied is doing the same thing. */
	case KOF_CAP_CRYPTO:
		return 3;
	/* A fourth, for the split above: forking and threading are the same
	 * move for a program that wants a second thing running. */
	case KOF_CAP_SPAWN:
	case KOF_CAP_THREAD:
		return 4;
	/* A fifth: the three ways of reaching into another process are each
	 * other's near neighbours, and a variant that queues an APC where
	 * another started a remote thread is the same move. */
	case KOF_CAP_PTRACE:
	case KOF_CAP_PROC_MEM:
	case KOF_CAP_PROC_EXEC:
		return 5;
	/*
	 * A SIXTH, and it is the kernel's version of the fifth: changing
	 * somebody else's credentials and putting a hook in somebody else's
	 * code path are both "reach into what is already running". A rootkit
	 * that escalates where another hooked is the same move, which is what
	 * a family means here.
	 *
	 * LIST_HIDE IS NOT IN IT. Hiding is a different act from taking
	 * control, and at 17% of clean modules it is the one term here that
	 * would carry an alignment on its own. It stays its own word.
	 */
	case KOF_CAP_CRED_SET:
	case KOF_CAP_HOOK:
	/* Turning a protection off is what a hook does first, on the side of
	 * the machine where the hook has to be written into somebody else's
	 * text - so it is the same move and belongs in the same family. */
	case KOF_CAP_PROT_OFF:
		return 6;
	default:
		return 0;
	}
}

/*
 * The windowed test - see kof_diag_near for why it has no table of names
 * behind it and what the window is worth.
 */
int kof_diag_near(const struct kof_flow_node *v, uint32_t n,
		  const uint8_t *cap, uint32_t n_cap, uint32_t window)
{
	uint32_t i;

	if (!v || !cap || !n_cap || n_cap > 32u || !window)
		return 0;
	if (n > KOF_PTH_SYMPTOM_MAX)
		n = KOF_PTH_SYMPTOM_MAX;
	for (i = 0; i < n; i++) {
		uint32_t seen = 0, j, k;

		for (j = i; j < n && j < i + window; j++)
			for (k = 0; k < n_cap; k++)
				if (v[j].cap == cap[k])
					seen |= 1u << k;
		if (seen == (n_cap >= 32u ? 0xffffffffu
					  : (1u << n_cap) - 1u))
			return 1;
	}
	return 0;
}

int kof_diag_worth(const struct kof_flow_node *v, uint32_t n)
{
	uint32_t i, w = 0;

	if (!v || n < KOF_DIAG_MIN_STEPS)
		return 0;
	for (i = 0; i < n; i++)
		w += kof_diag_weight(v[i].cap);
	/*
	 * TWELVE, AND IT WAS SWEPT AGAIN once the chains got shorter.
	 *
	 * Collapsing a loop to one step and dropping the duplicate node that
	 * every ELF import used to produce both shorten a chain, so the sum
	 * compared here fell for the same programs. Swept on the 2769
	 * x86-64 ELF objects of the corpus, where the bar actually binds:
	 * 1662 objects keep a chain at twelve and 2088 at six.
	 *
	 * FOUR HUNDRED OBJECTS, AND THE BAR IS STILL RIGHT. Reading the
	 * chains that only survive at six settles it - they are
	 * `file-open, alloc, read`, over and over: open a file, get memory,
	 * read it. That is the thing the first paragraph of this note says
	 * the bar exists to turn away, and it used to clear twelve only
	 * because each of those three steps was counted twice.
	 *
	 * So the number did not move. What moved is that it is now applied
	 * to a count of CLAIMS rather than to a count of occurrences, which
	 * is what "three notable capabilities" meant all along.
	 */
	return w >= KOF_DIAG_MIN_WEIGHT;
}

/*
 * THE COST MODEL, in the same units as the weights.
 *
 * A mismatch is PRICED AND NOT FORBIDDEN, which is the whole difference
 * between this and a pattern: a variant that swapped one step for another is
 * still the same program and should still line up, having paid for it.
 *
 * AFFINE GAPS - opening one costs, extending it costs less - because that is
 * the shape junk code has. A polymorphic engine inserts a BLOCK of filler in
 * one place; it does not sprinkle one instruction in twenty places. Measured
 * on the meterpreter stager: six junk instructions between two nodes moved the
 * normalised gap from 11 to 16, all of it in one run.
 */
#define S_FAMILY   1    /* aligned within a family, on top of nothing */
#define S_MISMATCH (-2)
#define S_GAP_OPEN (-3)
#define S_GAP_EXT  (-1)

#define AMAX 64u        /* the table's side; a region longer than this is
			 * clipped, and kof_flow already bounds what a sweep
			 * records */

/* Where a cell came from, so the alignment can be walked back. */
enum { FROM_NONE = 0, FROM_DIAG, FROM_UP, FROM_LEFT };

int kof_diag_align(const struct kof_flow_node *a, uint32_t na,
		   const struct kof_flow_node *b, uint32_t nb,
		   struct kof_diag_hit *out)
{
	/*
	 * NOT `static`, WHICH IS WHAT THEY WERE.
	 *
	 * The engine scans on N threads - see --jobs and unit_scan_mt - and a
	 * static matrix is one matrix shared by all of them: two threads
	 * aligning two different pairs would overwrite each other's cells and
	 * both would come back with a score neither pair has. Nothing memory
	 * unsafe, because the bounds are fixed, but a similarity answer that
	 * depends on what another thread was doing is worse than no answer.
	 *
	 * 12.6 KB of frame, against -Wframe-larger-than=131072.
	 */
	int16_t h[AMAX + 1u][AMAX + 1u];
	uint8_t bt[AMAX + 1u][AMAX + 1u];
	uint32_t i, j, bi = 0, bj = 0;
	int16_t best = 0;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!kof_diag_worth(a, na) || !kof_diag_worth(b, nb))
		return 0;
	if (na > AMAX) na = AMAX;
	if (nb > AMAX) nb = AMAX;

	memset(h, 0, sizeof h);
	memset(bt, 0, sizeof bt);

	for (i = 1; i <= na; i++) {
		for (j = 1; j <= nb; j++) {
			uint8_t ca = a[i - 1u].cap, cb = b[j - 1u].cap;
			int16_t diag, up, left, v;

			if (ca == cb)
				diag = (int16_t)(h[i - 1u][j - 1u] +
						 kof_diag_weight(ca));
			else if (family(ca) && family(ca) == family(cb))
				diag = (int16_t)(h[i - 1u][j - 1u] + S_FAMILY);
			else
				diag = (int16_t)(h[i - 1u][j - 1u] +
						 S_MISMATCH);

			up = (int16_t)(h[i - 1u][j] +
				       (bt[i - 1u][j] == FROM_UP ? S_GAP_EXT
								 : S_GAP_OPEN));
			left = (int16_t)(h[i][j - 1u] +
					 (bt[i][j - 1u] == FROM_LEFT
					  ? S_GAP_EXT : S_GAP_OPEN));

			v = diag;
			bt[i][j] = FROM_DIAG;
			if (up > v)   { v = up;   bt[i][j] = FROM_UP; }
			if (left > v) { v = left; bt[i][j] = FROM_LEFT; }
			/*
			 * LOCAL: a cell never goes below zero, which is what
			 * lets the alignment START anywhere. Without it the
			 * loader segment inside a trojan would be dragged
			 * under by the two hundred nodes in front of it.
			 */
			if (v < 0) { v = 0; bt[i][j] = FROM_NONE; }
			h[i][j] = v;
			if (v > best) { best = v; bi = i; bj = j; }
		}
	}
	if (!best)
		return 0;

	out->a_last = (uint8_t)(bi - 1u);
	out->b_last = (uint8_t)(bj - 1u);

	/* Walk back from the best cell to where it fell to zero: that run is
	 * the segment, and counting it is what the caller is told. */
	i = bi; j = bj;
	while (i && j && h[i][j] > 0) {
		if (bt[i][j] == FROM_DIAG) {
			uint8_t ca = a[i - 1u].cap, cb = b[j - 1u].cap;

			if (ca == cb) {
				if (out->matched < 255u) out->matched++;
				if (kof_diag_weight(ca) >= KOF_DIAG_W_RARE &&
				    out->rare < 255u)
					out->rare++;
				/*
				 * A MATCH THAT CARRIES THE EDGE COUNTS APART.
				 * "Both allocate" and "both allocate, and both
				 * jump into what they allocated" are different
				 * claims - see KOF_FLOWF_EXECUTED.
				 */
				if ((a[i - 1u].flags & (KOF_FLOWF_EXECUTED)) &&
				    (b[j - 1u].flags & (KOF_FLOWF_EXECUTED)) &&
				    out->chained < 255u)
					out->chained++;
				else if (kof_flow_from_any(&a[i - 1u]) &&
					 kof_flow_from_any(&b[j - 1u]) &&
					 out->chained < 255u)
					out->chained++;
			} else if (family(ca) && family(ca) == family(cb)) {
				if (out->related < 255u) out->related++;
			} else {
				if (out->mismatch < 255u) out->mismatch++;
			}
			out->a_first = (uint8_t)(i - 1u);
			out->b_first = (uint8_t)(j - 1u);
			i--; j--;
		} else if (bt[i][j] == FROM_UP) {
			if (out->gap_len < 255u) out->gap_len++;
			if (bt[i - 1u][j] != FROM_UP && out->gaps < 255u)
				out->gaps++;
			i--;
		} else if (bt[i][j] == FROM_LEFT) {
			if (out->gap_len < 255u) out->gap_len++;
			if (bt[i][j - 1u] != FROM_LEFT && out->gaps < 255u)
				out->gaps++;
			j--;
		} else {
			break;
		}
	}
	return out->matched ? 1 : 0;
}

uint32_t kof_diag_nodes(const struct kof_pth_symptom *c,
			      struct kof_flow_node *out)
{
	uint32_t i;

	if (!c || !out)
		return 0;
	memset(out, 0, sizeof *out * (c->n > KOF_PTH_SYMPTOM_MAX
				      ? KOF_PTH_SYMPTOM_MAX : c->n));
	for (i = 0; i < c->n && i < KOF_PTH_SYMPTOM_MAX; i++) {
		out[i].cap = c->s[i].cap;
		out[i].flags = c->s[i].flags;
		out[i].step = i;
		/* The link comes back as an index, which is what the aligner
		 * and kof_flow_from_any read. */
		if (c->s[i].back && c->s[i].back <= i)
			out[i].from[0] = (uint16_t)(i - c->s[i].back + 1u);
	}
	return i;
}

int kof_diag_of(const struct kof_flow_node *v, uint32_t n,
		      struct kof_pth_symptom *out)
{
	uint32_t i, j;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!kof_diag_worth(v, n))
		return 0;
	if (n > KOF_PTH_SYMPTOM_MAX)
		n = KOF_PTH_SYMPTOM_MAX;
	for (i = 0; i < n; i++) {
		out->s[i].cap = v[i].cap;
		out->s[i].flags = (uint8_t)(v[i].flags & KOF_PTH_FLAG_KEEP);
		/*
		 * CARRIED, BUT NOT REQUIRED. The name is recorded so a
		 * researcher editing the rule can SEE which it was and pin it
		 * where the capability is too wide - see kof_pth_step.name -
		 * and kof_diag_pct only tests it when the step says so.
		 * Taking a chain off a sample must not quietly produce a rule
		 * that matches that sample's libc and nothing else.
		 */
		out->s[i].name = v[i].name;
		/*
		 * The first argument that names an earlier node, turned into a
		 * distance. A producer that fell outside the region keeps the
		 * step unlinked rather than pointing at nothing.
		 */
		for (j = 0; j < KOF_FLOW_ARGS; j++) {
			uint32_t src;

			if (!v[i].from[j])
				continue;
			src = v[i].from[j] - 1u;
			if (src < i && i - src < 256u) {
				out->s[i].back = (uint8_t)(i - src);
				break;
			}
		}
	}
	out->n = (uint8_t)n;
	return 1;
}

uint64_t kof_diag_mask(const struct kof_pth_symptom *c)
{
	uint32_t i;
	uint64_t m = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->n && i < KOF_PTH_SYMPTOM_MAX; i++) {
		/*
		 * `cap` is one byte out of a stored chain, and a stored chain
		 * arrives from a .ksig on disk. A shift by 32 or more is
		 * UNDEFINED, not merely wrong - so the vocabulary's own bound
		 * is checked here rather than assumed of the file.
		 */
		if (c->s[i].cap >= KOF_CAP_COUNT)
			continue;
		m |= 1ull << c->s[i].cap;
	}
	return m;
}

/*
 * HOW MUCH OF A STORED CHAIN A REGION CARRIES.
 *
 * NOT kof_diag_align, and the difference is the whole point.
 *
 * The aligner is SYMMETRIC - neither side is the rule - so it compares
 * capabilities and nothing else; the flags only colour what it reports. A rule
 * is not symmetric: "two allocations that are writable AND executable" is a
 * different claim from "two allocations", and measured, the second is one that
 * libswscale answers yes to. So the flags a rule asked for are REQUIRED here,
 * by containment: a step may carry more than the reference asked, never less.
 *
 *
 * ORDER IS ENFORCED ONLY WHERE A LINK DEMANDS IT.
 *
 * This was a total order and that was wrong. A compiler is free to open the
 * socket before it maps the page or after; both are the same program, and a
 * matcher that pins the order it happened to see pins an accident of layout.
 * `socket, mmap, read` and `mmap, socket, read` are one shape.
 *
 * What is NOT free is a step that consumes what an earlier one produced: read
 * cannot fill the mapping before mmap returned it. That constraint is already
 * recorded - kof_diag_step.back - and it is the ONLY thing here that fixes an
 * order. Everything else matches in any order.
 *
 * SO THE LINKS ARE THE SKELETON AND THE REST IS A SET. Which also says how
 * much a chain is worth on each platform, and the measurement is not
 * comforting: links were found in 13.6% of multi-node regions in /usr/bin and
 * in NONE of 1501 PE regions, because Windows compilers spill the returned
 * pointer to a stack slot that this sweep does not follow. On a PE, therefore,
 * a chain today is a SET of capabilities with a span bound and no skeleton at
 * all - which is the honest description of it, and the reason a PE chain rule
 * should lean on the flags rather than on the sequence.
 *
 * THE GAP IS COUNTED IN NODES, which is the unit junk code cannot move.
 * Inserting instructions changes the byte distance and the instruction
 * distance and leaves the node distance alone - measured, six junk
 * instructions moved the normalised gap from 11 to 16 and moved the node
 * sequence not at all. Bytes are what bases/signatures/meterp_00.c pins and
 * are the reason it misses variants. With the order gone the bound applies to
 * the whole matched SPAN rather than to each consecutive pair, which is the
 * same claim over a set instead of a sequence.
 *
 * GREEDY, AND SAID SO. A step takes the first node that satisfies it, which
 * can strand a later step whose link needed that node. Both sides hold at most
 * KOF_PTH_SYMPTOM_MAX steps and links are sparse, so the exhaustive answer
 * would differ rarely and cost a search; if a measured case ever turns up, it
 * belongs here rather than in a threshold somewhere else.
 */
#define KOF_DIAG_CHAIN_GAP 4u   /* nodes allowed between two matched steps */

/* Does this node satisfy this step - capability, the flags the rule asked for,
 * and the link if it asked for one. `at` holds which node each earlier step
 * took, so a link is checked against the node that actually matched. */
static int step_fits(const struct kof_pth_step *st, uint32_t i,
		     const struct kof_flow_node *v, uint32_t j,
		     const uint8_t *at, const uint8_t *have)
{
	uint32_t q, src;

	if (v[j].cap != st->cap || (v[j].flags & st->flags) != st->flags)
		return 0;
	/* A step that named one is about that name; one that did not is
	 * about the capability, which is every rule written before names
	 * existed - see kof_pth_step.name. */
	if (st->name && v[j].name != st->name)
		return 0;
	if (!st->back)
		return 1;
	if (st->back > i || !have[i - st->back])
		return 0;      /* the producer is not in this match */
	src = at[i - st->back];
	for (q = 0; q < KOF_FLOW_ARGS; q++)
		if (v[j].from[q] && v[j].from[q] - 1u == src)
			return 1;
	return 0;
}

uint32_t kof_diag_pct(const struct kof_pth_symptom *ref,
			    const struct kof_flow_node *v, uint32_t n)
{
	uint32_t start, best = 0;

	if (!ref || !ref->n || !v || !n)
		return 0;
	if (n > KOF_PTH_SYMPTOM_MAX)
		n = KOF_PTH_SYMPTOM_MAX;

	for (start = 0; start < n; start++) {
		uint8_t at[KOF_PTH_SYMPTOM_MAX], have[KOF_PTH_SYMPTOM_MAX];
		uint32_t used = 0, got = 0, lo = n, hi = 0, i;

		memset(have, 0, sizeof have);
		/*
		 * The reference's own order is a topological one - a link
		 * always points backwards - so walking it in index order means
		 * a producer is already placed when its consumer is tried.
		 */
		for (i = 0; i < ref->n && i < KOF_PTH_SYMPTOM_MAX; i++) {
			uint32_t j;

			for (j = start; j < n; j++) {
				if (used & (1u << j))
					continue;
				if (!step_fits(&ref->s[i], i, v, j, at, have))
					continue;
				used |= 1u << j;
				at[i] = (uint8_t)j;
				have[i] = 1;
				got++;
				if (j < lo) lo = j;
				if (j > hi) hi = j;
				break;
			}
		}
		/*
		 * AND THE MATCH HAS TO BE ONE STRETCH OF CODE. Without this a
		 * step matched at the top of a large region and another at the
		 * bottom would read as a chain, and they are two unrelated
		 * things that happen to be in one function.
		 */
		if (got > 1u && hi - lo + 1u - got >
		    KOF_DIAG_CHAIN_GAP * (got - 1u))
			continue;
		if (got > best)
			best = got;
		if (best >= ref->n)
			break;
	}
	return best * 100u / ref->n;
}
