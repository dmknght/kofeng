/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kofproc.h - build the record the engine scans a process as.
 *
 * WHY THIS IS ONE PIECE OF CODE AND NOT ONE PER COLLECTOR.
 *
 * kofmod/proc.h defines the layout; something has to WRITE it. If each
 * collector wrote its own, libkofgrille and libkofantarc would each have a
 * private opinion about where the arena starts, what order its strings go in,
 * and which offsets are zero when a field is absent - and the first time they
 * disagreed, the symptom would not be a build error. It would be a rule that
 * fires on one platform and is silent on the other, for a reason nobody can
 * see by reading either side.
 *
 * The string ORDER in particular is not cosmetic: kofmod/proc.h partitions the
 * record into META, CMDLINE and FD, and that partition only holds because the
 * arena is written identity-first, command line next, descriptor links last.
 * A collector that wrote them in a different order would produce a record
 * whose regions overlap, which the region contract forbids and which no test
 * on that collector alone would notice.
 *
 * So: one builder, in orbit, taking plain values. It knows nothing about
 * /proc, nothing about ETW, and nothing about either collector's own record -
 * each of them fills the struct below from whatever it has and calls this.
 * That is the same shape kofw_evt_to_kof has on the Windows side: the
 * conversion is the collector's, the TARGET LAYOUT is shared.
 *
 * IT LIVES IN ORBIT because orbit is allowed to know the engine's types and
 * the engine must never know orbit's - see koffridge.h. A record layout is an
 * engine type; a collector is not.
 */

#ifndef KOFORBIT_KOFPROC_H
#define KOFORBIT_KOFPROC_H

#include <stdint.h>

#include <kofmod/proc.h>

/*
 * What a collector hands over. Every string may be NULL or "", which is how
 * "this platform does not have one" and "it could not be read" are both said -
 * the offset comes back zero and a rule sees the field as absent.
 */
struct kof_proc_build {
	uint8_t  os;             /* enum kof_evt_platform */

	uint32_t pid, ppid;
	uint64_t start_time;

	uint32_t n_fd, n_socket, n_like_stdin;
	uint32_t flags;          /* KOF_PROC_F_* */

	/*
	 * The per-platform tail, already in the order kof_proc_rec's union
	 * expects: uid then gid on Linux, session then integrity on Windows.
	 * Two plain words, because this builder must not have to learn what
	 * either platform's second word means.
	 */
	uint32_t plat_a, plat_b;

	const char *exe, *comm, *cmdline;
	const char *fd0, *fd1, *fd2;
};

/*
 * Write the record into `buf`. Returns its length, or 0 when it does not fit.
 *
 * TRUNCATES NOTHING. A record that will not fit is refused outright rather
 * than written short, because a short one is still a valid record by every
 * check the parser makes - it would simply describe a process with no command
 * line, and a rule would read that as a fact.
 *
 * KOF_PROC_REC_MAX is what a caller should give it: the arena is bounded by
 * a path, a command line and three link strings, none of which is unbounded in
 * practice, and a caller that wants to be sure sizes the buffer to this.
 */
#define KOF_PROC_REC_MAX 8192u

uint32_t kof_proc_build_rec(const struct kof_proc_build *, void *buf,
			    uint32_t cap);

#endif /* KOFORBIT_KOFPROC_H */
