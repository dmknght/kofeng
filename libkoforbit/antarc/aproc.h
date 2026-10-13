/*
 * aproc.h - what is running right now on Linux, and what is inside it.
 *
 * THE SNAPSHOT HALF, AND IT LOOKS THE OPPOSITE WAY FROM A STREAM.
 *
 * A collector sees things that happen, in the order they happen, from the
 * moment it opened. That has one property it can never fix - it cannot see
 * backwards. A machine compromised on Tuesday with a sensor installed on
 * Thursday produces a perfectly clean stream, because everything that mattered
 * happened before anything was watching, and the payload that is still
 * resident has not raised an event since.
 *
 * This answers "what is here" instead. Every process that exists at this
 * instant, every region of its address space, and the bytes in any of them.
 *
 * Shape:
 *
 *	struct kofa_plist *l = kofa_plist_open(NULL, &err);
 *	struct kofa_proc   p;
 *
 *	while (kofa_plist_next(l, &p)) {
 *		struct kofa_pmem  *m = kofa_pmem_open(p.pid, p.start_time,
 *						      NULL, &err);
 *		struct kofa_region r;
 *
 *		if (!m)
 *			continue;
 *		while (kofa_pmem_next_region(m, &r))
 *			if (r.flags & KOFA_RGF_UNBACKED)
 *				... kofa_pmem_read(m, r.base, buf, n) ...
 *		kofa_pmem_close(m);
 *	}
 *	kofa_plist_close(l);
 *
 *
 * STILL NO JUDGING, and this is the file where it is tempting to break.
 *
 * "Anonymous, executable, and an ELF header in it" is three facts away from a
 * verdict, and a library that shipped the verdict would be one nobody can
 * tune, test against a corpus, or disagree with. So every flag below is
 * something that is TRUE of a region, never something that is WRONG with it.
 *
 * The measured example, on the machine this was written on: SEVEN anonymous
 * rwxp regions of 512 MB each, in seven different processes. Every one of them
 * is V8 - Electron, VS Code, node. An rwx region is not a finding on Linux and
 * anything that treats it as one will spend its life explaining itself.
 *
 *
 * ================================================================
 * THE MEASUREMENTS THIS FILE IS BUILT ON
 * ================================================================
 *
 * Taken 2026-09-12 on the development machine as an ordinary user: 34 readable
 * processes, 10182 VMAs. Running as root reaches roughly ten times as many
 * processes, but the SHAPE below does not change, and the shape is what the
 * design rests on.
 *
 *	region class               VMAs      virtual     RESIDENT
 *	-------------------------------------------------------------
 *	exec, file-backed          1076      2736 MB     scanned as FILES
 *	exec, ANONYMOUS              43      3777 MB     ~12 MB
 *	rw anonymous (heap)        2478     19346 MB     1867 MB
 *	mappings marked (deleted)    94
 *	memfd mappings                8
 *
 * READ THAT SECOND ROW AGAIN. The set this library exists to find - code with
 * no file behind it - looks like 3777 MB and IS 12 MB. The difference is not
 * an optimisation opportunity, it is the difference between a sweep that
 * finishes and one that does not.
 *
 * Where the lie comes from, measured on five real processes:
 *
 *	pid 748  code    512.0 MB virtual ->  4.76 MB resident (0.93%), 11 runs
 *	pid 575  code    512.0 MB virtual ->  0.15 MB resident (0.03%), 13 runs
 *	pid 383  code    512.0 MB virtual ->  1.92 MB resident (0.38%),  2 runs
 *	pid  22  code    512.0 MB virtual ->  3.52 MB resident (0.69%),  5 runs
 *	pid 660  claude   64.0 MB virtual ->  1.61 MB resident (2.51%), 30 runs
 *
 * A VMA is a RESERVATION. Windows distinguishes reserved from committed and
 * VirtualQuery reports which; Linux does not, and /proc/<pid>/maps reports the
 * reservation with no hint of how much of it exists. Anything that sizes its
 * work from maps alone is sizing it from a number two orders of magnitude too
 * big.
 *
 *
 * SO THE WALK IS GUIDED BY /proc/<pid>/pagemap, and here is what that buys:
 *
 *	pid 748: pagemap 0.4 ms | blind readv 80.7 ms | guided 0.5 ms -> 148x
 *	pid 575: pagemap 0.5 ms | blind readv 80.8 ms | guided 0.1 ms -> 887x
 *	pid 383: pagemap 0.5 ms | blind readv 81.1 ms | guided 0.3 ms -> 308x
 *	pid  22: pagemap 0.5 ms | blind readv 78.8 ms | guided 0.7 ms -> 120x
 *	pid 660: pagemap 0.1 ms | blind readv  8.5 ms | guided 0.2 ms ->  37x
 *
 * Eight bytes per page buys the right to skip the other 4088. A 512 MB region
 * costs a 1 MB pagemap read and yields between 2 and 13 contiguous runs, so
 * the number of process_vm_readv calls is small as well as the number of bytes.
 *
 * Three things were verified with purpose-built programs rather than assumed,
 * because each would have been a silent wrong answer:
 *
 *   - /proc/<pid>/pagemap IS readable as an ordinary user for one's own
 *     processes, and bit 63 (PRESENT) is correct. Without CAP_SYS_ADMIN the
 *     PFN field reads as zero, which does not matter: nothing here wants the
 *     PFN.
 *
 *   - A BLIND READ DESTROYS THE SIGNAL THAT MAKES THE FAST PATH POSSIBLE, and
 *     this was measured the wrong way round first, so the wrong conclusion is
 *     recorded here beside the right one.
 *
 *     What was measured first: a child mapped 64 MB, touched four pages, and
 *     had all 64 MB read out of it with process_vm_readv; its RSS was 2908 KB
 *     before and 2908 KB after. The conclusion drawn was "reading does not
 *     perturb the target", and it is HALF TRUE in the way that matters least.
 *
 *     What was measured after the region walk started disagreeing with smaps:
 *     the same child, counting PRESENT pages in its pagemap rather than its
 *     RSS.
 *
 *         after the child wrote 4 pages : 512 present, RSS 2996 KB
 *         after 64 MB was read from it  : 16384 present, RSS 2996 KB
 *
 *     Every page became present and not one byte became resident. A READ fault
 *     on an untouched anonymous page maps THE SHARED ZERO PAGE: the PTE is
 *     installed, so pagemap reports the page present forever after, and the
 *     zero page is not charged to anyone, so RSS does not move.
 *
 *     Three consequences, and the third is the one that bites:
 *
 *       a) PRESENT DOES NOT MEAN "HAS CONTENT". It means a PTE exists, and
 *          for an anonymous page that PTE may point at 4096 shared zeroes.
 *
 *       b) So `rss` cannot come from pagemap alone. It comes from smaps, whose
 *          Rss excludes the zero page - see KOFA_MW_SMAPS. pagemap says WHERE
 *          content can be; smaps says HOW MUCH there is. Neither answers the
 *          other's question.
 *
 *       c) A SCANNER THAT READS BLIND ONCE POISONS EVERY LATER SCAN, its own
 *          and every other tool's, because the page tables it populated stay
 *          populated. This is not a theory: three of the five V8 processes
 *          measured at the top of this file came back 100% present on the
 *          second day, and the thing that had read them was the benchmark
 *          written to prove blind reads were merely slow.
 *
 *     Which is why KOFA_MW_PAGEMAP is on by default and the option to turn it
 *     off is documented as DESTRUCTIVE rather than merely slow.
 *
 *   - TRANSPARENT HUGE PAGES MAKE pagemap AN UPPER BOUND, not an exact
 *     answer. Measured: a child touched 100 scattered pages across 512 MB and
 *     came back with 205 MB resident and AnonHugePages: 204800 kB - the
 *     granularity is 2 MB, not 4 KB. On real processes, whose allocations are
 *     not scattered on purpose, the overshoot is small; the five rows above
 *     are real processes. But a caller must read `rss` below as "no more than
 *     this", and nothing here may treat it as a byte count.
 *
 * ================================================================
 *
 *
 * WHAT LINUX CANNOT ANSWER THAT WINDOWS CAN, said here rather than papered
 * over. These are the reasons this is not a port of wproc.h.
 *
 *   - NO KERNEL ACCOUNT OF WHAT A REGION IS. Windows records MEM_PRIVATE,
 *     MEM_MAPPED and MEM_IMAGE, and wproc.h keeps that as `kind` SEPARATELY
 *     from its own reading in `use`, so that a classification which can be
 *     wrong sits beside the fact it was derived from. Linux records only
 *     whether a file is behind the mapping. There is therefore NO `kind` field
 *     here. It was not renamed or approximated - a field that claims the
 *     kernel's authority for this library's guess is worse than no field.
 *
 *   - RESERVED VERSUS COMMITTED EXISTS AFTER ALL, AND IT IS SPELT PROT_NONE.
 *     Windows says MEM_RESERVE outright. Linux says it by mapping a range with
 *     no permissions at all, and the first walk written against this file
 *     found out how much of it there is the hard way: SEVEN regions of
 *     roughly 1.3 TB each, one per Chromium process, `---p`, 9.1 TB of
 *     address space in total on an ordinary desktop. A walk that sums region
 *     sizes without excluding them reports ten terabytes of memory on a
 *     machine with sixteen gigabytes, and a walk that reads their pagemap asks
 *     for 2.7 GB of entries describing pages that cannot exist.
 *
 *     So a region with no access at all is KOFA_USE_UNKNOWN and is filtered
 *     out by default. It holds nothing, it cannot be read, and it is not a
 *     place anything can hide.
 *
 *   - NO ALLOCATION GROUPING. Windows gives every region an AllocationBase, so
 *     the four runs of one hand-mapped DLL group back into one thing. Linux
 *     has no such concept: a VMA is what mmap made and nothing records that
 *     three adjacent VMAs were one request. Runs are grouped here by adjacency
 *     and by backing file, in the .c, and that is a heuristic - so a caller
 *     that reports per-region will report one payload two or three times
 *     unless it groups by `group_id` below.
 *
 *   - A PROCESS IS NAMED BY (pid, start_time), NOT BY pid. Same argument
 *     wproc.h makes with create_time and a stronger one here: pid_max is 4194304
 *     by default but the numbers are handed out sequentially from a small
 *     space and wrap in minutes on a busy machine. Every call below that takes
 *     a pid takes the pair, and checks it.
 *
 * The text is in three parts by purpose, included below: aproc_proc.h (a process and
 * the list), aproc_region.h (a region) and aproc_pmem.h (walking one process).
 */

#ifndef KOFANTARC_APROC_H
#define KOFANTARC_APROC_H

#include <stdint.h>
#include <stddef.h>

#include "kofantarc.h"

#include "aproc_proc.h"
#include "aproc_region.h"
#include "aproc_pmem.h"

#endif /* KOFANTARC_APROC_H */
