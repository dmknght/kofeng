/*
 * kofemu.c - the interpreter. See kofemu.h for what it is for.
 *
 *
 * HOW AN INSTRUCTION IS CARRIED OUT
 *
 * Not as one switch over several hundred mnemonics. bddisasm hands back a
 * decoded operand list - for each operand: is it a register, a memory
 * reference or an immediate, how wide, and is it read, written or both. So the
 * shape here is
 *
 *      read every source operand generically
 *      switch on the mnemonic to compute a result   <- small
 *      write the destination generically
 *
 * and the switch holds arithmetic rather than addressing. Adding an
 * instruction is then usually one case, and the addressing modes it inherits
 * are the ones already tested by every other instruction.
 *
 *
 * FLAGS ARE COMPUTED EAGERLY
 *
 * A real CPU defers them and so do fast emulators. This one does not: a packer
 * stub is a few hundred thousand instructions, the budget stops it long before
 * the difference is measurable, and a lazy flag bug is the kind that shows up
 * as one wrong branch a hundred thousand instructions later. Correctness that
 * can be read beats speed that cannot.
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "kofemu.h"
#include "bddisasm.h"

#define DEF_MAX_INSN   (2u * 1000u * 1000u)
#define VSYSCALL_BASE  0xffffffffff600000ull
#define DEF_MAX_PAGES  (16u * 1024u)          /* 64 MB of emulated space */

/* ---- memory ---------------------------------------------------------------
 *
 * Sparse, because a packer maps a few megabytes inside a 47 bit address space
 * and a flat array of that is not a thing. Open addressing on the page number:
 * the table is sized from the page budget at construction so it never has to
 * grow while an emulation is in flight.
 */
struct page {
	uint64_t va;                  /* page aligned; 0 means the slot is free */
	uint8_t *data;
	unsigned prot;
	int      written;             /* the stub wrote here - this is the payload */
};

struct kof_emu {
	struct page *tab;
	uint32_t     tab_mask;        /* size - 1; size is a power of two */
	uint32_t     n_pages, max_pages;

	uint64_t gpr[KOF_EMU_NGPR];
	uint64_t rip;
	uint64_t flags;               /* only the six that matter, see FL_* */

	uint64_t max_insn, insn;
	int      stop_on_written_jump;
	/* The address the last failed access asked for. A fault with no address
	 * is a fault nobody can act on. */
	uint64_t fault_va;
	char     fault_kind[8];

	uint64_t trace[KOF_EMU_TRACE];
	uint64_t trace_n;

	/*
	 * MAPPINGS THAT HAVE NOT COST ANYTHING YET.
	 *
	 * A Go runtime commits its heap in 64 MB pieces and touches a few
	 * kilobytes of each. Materialising those eagerly exhausted the page
	 * budget during start-up and the runtime quit with "out of memory"
	 * before running any of the packer's own code. A range recorded here
	 * becomes real one page at a time, when something actually reads or
	 * writes it - which is what the kernel does too.
	 */
	struct vma { uint64_t base, len, off; unsigned prot; int backed; } *vma;
	uint32_t n_vma, max_vma;

	/*
	 * What the RUN is allowed to cost the host, as against what the guest
	 * thinks it has. Every one of these is reachable from guest code doing
	 * something legal in a loop, so each is a ceiling rather than a
	 * guideline - a guest that hits one is told no and carries on.
	 */
	uint64_t snap_bytes;

	/* Where the next hintless mmap lands. Its OWN cursor: deriving it from
	 * the page count made two mappings overlap whenever anything else added
	 * a page between them, which is a corruption the stub then executes. */
	uint64_t mmap_next;

	uint32_t unksys[KOF_EMU_UNKSYS];
	uint32_t n_unksys;
	struct kof_emu_syscall syslog[KOF_EMU_SYSLOG];
	uint32_t n_syslog;

	/*
	 * SSE, BECAUSE A GO RUNTIME CANNOT START WITHOUT IT.
	 *
	 * Not vector arithmetic - the moves, the bitwise ops and the byte
	 * compare that memmove, memset and the string routines are built from.
	 * That is what a packer's runtime executes before it ever reaches its
	 * own unpacking code.
	 */
	uint8_t xmm[16][16];

	/* The thread pointer, as arch_prctl set it. */
	uint64_t fs_base, gs_base;

	/*
	 * THE CLOCK, WHICH IS AN ANTI-EMULATION SURFACE AND NOT A CONVENIENCE.
	 *
	 * It advances with instructions retired rather than with real time, so a
	 * run is reproducible and so the RATIO a stub measures stays plausible:
	 * code that does more work reads a larger delta, which is the only thing
	 * a timing check is really looking at. Real time would make the same
	 * scan answer differently twice, and a frozen clock announces the
	 * emulator to anything that reads it twice.
	 *
	 * `tsc_skew` is time that passed without instructions - a sleep granted
	 * in full without waiting for it.
	 */
	uint64_t tsc_skew;

	/*
	 * How a delay loop ends.
	 *
	 * A stub that spins on the clock until N ticks have gone by would
	 * otherwise run until the budget is gone, having done nothing. Reading
	 * the clock twice in quick succession with no work between is what that
	 * loop looks like from here and looks like nothing else - ordinary code
	 * does not ask the time in a tight loop - so the wait is granted in
	 * jumps that grow until the loop's own condition is met. Nothing else
	 * accelerates: a check that times a piece of REAL work sees the honest
	 * per-instruction rate.
	 */
	uint64_t tsc_last_insn;
	uint32_t tsc_spin;

	/* Thread ids handed to clone, none of which ever run. */
	uint64_t next_tid;

	/* The address of the last futex wait, and how many in a row. */
	uint64_t futex_va;
	uint32_t futex_spin;

	/* The opening bytes of whatever the guest wrote to stdout or stderr. */
	char     say[KOF_EMU_SAY];
	uint32_t n_say;

	/* The one open file an emulated process has: itself. */
	const uint8_t *self;
	uint64_t       self_n, self_pos;

	/* Payload images caught at the mprotect that made them executable. */
	struct snap { uint64_t va, len; uint8_t *bytes; } *snap;
	uint32_t n_snap, max_snap;

	uint64_t watch_va;
	int      watch_on;
	uint64_t watch_rip[KOF_EMU_WATCH_MAX], watch_val[KOF_EMU_WATCH_MAX];
	unsigned watch_n;
	enum kof_emu_stop stop;
	char     detail[48];

	/* Sorted page list, built on demand by kof_emu_next_written, and the
	 * one run handed out at a time - freed when the next is asked for, so a
	 * caller never has to. */
	uint64_t *sorted;
	uint32_t  n_sorted;
	uint8_t  *run_buf;
};

#define FL_CF  (1u << 0)
#define FL_PF  (1u << 2)
#define FL_AF  (1u << 4)
#define FL_ZF  (1u << 6)
#define FL_SF  (1u << 7)
#define FL_DF  (1u << 10)
#define FL_OF  (1u << 11)

static uint32_t page_hash(uint64_t pn)
{
	pn ^= pn >> 33; pn *= 0xff51afd7ed558ccdull;
	pn ^= pn >> 29; pn *= 0xc4ceb9fe1a85ec53ull;
	return (uint32_t)(pn ^ (pn >> 32));
}

static struct page *vma_commit(struct kof_emu *e, uint64_t base);

static struct page *page_find(struct kof_emu *e, uint64_t va)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	uint32_t i = page_hash(base) & e->tab_mask, n = 0;

	if (!base)
		return NULL;          /* page zero is never mapped: a NULL deref
				       * has to fault rather than read zeroes */
	while (n++ <= e->tab_mask) {
		struct page *p = &e->tab[i];

		if (!p->va)
			return vma_commit(e, base);
		if (p->va == base)
			return p;
		i = (i + 1u) & e->tab_mask;
	}
	return NULL;
}

static struct page *page_add(struct kof_emu *e, uint64_t base, unsigned prot)
{
	uint32_t i, n = 0;

	if (e->n_pages >= e->max_pages || !base)
		return NULL;
	i = page_hash(base) & e->tab_mask;
	while (n++ <= e->tab_mask) {
		struct page *p = &e->tab[i];

		if (p->va == base)
			return p;
		if (!p->va) {
			p->data = calloc(1, KOF_EMU_PAGE);
			if (!p->data)
				return NULL;
			p->va = base;
			p->prot = prot;
			e->n_pages++;
			free(e->sorted);
			e->sorted = NULL;
			return p;
		}
		i = (i + 1u) & e->tab_mask;
	}
	return NULL;
}

/* Record a mapping without committing any of it. */
static int vma_add(struct kof_emu *e, uint64_t base, uint64_t len,
		   uint64_t off, unsigned prot, int backed)
{
	struct vma *v;

	/*
	 * A ceiling on the number of live mappings, not on their size.
	 *
	 * mmap is the one call a guest can make in a loop that costs the HOST
	 * memory without costing the guest a page: a reservation commits
	 * nothing, so a loop of them grows this list and nothing else stops it.
	 * Real programs use tens; a Go runtime reserving its arenas uses a few
	 * hundred.
	 */
	if (e->n_vma >= KOF_EMU_MAX_VMA)
		return 0;
	if (e->n_vma == e->max_vma) {
		uint32_t m = e->max_vma ? e->max_vma * 2u : 8u;
		struct vma *t = realloc(e->vma, (size_t)m * sizeof *t);

		if (!t)
			return 0;
		e->vma = t;
		e->max_vma = m;
	}
	v = &e->vma[e->n_vma++];
	v->base = base; v->len = len; v->off = off;
	v->prot = prot; v->backed = backed;
	return 1;
}

/*
 * Turn one page of a recorded mapping into a real one. Later mappings win, so
 * the search runs backwards: a MAP_FIXED over part of an earlier range is what
 * that address means now.
 */
static struct page *vma_commit(struct kof_emu *e, uint64_t base)
{
	uint32_t k = e->n_vma;

	while (k--) {
		struct vma *v = &e->vma[k];
		struct page *p;

		if (base < v->base || base - v->base >= v->len)
			continue;
		p = page_add(e, base, v->prot);
		if (!p)
			return NULL;
		if (v->backed && e->self) {
			uint64_t o = v->off + (base - v->base);
			uint64_t n = o < e->self_n ? e->self_n - o : 0;

			if (n > KOF_EMU_PAGE)
				n = KOF_EMU_PAGE;
			if (n)
				memcpy(p->data, e->self + o, (size_t)n);
		}
		return p;
	}
	return NULL;
}

/*
 * Every read and write goes through these, one byte at a time.
 *
 * A byte at a time because an access may straddle a page boundary and the two
 * pages need not be adjacent in the table - and because a straddling access
 * that half succeeds is the bug this design exists to make impossible. Speed
 * is not the constraint; the budget is.
 */
static int mem_rd(struct kof_emu *e, uint64_t va, void *dst, unsigned n)
{
	uint8_t *d = dst;
	unsigned i;

	for (i = 0; i < n; i++) {
		struct page *p = page_find(e, va + i);

		if (!p) {
			e->fault_va = va + i;
			memcpy(e->fault_kind, "read", 5);
			return 0;
		}
		d[i] = p->data[(va + i) & (KOF_EMU_PAGE - 1u)];
	}
	return 1;
}

static int mem_wr(struct kof_emu *e, uint64_t va, const void *src, unsigned n)
{
	const uint8_t *s = src;
	unsigned i;

	for (i = 0; i < n; i++) {
		struct page *p = page_find(e, va + i);

		if (!p) {
			e->fault_va = va + i;
			memcpy(e->fault_kind, "write", 6);
			return 0;
		}
		p->data[(va + i) & (KOF_EMU_PAGE - 1u)] = s[i];
		p->written = 1;
		if (e->watch_on && va + i == e->watch_va &&
		    e->watch_n < KOF_EMU_WATCH_MAX) {
			e->watch_rip[e->watch_n] = e->rip;
			e->watch_val[e->watch_n] = s[i];
			e->watch_n++;
		}
	}
	return 1;
}

/* ---- construction --------------------------------------------------------- */

static uint32_t pow2_at_least(uint32_t n)
{
	uint32_t v = 16;

	while (v < n)
		v <<= 1;
	return v;
}

struct kof_emu *kof_emu_new(const struct kof_emu_cfg *cfg)
{
	struct kof_emu *e = calloc(1, sizeof *e);
	uint64_t pages = cfg && cfg->max_pages ? cfg->max_pages : DEF_MAX_PAGES;

	if (!e)
		return NULL;
	if (pages > (1u << 22))
		pages = 1u << 22;
	e->max_pages = (uint32_t)pages;
	/* Twice the budget, so the table never passes half full and the probe
	 * chains stay short whatever the addresses look like. */
	e->tab_mask = pow2_at_least((uint32_t)pages * 2u) - 1u;
	e->tab = calloc((size_t)e->tab_mask + 1u, sizeof *e->tab);
	if (!e->tab) {
		free(e);
		return NULL;
	}
	e->max_insn = cfg && cfg->max_insn ? cfg->max_insn : DEF_MAX_INSN;
	e->stop_on_written_jump = cfg ? cfg->stop_on_written_jump : 0;
	/*
	 * THE VSYSCALL PAGE, WHICH A REAL KERNEL ALWAYS PROVIDES.
	 *
	 * A runtime with no vDSO in its auxv falls back to calling the fixed
	 * addresses here, and finding nothing at them looks like a wild jump to
	 * 0xffffffffff600000 rather than the ordinary fallback it is. Three
	 * entries at their architectural offsets, each doing the syscall it
	 * stands for: mov eax, nr / syscall / ret.
	 */
	{
		static const uint16_t nrs[3] = { 96, 201, 309 }; /* gettimeofday,
								 * time, getcpu */
		uint8_t pg[KOF_EMU_PAGE];
		unsigned k;

		memset(pg, 0xcc, sizeof pg);
		for (k = 0; k < 3; k++) {
			uint8_t *p = pg + k * 0x400u;

			p[0] = 0xb8;                             /* mov eax, */
			p[1] = (uint8_t)nrs[k];
			p[2] = (uint8_t)(nrs[k] >> 8);
			p[3] = 0; p[4] = 0;
			p[5] = 0x0f; p[6] = 0x05;                /* syscall */
			p[7] = 0xc3;                             /* ret     */
		}
		kof_emu_map(e, VSYSCALL_BASE, pg, sizeof pg, sizeof pg,
			    KOF_EMU_R | KOF_EMU_X);
	}
	return e;
}

void kof_emu_free(struct kof_emu *e)
{
	uint32_t i;

	if (!e)
		return;
	for (i = 0; i <= e->tab_mask; i++)
		free(e->tab[i].data);
	free(e->tab);
	free(e->sorted);
	free(e->run_buf);
	free(e->vma);
	for (i = 0; i < e->n_snap; i++)
		free(e->snap[i].bytes);
	free(e->snap);
	free(e);
}

int kof_emu_map(struct kof_emu *e, uint64_t va, const uint8_t *src, uint64_t n,
		uint64_t memsz, unsigned prot)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	uint64_t end, off;

	if (!e || memsz < n)
		memsz = n;
	if (!e || !memsz)
		return 0;
	end = va + memsz;
	if (end < va)
		return 0;                     /* wrapped: refuse rather than clamp */
	for (off = base; off < end; off += KOF_EMU_PAGE)
		if (!page_add(e, off, prot))
			return 0;
	/*
	 * Written through page_add's pages directly rather than through mem_wr:
	 * loading an image is not the stub writing, and marking these pages
	 * dirty would hand the whole file back as "what the stub produced".
	 */
	for (off = 0; off < n; off++) {
		struct page *p = page_find(e, va + off);

		if (!p)
			return 0;
		p->data[(va + off) & (KOF_EMU_PAGE - 1u)] = src ? src[off] : 0;
	}
	return 1;
}

void kof_emu_set_self(struct kof_emu *e, const uint8_t *b, uint64_t n)
{
	e->self = b;
	e->self_n = n;
	e->self_pos = 0;
}

void kof_emu_set_rip(struct kof_emu *e, uint64_t rip) { e->rip = rip; }
void kof_emu_set_reg(struct kof_emu *e, unsigned g, uint64_t v)
{
	if (g < KOF_EMU_NGPR)
		e->gpr[g] = v;
}
uint64_t kof_emu_get_reg(const struct kof_emu *e, unsigned g)
{
	return g < KOF_EMU_NGPR ? e->gpr[g] : 0;
}
uint64_t kof_emu_rip(const struct kof_emu *e) { return e->rip; }
uint64_t kof_emu_insn_count(const struct kof_emu *e) { return e->insn; }
const char *kof_emu_stop_detail(const struct kof_emu *e) { return e->detail; }

void kof_emu_watch(struct kof_emu *e, uint64_t va)
{
	e->watch_va = va;
	e->watch_on = 1;
	e->watch_n = 0;
}

unsigned kof_emu_watch_hits(const struct kof_emu *e, uint64_t *rip,
			    uint64_t *val, unsigned n)
{
	unsigned k, got = e->watch_n < n ? e->watch_n : n;

	for (k = 0; k < got; k++) { rip[k] = e->watch_rip[k]; val[k] = e->watch_val[k]; }
	return got;
}

int kof_emu_read(struct kof_emu *e, uint64_t va, void *dst, unsigned n)
{
	return mem_rd(e, va, dst, n);
}

/*
 * Keep a copy of [va, va+len) if the run wrote any of it. Pages it never
 * touched are the file's own bytes and are already scannable from the file, so
 * a mapping with nothing written under it is not a payload and is skipped.
 */
static void snap_take(struct kof_emu *e, uint64_t va, uint64_t len)
{
	uint64_t base = va & ~(uint64_t)(KOF_EMU_PAGE - 1u), off, n;
	struct page *p;
	struct snap *s;
	int any = 0;

	len = (va - base) + len;
	n = (len + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
	if (!n || n > (uint64_t)e->n_pages * KOF_EMU_PAGE)
		return;
	for (off = 0; off < n; off += KOF_EMU_PAGE) {
		p = page_find(e, base + off);
		if (p && p->written) {
			any = 1;
			break;
		}
	}
	if (!any)
		return;
	/*
	 * Snapshots are copies, so they are the one thing here that can cost
	 * the host more memory than the guest was ever given: mprotect(PROT_EXEC)
	 * over written pages, in a loop, would copy the whole address space
	 * once per call. Bounded by both count and total bytes, because either
	 * alone leaves the other free - a thousand small ones, or one enormous
	 * one repeated.
	 */
	if (e->n_snap >= KOF_EMU_MAX_SNAP ||
	    e->snap_bytes + n > (uint64_t)e->max_pages * KOF_EMU_PAGE)
		return;
	if (e->n_snap == e->max_snap) {
		uint32_t m = e->max_snap ? e->max_snap * 2u : 8u;
		struct snap *t = realloc(e->snap, (size_t)m * sizeof *t);

		if (!t)
			return;
		e->snap = t;
		e->max_snap = m;
	}
	s = &e->snap[e->n_snap];
	s->bytes = malloc((size_t)n);
	if (!s->bytes)
		return;
	for (off = 0; off < n; off += KOF_EMU_PAGE) {
		p = page_find(e, base + off);
		if (p)
			memcpy(s->bytes + off, p->data, KOF_EMU_PAGE);
		else
			memset(s->bytes + off, 0, KOF_EMU_PAGE);
	}
	s->va = base;
	s->len = n;
	e->snap_bytes += n;
	e->n_snap++;
}

int kof_emu_next_snapshot(struct kof_emu *e, uint32_t *it, uint64_t *va,
			  const uint8_t **bytes, uint64_t *len)
{
	if (*it >= e->n_snap)
		return 0;
	*va    = e->snap[*it].va;
	*bytes = e->snap[*it].bytes;
	*len   = e->snap[*it].len;
	(*it)++;
	return 1;
}

/*
 * Roughly a cycle per instruction, which is what a real machine retires. The
 * number only has to keep the ratio between two readings believable.
 */
#define TSC_PER_INSN  1u

/* The jump a recognised delay loop is granted, doubling while it persists. */
#define TSC_SPIN_MIN  (1u << 16)
#define TSC_SPIN_AT   8u

static uint64_t tsc_read(struct kof_emu *e)
{
	uint64_t gap = e->insn - e->tsc_last_insn;

	if (gap < 64u) {
		/* Asked again having done nothing: a wait, not a measurement. */
		if (++e->tsc_spin > TSC_SPIN_AT) {
			uint32_t k = e->tsc_spin - TSC_SPIN_AT;

			e->tsc_skew += (uint64_t)TSC_SPIN_MIN <<
				       (k > 20u ? 20u : k);
		}
	} else {
		e->tsc_spin = 0;
	}
	e->tsc_last_insn = e->insn;
	return e->insn * TSC_PER_INSN + e->tsc_skew;
}

/* Nanoseconds, from the same clock. A tick is taken to be a nanosecond: the
 * unit is arbitrary and one that needs no conversion is one that cannot be
 * converted wrongly. */
static uint64_t tsc_ns(struct kof_emu *e)
{
	return tsc_read(e);
}

static uint64_t syscall_do(struct kof_emu *e, int *stop_out);

static uint64_t do_syscall(struct kof_emu *e, int *stop_out)
{
	struct kof_emu_syscall *s;
	uint64_t ret;

	s = &e->syslog[e->n_syslog % KOF_EMU_SYSLOG];
	s->nr     = e->gpr[KOF_EMU_RAX];
	s->arg[0] = e->gpr[KOF_EMU_RDI];
	s->arg[1] = e->gpr[KOF_EMU_RSI];
	s->arg[2] = e->gpr[KOF_EMU_RDX];
	s->arg[3] = e->gpr[KOF_EMU_R10];
	s->arg[4] = e->gpr[KOF_EMU_R8];
	s->arg[5] = e->gpr[KOF_EMU_R9];
	ret = syscall_do(e, stop_out);
	s->ret = ret;
	e->n_syslog++;
	return ret;
}

unsigned kof_emu_said(const struct kof_emu *e, char *out, unsigned n)
{
	unsigned got = e->n_say < n ? e->n_say : n;

	memcpy(out, e->say, got);
	return got;
}

unsigned kof_emu_syscall_log(const struct kof_emu *e,
			     struct kof_emu_syscall *out, unsigned n)
{
	unsigned k, got = e->n_syslog < KOF_EMU_SYSLOG ? e->n_syslog : KOF_EMU_SYSLOG;
	uint32_t first = e->n_syslog - got;

	if (got > n)
		got = n;
	for (k = 0; k < got; k++)
		out[k] = e->syslog[(first + k) % KOF_EMU_SYSLOG];
	return got;
}

unsigned kof_emu_unknown_syscalls(const struct kof_emu *e, uint32_t *out,
				  unsigned n)
{
	unsigned k, got = e->n_unksys < n ? e->n_unksys : n;

	for (k = 0; k < got; k++)
		out[k] = e->unksys[k];
	return got;
}

unsigned kof_emu_trace(const struct kof_emu *e, uint64_t *out, unsigned n)
{
	uint64_t have = e->trace_n < KOF_EMU_TRACE ? e->trace_n : KOF_EMU_TRACE;
	unsigned k, got = (unsigned)(have < n ? have : n);

	for (k = 0; k < got; k++)
		out[k] = e->trace[(e->trace_n - got + k) % KOF_EMU_TRACE];
	return got;
}

const char *kof_emu_stop_name(enum kof_emu_stop s)
{
	switch (s) {
	case KOF_EMU_STOP_BUDGET:      return "budget";
	case KOF_EMU_STOP_EXIT:        return "exit";
	case KOF_EMU_STOP_HANDOFF:     return "handoff";
	case KOF_EMU_STOP_FAULT:       return "fault";
	case KOF_EMU_STOP_UNSUPPORTED: return "unsupported";
	case KOF_EMU_STOP_DECODE:      return "decode";
	case KOF_EMU_STOP_STALLED:     return "stalled";
	}
	return "?";
}

/* ---- registers ------------------------------------------------------------
 *
 * x86 register writes are not uniform and the irregularity is load bearing: a
 * 32 bit write ZEROES the upper half, an 8 or 16 bit write PRESERVES it, and
 * AH/CH/DH/BH address byte one of the first four registers rather than byte
 * zero of the second four. Getting any of those wrong produces a stub that
 * runs for a while and then computes one wrong address.
 */
static uint64_t mask_of(unsigned bytes)
{
	return bytes >= 8 ? ~(uint64_t)0 : ((uint64_t)1 << (bytes * 8)) - 1u;
}

/* Sign-extend the low `bytes` bytes of v to 64 bits. */
static uint64_t sext(uint64_t v, unsigned bytes)
{
	uint64_t m;

	if (bytes >= 8)
		return v;
	m = (uint64_t)1 << (bytes * 8u - 1u);
	v &= mask_of(bytes);
	return (v ^ m) - m;
}


static uint64_t reg_rd(const struct kof_emu *e, unsigned r, unsigned bytes,
		       int high8)
{
	uint64_t v;

	if (high8)
		return (e->gpr[r & 3u] >> 8) & 0xffu;
	if (r >= KOF_EMU_NGPR)
		return 0;
	v = e->gpr[r];
	return bytes >= 8 ? v : v & mask_of(bytes);
}

static void reg_wr(struct kof_emu *e, unsigned r, unsigned bytes, int high8,
		   uint64_t v)
{
	if (high8) {
		unsigned i = r & 3u;

		e->gpr[i] = (e->gpr[i] & ~(uint64_t)0xff00) |
			    ((v & 0xffu) << 8);
		return;
	}
	if (r >= KOF_EMU_NGPR)
		return;
	if (bytes >= 8)
		e->gpr[r] = v;
	else if (bytes == 4)
		e->gpr[r] = v & 0xffffffffu;     /* zero extends - the one that bites */
	else
		e->gpr[r] = (e->gpr[r] & ~mask_of(bytes)) | (v & mask_of(bytes));
}

/* ---- flags ---------------------------------------------------------------- */

static int parity8(uint64_t v)
{
	unsigned x = (unsigned)(v & 0xffu), c = 0;

	while (x) { c ^= 1u; x &= x - 1u; }
	return !c;                                /* PF is set when EVEN */
}

static void fl_logic(struct kof_emu *e, uint64_t r, unsigned bytes)
{
	uint64_t m = mask_of(bytes);

	r &= m;
	e->flags &= ~(uint64_t)(FL_CF | FL_OF | FL_ZF | FL_SF | FL_PF | FL_AF);
	if (!r)                       e->flags |= FL_ZF;
	if (r >> (bytes * 8u - 1u))   e->flags |= FL_SF;
	if (parity8(r))               e->flags |= FL_PF;
}

static void fl_add(struct kof_emu *e, uint64_t a, uint64_t b, uint64_t cin,
		   unsigned bytes)
{
	uint64_t m = mask_of(bytes), r = (a + b + cin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	fl_logic(e, r, bytes);
	if ((a & m) + (b & m) + cin > m)                       e->flags |= FL_CF;
	if (~((a ^ b)) & (a ^ r) & sign)                       e->flags |= FL_OF;
	if (((a & 0xfu) + (b & 0xfu) + cin) > 0xfu)            e->flags |= FL_AF;
}

static void fl_sub(struct kof_emu *e, uint64_t a, uint64_t b, uint64_t bin,
		   unsigned bytes)
{
	uint64_t m = mask_of(bytes), r = (a - b - bin) & m;
	uint64_t sign = (uint64_t)1 << (bytes * 8u - 1u);

	fl_logic(e, r, bytes);
	if ((a & m) < (b & m) + bin)                           e->flags |= FL_CF;
	if ((a ^ b) & (a ^ r) & sign)                          e->flags |= FL_OF;
	if ((a & 0xfu) < (b & 0xfu) + bin)                     e->flags |= FL_AF;
}

static int cond_true(const struct kof_emu *e, unsigned cc)
{
	uint64_t f = e->flags;
	int r;

	switch (cc >> 1) {
	case 0: r = (f & FL_OF) != 0; break;                    /* O   */
	case 1: r = (f & FL_CF) != 0; break;                    /* B   */
	case 2: r = (f & FL_ZF) != 0; break;                    /* Z   */
	case 3: r = (f & (FL_CF | FL_ZF)) != 0; break;          /* BE  */
	case 4: r = (f & FL_SF) != 0; break;                    /* S   */
	case 5: r = (f & FL_PF) != 0; break;                    /* P   */
	case 6: r = ((f & FL_SF) != 0) != ((f & FL_OF) != 0); break;   /* L  */
	default: r = (((f & FL_SF) != 0) != ((f & FL_OF) != 0)) ||
		     (f & FL_ZF) != 0; break;                   /* LE  */
	}
	return (cc & 1u) ? !r : r;
}

/* ---- operands -------------------------------------------------------------- */

static int ea_of(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t *out)
{
	const ND_OPDESC_MEMORY *m = &op->Info.Memory;
	uint64_t a = 0;

	if (m->IsRipRel) {
		*out = e->rip + ix->Length + m->Disp;
		return 1;
	}
	if (m->HasBase)
		a += reg_rd(e, m->Base, m->BaseSize, 0);
	if (m->HasIndex)
		a += reg_rd(e, m->Index, m->IndexSize, 0) * (m->Scale ? m->Scale : 1u);
	if (m->HasDisp)
		a += m->Disp;
	/*
	 * FS AND GS ARE A BASE, NOT A REFUSAL.
	 *
	 * A Go-built packer sets its thread pointer with arch_prctl and then
	 * addresses everything through fs:. Refusing the segment stopped Ezuri
	 * 48 instructions in - the runtime saw arch_prctl fail and executed its
	 * own deliberate trap. There is one thread here, so one base each is all
	 * a segment means.
	 */
	if (m->HasSeg) {
		if (m->Seg == 4)
			a += e->fs_base;
		else if (m->Seg == 5)
			a += e->gs_base;
	}
	*out = a;
	return 1;
}

static int op_rd(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t *out)
{
	unsigned sz = op->Size ? op->Size : 8u;

	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type != ND_REG_GPR)
			return 0;
		*out = reg_rd(e, op->Info.Register.Reg, op->Info.Register.Size,
			      op->Info.Register.IsHigh8);
		return 1;
	case ND_OP_IMM:
		*out = op->Info.Immediate.Imm;
		return 1;
	case ND_OP_CONST:
		*out = op->Info.Constant.Const;
		return 1;
	case ND_OP_OFFS:
		*out = e->rip + ix->Length + op->Info.RelativeOffset.Rel;
		return 1;
	case ND_OP_MEM: {
		uint64_t ea, v = 0;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;                 /* vector width: not carried */
		if (!mem_rd(e, ea, &v, sz))
			return 0;
		*out = v;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Read a vector operand into `buf`, returning its width in bytes. A register
 * operand wider than 16 is a YMM/ZMM this does not keep, and is refused rather
 * than silently truncated to its low half.
 */
static int vec_rd(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		  uint8_t *buf, unsigned *sz)
{
	unsigned n = op->Size ? op->Size : 16u;

	if (n > 16)
		return 0;
	memset(buf, 0, 16);
	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type == ND_REG_SSE) {
			if (op->Info.Register.Reg >= 16)
				return 0;
			memcpy(buf, e->xmm[op->Info.Register.Reg], n);
		} else if (op->Info.Register.Type == ND_REG_GPR) {
			uint64_t v = reg_rd(e, op->Info.Register.Reg,
					    op->Info.Register.Size, 0);

			memcpy(buf, &v, n > 8 ? 8u : n);
		} else {
			return 0;
		}
		*sz = n;
		return 1;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea) || !mem_rd(e, ea, buf, n))
			return 0;
		*sz = n;
		return 1;
	}
	default:
		return 0;
	}
}

/*
 * Write `sz` bytes back. Writing a vector register always clears what is above
 * the bytes written, which is what the non-VEX encodings do for the 128-bit
 * register this keeps.
 */
static int vec_wr(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		  const uint8_t *buf, unsigned sz)
{
	unsigned n = op->Size ? op->Size : 16u;

	if (n > 16 || sz > 16)
		return 0;
	if (n > sz)
		n = sz;
	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type == ND_REG_SSE) {
			if (op->Info.Register.Reg >= 16)
				return 0;
			memset(e->xmm[op->Info.Register.Reg], 0, 16);
			memcpy(e->xmm[op->Info.Register.Reg], buf, n);
			return 1;
		}
		if (op->Info.Register.Type == ND_REG_GPR) {
			uint64_t v = 0;

			memcpy(&v, buf, n > 8 ? 8u : n);
			reg_wr(e, op->Info.Register.Reg,
			       op->Info.Register.Size, 0, v);
			return 1;
		}
		return 0;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		return mem_wr(e, ea, buf, n);
	}
	default:
		return 0;
	}
}

static int op_wr(struct kof_emu *e, const INSTRUX *ix, const ND_OPERAND *op,
		 uint64_t v)
{
	unsigned sz = op->Size ? op->Size : 8u;

	switch (op->Type) {
	case ND_OP_REG:
		if (op->Info.Register.Type != ND_REG_GPR)
			return 0;
		reg_wr(e, op->Info.Register.Reg, op->Info.Register.Size,
		       op->Info.Register.IsHigh8, v);
		return 1;
	case ND_OP_MEM: {
		uint64_t ea;

		if (!ea_of(e, ix, op, &ea))
			return 0;
		if (sz > 8)
			return 0;
		return mem_wr(e, ea, &v, sz);
	}
	default:
		return 0;
	}
}

static int push(struct kof_emu *e, uint64_t v)
{
	e->gpr[KOF_EMU_RSP] -= 8;
	return mem_wr(e, e->gpr[KOF_EMU_RSP], &v, 8);
}

static int pop(struct kof_emu *e, uint64_t *v)
{
	uint64_t t = 0;

	if (!mem_rd(e, e->gpr[KOF_EMU_RSP], &t, 8))
		return 0;
	e->gpr[KOF_EMU_RSP] += 8;
	*v = t;
	return 1;
}

/* ---- syscalls -------------------------------------------------------------
 *
 * The whole environment, and it is this short on purpose. A packer stub wants
 * memory and then it wants to hand over; everything else it asks for can be
 * answered with a plausible number, because nothing downstream of this module
 * depends on the answer being true. What matters is that the stub keeps going
 * far enough to write its payload.
 *
 * An unknown call returns -ENOSYS rather than stopping. A stub that checks is
 * rare, and a stub that stops because we stopped it learns more than one that
 * gets a refusal it was already coded to survive.
 */
enum {
	SYS_READ = 0, SYS_WRITE = 1, SYS_OPEN = 2, SYS_CLOSE = 3,
	SYS_FSTAT = 5, SYS_LSEEK = 8,
	SYS_MMAP = 9, SYS_MPROTECT = 10, SYS_MUNMAP = 11, SYS_BRK = 12,
	SYS_PREAD64 = 17, SYS_FTRUNCATE = 77, SYS_READLINK = 89,
	SYS_ARCH_PRCTL = 158, SYS_EXECVE = 59, SYS_EXIT = 60, SYS_EXIT_GROUP = 231,
	SYS_OPENAT = 257, SYS_NEWFSTATAT = 262, SYS_MEMFD_CREATE = 319,
	SYS_IOCTL = 16, SYS_SCHED_YIELD = 24, SYS_NANOSLEEP = 35,
	SYS_GETPID = 39, SYS_CLONE = 56, SYS_RT_SIGACTION = 13,
	SYS_RT_SIGPROCMASK = 14, SYS_SIGALTSTACK = 131, SYS_GETTID = 186,
	SYS_FUTEX = 202, SYS_SCHED_GETAFFINITY = 204, SYS_SET_TID_ADDRESS = 218,
	SYS_CLOCK_GETTIME = 228, SYS_SET_ROBUST_LIST = 273, SYS_PRLIMIT64 = 302,
	SYS_GETRANDOM = 318, SYS_MADVISE = 28, SYS_TGKILL = 234,
	SYS_RSEQ = 334, SYS_SIGRETURN = 15,
	SYS_GETTIMEOFDAY = 96, SYS_TIME = 201, SYS_GETCPU = 309,
	SYS_CLOCK_NANOSLEEP = 230, SYS_ALARM = 37, SYS_SETITIMER = 38,
	SYS_TIMER_CREATE = 222, SYS_TIMER_SETTIME = 223, SYS_PTRACE = 101,
	SYS_PAUSE = 34, SYS_SELECT = 23, SYS_POLL = 7, SYS_KILL = 62
};

/* The descriptor an emulated process gets for itself, and for anything else it
 * opens - there is only one file here and pretending otherwise would need a
 * filesystem nobody is going to write. */
#define EMU_SELF_FD  3

static uint64_t self_read(struct kof_emu *e, uint64_t va, uint64_t off,
			  uint64_t want)
{
	uint64_t n;

	if (!e->self || off >= e->self_n)
		return 0;
	n = e->self_n - off;
	if (n > want)
		n = want;
	if (!mem_wr(e, va, e->self + off, (unsigned)(n > 4096u ? 4096u : n)))
		return (uint64_t)-14;                           /* EFAULT */
	/* Written in page-sized bites so a large read cannot be half applied
	 * and then fail; the loop is here rather than in mem_wr because only
	 * this caller has a length the stub chose. */
	{
		uint64_t done = n > 4096u ? 4096u : n;

		while (done < n) {
			uint64_t chunk = n - done > 4096u ? 4096u : n - done;

			if (!mem_wr(e, va + done, e->self + off + done,
				    (unsigned)chunk))
				break;
			done += chunk;
		}
		return done;
	}
}

/* Where an mmap with no hint lands. High, and far from anything an ELF asks
 * for, so a stub that stores a returned pointer cannot be confused with one
 * that computed an address inside its own image. */
#define EMU_MMAP_BASE  0x00007f0000000000ull

static uint64_t syscall_do(struct kof_emu *e, int *stop_out)
{
	uint64_t nr = e->gpr[KOF_EMU_RAX];
	uint64_t a0 = e->gpr[KOF_EMU_RDI], a1 = e->gpr[KOF_EMU_RSI];

	*stop_out = 0;
	switch (nr) {
	case SYS_EXIT:
	case SYS_EXIT_GROUP:
		*stop_out = KOF_EMU_STOP_EXIT + 1;
		return 0;
	case SYS_EXECVE:
		/* The stub is done and is handing control to what it produced.
		 * Everything worth dumping has already been written. */
		*stop_out = KOF_EMU_STOP_HANDOFF + 1;
		return 0;
	case SYS_MMAP: {
		uint64_t len = (a1 + KOF_EMU_PAGE - 1u) & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint64_t prot = e->gpr[KOF_EMU_RDX];
		/*
		 * The descriptor is an int, and a caller that sets it with a
		 * 32-bit MOV leaves 0x00000000ffffffff in the register - which
		 * read as a valid fd, so every anonymous mapping was filled
		 * with the scanned file's bytes. A Go runtime allocated its
		 * heap that way and then followed a pointer made of file data.
		 * MAP_ANONYMOUS settles it regardless of what the fd looks
		 * like.
		 */
		int32_t  fd    = (int32_t)e->gpr[KOF_EMU_R8];
		uint64_t flags = e->gpr[KOF_EMU_R10];
		uint64_t off = e->gpr[KOF_EMU_R9];
		uint64_t at;

		if (!len)
			return (uint64_t)-12;                   /* ENOMEM */
		if (a0) {
			at = a0 & ~(uint64_t)(KOF_EMU_PAGE - 1u);
		} else {
			if (!e->mmap_next)
				e->mmap_next = EMU_MMAP_BASE;
			at = e->mmap_next;
			/* A guard page between mappings, so a stub that runs off
			 * the end of one faults here rather than silently
			 * scribbling on the next. */
			e->mmap_next += len + KOF_EMU_PAGE;
		}
		/*
		 * PROT_NONE is a reservation and never becomes memory: nothing
		 * can read or write it while it stays that way, and Go reserves
		 * its heap in pieces far larger than this emulator would ever
		 * commit.
		 */
		if (!(prot & (KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)))
			return at;
		/*
		 * A FILE-BACKED MAPPING IS HOW A STUB READS ITSELF.
		 *
		 * UPX never calls read(): it opens /proc/self/exe and maps the
		 * file, so the compressed image simply appears at an address.
		 * Answering that with anonymous zeroes hands the decompressor
		 * an empty buffer, and it fails without complaining - it walks
		 * an all-zero ELF header, finds e_phnum == 0, skips the whole
		 * load and returns a nonsense entry point. Every descriptor
		 * this emulator hands out refers to the scanned file, so any
		 * mapping of one is a window onto its bytes.
		 */
		if (!vma_add(e, at, len, off, (unsigned)prot & 7u,
			     fd >= 0 && !(flags & 0x20u) && e->self != NULL))
			return (uint64_t)-12;
		return at;
	}
	case SYS_MPROTECT:
		if (e->gpr[KOF_EMU_RDX] & KOF_EMU_X)
			snap_take(e, a0, a1);
		return 0;
	case SYS_MUNMAP:
	case SYS_BRK:
	case SYS_FTRUNCATE:
	case SYS_CLOSE:
		return 0;
	/*
	 * SERVICES A RUNTIME DEMANDS AND A PACKER NEVER USES.
	 *
	 * None of this changes a byte of what gets unpacked, but a Go runtime
	 * checks the return of each one and executes its own trap when the
	 * answer is -ENOSYS - so refusing them stops the emulation before the
	 * packer's own code runs at all. Each answers the least eventful thing
	 * that is true of this machine: one thread, one CPU, no signals, a
	 * clock that only moves forward.
	 */
	case SYS_FUTEX:
		/*
		 * A WAIT NOBODY WILL END.
		 *
		 * clone reports a thread id and nothing runs behind it, so the
		 * wake this caller wants can never arrive. Returning "woken"
		 * leaves it re-checking the word forever; writing the word a
		 * wakeup would have written was worse - measured, it let a Go
		 * scheduler run on past a handoff it had not really made, and
		 * it died on its own consistency check. So the wait is answered
		 * honestly, and a caller that keeps asking about the same
		 * address is recognised as stuck rather than humoured.
		 */
		if ((a1 & 0x7fu) == 0) {                    /* FUTEX_WAIT */
			if (a0 == e->futex_va && ++e->futex_spin > 64u) {
				*stop_out = KOF_EMU_STOP_STALLED + 1;
				return 0;
			}
			if (a0 != e->futex_va) {
				e->futex_va = a0;
				e->futex_spin = 0;
			}
		}
		return 0;
	/*
	 * A DELAY IS GRANTED IN FULL AND WAITED FOR NOT AT ALL.
	 *
	 * Sleeping is the cheapest anti-emulation trick there is: a stub that
	 * sleeps thirty seconds before unpacking costs an analyst nothing to
	 * run and costs an automated scan its entire time budget. Returning
	 * immediately and leaving the clock alone is the wrong fix, because the
	 * next thing such a stub does is ask what time it is - and a sleep that
	 * took no time is a louder signal than a slow machine. So the requested
	 * interval is added to the clock and the call returns at once: from
	 * inside, the sleep happened.
	 */
	case SYS_NANOSLEEP:
	case SYS_CLOCK_NANOSLEEP: {
		uint64_t req = (nr == SYS_NANOSLEEP) ? a0 : e->gpr[KOF_EMU_RDX];
		uint64_t ts[2], rem[2] = { 0, 0 };
		uint64_t back = (nr == SYS_NANOSLEEP) ? a1 : e->gpr[KOF_EMU_R10];

		if (req && mem_rd(e, req, ts, sizeof ts))
			e->tsc_skew += ts[0] * 1000000000u + ts[1];
		/* Nothing was interrupted, so nothing remains. */
		if (back)
			mem_wr(e, back, rem, sizeof rem);
		return 0;
	}
	case SYS_PAUSE:
	case SYS_SELECT:
	case SYS_POLL:
		/*
		 * Waiting for something outside this process, which is a place
		 * nothing here can come from. Answered as a timeout - no
		 * descriptor is ready - so a caller that loops on it makes
		 * progress instead of blocking on an event that cannot arrive.
		 */
		return 0;
	case SYS_ALARM:
	case SYS_SETITIMER:
	case SYS_TIMER_CREATE:
	case SYS_TIMER_SETTIME:
		/* Armed, and it will never fire: signals are not delivered here.
		 * A watchdog that never goes off is the harmless direction. */
		return 0;
	case SYS_KILL:
		/* Including a stub signalling itself to die on a failed check.
		 * Refused rather than obeyed - the run ends on its own terms. */
		return (uint64_t)-1;                        /* EPERM */
	case SYS_PTRACE:
		/*
		 * PTRACE_TRACEME succeeds, which is what a process that is NOT
		 * already being debugged sees. The trick is to call it and
		 * treat failure as proof of a debugger; answering 0 says there
		 * is none.
		 */
		return 0;
	case SYS_MADVISE:
	case SYS_SCHED_YIELD:
	case SYS_SET_ROBUST_LIST:
	case SYS_SIGALTSTACK:
	case SYS_TGKILL:
	case SYS_RSEQ:
		return 0;
	case SYS_GETPID:
	case SYS_GETTID:
	case SYS_SET_TID_ADDRESS:
		return 1;
	case SYS_IOCTL:
		return (uint64_t)-25;                       /* ENOTTY: not a tty */
	case SYS_CLONE:
		/*
		 * The parent's half of a clone, and only that. This returns
		 * once, with a thread id, and the child never runs - there is
		 * one instruction pointer here. Refusing instead was worse: a
		 * Go runtime treats a failed thread creation as fatal and quits
		 * before reaching the packer's code. A child that is never
		 * scheduled is a thread that has not got started yet, which is
		 * a state every threaded program is written to tolerate.
		 */
		e->next_tid++;
		return e->next_tid;
	case SYS_RT_SIGACTION:
	case SYS_RT_SIGPROCMASK: {
		/* The old value, if asked for, is "nothing was set". */
		uint64_t old = (nr == SYS_RT_SIGACTION) ? e->gpr[KOF_EMU_RDX] : a1;
		uint8_t z[152];

		if (old) {
			memset(z, 0, sizeof z);
			mem_wr(e, old, z, nr == SYS_RT_SIGACTION ? 32u : 8u);
		}
		return 0;
	}
	case SYS_SCHED_GETAFFINITY: {
		uint64_t mask = 1;                          /* one CPU, cpu 0 */

		if (a1 < 8 || !mem_wr(e, e->gpr[KOF_EMU_RDX], &mask, 8))
			return (uint64_t)-22;               /* EINVAL */
		return 8;
	}
	case SYS_GETTIMEOFDAY: {
		uint64_t now = tsc_ns(e), tv[2];

		tv[0] = now / 1000000000u;
		tv[1] = (now % 1000000000u) / 1000u;
		if (a0 && !mem_wr(e, a0, tv, sizeof tv))
			return (uint64_t)-14;
		return 0;
	}
	case SYS_TIME: {
		uint64_t now = tsc_ns(e) / 1000000000u;

		if (a0 && !mem_wr(e, a0, &now, 8))
			return (uint64_t)-14;
		return now;
	}
	case SYS_GETCPU: {
		uint64_t z = 0;

		if (a0 && !mem_wr(e, a0, &z, 4))
			return (uint64_t)-14;
		if (a1 && !mem_wr(e, a1, &z, 4))
			return (uint64_t)-14;
		return 0;
	}
	case SYS_CLOCK_GETTIME: {
		/* Same clock RDTSC reports, in nanoseconds. */
		uint64_t now = tsc_ns(e), ts[2];

		ts[0] = now / 1000000000u;
		ts[1] = now % 1000000000u;
		if (!mem_wr(e, a1, ts, sizeof ts))
			return (uint64_t)-14;
		return 0;
	}
	case SYS_PRLIMIT64: {
		/* 8 MB of stack, and as many descriptors as anyone asks for. */
		uint64_t lim[2] = { 8u * 1024u * 1024u, ~(uint64_t)0 };

		if (e->gpr[KOF_EMU_R10] &&
		    !mem_wr(e, e->gpr[KOF_EMU_R10], lim, sizeof lim))
			return (uint64_t)-14;
		return 0;
	}
	case SYS_GETRANDOM: {
		/*
		 * Deterministic on purpose. A scan that returns a different
		 * answer each run cannot be tested, and nothing that unpacks a
		 * payload takes its key from here - the key travels with the
		 * file.
		 */
		uint64_t n = a1, k;
		uint8_t b[256];

		/*
		 * Bounded, because this loop is inside ONE guest instruction
		 * and the instruction budget therefore does not see it. A guest
		 * asking for a terabyte of randomness would spin here with the
		 * budget untouched. The real call is capped too, so a short
		 * return is an answer a caller is written to handle.
		 */
		if (n > (1u << 20))
			n = 1u << 20;
		for (k = 0; k < n; k += sizeof b) {
			uint64_t c = n - k < sizeof b ? n - k : sizeof b, j;

			for (j = 0; j < c; j++)
				b[j] = (uint8_t)((k + j) * 37u + 11u);
			if (!mem_wr(e, a0 + k, b, (unsigned)c))
				return (uint64_t)-14;
		}
		return n;
	}
	case SYS_ARCH_PRCTL:
		/* ARCH_SET_FS / ARCH_SET_GS. The two GET codes report where the
		 * emulator put them, so a runtime that reads its own thread
		 * pointer back gets what it wrote. */
		if (a0 == 0x1002)      { e->fs_base = a1; return 0; }
		if (a0 == 0x1001)      { e->gs_base = a1; return 0; }
		if (a0 == 0x1003 || a0 == 0x1004) {
			uint64_t v = (a0 == 0x1003) ? e->fs_base : e->gs_base;

			if (!mem_wr(e, a1, &v, 8))
				return (uint64_t)-14;
			return 0;
		}
		return (uint64_t)-22;                       /* EINVAL */
	case SYS_MEMFD_CREATE:
	case SYS_OPEN:
		return EMU_SELF_FD;
	case SYS_OPENAT:
		return EMU_SELF_FD;
	case SYS_READLINK: {
		/* Whatever was asked about is this process. The path only has to
		 * be openable, and every open here answers with the same file. */
		static const char path[] = "/proc/self/exe";
		uint64_t n = sizeof path - 1u;

		if (n > e->gpr[KOF_EMU_RDX])
			n = e->gpr[KOF_EMU_RDX];
		if (!mem_wr(e, a1, path, (unsigned)n))
			return (uint64_t)-14;
		return n;
	}
	case SYS_LSEEK: {
		uint64_t whence = e->gpr[KOF_EMU_RDX];

		if (whence == 0)      e->self_pos = a1;
		else if (whence == 1) e->self_pos += a1;
		else                  e->self_pos = e->self_n + a1;
		return e->self_pos;
	}
	case SYS_PREAD64:
		return self_read(e, a1, e->gpr[KOF_EMU_R10], e->gpr[KOF_EMU_RDX]);
	case SYS_FSTAT:
	case SYS_NEWFSTATAT: {
		/* struct stat is 144 bytes on amd64 and the only field a stub
		 * reads is st_size at offset 48. The rest stays zero, which is
		 * a stat nobody here will look at twice. */
		uint64_t at = (nr == SYS_FSTAT) ? a1 : e->gpr[KOF_EMU_RDX];
		uint8_t st[144];

		memset(st, 0, sizeof st);
		memcpy(st + 48, &e->self_n, 8);
		if (!mem_wr(e, at, st, sizeof st))
			return (uint64_t)-14;
		return 0;
	}
	case SYS_WRITE: {
		uint64_t n = e->gpr[KOF_EMU_RDX];

		if (a0 <= 2 && e->n_say < KOF_EMU_SAY) {
			uint64_t room = KOF_EMU_SAY - e->n_say;

			if (n < room)
				room = n;
			if (mem_rd(e, a1, e->say + e->n_say, (unsigned)room))
				e->n_say += (uint32_t)room;
		}
		return n;                                       /* wrote it all */
	}
	case SYS_READ: {
		uint64_t got = self_read(e, a1, e->self_pos, e->gpr[KOF_EMU_RDX]);

		if ((int64_t)got > 0)
			e->self_pos += got;
		return got;
	}
	default:
		if (e->n_unksys < KOF_EMU_UNKSYS) {
			uint32_t i;

			for (i = 0; i < e->n_unksys; i++)
				if (e->unksys[i] == (uint32_t)nr)
					break;
			if (i == e->n_unksys)
				e->unksys[e->n_unksys++] = (uint32_t)nr;
		}
		return (uint64_t)-38;                           /* ENOSYS */
	}
}

/* ---- the loop -------------------------------------------------------------- */

static void fail(struct kof_emu *e, enum kof_emu_stop s, const INSTRUX *ix)
{
	e->stop = s;
	if (s == KOF_EMU_STOP_FAULT) {
		snprintf(e->detail, sizeof e->detail, "%s at %#llx from rip %#llx",
			 e->fault_kind[0] ? e->fault_kind : "access",
			 (unsigned long long)e->fault_va,
			 (unsigned long long)e->rip);
		return;
	}
	if (ix && s == KOF_EMU_STOP_UNSUPPORTED) {
		char t[ND_MIN_BUF_SIZE];

		if (ND_SUCCESS(NdToText(ix, e->rip, sizeof t, t))) {
			/*
			 * The WHOLE text. "MOV" is not a thing to go and
			 * implement - every build already has MOV - whereas
			 * "MOV rax, fs:[0x0]" names the actual gap.
			 */
			size_t i = 0;

			while (i + 1u < sizeof e->detail && t[i]) {
				e->detail[i] = t[i];
				i++;
			}
			while (i && e->detail[i - 1u] == ' ')
				i--;
			e->detail[i] = 0;
		}
	}
}

enum kof_emu_stop kof_emu_run(struct kof_emu *e)
{
	e->stop = KOF_EMU_STOP_BUDGET;
	e->detail[0] = 0;

	while (e->insn < e->max_insn) {
		uint8_t code[16];
		INSTRUX ix;
		NDSTATUS st;
		uint64_t a = 0, b = 0, r = 0, next;
		unsigned sz;
		int jumped = 0;

		if (!mem_rd(e, e->rip, code, sizeof code)) {
			/* The tail of a mapping is a legitimate place to be: try
			 * the shortest fetch that can still hold an instruction
			 * before calling it a fault. */
			unsigned got = 0;

			while (got < sizeof code &&
			       mem_rd(e, e->rip + got, code + got, 1))
				got++;
			if (got < 1) {
				e->fault_va = e->rip;
				memcpy(e->fault_kind, "fetch", 6);
				fail(e, KOF_EMU_STOP_FAULT, NULL);
				break;
			}
			memset(code + got, 0, sizeof code - got);
		}
		st = NdDecodeEx(&ix, code, sizeof code, ND_CODE_64, ND_DATA_64);
		if (!ND_SUCCESS(st)) { fail(e, KOF_EMU_STOP_DECODE, NULL); break; }

		e->trace[e->trace_n++ % KOF_EMU_TRACE] = e->rip;
		/* Cleared per instruction so the stop below can tell an operand
		 * this build cannot express from one it simply could not read.
		 * They were reported the same way, and an ordinary CMP against
		 * an unmapped address read as a missing instruction. */
		e->fault_va = 0;
		e->fault_kind[0] = 0;
		next = e->rip + ix.Length;
		sz = ix.Operands[0].Size ? ix.Operands[0].Size : 8u;
		e->insn++;

		switch (ix.Instruction) {
		/*
		 * Nothing to do, for a reason rather than by omission. The
		 * fences order accesses between threads and there is one
		 * thread; PAUSE hints at a spin loop; the prefetches move no
		 * architectural state; ENDBR is a landing pad.
		 */
		case ND_INS_NOP:
		case ND_INS_LFENCE: case ND_INS_SFENCE: case ND_INS_MFENCE:
		case ND_INS_PAUSE:  case ND_INS_ENDBR:
		case ND_INS_PREFETCHT0: case ND_INS_PREFETCHT1:
		case ND_INS_PREFETCHT2: case ND_INS_PREFETCHNTA:
		case ND_INS_PREFETCHW:
			break;

		/*
		 * A clock that only moves forward. Real time would make a run
		 * unreproducible, and a stub that times itself is looking for a
		 * debugger - a steady tick reads as an ordinary machine.
		 */
		case ND_INS_RDTSC: case ND_INS_RDTSCP: {
			uint64_t now = tsc_read(e);

			reg_wr(e, KOF_EMU_RAX, 4, 0, now & 0xffffffffu);
			reg_wr(e, KOF_EMU_RDX, 4, 0, now >> 32);
			if (ix.Instruction == ND_INS_RDTSCP)
				reg_wr(e, KOF_EMU_RCX, 4, 0, 0);
			break;
		}

		/* XCR0: x87 and SSE enabled, nothing wider - which is the truth
		 * about this machine, and keeps a runtime off the AVX paths. */
		case ND_INS_XGETBV:
			reg_wr(e, KOF_EMU_RAX, 4, 0, 3);
			reg_wr(e, KOF_EMU_RDX, 4, 0, 0);
			break;

		/*
		 * The atomics a runtime starts on. LOCK is a no-op here - one
		 * thread, so the read-modify-write is already indivisible.
		 */
		case ND_INS_CMPXCHG: {
			uint64_t dst, src, acc = reg_rd(e, KOF_EMU_RAX, sz, 0);

			if (!op_rd(e, &ix, &ix.Operands[0], &dst) ||
			    !op_rd(e, &ix, &ix.Operands[1], &src))
				goto unsupported;
			fl_sub(e, acc, dst, 0, sz);
			if (((acc ^ dst) & mask_of(sz)) == 0) {
				if (!op_wr(e, &ix, &ix.Operands[0], src))
					goto unsupported;
			} else {
				reg_wr(e, KOF_EMU_RAX, sz, 0, dst);
			}
			break;
		}

		case ND_INS_XADD: {
			uint64_t dst, src;

			if (!op_rd(e, &ix, &ix.Operands[0], &dst) ||
			    !op_rd(e, &ix, &ix.Operands[1], &src))
				goto unsupported;
			fl_add(e, dst, src, 0, sz);
			if (!op_wr(e, &ix, &ix.Operands[1], dst) ||
			    !op_wr(e, &ix, &ix.Operands[0], dst + src))
				goto unsupported;
			break;
		}

		/*
		 * Unsigned multiply and both divides. The 128-bit dividend a
		 * 64-bit DIV can take is not representable here, so that one
		 * case stops rather than returning a wrong quotient - and a
		 * divide by zero stops too, since there is no #DE to raise.
		 */
		case ND_INS_MUL: {
			uint64_t acc = reg_rd(e, KOF_EMU_RAX, sz, 0), hi;

			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			if (sz == 8) {
				uint64_t al = acc & 0xffffffffu, ah = acc >> 32;
				uint64_t bl = a & 0xffffffffu, bh = a >> 32;
				uint64_t m0 = al * bl, m1 = al * bh, m2 = ah * bl;
				uint64_t carry = ((m0 >> 32) + (m1 & 0xffffffffu) +
						  (m2 & 0xffffffffu)) >> 32;

				hi = ah * bh + (m1 >> 32) + (m2 >> 32) + carry;
				reg_wr(e, KOF_EMU_RAX, 8, 0, acc * a);
				reg_wr(e, KOF_EMU_RDX, 8, 0, hi);
			} else {
				uint64_t r64 = (acc & mask_of(sz)) * (a & mask_of(sz));

				hi = (r64 >> (sz * 8u)) & mask_of(sz);
				reg_wr(e, KOF_EMU_RAX, sz, 0, r64);
				if (sz == 1)
					reg_wr(e, KOF_EMU_RAX, 2, 0, r64);
				else
					reg_wr(e, KOF_EMU_RDX, sz, 0, hi);
			}
			e->flags = hi ? (e->flags | FL_CF | FL_OF)
				      : (e->flags & ~(uint64_t)(FL_CF | FL_OF));
			break;
		}

		case ND_INS_DIV: case ND_INS_IDIV: {
			uint64_t lo = reg_rd(e, KOF_EMU_RAX, sz, 0);
			uint64_t hi = reg_rd(e, KOF_EMU_RDX, sz, 0);

			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			a &= mask_of(sz);
			if (!a || (sz == 8 && hi))
				goto unsupported;
			if (sz == 8) {
				if (ix.Instruction == ND_INS_DIV) {
					reg_wr(e, KOF_EMU_RAX, 8, 0, lo / a);
					reg_wr(e, KOF_EMU_RDX, 8, 0, lo % a);
				} else {
					int64_t n = (int64_t)lo, d = (int64_t)a;

					reg_wr(e, KOF_EMU_RAX, 8, 0, (uint64_t)(n / d));
					reg_wr(e, KOF_EMU_RDX, 8, 0, (uint64_t)(n % d));
				}
			} else {
				uint64_t n = (hi << (sz * 8u)) | (lo & mask_of(sz));

				if (ix.Instruction == ND_INS_IDIV) {
					int64_t sn = (int64_t)sext(n, sz * 2u);
					int64_t sd = (int64_t)sext(a, sz);

					if (!sd)
						goto unsupported;
					reg_wr(e, KOF_EMU_RAX, sz, 0, (uint64_t)(sn / sd));
					reg_wr(e, KOF_EMU_RDX, sz, 0, (uint64_t)(sn % sd));
				} else {
					reg_wr(e, KOF_EMU_RAX, sz, 0, n / a);
					reg_wr(e, KOF_EMU_RDX, sz, 0, n % a);
				}
			}
			break;
		}

		/* Bit test and set/reset/complement: CPU feature bitmaps. */
		case ND_INS_BT: case ND_INS_BTS: case ND_INS_BTR: case ND_INS_BTC: {
			uint64_t bit, val;
			unsigned w = sz * 8u;

			if (!op_rd(e, &ix, &ix.Operands[0], &val) ||
			    !op_rd(e, &ix, &ix.Operands[1], &bit))
				goto unsupported;
			bit &= w - 1u;
			e->flags = (e->flags & ~FL_CF) |
				   (((val >> bit) & 1u) ? FL_CF : 0u);
			if (ix.Instruction == ND_INS_BTS)      val |=  (uint64_t)1 << bit;
			else if (ix.Instruction == ND_INS_BTR) val &= ~((uint64_t)1 << bit);
			else if (ix.Instruction == ND_INS_BTC) val ^=  (uint64_t)1 << bit;
			if (ix.Instruction != ND_INS_BT &&
			    !op_wr(e, &ix, &ix.Operands[0], val))
				goto unsupported;
			break;
		}

		/* Scan for the first or last set bit; ZF says there was none. */
		case ND_INS_BSF: case ND_INS_BSR:
		case ND_INS_TZCNT: case ND_INS_LZCNT: {
			uint64_t v, k;
			unsigned w = sz * 8u;

			if (!op_rd(e, &ix, &ix.Operands[1], &v))
				goto unsupported;
			if (!v) {
				e->flags |= FL_ZF;
				if (ix.Instruction == ND_INS_TZCNT ||
				    ix.Instruction == ND_INS_LZCNT) {
					e->flags |= FL_CF;
					if (!op_wr(e, &ix, &ix.Operands[0], w))
						goto unsupported;
				}
				break;
			}
			e->flags &= ~(uint64_t)(FL_ZF | FL_CF);
			if (ix.Instruction == ND_INS_BSF ||
			    ix.Instruction == ND_INS_TZCNT) {
				for (k = 0; !((v >> k) & 1u); k++)
					;
			} else {
				for (k = w - 1u; !((v >> k) & 1u); k--)
					;
				if (ix.Instruction == ND_INS_LZCNT)
					k = w - 1u - k;
			}
			if (!op_wr(e, &ix, &ix.Operands[0], k))
				goto unsupported;
			break;
		}

		case ND_INS_POPCNT: {
			uint64_t v, n = 0;

			if (!op_rd(e, &ix, &ix.Operands[1], &v))
				goto unsupported;
			while (v) { n += v & 1u; v >>= 1; }
			e->flags = (e->flags & ~(uint64_t)(FL_ZF | FL_CF | FL_OF |
							   FL_SF | FL_PF | FL_AF)) |
				   (n ? 0u : FL_ZF);
			if (!op_wr(e, &ix, &ix.Operands[0], n))
				goto unsupported;
			break;
		}

		/*
		 * The SSE a runtime uses to move and compare bytes. Vector
		 * arithmetic is deliberately absent: nothing that unpacks a
		 * payload needs it, and guessing at it would produce wrong
		 * bytes instead of an honest stop.
		 */
		case ND_INS_MOVUPS: case ND_INS_MOVAPS:
		case ND_INS_MOVUPD: case ND_INS_MOVAPD:
		case ND_INS_MOVDQU: case ND_INS_MOVDQA:
		case ND_INS_MOVSS:  case ND_INS_MOVSD:
		case ND_INS_MOVD:   case ND_INS_MOVQ: {
			uint8_t v[16];
			unsigned n;

			if (!vec_rd(e, &ix, &ix.Operands[1], v, &n) ||
			    !vec_wr(e, &ix, &ix.Operands[0], v, n))
				goto unsupported;
			break;
		}

		case ND_INS_XORPS: case ND_INS_XORPD: case ND_INS_PXOR:
		case ND_INS_POR:   case ND_INS_PAND:  case ND_INS_PANDN:
		case ND_INS_ORPS:  case ND_INS_ORPD:
		case ND_INS_ANDPS: case ND_INS_ANDPD:
		case ND_INS_ANDNPS: case ND_INS_ANDNPD:
		case ND_INS_PCMPEQB: case ND_INS_PSUBB: {
			uint8_t x[16], y[16];
			unsigned nx, ny, k;

			if (!vec_rd(e, &ix, &ix.Operands[0], x, &nx) ||
			    !vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 16; k++)
				switch (ix.Instruction) {
				case ND_INS_XORPS: case ND_INS_XORPD:
				case ND_INS_PXOR:    x[k] ^= y[k]; break;
				case ND_INS_POR:  case ND_INS_ORPS:
				case ND_INS_ORPD:    x[k] |= y[k]; break;
				case ND_INS_PAND: case ND_INS_ANDPS:
				case ND_INS_ANDPD:   x[k] &= y[k]; break;
				case ND_INS_PANDN: case ND_INS_ANDNPS:
				case ND_INS_ANDNPD:  x[k] = (uint8_t)(~x[k] & y[k]); break;
				case ND_INS_PSUBB:   x[k] = (uint8_t)(x[k] - y[k]); break;
				default:             x[k] = x[k] == y[k] ? 0xffu : 0u; break;
				}
			if (!vec_wr(e, &ix, &ix.Operands[0], x, nx))
				goto unsupported;
			break;
		}

		/*
		 * SCALAR DOUBLE AND SINGLE, WHICH IS NOT OPTIONAL EITHER.
		 *
		 * No packer needs floating point to unpack, but a Go runtime
		 * checks its own arithmetic before running anything and traps
		 * when the answers are wrong - so a Go-built packer never
		 * reaches its payload without these. The host is IEEE754 and
		 * so is the guest, so the host's own double does the work.
		 */
		case ND_INS_ADDSD: case ND_INS_SUBSD: case ND_INS_MULSD:
		case ND_INS_DIVSD: case ND_INS_MAXSD: case ND_INS_MINSD:
		case ND_INS_SQRTSD:
		case ND_INS_ADDSS: case ND_INS_SUBSS: case ND_INS_MULSS:
		case ND_INS_DIVSS: {
			uint8_t x[16], y[16];
			unsigned nx, ny;
			int dbl = ix.Instruction == ND_INS_ADDSD ||
				  ix.Instruction == ND_INS_SUBSD ||
				  ix.Instruction == ND_INS_MULSD ||
				  ix.Instruction == ND_INS_DIVSD ||
				  ix.Instruction == ND_INS_MAXSD ||
				  ix.Instruction == ND_INS_MINSD ||
				  ix.Instruction == ND_INS_SQRTSD;
			double u, v, w;
			float  fu, fv, fw;

			if (!vec_rd(e, &ix, &ix.Operands[0], x, &nx) ||
			    !vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
			else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
			switch (ix.Instruction) {
			case ND_INS_ADDSD: case ND_INS_ADDSS: w = u + v; break;
			case ND_INS_SUBSD: case ND_INS_SUBSS: w = u - v; break;
			case ND_INS_MULSD: case ND_INS_MULSS: w = u * v; break;
			case ND_INS_DIVSD: case ND_INS_DIVSS: w = u / v; break;
			case ND_INS_MAXSD: w = v > u ? v : u; break;
			case ND_INS_MINSD: w = v < u ? v : u; break;
			default:           w = v >= 0 ? sqrt(v) : (v - v) / (v - v); break;
			}
			if (dbl) { memcpy(x, &w, 8); }
			else     { fw = (float)w; memcpy(x, &fw, 4); }
			if (!vec_wr(e, &ix, &ix.Operands[0], x, nx))
				goto unsupported;
			break;
		}

		case ND_INS_UCOMISD: case ND_INS_COMISD:
		case ND_INS_UCOMISS: case ND_INS_COMISS: {
			uint8_t x[16], y[16];
			unsigned nx, ny;
			int dbl = ix.Instruction == ND_INS_UCOMISD ||
				  ix.Instruction == ND_INS_COMISD;
			double u, v;
			float fu, fv;

			if (!vec_rd(e, &ix, &ix.Operands[0], x, &nx) ||
			    !vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
			else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
			e->flags &= ~(uint64_t)(FL_ZF | FL_PF | FL_CF | FL_OF |
						FL_SF | FL_AF);
			if (u != u || v != v)          /* unordered */
				e->flags |= FL_ZF | FL_PF | FL_CF;
			else if (u < v)                e->flags |= FL_CF;
			else if (u == v)               e->flags |= FL_ZF;
			break;
		}

		case ND_INS_CVTSI2SD: case ND_INS_CVTSI2SS:
		case ND_INS_CVTSD2SS: case ND_INS_CVTSS2SD: {
			uint8_t x[16] = { 0 }, y[16];
			unsigned ny;
			double d;
			float f;

			if (ix.Instruction == ND_INS_CVTSI2SD ||
			    ix.Instruction == ND_INS_CVTSI2SS) {
				if (!op_rd(e, &ix, &ix.Operands[1], &a))
					goto unsupported;
				d = (double)(int64_t)sext(a,
					ix.Operands[1].Size ? ix.Operands[1].Size : 8u);
			} else {
				if (!vec_rd(e, &ix, &ix.Operands[1], y, &ny))
					goto unsupported;
				if (ix.Instruction == ND_INS_CVTSS2SD) {
					memcpy(&f, y, 4); d = f;
				} else {
					memcpy(&d, y, 8);
				}
			}
			if (ix.Instruction == ND_INS_CVTSI2SS ||
			    ix.Instruction == ND_INS_CVTSD2SS) {
				f = (float)d; memcpy(x, &f, 4);
			} else {
				memcpy(x, &d, 8);
			}
			if (!vec_wr(e, &ix, &ix.Operands[0], x, 16))
				goto unsupported;
			break;
		}

		case ND_INS_CVTTSD2SI: case ND_INS_CVTTSS2SI: {
			uint8_t y[16];
			unsigned ny;
			double d;
			float f;

			if (!vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			if (ix.Instruction == ND_INS_CVTTSD2SI)
				memcpy(&d, y, 8);
			else { memcpy(&f, y, 4); d = f; }
			if (!op_wr(e, &ix, &ix.Operands[0], (uint64_t)(int64_t)d))
				goto unsupported;
			break;
		}

		case ND_INS_PMOVMSKB: {
			uint8_t y[16];
			unsigned ny, k;
			uint64_t m = 0;

			if (!vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 16; k++)
				m |= (uint64_t)(y[k] >> 7) << k;
			if (!op_wr(e, &ix, &ix.Operands[0], m))
				goto unsupported;
			break;
		}

		case ND_INS_PSLLDQ: case ND_INS_PSRLDQ: {
			uint8_t x[16], q[16] = { 0 };
			unsigned nx, k;
			uint64_t sh;

			if (!vec_rd(e, &ix, &ix.Operands[0], x, &nx) ||
			    !op_rd(e, &ix, &ix.Operands[1], &sh))
				goto unsupported;
			if (sh < 16)
				for (k = 0; k < 16u - sh; k++) {
					if (ix.Instruction == ND_INS_PSLLDQ)
						q[k + sh] = x[k];
					else
						q[k] = x[k + sh];
				}
			if (!vec_wr(e, &ix, &ix.Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_PUNPCKLBW: {
			uint8_t x[16], y[16], q[16];
			unsigned nx, ny, k;

			if (!vec_rd(e, &ix, &ix.Operands[0], x, &nx) ||
			    !vec_rd(e, &ix, &ix.Operands[1], y, &ny))
				goto unsupported;
			for (k = 0; k < 8; k++) {
				q[k * 2u]      = x[k];
				q[k * 2u + 1u] = y[k];
			}
			if (!vec_wr(e, &ix, &ix.Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_PSHUFD: {
			uint8_t y[16], q[16];
			unsigned ny, k;
			uint64_t sel;

			if (!vec_rd(e, &ix, &ix.Operands[1], y, &ny) ||
			    !op_rd(e, &ix, &ix.Operands[2], &sel))
				goto unsupported;
			for (k = 0; k < 4; k++)
				memcpy(q + k * 4u, y + ((sel >> (k * 2u)) & 3u) * 4u, 4);
			if (!vec_wr(e, &ix, &ix.Operands[0], q, 16))
				goto unsupported;
			break;
		}

		case ND_INS_MOV:
		case ND_INS_MOVZX:
			if (!op_rd(e, &ix, &ix.Operands[1], &b) ||
			    !op_wr(e, &ix, &ix.Operands[0], b))
				goto unsupported;
			break;

		case ND_INS_MOVSX:
		case ND_INS_MOVSXD: {
			unsigned sb = ix.Operands[1].Size ? ix.Operands[1].Size : 1u;

			if (!op_rd(e, &ix, &ix.Operands[1], &b))
				goto unsupported;
			if (sb < 8 && (b >> (sb * 8u - 1u)) & 1u)
				b |= ~mask_of(sb);
			if (!op_wr(e, &ix, &ix.Operands[0], b))
				goto unsupported;
			break;
		}

		case ND_INS_LEA: {
			uint64_t ea;

			if (!ea_of(e, &ix, &ix.Operands[1], &ea) ||
			    !op_wr(e, &ix, &ix.Operands[0], ea))
				goto unsupported;
			break;
		}

		case ND_INS_XCHG:
			if (!op_rd(e, &ix, &ix.Operands[0], &a) ||
			    !op_rd(e, &ix, &ix.Operands[1], &b) ||
			    !op_wr(e, &ix, &ix.Operands[0], b) ||
			    !op_wr(e, &ix, &ix.Operands[1], a))
				goto unsupported;
			break;

		case ND_INS_ADD: case ND_INS_ADC:
		case ND_INS_SUB: case ND_INS_SBB: case ND_INS_CMP:
		case ND_INS_AND: case ND_INS_OR:  case ND_INS_XOR:
		case ND_INS_TEST: {
			uint64_t cin = 0;

			if (!op_rd(e, &ix, &ix.Operands[0], &a) ||
			    !op_rd(e, &ix, &ix.Operands[1], &b))
				goto unsupported;
			if (ix.Instruction == ND_INS_ADC ||
			    ix.Instruction == ND_INS_SBB)
				cin = (e->flags & FL_CF) ? 1u : 0u;
			switch (ix.Instruction) {
			case ND_INS_ADD: case ND_INS_ADC:
				r = a + b + cin; fl_add(e, a, b, cin, sz); break;
			case ND_INS_SUB: case ND_INS_SBB: case ND_INS_CMP:
				r = a - b - cin; fl_sub(e, a, b, cin, sz); break;
			case ND_INS_AND: case ND_INS_TEST:
				r = a & b; fl_logic(e, r, sz); break;
			case ND_INS_OR:
				r = a | b; fl_logic(e, r, sz); break;
			default:
				r = a ^ b; fl_logic(e, r, sz); break;
			}
			if (ix.Instruction != ND_INS_CMP &&
			    ix.Instruction != ND_INS_TEST &&
			    !op_wr(e, &ix, &ix.Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_INC: case ND_INS_DEC: {
			uint64_t cf = e->flags & FL_CF;

			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			if (ix.Instruction == ND_INS_INC) {
				r = a + 1u; fl_add(e, a, 1u, 0, sz);
			} else {
				r = a - 1u; fl_sub(e, a, 1u, 0, sz);
			}
			/* INC and DEC leave CF alone - the one thing that makes
			 * them different from ADD/SUB by one, and the reason a
			 * carry-chained loop written with them still works. */
			e->flags = (e->flags & ~(uint64_t)FL_CF) | cf;
			if (!op_wr(e, &ix, &ix.Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_NEG:
			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			r = 0u - a;
			fl_sub(e, 0, a, 0, sz);
			if (!op_wr(e, &ix, &ix.Operands[0], r))
				goto unsupported;
			break;

		case ND_INS_NOT:
			if (!op_rd(e, &ix, &ix.Operands[0], &a) ||
			    !op_wr(e, &ix, &ix.Operands[0], ~a))
				goto unsupported;
			break;

		case ND_INS_SHL: case ND_INS_SHR: case ND_INS_SAR:
		case ND_INS_ROL: case ND_INS_ROR: {
			unsigned n, w = sz * 8u;

			if (!op_rd(e, &ix, &ix.Operands[0], &a) ||
			    !op_rd(e, &ix, &ix.Operands[1], &b))
				goto unsupported;
			n = (unsigned)(b & (sz == 8 ? 63u : 31u));
			if (!n) break;                    /* no shift, no flags */
			a &= mask_of(sz);
			switch (ix.Instruction) {
			case ND_INS_SHL: r = a << n; break;
			case ND_INS_SHR: r = a >> n; break;
			case ND_INS_SAR:
				r = (uint64_t)(((int64_t)(a << (64u - w))) >>
					       (64u - w + n));
				break;
			case ND_INS_ROL: r = (a << n) | (a >> (w - n)); break;
			default:         r = (a >> n) | (a << (w - n)); break;
			}
			fl_logic(e, r, sz);
			if (ix.Instruction == ND_INS_SHL)
				{ if ((a >> (w - n)) & 1u) e->flags |= FL_CF; }
			else if (ix.Instruction != ND_INS_ROL &&
				 ix.Instruction != ND_INS_ROR)
				{ if ((a >> (n - 1u)) & 1u) e->flags |= FL_CF; }
			if (!op_wr(e, &ix, &ix.Operands[0], r))
				goto unsupported;
			break;
		}

		case ND_INS_PUSH:
			if (!op_rd(e, &ix, &ix.Operands[0], &a) || !push(e, a))
				goto fault;
			break;

		case ND_INS_POP:
			if (!pop(e, &a) || !op_wr(e, &ix, &ix.Operands[0], a))
				goto fault;
			break;

		case ND_INS_LEAVE:
			e->gpr[KOF_EMU_RSP] = e->gpr[KOF_EMU_RBP];
			if (!pop(e, &e->gpr[KOF_EMU_RBP]))
				goto fault;
			break;

		case ND_INS_CALLNR:
		case ND_INS_CALLNI:
			if (!op_rd(e, &ix, &ix.Operands[0], &a) || !push(e, next))
				goto fault;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_RETN:
			if (!pop(e, &a))
				goto fault;
			if (ix.OperandsCount > 0 &&
			    ix.Operands[0].Type == ND_OP_IMM)
				e->gpr[KOF_EMU_RSP] += ix.Operands[0].Info.Immediate.Imm;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_JMPNR:
		case ND_INS_JMPNI:
			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			e->rip = a; jumped = 1;
			break;

		case ND_INS_Jcc:
			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			if (cond_true(e, ix.Condition)) { e->rip = a; jumped = 1; }
			break;

		case ND_INS_SETcc:
			if (!op_wr(e, &ix, &ix.Operands[0],
				   cond_true(e, ix.Condition) ? 1u : 0u))
				goto unsupported;
			break;

		case ND_INS_CMOVcc:
			if (!op_rd(e, &ix, &ix.Operands[1], &b))
				goto unsupported;
			if (cond_true(e, ix.Condition) &&
			    !op_wr(e, &ix, &ix.Operands[0], b))
				goto unsupported;
			break;

		/* Sign of the accumulator into the whole of RDX/DX. */
		case ND_INS_CWD:
			reg_wr(e, KOF_EMU_RDX, 2, 0,
			       (int16_t)e->gpr[KOF_EMU_RAX] < 0 ? 0xffffu : 0u);
			break;
		case ND_INS_CDQ: case ND_INS_CQO:
			e->gpr[KOF_EMU_RDX] =
				(ix.Instruction == ND_INS_CQO)
				? ((int64_t)e->gpr[KOF_EMU_RAX] < 0 ? ~(uint64_t)0 : 0)
				: (uint64_t)(uint32_t)((int32_t)e->gpr[KOF_EMU_RAX] >> 31);
			break;

		/* Widen the accumulator in place. */
		case ND_INS_CBW:
			reg_wr(e, KOF_EMU_RAX, 2, 0,
			       (uint64_t)(uint16_t)(int16_t)(int8_t)e->gpr[KOF_EMU_RAX]);
			break;
		case ND_INS_CWDE:
			e->gpr[KOF_EMU_RAX] =
				(uint64_t)(uint32_t)(int32_t)(int16_t)e->gpr[KOF_EMU_RAX];
			break;
		case ND_INS_CDQE:
			e->gpr[KOF_EMU_RAX] = (uint64_t)(int64_t)(int32_t)e->gpr[KOF_EMU_RAX];
			break;

		/* The count-and-branch forms. RCX is the counter and is NOT a
		 * flag setter - only the branch decision reads ZF. */
		case ND_INS_LOOP: case ND_INS_LOOPZ: case ND_INS_LOOPNZ: {
			uint64_t cnt = --e->gpr[KOF_EMU_RCX];
			int take = cnt != 0;

			if (ix.Instruction == ND_INS_LOOPZ)
				take = take && (e->flags & FL_ZF);
			else if (ix.Instruction == ND_INS_LOOPNZ)
				take = take && !(e->flags & FL_ZF);
			if (take) {
				if (!op_rd(e, &ix, &ix.Operands[0], &a))
					goto unsupported;
				next = a;
			}
			break;
		}

		case ND_INS_BSWAP:
			if (!op_rd(e, &ix, &ix.Operands[0], &a))
				goto unsupported;
			r = 0;
			for (unsigned i = 0; i < sz; i++)
				r |= ((a >> (i * 8u)) & 0xffu) << ((sz - 1u - i) * 8u);
			if (!op_wr(e, &ix, &ix.Operands[0], r))
				goto unsupported;
			break;

		/*
		 * Count only the operands the encoding spells out. The full
		 * count includes the implicit RFLAGS, so a two-operand
		 * "IMUL rdx, rdi" looked like the three-operand form and read
		 * the flags register as its multiplier.
		 */
		case ND_INS_IMUL:
			if (ix.ExpOperandsCount >= 3) {
				if (!op_rd(e, &ix, &ix.Operands[1], &a) ||
				    !op_rd(e, &ix, &ix.Operands[2], &b) ||
				    !op_wr(e, &ix, &ix.Operands[0], a * b))
					goto unsupported;
			} else if (ix.ExpOperandsCount == 2) {
				if (!op_rd(e, &ix, &ix.Operands[0], &a) ||
				    !op_rd(e, &ix, &ix.Operands[1], &b) ||
				    !op_wr(e, &ix, &ix.Operands[0], a * b))
					goto unsupported;
			} else {
				/* One operand: the widening form, into RDX:RAX. */
				uint64_t acc = reg_rd(e, KOF_EMU_RAX, sz, 0);
				int64_t  x, y;

				if (!op_rd(e, &ix, &ix.Operands[0], &b))
					goto unsupported;
				x = (int64_t)sext(acc, sz);
				y = (int64_t)sext(b, sz);
				reg_wr(e, KOF_EMU_RAX, sz, 0, (uint64_t)(x * y));
				if (sz < 8)
					reg_wr(e, KOF_EMU_RDX, sz, 0,
					       (uint64_t)((x * y) >> (sz * 8u)));
				else
					reg_wr(e, KOF_EMU_RDX, 8, 0,
					       (uint64_t)((x < 0) != (y < 0) ? -1 : 0));
			}
			break;

		/*
		 * STRING OPERATIONS, ONE ITERATION AT A TIME.
		 *
		 * UPX's NRV decompressor is built out of these and a REP MOVS
		 * is how the payload actually lands, so this is not an optional
		 * corner. The repeat runs here rather than by re-entering the
		 * decoder, but every iteration still costs a unit of budget:
		 * a REP over a megabyte IS a megabyte of work and a budget that
		 * pretended otherwise would be a budget that does not bound
		 * anything.
		 */
		/* The flag instructions, which cost a line each and stop real
		 * samples when they are missing. */
		case ND_INS_STC: e->flags |= FL_CF;  break;
		case ND_INS_CLC: e->flags &= ~(uint64_t)FL_CF; break;
		case ND_INS_CMC: e->flags ^= FL_CF;  break;
		case ND_INS_SAHF:
			e->flags = (e->flags & ~(uint64_t)(FL_SF | FL_ZF | FL_AF |
							   FL_PF | FL_CF)) |
				   (reg_rd(e, KOF_EMU_RAX, 2, 0) >> 8 &
				    (FL_SF | FL_ZF | FL_AF | FL_PF | FL_CF));
			break;
		case ND_INS_LAHF:
			reg_wr(e, KOF_EMU_RAX, 1, 1,
			       (e->flags & (FL_SF | FL_ZF | FL_AF | FL_PF |
					    FL_CF)) | 2u);
			break;

		case ND_INS_LODS: case ND_INS_STOS:
		case ND_INS_MOVS: case ND_INS_SCAS: case ND_INS_CMPS: {
			unsigned w = ix.Operands[0].Size ? ix.Operands[0].Size : 1u;
			int64_t step = (e->flags & FL_DF) ? -(int64_t)w : (int64_t)w;
			uint64_t iter = 1;

			if (ix.IsRepeated) {
				iter = e->gpr[KOF_EMU_RCX];
				if (!iter) break;
				if (iter > e->max_insn - e->insn)
					iter = e->max_insn - e->insn;
			}
			while (iter--) {
				uint64_t v = 0;

				switch (ix.Instruction) {
				case ND_INS_LODS:
					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &v, w))
						goto fault;
					reg_wr(e, KOF_EMU_RAX, w, 0, v);
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					break;
				case ND_INS_STOS:
					v = reg_rd(e, KOF_EMU_RAX, w, 0);
					if (!mem_wr(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				case ND_INS_MOVS:
					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &v, w) ||
					    !mem_wr(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				case ND_INS_CMPS: {
					uint64_t rhs;

					if (!mem_rd(e, e->gpr[KOF_EMU_RSI], &a, w) ||
					    !mem_rd(e, e->gpr[KOF_EMU_RDI], &rhs, w))
						goto fault;
					fl_sub(e, a, rhs, 0, w);
					e->gpr[KOF_EMU_RSI] += (uint64_t)step;
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				}
				default:
					if (!mem_rd(e, e->gpr[KOF_EMU_RDI], &v, w))
						goto fault;
					a = reg_rd(e, KOF_EMU_RAX, w, 0);
					fl_sub(e, a, v, 0, w);
					e->gpr[KOF_EMU_RDI] += (uint64_t)step;
					break;
				}
				if (ix.IsRepeated) {
					e->gpr[KOF_EMU_RCX]--;
					e->insn++;
					/* REPZ/REPNZ on a compare stop on the flag
					 * as well as on the count; REP on a move
					 * only on the count. */
					if (ix.Instruction == ND_INS_SCAS ||
					    ix.Instruction == ND_INS_CMPS) {
						int z = (e->flags & FL_ZF) != 0;

						if (ix.Rep == 0xF3 ? !z : z)
							break;
					}
				}
			}
			break;
		}

		case ND_INS_CLD: e->flags &= ~(uint64_t)FL_DF; break;
		case ND_INS_STD: e->flags |=  (uint64_t)FL_DF; break;

		/*
		 * CPUID, answered rather than refused.
		 *
		 * A stub asks in order to pick a code path, and the safest
		 * answer is a plain old CPU: no AVX, no fancy string support,
		 * so whatever it selects is the simple path this interpreter
		 * has the best chance of carrying. Refusing instead would stop
		 * the run at the first sample that merely wanted to know.
		 */
		case ND_INS_CPUID: {
			uint32_t leaf = (uint32_t)e->gpr[KOF_EMU_RAX];

			e->gpr[KOF_EMU_RAX] = e->gpr[KOF_EMU_RBX] =
			e->gpr[KOF_EMU_RCX] = e->gpr[KOF_EMU_RDX] = 0;
			if (leaf == 0) {
				e->gpr[KOF_EMU_RAX] = 1;          /* max leaf */
				e->gpr[KOF_EMU_RBX] = 0x756e6547;  /* "Genu" */
				e->gpr[KOF_EMU_RDX] = 0x49656e69;  /* "ineI" */
				e->gpr[KOF_EMU_RCX] = 0x6c65746e;  /* "ntel" */
			} else if (leaf == 1) {
				e->gpr[KOF_EMU_RAX] = 0x000306a9;  /* a plausible model */
				e->gpr[KOF_EMU_RDX] = 0x078bfbff;  /* fpu..sse2, no avx */
			}
			break;
		}

		case ND_INS_SYSCALL: {
			int s = 0;
			uint64_t ret = do_syscall(e, &s);

			if (s) { e->stop = (enum kof_emu_stop)(s - 1); goto done; }
			e->gpr[KOF_EMU_RAX] = ret;
			break;
		}

		default:
			goto unsupported;
		}

		if (!jumped)
			e->rip = next;
		else {
			/*
			 * A jump into a page the run wrote LOOKS like the
			 * handoff, and often is not - see
			 * kof_emu_cfg.stop_on_written_jump for what UPX does to
			 * that idea. Off unless the caller asked.
			 */
			struct page *p = e->stop_on_written_jump
					 ? page_find(e, e->rip) : NULL;

			if (p && p->written) {
				e->stop = KOF_EMU_STOP_HANDOFF;
				goto done;
			}
		}
		continue;

unsupported:
		fail(e, e->fault_kind[0] ? KOF_EMU_STOP_FAULT
					 : KOF_EMU_STOP_UNSUPPORTED, &ix);
		goto done;
fault:
		fail(e, KOF_EMU_STOP_FAULT, NULL);
		goto done;
	}
done:
	return e->stop;
}

/* ---- what came out --------------------------------------------------------- */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

int kof_emu_next_written(struct kof_emu *e, uint32_t *it, uint64_t *va,
			 const uint8_t **bytes, uint64_t *len)
{
	uint32_t i;

	if (!e->sorted) {
		uint32_t n = 0;

		e->sorted = calloc(e->n_pages ? e->n_pages : 1u, sizeof *e->sorted);
		if (!e->sorted)
			return 0;
		for (i = 0; i <= e->tab_mask; i++)
			if (e->tab[i].va && e->tab[i].written)
				e->sorted[n++] = e->tab[i].va;
		qsort(e->sorted, n, sizeof *e->sorted, cmp_u64);
		e->n_sorted = n;
	}
	if (*it >= e->n_sorted)
		return 0;
	{
		/*
		 * One run rather than one page: a decompressed payload is
		 * megabytes of neighbours, and handing the scanner three
		 * hundred separate children of four kilobytes each would lose
		 * every marker that straddles a page.
		 */
		uint32_t s = *it, n = 1;
		struct page *p;
		uint8_t *buf;
		uint64_t k;

		while (s + n < e->n_sorted &&
		       e->sorted[s + n] == e->sorted[s + n - 1u] + KOF_EMU_PAGE)
			n++;
		buf = malloc((size_t)n * KOF_EMU_PAGE);
		if (!buf)
			return 0;
		for (k = 0; k < n; k++) {
			p = page_find(e, e->sorted[s + k]);
			memcpy(buf + k * KOF_EMU_PAGE, p->data, KOF_EMU_PAGE);
		}
		/* Owned by the emulator, replaced on the next call. One live run
		 * at a time is all a caller needs and all this has to track. */
		free(e->run_buf);
		e->run_buf = buf;
		*va = e->sorted[s];
		*bytes = buf;
		*len = (uint64_t)n * KOF_EMU_PAGE;
		*it = s + n;
		return 1;
	}
}
