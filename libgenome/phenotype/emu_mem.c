/*
 * emu_mem.c - the emulated address space: pages, mappings, and the byte-wise reads and writes every other file goes through.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"


static uint32_t page_hash(uint64_t pn)
{
	pn ^= pn >> 33; pn *= 0xff51afd7ed558ccdull;
	pn ^= pn >> 29; pn *= 0xc4ceb9fe1a85ec53ull;
	return (uint32_t)(pn ^ (pn >> 32));
}

/*
 * Ask the caller's allowance for `bytes` the machine is about to take (cfg.account).
 * 1 when there is no allowance to ask or it agrees; 0 when it refuses, and the
 * machine says so - KGENOME_EMU_HIT_MEM - because what it then does not make is
 * a part of the answer.
 */
int kgenome_emu_acct(struct kgenome_emu *e, uint64_t bytes)
{
	if (!e->account)
		return 1;
	if (!e->account(e->account_user, (int64_t)bytes)) {
		e->hit |= KGENOME_EMU_HIT_MEM;
		return 0;
	}
	e->acct += bytes;
	return 1;
}

/* One private page's worth of what the caller granted, asking for the next chunk when it
 * is spent: a run takes a dozen pages and is charged for a dozen, not for the most it
 * may own. */
static int page_credit_take(struct kgenome_emu *e)
{
	if (!e->account)
		return 1;
	if (e->page_credit < KGENOME_EMU_PAGE) {
		if (!kgenome_emu_acct(e, (uint64_t)KGENOME_EMU_GRANT_PAGES * KGENOME_EMU_PAGE))
			return 0;
		e->page_credit += (uint64_t)KGENOME_EMU_GRANT_PAGES * KGENOME_EMU_PAGE;
	}
	e->page_credit -= KGENOME_EMU_PAGE;
	return 1;
}

/* The first store to a page forked from a template, or borrowed from the caller's bytes,
 * takes its own copy. */
int kgenome_emu_page_own(struct kgenome_emu *e, struct kgenome_emu_page *p)
{
	uint8_t *d;

	if (!p->shared)
		return 1;
	if (!page_credit_take(e))
		return 0;
	d = malloc(KGENOME_EMU_PAGE);
	if (!d) {
		KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "page copy not allocated");
		return 0;
	}
	memcpy(d, p->data, KGENOME_EMU_PAGE);
	p->data = d;
	p->shared = 0;
	return 1;
}

static struct kgenome_emu_page *vma_commit(struct kgenome_emu *e, uint64_t base);

struct kgenome_emu_page *kgenome_emu_page_find(struct kgenome_emu *e, uint64_t va)
{
	uint64_t base = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	uint32_t i = page_hash(base) & e->tab_mask, n = 0;

	if (!base)
		return NULL;          /* page zero is never mapped: a NULL deref
				       * has to fault rather than read zeroes */
	while (n++ <= e->tab_mask) {
		struct kgenome_emu_page *p = &e->tab[i];

		if (!p->va)
			return vma_commit(e, base);
		if (p->va == base)
			return p;
		i = (i + 1u) & e->tab_mask;
	}
	return NULL;
}

struct kgenome_emu_page *kgenome_emu_page_add(struct kgenome_emu *e, uint64_t base, unsigned prot)
{
	uint32_t i, n = 0;

	if (e->n_pages >= e->max_pages || !base)
		return NULL;
	i = page_hash(base) & e->tab_mask;
	while (n++ <= e->tab_mask) {
		struct kgenome_emu_page *p = &e->tab[i];

		if (p->va == base)
			return p;
		if (!p->va) {
			if (!page_credit_take(e))
				return NULL;
			p->data = calloc(1, KGENOME_EMU_PAGE);
			if (!p->data) {
				KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "page not allocated");
				return NULL;
			}
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

/*
 * A page that holds nothing yet, WITHOUT ALLOCATING IT: it points at one
 * read-only page of zeroes and is marked shared, so the first store takes its
 * own copy (page_own) exactly as a page forked from a template does.
 *
 * WHY. The Windows environment maps every modelled library as a span of
 * K32_SPAN bytes of which a few pages hold the export directory and the stubs;
 * the rest is zero, because a loader that walks an image the header declares
 * reads around it. MEASURED (callgrind, a 6.6 KB PE): those zero pages were
 * 12.3 of the 23.7 million instructions of the whole scan, every run, and no
 * run touches more than a handful of them. Only kgenome_emu_map uses this - a page
 * that is about to be filled is page_add - so every other writer still sees
 * a private page.
 */
static const uint8_t zero_page[KGENOME_EMU_PAGE];

struct kgenome_emu_page *kgenome_emu_page_add_zero(struct kgenome_emu *e, uint64_t base,
				  unsigned prot)
{
	uint32_t i, n = 0;

	if (e->n_pages >= e->max_pages || !base)
		return NULL;
	i = page_hash(base) & e->tab_mask;
	while (n++ <= e->tab_mask) {
		struct kgenome_emu_page *p = &e->tab[i];

		if (p->va == base)
			return p;
		if (!p->va) {
			p->data = (uint8_t *)(uintptr_t)zero_page;
			p->shared = 1;
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

/*
 * A page whose bytes are the CALLER'S, borrowed: it points at `src` and is marked
 * shared, so the first store takes a private copy exactly as a forked page does.
 * For an image that is mapped from bytes the caller keeps for as long as the
 * machine lives (the object being run): a page nobody stores to costs a table
 * slot instead of 4 KiB. An existing page is returned as it is - the caller then
 * copies into it the ordinary way.
 */
struct kgenome_emu_page *kgenome_emu_page_add_borrow(struct kgenome_emu *e, uint64_t base,
				  unsigned prot, const uint8_t *src)
{
	uint32_t i, n = 0;

	if (e->n_pages >= e->max_pages || !base)
		return NULL;
	i = page_hash(base) & e->tab_mask;
	while (n++ <= e->tab_mask) {
		struct kgenome_emu_page *p = &e->tab[i];

		if (p->va == base)
			return p;
		if (!p->va) {
			p->data = (uint8_t *)(uintptr_t)src;
			p->shared = 1;
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
int kgenome_emu_vma_add(struct kgenome_emu *e, uint64_t base, uint64_t len,
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
	if (e->n_vma >= (e->max_pages > KGENOME_EMU_MAX_VMA ? e->max_pages : KGENOME_EMU_MAX_VMA)) {
		/* the page budget is what a mapping may eventually cost, so it scales this bound;
		 * past it the guest is told no, and so is the caller */
		e->hit |= KGENOME_EMU_HIT_VMA;
		return 0;
	}
	if (e->n_vma == e->max_vma) {
		uint32_t m = e->max_vma ? e->max_vma * 2u : 8u;
		struct vma *t = realloc(e->vma, (size_t)m * sizeof *t);

		if (!t) {
			KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "mapping table not grown");
			return 0;
		}
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
static struct kgenome_emu_page *vma_commit(struct kgenome_emu *e, uint64_t base)
{
	uint32_t k = e->n_vma;

	while (k--) {
		struct vma *v = &e->vma[k];
		struct kgenome_emu_page *p;

		if (base < v->base || base - v->base >= v->len)
			continue;
		p = kgenome_emu_page_add(e, base, v->prot);
		if (!p)
			return NULL;
		if (v->backed && e->self) {
			uint64_t o = v->off + (base - v->base);
			uint64_t n = o < e->self_n ? e->self_n - o : 0;

			if (n > KGENOME_EMU_PAGE)
				n = KGENOME_EMU_PAGE;
			if (n)
				memcpy(p->data, e->self + o, (size_t)n);
		}
		return p;
	}
	return NULL;
}

/*
 * page_find with a one-entry memo of the last non-NULL result.
 *
 * mem_rd/mem_wr resolve one byte at a time, and consecutive bytes share a page
 * except at a boundary, so the memo answers all but the first byte of an
 * access without hashing. It never memoises a miss - see the note on
 * cache_page - so a base that is unmapped now and filled later still resolves
 * through page_find, and the per-byte straddle behaviour is unchanged: every
 * byte still resolves its own page independently, just more cheaply.
 */

/*
 * Every read and write goes through these, one byte at a time.
 *
 * A byte at a time because an access may straddle a page boundary and the two
 * pages need not be adjacent in the table - and because a straddling access
 * that half succeeds is the bug this design exists to make impossible. The
 * per-byte page resolution goes through page_lookup so that a within-page run
 * costs one hash rather than one per byte.
 */
int kgenome_emu_mem_rd(struct kgenome_emu *e, uint64_t va, void *dst, unsigned n)
{
	uint8_t *d = dst;
	unsigned i;

	/*
	 * A READ THROUGH A NULL POINTER IS ZERO, NOT THE END OF THE RUN.
	 *
	 * On Windows it faults and the process dies. Here the process dying is
	 * the thing to avoid: what the run is FOR is the plaintext the guest
	 * writes, and a guest that took a null from something this environment
	 * could not answer - a function in a library whose export list is
	 * empty, a handle it never got - then reads a field off it, and the
	 * run used to end there with the payload still encrypted. Measured on
	 * an MPRESS sample: `read at 0x14`, one field off a null pointer, at
	 * 16477255 instructions.
	 *
	 * READS ONLY. Execution at zero is still a fault and still means
	 * "called an import this environment does not have"; a write is still
	 * a fault, because a write that goes nowhere loses the very bytes this
	 * exists to collect. The two cases stay apart from this one.
	 *
	 * Only the first page, and only where the guest mapped nothing: a guest
	 * that genuinely mapped page zero is reading its own memory.
	 */
	if (va < KGENOME_EMU_PAGE && (uint64_t)n <= KGENOME_EMU_PAGE - va &&
	    !kgenome_emu_page_lookup(e, va)) {
		e->null_reads++;
		memset(d, 0, n);
		return 1;
	}

	/*
	 * READS INTO A LIBRARY IMAGE, COUNTED ONLY WHEN ASKED FOR.
	 *
	 * "It called nothing" and "it walked the export table and found
	 * nothing" look identical from a stop reason and mean opposite things:
	 * the first says the environment's function list is beside the point,
	 * the second says exactly which name is missing. Counting the reads
	 * separates them.
	 *
	 * Behind a flag because this is the hottest path in the interpreter and
	 * eight range tests per byte would be measurable; with the flag clear
	 * it is one predictable branch.
	 */
	if (e->count_mod_reads) {
		unsigned m;

		for (m = 0; m < KGENOME_EMU_WIN_MOD_COUNT; m++) {
			uint64_t b = e->win_mod_base[m];

			if (b && va >= b && va < b + (256u * KGENOME_EMU_PAGE)) {
				e->mod_reads[m]++;
				break;
			}
		}
	}

	for (i = 0; i < n; i++) {
		struct kgenome_emu_page *p = kgenome_emu_page_lookup(e, va + i);

		if (!p) {
			/*
			 * A DATA READ FROM NOWHERE ANSWERS ZERO, UNDER
			 * MEASUREMENT - see KOF_EMU_SOFTREAD.
			 *
			 * The engine already makes this trade for page zero,
			 * with the argument written beside it: what a run is
			 * FOR is the plaintext the guest writes, and a read of
			 * a field off a pointer the environment could not
			 * supply should not end it. The same argument applies
			 * to a pointer that is garbage rather than null, and
			 * the published designs call a run that dies this way
			 * an INCORRECT termination - something to recover from
			 * rather than to report.
			 *
			 * Measured before it is believed: 125 of 129 runs over
			 * a Windows corpus end in a fault. Whether tolerating
			 * them produces anything is the question this flag
			 * exists to answer, so it is off by default.
			 */
			if (e->softread && !e->in_fetch && e->running) {
				e->soft_reads++;
				d[i] = 0;
				continue;
			}
			e->fault_va = va + i;
			memcpy(e->fault_kind, "read", 5);
			return 0;
		}
		d[i] = p->data[(va + i) & (KGENOME_EMU_PAGE - 1u)];
	}
	/* A DATA read, not the fetch of an instruction - see `last_read_va`.
	 * The fetch reads memory too and counting it would make every program
	 * look like it was decrypting itself. */
	if (e->running && !e->in_fetch) {
		e->last_read[e->last_read_n % KGENOME_EMU_RDRING] = va;
		e->last_read_n++;
	}
	return 1;
}

int kgenome_emu_mem_wr(struct kgenome_emu *e, uint64_t va, const void *src, unsigned n)
{
	const uint8_t *s = src;
	unsigned i;

	for (i = 0; i < n; i++) {
		struct kgenome_emu_page *p = kgenome_emu_page_lookup(e, va + i);

		if (!p) {
			/*
			 * A WRITE TO NOWHERE GETS A PAGE, UNDER MEASUREMENT -
			 * see KOF_EMU_SOFTWRITE.
			 *
			 * THE ARGUMENT FOR REFUSING IS THE ARGUMENT FOR THIS.
			 * The note beside the read path says a write that goes
			 * nowhere "loses the very bytes this exists to
			 * collect" - and refusing it loses them just as
			 * completely, by ending the run. Giving the guest the
			 * page keeps them, and keeps whatever it writes next.
			 *
			 * Measured over 300 Windows samples: of seventeen runs
			 * that ended in a fault, SEVEN were a write to an
			 * address nothing mapped.
			 *
			 * STILL BOUNDED. page_add refuses past the page budget,
			 * so a guest that writes at random addresses buys a
			 * fixed number of pages and then ends exactly as it
			 * does today.
			 */
			if (e->softwrite && e->running) {
				p = kgenome_emu_page_add(e, (va + i) &
					     ~(uint64_t)(KGENOME_EMU_PAGE - 1u),
					     KGENOME_EMU_R | KGENOME_EMU_W);
				if (p)
					e->soft_writes++;
			}
			if (!p) {
				e->fault_va = va + i;
				memcpy(e->fault_kind, "write", 6);
				return 0;
			}
		}
		{
			uint32_t po = (uint32_t)((va + i) &
						 (KGENOME_EMU_PAGE - 1u));

			if (p->shared && !kgenome_emu_page_own(e, p)) {
				e->fault_va = va + i;
				memcpy(e->fault_kind, "write", 6);
				return 0;
			}
			p->data[po] = s[i];
			if (po + 1u > p->wr_hi)
				p->wr_hi = (uint16_t)(po + 1u);
		}
		/*
		 * A WRITE BACK TO WHAT WAS JUST READ, near where the last one
		 * was - see `last_read_va`. Eight bytes of slack, so a loop
		 * working a dword or a qword at a time is still one stride.
		 */
		/*
		 * ---- IS THE GUEST STILL DECRYPTING --------------------------
		 *
		 * A WRITE NEXT TO THE LAST ONE. See `last_read` for why the
		 * signal has to be a memory trace rather than an opcode; this
		 * is which trace, and it was measured rather than assumed.
		 *
		 * THE PUBLISHED HEURISTIC IS A READ FOLLOWED BY A WRITE BACK TO
		 * THE SAME ADDRESS - decryption in place - AND IT DOES NOT FIT
		 * THIS FAMILY. Measured on a Sality body: of 408,441 guest
		 * writes, 350,346 were indeed writes back to something just
		 * read, and every one of them was the STACK - push and pop
		 * touching the same slot. The decryption itself reads from one
		 * place and writes to another, so it never made that pattern
		 * once in twenty million instructions.
		 *
		 * What it does make is a SEQUENTIAL WRITE STREAM: 58,076 writes
		 * landing within eight bytes of the one before, against 58,066
		 * loop iterations counted independently. That is the output of
		 * the decryption, and a decryptor cannot avoid producing it
		 * whatever instructions it is spelled with.
		 *
		 * THE STACK IS EXCLUDED, and it has to be: a run of pushes is
		 * also a sequential write stream, and without this every
		 * function prologue would read as decryption.
		 */
		if (e->running && !i) {
			uint64_t sp = e->gpr[KGENOME_EMU_RSP];
			uint64_t d = va > sp ? va - sp : sp - va;

			if (d > (64u << 10)) {
				d = va > e->pair_va ? va - e->pair_va
						    : e->pair_va - va;
				if (e->pair_va && d && d <= 8u) {
					if (e->active_n &&
					    e->since_active > e->gap_max)
						e->gap_max = e->since_active;
					e->active_n++;
					e->since_active = 0;
				}
				e->pair_va = va;
			}
		}
		/* The first write to a page is the unit of progress: see
		 * KGENOME_EMU_IDLE. Recorded here, where it happens, so nothing
		 * else has to remember to. */
		if (!p->written) {
			e->last_new_page = e->insn;
			e->idle_credit = 0;
			/* a page written for the first time joins the written list: a walk
			 * made earlier is stale */
			if (e->sorted) {
				free(e->sorted);
				e->sorted = NULL;
			}
		} else if (e->running && e->idle_credit < KGENOME_EMU_IDLE_CREDIT_MAX) {
			/*
			 * A STORE TO A NEW CACHE LINE OF A PAGE ALREADY WRITTEN
			 * IS PROGRESS TOO, within a credit.
			 *
			 * "No new page for KGENOME_EMU_IDLE instructions" cut a
			 * stub that was still working: the call-operand
			 * unfilter that ends a UPX 5 x64 stub sweeps 2.6 MB of
			 * the decompressed code, reading all of it and
			 * patching a few bytes per call site - all on pages
			 * the decompressor had already written. Measured on
			 * four such samples: stalled at 18-25 million
			 * instructions with the jump to the entry point still
			 * to come.
			 *
			 * A spin loop touches one line and so earns one credit,
			 * the stack is not counted, and credits are bounded and
			 * restored only by a genuinely new page, so a guest
			 * that sweeps a buffer for ever is still stopped - by
			 * the credit and then by the same ceiling as before.
			 */
			uint64_t sp = e->gpr[KGENOME_EMU_RSP];
			uint64_t dsp = va > sp ? va - sp : sp - va;
			uint64_t line = va >> 6;

			if (dsp > (64u << 10) && line != e->last_wr_line) {
				e->last_wr_line = line;
				e->idle_credit++;
				e->last_new_page = e->insn;
			}
		}
		p->written = 1;
		/* Only while the guest is the one running - see `gwritten`. */
		if (e->running)
			p->gwritten = 1;
		/*
		 * A WRITE INTO CIPHERTEXT IS THE MOMENT THE PROGRAM APPEARS.
		 *
		 * A protector's loader decrypts the program's own sections in
		 * place, so the first write into one of them is the only signal
		 * that does not depend on guessing where it will jump
		 * afterwards. themida-dumper watches exactly this from outside
		 * the process - it fingerprints the encrypted sections and
		 * polls them for change - and this is the same test made from
		 * inside, where it costs a range check instead of a poll. See
		 * THIRD-PARTY.md.
		 *
		 * The image is taken ONCE, at the first such write, and the run
		 * carries on: a loader decrypts several sections and stopping at
		 * the first would take the image before the rest exist. The
		 * snapshot is of the whole image because a section decrypted
		 * alone is not a program.
		 */
		if (e->n_wwatch && !e->wwatch_hit &&
		    kgenome_emu_wrange_has(e->wwatch, e->n_wwatch, va + i))
			e->wwatch_hit = 1;
		if (e->watch_on && va + i == e->watch_va &&
		    e->watch_n < KGENOME_EMU_WATCH_MAX) {
			e->watch_rip[e->watch_n] = e->rip;
			e->watch_val[e->watch_n] = s[i];
			e->watch_n++;
		}
	}
	return 1;
}
