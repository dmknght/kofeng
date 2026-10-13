/*
 * emu_api.c - construction, the host-facing setters and getters, the watches and the snapshots. See emu.h.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- construction --------------------------------------------------------- */

static uint32_t pow2_at_least(uint32_t n)
{
	uint32_t v = 16;

	while (v < n)
		v <<= 1;
	return v;
}

struct kgenome_emu *kgenome_emu_new(const struct kgenome_emu_cfg *cfg)
{
	struct kgenome_emu *e = calloc(1, sizeof *e);
	uint64_t pages = cfg && cfg->max_pages ? cfg->max_pages : KGENOME_EMU_DEF_MAX_PAGES;

	if (!e)
		return NULL;
	if (pages > (1u << 22))
		pages = 1u << 22;
	e->max_pages = (uint32_t)pages;
	/* Lazily sized once, here, so the run loop never allocates. A failure
	 * is not fatal: the cache is an optimisation and the loop checks for
	 * it - see `ic`. */
	e->ic = calloc(KGENOME_EMU_ICACHE, sizeof *e->ic);
	/* Twice the budget, so the table never passes half full and the probe
	 * chains stay short whatever the addresses look like. */
	e->tab_mask = pow2_at_least((uint32_t)pages * 2u) - 1u;
	e->tab = calloc((size_t)e->tab_mask + 1u, sizeof *e->tab);
	if (!e->tab) {
		free(e);
		return NULL;
	}
	/* Not a page base - page bases are aligned - so the first fetch always
	 * takes the slow path and checks execute permission. See the fetch. */
	e->fetch_page = ~(uint64_t)0;
	e->mxcsr = 0x1f80u;             /* the reset value: all exceptions masked */
	e->max_insn = cfg && cfg->max_insn ? cfg->max_insn : KGENOME_EMU_DEF_MAX_INSN;
	e->idle = KGENOME_EMU_IDLE;
	e->stop_on_written_jump = cfg ? cfg->stop_on_written_jump : 0;
	/* 0 means 64: a caller written before the field existed asks for what
	 * it always got. */
	e->bits = (cfg && cfg->bits == 32) ? 32u : 64u;
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
		uint8_t pg[KGENOME_EMU_PAGE];
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
		kgenome_emu_map(e, KGENOME_EMU_VSYSCALL_BASE, pg, sizeof pg, sizeof pg,
			    KGENOME_EMU_R | KGENOME_EMU_X);
	}
	return e;
}

void kgenome_emu_last_calls(const struct kgenome_emu *e, uint64_t out[2])
{
	out[0] = e->last_call_at;
	out[1] = e->prev_call_at;
}

void kgenome_emu_set_icache(struct kgenome_emu *e, int on)
{
	free(e->ic);
	e->ic = on ? calloc(KGENOME_EMU_ICACHE, sizeof *e->ic) : NULL;
}

void kgenome_emu_free(struct kgenome_emu *e)
{
	if (e)
		free(e->itr);
	uint32_t i;

	if (!e)
		return;
	free(e->wev);
	free(e->wev_tab);
	if (e->hot) {
		uint64_t tot = 0, top = 0, best;
		uint32_t q, n_used = 0, j, k, bi;

		for (q = 0; q <= e->hot_mask; q++)
			if (e->hot[q].n) { tot += e->hot[q].n; n_used++; }
		fprintf(stderr, "[act] active=%llu gapmax=%llu tail=%llu\n",
			(unsigned long long)e->active_n,
			(unsigned long long)e->gap_max,
			(unsigned long long)e->since_active);
		fprintf(stderr, "[hot] miss: empty=%llu va=%llu pg=%llu bytes=%llu\n",
			(unsigned long long)e->m_empty,
			(unsigned long long)e->m_va,
			(unsigned long long)e->m_pg,
			(unsigned long long)e->m_bytes);
		fprintf(stderr, "[hot] icache hit=%llu miss=%llu (%.2f%%)\n",
			(unsigned long long)e->ic_hit,
			(unsigned long long)e->ic_miss,
			e->ic_hit + e->ic_miss ? 100.0 * (double)e->ic_hit /
				(double)(e->ic_hit + e->ic_miss) : 0.0);
		fprintf(stderr, "[hot] distinct=%u total=%llu\n", n_used,
			(unsigned long long)tot);
		for (j = 0; j < 12u; j++) {
			best = 0; bi = 0;
			for (k = 0; k <= e->hot_mask; k++)
				if (e->hot[k].n > best) {
					best = e->hot[k].n; bi = k;
				}
			if (!best)
				break;
			top += best;
			fprintf(stderr, "[hot] %2u %#010llx %llu (%.1f%%)\n",
				j, (unsigned long long)e->hot[bi].va,
				(unsigned long long)best,
				tot ? 100.0 * (double)best / (double)tot : 0.0);
			e->hot[bi].n = 0;
		}
		fprintf(stderr, "[hot] top12 = %.1f%% of the run\n",
			tot ? 100.0 * (double)top / (double)tot : 0.0);
	}
	free(e->hot);
	free(e->ic);
	for (i = 0; i <= e->tab_mask; i++)
		if (!e->tab[i].shared)
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

/*
 * A SECOND EMULATOR WITH THE SAME MEMORY AND REGISTERS, for a caller that
 * builds one image and runs many short spans on it.
 *
 * WHY IT IS HERE AND NOT A RESET. Undoing a run means knowing every field a
 * run can touch, and this struct has a hundred of them; a copy of a PRISTINE
 * image has nothing to undo. So the rule is the narrow one: a template that
 * has never run. Anything a run leaves behind - a trace ring, an event log,
 * a hot histogram, a snapshot, the run buffer - makes this refuse, which is
 * an honest "not a template" rather than a copy that carries half a run.
 *
 * What it owns is copied (pages, table, mappings); what it borrows is shared
 * (the caller's `self` bytes, which a backed mapping reads from) and so are
 * the pages' bytes, until a fork stores to one. THE TEMPLATE MUST OUTLIVE
 * EVERY FORK and must not be run itself.
 */
struct kgenome_emu *kgenome_emu_fork(const struct kgenome_emu *t)
{
	struct kgenome_emu *e;
	uint32_t i;

	if (!t || t->insn || t->itr || t->wev || t->hot || t->run_buf ||
	    t->snap || t->n_snap)
		return NULL;
	e = malloc(sizeof *e);
	if (!e)
		return NULL;
	memcpy(e, t, sizeof *e);
	e->cache_base = 0;
	e->cache_page = NULL;
	e->sorted = NULL;
	e->vma = NULL;
	e->max_vma = 0;
	e->ic = t->ic ? calloc(KGENOME_EMU_ICACHE, sizeof *e->ic) : NULL;
	e->tab = calloc((size_t)t->tab_mask + 1u, sizeof *e->tab);
	if (!e->tab)
		goto bad;
	memcpy(e->tab, t->tab, ((size_t)t->tab_mask + 1u) * sizeof *e->tab);
	/* PAGES ARE SHARED, NOT COPIED: a span writes a stack page and a few
	 * others, and copying the whole file per span was 1.4 of 7.6 billion
	 * instructions. The template must outlive its forks. */
	for (i = 0; i <= t->tab_mask; i++)
		if (e->tab[i].data)
			e->tab[i].shared = 1;
	if (t->n_vma) {
		e->vma = malloc((size_t)t->n_vma * sizeof *e->vma);
		if (!e->vma)
			goto bad;
		memcpy(e->vma, t->vma, (size_t)t->n_vma * sizeof *e->vma);
		e->max_vma = t->n_vma;
	}
	return e;
bad:
	free(e->tab);
	free(e->ic);
	free(e->vma);
	free(e);
	return NULL;
}

int kgenome_emu_map(struct kgenome_emu *e, uint64_t va, const uint8_t *src, uint64_t n,
		uint64_t memsz, unsigned prot)
{
	uint64_t base = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	uint64_t end, off;

	if (!e || memsz < n)
		memsz = n;
	if (!e || !memsz)
		return 0;
	end = va + memsz;
	if (end < va)
		return 0;                     /* wrapped: refuse rather than clamp */
	/* A page the bytes reach is private from the start; the zero tail of the
	 * span - past `n` - is the shared zero page, see page_add_zero. */
	for (off = base; off < end; off += KGENOME_EMU_PAGE)
		if (!(off < va + n ? kgenome_emu_page_add(e, off, prot)
				   : kgenome_emu_page_add_zero(e, off, prot)))
			return 0;
	/*
	 * Written through page_add's pages directly rather than through mem_wr:
	 * loading an image is not the stub writing, and marking these pages
	 * dirty would hand the whole file back as "what the stub produced".
	 */
	/*
	 * A PAGE AT A TIME. This was a byte at a time with a page lookup per byte:
	 * MEASURED on 100 kernel modules, 20.5 million lookups and 15.7% of the
	 * whole scan for the four modules that reached the emulator at all - every
	 * function it ran rebuilt the image, and each rebuild looked up the same
	 * page once per byte of it. One lookup per page copies the same bytes.
	 */
	for (off = 0; off < n; ) {
		struct kgenome_emu_page *p = kgenome_emu_page_find(e, va + off);
		uint64_t in = (va + off) & (KGENOME_EMU_PAGE - 1u);
		uint64_t chunk = KGENOME_EMU_PAGE - in;

		if (chunk > n - off)
			chunk = n - off;
		if (!p || !kgenome_emu_page_own(p))
			return 0;
		if (src)
			memcpy(p->data + in, src + off, (size_t)chunk);
		else
			memset(p->data + in, 0, (size_t)chunk);
		off += chunk;
	}
	return 1;
}

void kgenome_emu_set_self(struct kgenome_emu *e, const uint8_t *b, uint64_t n)
{
	e->self = b;
	e->self_n = n;
	e->self_pos = 0;
}

void kgenome_emu_set_rip(struct kgenome_emu *e, uint64_t rip) { e->rip = rip; }
void kgenome_emu_set_reg(struct kgenome_emu *e, unsigned g, uint64_t v)
{
	if (g < KGENOME_EMU_NGPR)
		e->gpr[g] = v;
}
void kgenome_emu_set_seg_base(struct kgenome_emu *e, unsigned seg, uint64_t base)
{
	if (seg == 4u)
		e->fs_base = base;
	else if (seg == 5u)
		e->gs_base = base;
}
uint64_t kgenome_emu_get_reg(const struct kgenome_emu *e, unsigned g)
{
	return g < KGENOME_EMU_NGPR ? e->gpr[g] : 0;
}

uint64_t kgenome_emu_get_rip(const struct kgenome_emu *e)
{
	return e ? e->rip : 0;
}
uint64_t kgenome_emu_rip(const struct kgenome_emu *e) { return e->rip; }
/*
 * How many faults were offered to a guest handler, and how many a handler
 * actually took. The pair is the measurement that says whether exception
 * dispatch is reaching anything: raised without taken means the records are
 * being built and nobody is registered to receive them, which is a different
 * problem from not building them.
 */
void kgenome_emu_exc_counts(const struct kgenome_emu *e, uint32_t *raised,
			uint32_t *taken, uint32_t *veh)
{
	if (raised) *raised = e->exc_raised;
	if (taken)  *taken  = e->exc_taken;
	if (veh)    *veh    = e->n_veh;
}

uint64_t kgenome_emu_last_write(const struct kgenome_emu *e)
{
	return e->last_new_page;
}

uint64_t kgenome_emu_now_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return 0;
	return (uint64_t)t.tv_sec * 1000ull + (uint64_t)(t.tv_nsec / 1000000);
}

unsigned kgenome_emu_null_calls(const struct kgenome_emu *e)
{
	return e ? e->null_calls : 0u;
}

unsigned kgenome_emu_unhandled(const struct kgenome_emu *e)
{
	return e ? e->exc_unhandled : 0u;
}

unsigned kgenome_emu_null_reads(const struct kgenome_emu *e)
{
	return e ? e->null_reads : 0u;
}

/* The longest the run went without touching a new page - what the stall
 * ceiling has to clear for a run like this one to finish. */
uint64_t kgenome_emu_idle_max(const struct kgenome_emu *e)
{
	return e ? e->idle_max : 0u;
}

void kgenome_emu_set_idle(struct kgenome_emu *e, uint64_t n)
{
	if (e && n)
		e->idle = n;
}

void kgenome_emu_set_deadline(struct kgenome_emu *e, uint64_t ms)
{
	if (!e)
		return;
	e->deadline_ms = ms;
	e->started_ms = ms ? kgenome_emu_now_ms() : 0;
}

/*
 * EXECUTE EXACTLY THE INSTRUCTION THE RUN IS STOPPED ON, watch and all.
 *
 * WHY IT HAS TO EXIST. kgenome_emu_watch_insn pauses BEFORE the instruction and
 * leaves rip on it, which is what makes the pause useful - a `ret` still has
 * its return address on the stack. But it also means kgenome_emu_run cannot get
 * past it: the next call pauses on the same bytes at the same address, and a
 * caller that wants to see what the instruction DID has no way to let it run.
 *
 * MEASURED, because the symptom is silent: the diagnose walk stopped at every
 * syscall, resumed, and read a result register that still held the syscall
 * NUMBER - mmap came back as 9 and socket as 41, so every value it linked on
 * afterwards was the number rather than the mapping or the descriptor.
 *
 * One instruction, then the budget and the watch are exactly as they were.
 */
enum kgenome_emu_stop kgenome_emu_step(struct kgenome_emu *e)
{
	uint64_t keep;
	enum kgenome_emu_stop st;

	if (!e)
		return KGENOME_EMU_STOP_FAULT;
	keep = e->max_insn;
	e->iw_skip = 1;
	e->max_insn = e->insn + 1u;
	st = kgenome_emu_run(e);
	e->iw_skip = 0;
	e->max_insn = keep;
	return st;
}

void kgenome_emu_set_max_insn(struct kgenome_emu *e, uint64_t n)
{
	if (e && n > e->max_insn)
		e->max_insn = n;
}

uint64_t kgenome_emu_insn_count(const struct kgenome_emu *e) { return e->insn; }
const char *kgenome_emu_stop_detail(const struct kgenome_emu *e) { return e->detail; }

void kgenome_emu_watch(struct kgenome_emu *e, uint64_t va)
{
	e->watch_va = va;
	e->watch_on = 1;
	e->watch_n = 0;
}

unsigned kgenome_emu_watch_hits(const struct kgenome_emu *e, uint64_t *rip,
			    uint64_t *val, unsigned n)
{
	unsigned k, got = e->watch_n < n ? e->watch_n : n;

	for (k = 0; k < got; k++) { rip[k] = e->watch_rip[k]; val[k] = e->watch_val[k]; }
	return got;
}

/*
 * THE RANGE IS CHECKED BEFORE ANY OF IT IS COPIED, and that is what makes the
 * contract above true rather than nearly true.
 *
 * `mem_rd` is the interpreter's own path and it copies byte by byte, stopping
 * at the first page the guest does not have - so by the time it refuses, the
 * bytes before the hole are already in the caller's buffer. The interpreter
 * does not care: a refusal there ends the run. A MODULE does care, because a
 * module reads a span it is about to search or parse, and a refusal it does
 * not check leaves it looking at a mixture of new bytes and whatever the
 * buffer held before. Measured by tests/unit/emu_span_read.
 *
 * The check is per PAGE, not per byte, so a 4096-byte span costs two lookups
 * and the interpreter's hot path is not touched at all.
 *
 * THE NULL PAGE IS LEFT TO mem_rd. A read off a null pointer answers zeros by
 * design - see the note there - and pre-rejecting it as unmapped would undo
 * that.
 */
int kgenome_emu_read(struct kgenome_emu *e, uint64_t va, void *dst, unsigned n)
{
	uint64_t pg, last;

	if (!e || !dst)
		return 0;
	if (!n)
		return 1;
	if (va + n < va)                        /* the span wraps */
		return 0;
	if (!(va < KGENOME_EMU_PAGE && (uint64_t)n <= KGENOME_EMU_PAGE - va)) {
		last = (va + n - 1u) & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
		for (pg = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);; pg += KGENOME_EMU_PAGE) {
			if (!kgenome_emu_page_lookup(e, pg)) {
				e->fault_va = pg < va ? va : pg;
				memcpy(e->fault_kind, "read", 5);
				return 0;
			}
			if (pg == last)
				break;
		}
	}
	return kgenome_emu_mem_rd(e, va, dst, n);
}

/*
 * Write into the guest before it runs, which is what a loader does and what
 * nothing else should.
 *
 * It goes through mem_wr rather than round the side of it, so a write to an
 * address the guest does not have fails here instead of silently landing
 * somewhere - and so a page this touches is marked written exactly as one the
 * guest touched would be.
 */
int kgenome_emu_write(struct kgenome_emu *e, uint64_t va, const void *src, unsigned n)
{
	return kgenome_emu_mem_wr(e, va, src, n);
}


/* Recompute the span of the unseen hops - after one is added or entered. */
void kgenome_emu_hop_bounds(struct kgenome_emu *e)
{
	uint32_t i;

	e->hop_unseen = 0;
	e->hop_lo = ~(uint64_t)0;
	e->hop_hi = 0;
	for (i = 0; i < e->n_hop; i++) {
		if (e->hop[i].seen)
			continue;
		e->hop_unseen++;
		if (e->hop[i].lo < e->hop_lo)
			e->hop_lo = e->hop[i].lo;
		if (e->hop[i].hi > e->hop_hi)
			e->hop_hi = e->hop[i].hi;
	}
}

void kgenome_emu_hop_add(struct kgenome_emu *e, uint64_t lo, uint64_t hi, int seen)
{
	if (!e || hi <= lo || e->n_hop >= KGENOME_EMU_EXEC_WATCH)
		return;
	e->hop[e->n_hop].lo = lo;
	e->hop[e->n_hop].hi = hi;
	e->hop[e->n_hop].seen = (uint8_t)(seen != 0);
	e->n_hop++;
	kgenome_emu_hop_bounds(e);
}



/* Where the image is, so the run can dump it at the moment it hands over. */
/* Arm the handover test - see the note where it fires. Off by default so a
 * caller that wants the old behaviour keeps it. */
void kgenome_emu_set_oep_watch(struct kgenome_emu *e, int on)
{
	if (e)
		e->oep_watch = on;
}

void kgenome_emu_set_image_range(struct kgenome_emu *e, uint64_t lo, uint64_t hi)
{
	if (e) {
		e->img_lo = lo;
		e->img_hi = hi;
	}
}

void kgenome_emu_set_stack_range(struct kgenome_emu *e, uint64_t lo, uint64_t hi)
{
	if (e && hi > lo) {
		e->stack_lo = lo;
		e->stack_hi = hi;
	}
}

void kgenome_emu_set_stub_range(struct kgenome_emu *e, uint64_t lo, uint64_t hi)
{
	if (e && hi > lo) {
		e->stub_lo = lo;
		e->stub_hi = hi;
	}
}

/* Where the ciphertext is, so the run can tell when it stops being ciphertext.
 * See the write path for what happens then. */
void kgenome_emu_watch_write(struct kgenome_emu *e, uint64_t lo, uint64_t hi)
{
	if (e)
		kgenome_emu_wrange_add(e->wwatch, &e->n_wwatch, lo, hi);
}

/* 1 once anything has been written into one of those ranges. */
int kgenome_emu_write_seen(const struct kgenome_emu *e)
{
	return e ? e->wwatch_hit : 0;
}

void kgenome_emu_watch_insn(struct kgenome_emu *e, const uint8_t *bytes, unsigned n)
{
	if (!e)
		return;
	/*
	 * NO BYTES DISARMS, and a module needs that as much as it needs the
	 * watch. A run paused more times than the module is willing to look at
	 * still has to FINISH - what it decrypted is worth having whether or
	 * not the module could name it - and without a way to stop pausing the
	 * only exit was to abandon the machine ungathered. Measured: three of
	 * four Sality samples produced nothing at all for exactly that reason.
	 */
	if (!bytes || !n) {
		e->n_iw = 0;
		e->iw_len = 0;
		return;
	}
	if (n > KGENOME_EMU_INSN_WATCH_LEN || e->n_iw >= KGENOME_EMU_INSN_WATCH)
		return;
	memcpy(e->iw[e->n_iw].b, bytes, n);
	e->iw[e->n_iw].n = (uint8_t)n;
	e->n_iw++;
}

void kgenome_emu_watch_insn_len(struct kgenome_emu *e, unsigned len)
{
	if (e)
		e->iw_len = len;
}


void kgenome_emu_watch_exec(struct kgenome_emu *e, uint64_t lo, uint64_t hi)
{
	if (e)
		kgenome_emu_wrange_add(e->xwatch, &e->n_xwatch, lo, hi);
}

/*
 * Keep a copy of [va, va+len) if the run wrote any of it. Pages it never
 * touched are the file's own bytes and are already scannable from the file, so
 * a mapping with nothing written under it is not a payload and is skipped.
 */
void kgenome_emu_snap_take(struct kgenome_emu *e, uint64_t va, uint64_t len)
{
	uint64_t base = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u), off, n;
	struct kgenome_emu_page *p;
	struct snap *s;
	int any = 0;

	len = (va - base) + len;
	n = (len + KGENOME_EMU_PAGE - 1u) & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	if (!n || n > (uint64_t)e->n_pages * KGENOME_EMU_PAGE)
		return;
	for (off = 0; off < n; off += KGENOME_EMU_PAGE) {
		p = kgenome_emu_page_find(e, base + off);
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
	if (e->n_snap >= KGENOME_EMU_MAX_SNAP ||
	    e->snap_bytes + n > (uint64_t)e->max_pages * KGENOME_EMU_PAGE)
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
	for (off = 0; off < n; off += KGENOME_EMU_PAGE) {
		p = kgenome_emu_page_find(e, base + off);
		if (p)
			memcpy(s->bytes + off, p->data, KGENOME_EMU_PAGE);
		else
			memset(s->bytes + off, 0, KGENOME_EMU_PAGE);
	}
	s->va = base;
	s->len = n;
	e->snap_bytes += n;
	e->n_snap++;
}

/*
 * HOW MUCH OF THE GUEST'S OWN WRITING SURROUNDS AN ADDRESS, in pages.
 *
 * Contiguous pages the guest wrote, counted both ways from `va` and bounded
 * by `cap` so a guest that wrote everything costs `cap` lookups, once per
 * candidate transfer. It is the "large and coherent" half of the question
 * "is this the program": a decompressed image is one unbroken run, a stage
 * of a loader's own bookkeeping is a page or two.
 */
unsigned kgenome_emu_written_run_pages(struct kgenome_emu *e, uint64_t va, unsigned cap)
{
	uint64_t lo = va & ~(uint64_t)(KGENOME_EMU_PAGE - 1u), hi = lo + KGENOME_EMU_PAGE;
	unsigned run = 1;
	struct kgenome_emu_page *q;

	while (run < cap && lo >= KGENOME_EMU_PAGE &&
	       (q = kgenome_emu_page_lookup(e, lo - KGENOME_EMU_PAGE)) && q->gwritten) {
		lo -= KGENOME_EMU_PAGE;
		run++;
	}
	while (run < cap && (q = kgenome_emu_page_lookup(e, hi)) && q->gwritten) {
		hi += KGENOME_EMU_PAGE;
		run++;
	}
	return run;
}

void kgenome_emu_snap_written(struct kgenome_emu *e)
{
	uint32_t it = 0;
	uint64_t va, len;
	const uint8_t *b;

	while (kgenome_emu_next_written(e, &it, &va, &b, &len))
		kgenome_emu_snap_take(e, va, len);
}


int kgenome_emu_next_snapshot(struct kgenome_emu *e, uint32_t *it, uint64_t *va,
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


unsigned kgenome_emu_trace(const struct kgenome_emu *e, uint64_t *out, unsigned n)
{
	uint64_t have = e->trace_n < KGENOME_EMU_TRACE ? e->trace_n : KGENOME_EMU_TRACE;
	unsigned k, got = (unsigned)(have < n ? have : n);

	for (k = 0; k < got; k++)
		out[k] = e->trace[(e->trace_n - got + k) % KGENOME_EMU_TRACE];
	return got;
}

const char *kgenome_emu_stop_name(enum kgenome_emu_stop s)
{
	switch (s) {
	case KGENOME_EMU_STOP_BUDGET:      return "budget";
	case KGENOME_EMU_STOP_EXIT:        return "exit";
	case KGENOME_EMU_STOP_HANDOFF:     return "handoff";
	case KGENOME_EMU_STOP_FAULT:       return "fault";
	case KGENOME_EMU_STOP_UNSUPPORTED: return "unsupported";
	case KGENOME_EMU_STOP_DECODE:      return "decode";
	case KGENOME_EMU_STOP_STALLED:     return "stalled";
	case KGENOME_EMU_STOP_INSN:        return "watched instruction";
	case KGENOME_EMU_STOP_QUIET:       return "decryption finished";
	}
	return "?";
}


/* ---- what came out --------------------------------------------------------- */

int kgenome_emu_next_written(struct kgenome_emu *e, uint32_t *it, uint64_t *va,
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
		qsort(e->sorted, n, sizeof *e->sorted, kof_cmp_u64);
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
		struct kgenome_emu_page *p;
		uint8_t *buf;
		uint64_t k, trim;

		while (s + n < e->n_sorted &&
		       e->sorted[s + n] == e->sorted[s + n - 1u] + KGENOME_EMU_PAGE)
			n++;
		buf = malloc((size_t)n * KGENOME_EMU_PAGE);
		if (!buf)
			return 0;
		for (k = 0; k < n; k++) {
			p = kgenome_emu_page_find(e, e->sorted[s + k]);
			memcpy(buf + k * KGENOME_EMU_PAGE, p->data, KGENOME_EMU_PAGE);
		}
		/*
		 * AND THE RUN ENDS WHERE THE WRITING DID - see page.wr_hi.
		 * Only the LAST page of the run is trimmed: an interior page
		 * is followed by another written page, so its tail is between
		 * two things the stub made and cutting it would put a hole in
		 * the middle of a payload.
		 */
		p = kgenome_emu_page_find(e, e->sorted[s + n - 1u]);
		trim = (uint64_t)(n - 1u) * KGENOME_EMU_PAGE +
		       (p && p->wr_hi ? p->wr_hi : KGENOME_EMU_PAGE);
		/* Owned by the emulator, replaced on the next call. One live run
		 * at a time is all a caller needs and all this has to track. */
		free(e->run_buf);
		e->run_buf = buf;
		*va = e->sorted[s];
		*bytes = buf;
		*len = trim;
		*it = s + n;
		return 1;
	}
}
