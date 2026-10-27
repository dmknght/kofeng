/*
 * diag_scan.c - the diagnose scan: the nodes an object holds, and what links them.
 * The scan object lives here; its parts are diag_origin.c, diag_hit.c, diag_site.c,
 * diag_sweep_cand.c, diag_sweep.c, diag_code.c and diag_str.c, and diag_scan_private.h is
 * what they share.
 *
 * WHAT THIS IS NOT. It is not a decompiler and it does not try to be. It
 * answers two questions about a piece of code and refuses the rest:
 *
 *   - this `syscall` instruction, or this call: which nucleo group is it?
 *   - this node's buffer, or its jump target: which earlier node did that
 *     value come from?
 *
 * Everything a decompiler exists for - the shape of the control flow, the
 * types, the names, a listing a person reads - is absent on purpose. The
 * two questions above are what a diagnose is written against, and nothing
 * else here has a caller.
 *
 * WHY A VALUE MODEL AT ALL, when celllysis already keeps a constant map. The
 * constant map answers "what number is in this register"; this needs
 * "which NODE did this value come from", which is a different question and
 * survives where the first does not: a pointer stays a pointer through a
 * push and a pop whether or not anyone knows its address.
 */

#include "diag_scan_private.h"
#include "diag_lineage.h"

/*
 * kgenome_diag_note sets a status on the scan: the one way a limit reports that
 * the answer is partial (kgenome_status.h). The ledger's own status (memory
 * refused) is merged in when the status is read.
 */
void kgenome_diag_note_at(struct kgenome_diag_scan *s, enum kgenome_status st,
			  const char *file, int line)
{
	if (st != KGENOME_OK)
		KOF_TRACE("[cut] %s:%d diagnose scan status %s\n", file, line, kgenome_status_name(st));
	(void)file; (void)line;
	if (s)
		s->status = kgenome_status_merge(s->status, st);
}

/* ---- the surface --------------------------------------------------------- */

/*
 * ---- THE SCENARIO TABLE ---------------------------------------------------
 *
 * One row per analysis routine - see KOF_DIAG_RUN_* in the header for why
 * they are separate at all. A row says which bit turns it on, what it is
 * called, and what it declines to run on; `fn` is then called with an object
 * it has already agreed applies to it.
 *
 * A TABLE AND NOT A CHAIN OF ifs, for the reason rule 5 gives everywhere
 * else: the next routine is a row, and nothing above has to be edited to add
 * it. The two that do not exist yet are listed with a null `fn` rather than
 * left out, so the names are in one place and `ran` can report honestly that
 * a routine was asked for and had nothing to run.
 */
typedef void (*diag_fn)(struct kgenome_diag_scan *, const struct kgenome_obj *,
			const uint8_t *, uint64_t);

struct diag_scenario {
	/* which row of the timing report this routine's cost lands in -
	 * is not an answer anybody can act on. */
	enum kof_time_slot slot;
	unsigned    bit;
	const char *name;
	diag_fn     fn;
	/* Runs after the nodes are folded (merge_sites): it names a node by its index, which is only final then. */
	int         after_merge;
};

static const struct diag_scenario diag_scenarios[] = {
	{ KOF_T_DIAG_SYSCALL, KGENOME_DIAG_RUN_SYSCALL, "syscall",
	  kgenome_diag_run_syscall, 0 },
	{ KOF_T_DIAG_SYMBOL,  KGENOME_DIAG_RUN_SYMBOL,  "symbol",
	  kgenome_diag_run_symbol, 0 },
	{ KOF_T_DIAG_EMULATE, KGENOME_DIAG_RUN_EMULATE, "emulate",
	  kgenome_diag_run_emulate, 0 },
	{ KOF_T_DIAG_APIHASH, KGENOME_DIAG_RUN_APIHASH, "apihash",
	  kgenome_diag_run_apihash, 0 },
	{ KOF_T_DIAG_LINEAGE, KGENOME_DIAG_RUN_LINEAGE, "lineage",
	  kgenome_diag_run_lineage, 1 }
};

/*
 * ---- THE PRUNE THAT USED TO BE HERE, AND WHY IT IS NOT ------------------
 *
 * It dropped every node whose capability no loaded diagnose had named, and
 * the argument was sound while it held: a node nobody asked about cannot
 * end a link, so carrying it for the life of the object buys nothing. It
 * halved the graph - measured, 1200 nodes to 600 over 200 stagers.
 *
 * THE ARGUMENT DIED WHEN A VERDICT STARTED READING THE GRAPH. A verdict is
 * an algorithm, not a tree: it counts, it asks whether something is merely
 * PRESENT, and the things it asks about are exactly the ones no diagnose
 * names. Measured twice, both times as a detection quietly disappearing -
 * the cr0 write a syscall-table verdict needs is nobody's child so no tree
 * can name it, and the socket a stager verdict needs belongs to no
 * diagnose either. The second cost 28 detections across three corpora
 * before it was found.
 *
 * SO THE GRAPH IS KEPT WHOLE. What bounds it is the analysis not running -
 * see the engine's demand gate and the signs on a diagnose - and not what is
 * thrown away afterwards.
 */

/*
 * ONE SITE, ONE NODE - run after the routes, because only then is the whole
 * set of answers in.
 *
 * THE ROUTES OVERLAP AND THAT IS THE DESIGN. The syscall sweep reads every
 * `syscall` instruction in the executable segments; the emulator reaches
 * the ones a run arrives at, with the values it resolved. The same call is
 * therefore found twice, and each copy carries the edges ITS route could
 * prove - measured on meter1, where the swept copy of the read has the
 * buffer edge and the emulated copy has the buffer edge AND the descriptor
 * edge.
 *
 * LEAVING THE COPIES IN LOSES THE JOIN, which is the whole reason this is
 * here. A diagnose binds the first node that satisfies its tree, so the
 * memory tree bound the swept read and the socket tree bound the emulated
 * one - two records of ONE call at 0xf1, so a verdict asking whether the
 * two behaviours meet at the read got no, on a sample where they plainly
 * do.
 *
 * NOT MERGED BY `at` ALONE: a site the run produced rather than read has
 * at == KGENOME_BROKEN, and every one of those would fold into one node.
 */
/*
 * The bits that say a route did NOT know something, as against the ones
 * that say it saw something. See the fold below.
 */
#define DOUBT ((uint8_t)(KGENOME_DIAG_H_ARG_UNKNOWN | KGENOME_DIAG_H_OPAQUE))

static void merge_sites(struct kgenome_diag_scan *s)
{
	uint16_t *map, *rep;
	uint32_t i, j, n = 0;
	uint8_t k;

	if (!s || s->n_hit < 2u)
		return;
	map = malloc((size_t)s->n_hit * sizeof *map);
	rep = malloc((size_t)s->n_hit * sizeof *rep);
	if (!map || !rep) {
		free(map);
		free(rep);
		kgenome_diag_note(s, KGENOME_NOMEM);    /* the copies stay: said */
		return;                 /* duplicates are worse, not fatal */
	}
	/*
	 * 1. which node each one becomes, and which old node speaks for it. The
	 * first node of a (site, capability) is its representative; it is found
	 * through a table of the representatives so far - the scan over all of
	 * them for every node was quadratic, and a static binary with 30000 nodes
	 * spent 3.5 G instructions here. A node at KGENOME_BROKEN is never
	 * folded and never looked for. Where the table cannot be had the scan is
	 * the same one as before.
	 */
	{
		/* KNOWN DEFECT REV-D7g (2026-10-25, Inference) [sev L]: merge_sites (diag_scan.c) keeps a hand-rolled
		 * open-addressing table of site representatives with its own multiplier, unseeded, instead of the shared helper
		 * (diag_oatab.h). Trigger: a binary with many nodes at addresses chosen by the file. Effect: none measured (the
		 * table is sized 2n, so probes stay short on honest input); duplicate logic. Reproducer: none. Fix: use
		 * kgenome_oatab_* (diag_oatab.h). */
		uint32_t tm = 1u, *tab = NULL;

		while (tm < 2u * s->n_hit)
			tm <<= 1;
		tab = calloc(tm, sizeof *tab);
		tm--;
		for (i = 0; i < s->n_hit; i++) {
			const uint64_t at = s->hit[i].at;
			uint32_t hx = 0;

			if (tab && at != KGENOME_BROKEN) {
				hx = (uint32_t)(((at * 0x9e3779b97f4a7c15ull) ^
						 ((uint64_t)s->hit[i].cap * 0xff51afd7ed558ccdull)) >> 32) & tm;
				for (; tab[hx]; hx = (hx + 1u) & tm) {
					j = tab[hx] - 1u;
					if (s->hit[rep[j]].at == at &&
					    s->hit[rep[j]].cap == s->hit[i].cap)
						break;
				}
				j = tab[hx] ? tab[hx] - 1u : n;
			} else if (at == KGENOME_BROKEN) {
				j = n;
			} else {
				for (j = 0; j < n; j++)
					if (s->hit[rep[j]].at == at &&
					    s->hit[rep[j]].cap == s->hit[i].cap)
						break;
			}
			map[i] = (uint16_t)j;
			if (j == n) {
				if (tab && at != KGENOME_BROKEN)
					tab[hx] = n + 1u;
				rep[n++] = (uint16_t)i;
			}
		}
		free(tab);
	}
	if (n == s->n_hit) {            /* nothing to fold - the common case */
		free(map);
		free(rep);
		return;
	}
	/*
	 * 2. RENUMBER BEFORE FOLDING, not after.
	 *
	 * kgenome_diag_note_in refuses an edge whose (parent, role, kind) it
	 * already holds, and that test is only true when both sides are
	 * numbered the same way. Folding first and renumbering afterwards
	 * turned "from 1" and "from 7" into two copies of "from 1" - the
	 * dedup had already run and could not see them.
	 */
	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in; k++) {
			uint16_t f = s->hit[i].in[k].from;

			if (f < s->n_hit)
				s->hit[i].in[k].from = map[f];
		}
	/*
	 * 3. THE UNION OF WHAT THE ROUTES SAW. Flags and bits are
	 * observations, so either route seeing one is enough; the attribute
	 * is a value, so the first one that resolved it stands rather than
	 * being overwritten by a zero.
	 */
	for (i = 0; i < s->n_hit; i++) {
		struct kgenome_diag_hit *h = &s->hit[rep[map[i]]];

		if (rep[map[i]] == i)
			continue;
		h->flags |= s->hit[i].flags;
		/*
		 * NOT EVERY BIT IS AN OBSERVATION. OR-ing them all made a
		 * resolved node unresolved: the sweep cannot read a call's
		 * arguments and says so with ARG_UNKNOWN, the emulator reads
		 * them, and the union of "I could not tell" with "it is a
		 * socket" came out as "I could not tell" - spec_ok then
		 * refused the node as an anchor and the whole socket tree
		 * stopped matching on every i386 stager here.
		 *
		 * A DOUBT SURVIVES ONLY IF EVERY ROUTE HELD IT.
		 */
		h->bits = (uint8_t)(((h->bits | s->hit[i].bits) & ~DOUBT) |
				    (h->bits & s->hit[i].bits & DOUBT));
		/*
		 * AND EVERY FIELD A BIT SPEAKS FOR, or the bit outlives what
		 * it refers to. MEASURED: the symbol route reads an operand's
		 * relocation and the emulator does not, so folding only the
		 * bits left a node saying "an argument named a symbol" with
		 * the offset of that name still zero - and a diagnose about
		 * __this_module matched one rootkit and missed another for a
		 * reason that was not about either of them.
		 *
		 * First one that knows wins, as with the attribute: a route
		 * that resolved something is not corrected by one that did
		 * not.
		 */
		if (!h->attr)
			h->attr = s->hit[i].attr;
		if (!h->val)
			h->val = s->hit[i].val;
		if (!h->symref) {
			h->symref = s->hit[i].symref;
			h->symadd = s->hit[i].symadd;
		}
		/*
		 * A FOLDED LINK KEEPS HOW SURE IT WAS. This went through kgenome_diag_note_in, which says PROVEN
		 * whatever the link was, so a MAY (two arms joined, a callee not read) became PROVEN the moment
		 * its node was folded into another route's. And the stronger statement wins a repeat: a link the
		 * run saw arrive is not kept out by the code-only route's MAY of the same relation.
		 */
		for (k = 0; k < s->hit[i].n_in; k++) {
			const struct kgenome_diag_in *fi = &s->hit[i].in[k];

			if (fi->how == KGENOME_DIAG_LINK_PROVEN)
				(void)kgenome_diag_note_in_seen(s, h, fi->from, fi->role, fi->kind);
			else
				(void)kgenome_diag_note_in_how(s, h, fi->from, fi->role, fi->kind, fi->how);
		}
	}
	/*
	 * 3b. THE NAMES FOLLOW THE NODES. Each kept name carries the index of
	 * the node of the call it was read at, and that index was the one
	 * before folding. Left alone, a name read at a node that was folded
	 * into another would point at whatever now sits in its old slot - a
	 * different call, or none - and nothing would say so: the name would
	 * simply stop belonging to the diagnose that matched its site.
	 *
	 * Rebuilt through kgenome_diag_str_add rather than patched in place, so two
	 * entries that become the same (capability, node, name) after the fold
	 * are one, which is the same rule the store keeps everywhere else.
	 */
	if (s->n_str) {
		struct kgenome_diag_str *old_str = malloc((size_t)s->n_str *
						      sizeof *old_str);
		uint32_t old_n = s->n_str, z;

		if (old_str) {
			memcpy(old_str, s->str, (size_t)old_n * sizeof *old_str);
			s->n_str = 0;
			memset(s->str_tab, 0,
			       ((size_t)s->str_tmask + 1u) * sizeof *s->str_tab);
			for (z = 0; z < old_n; z++) {
				uint16_t nd = old_str[z].node;

				if (nd < s->n_hit)
					nd = map[nd];
				kgenome_diag_str_add(s, old_str[z].cap, nd,
						 old_str[z].s);
			}
			free(old_str);
		} else {
			/* The names keep the OLD node numbers: some now point at the
			 * wrong node. Said, not hidden. */
			kgenome_diag_note(s, KGENOME_NOMEM);
		}
	}
	/* 4. close the gaps */
	for (j = 0; j < n; j++)
		if (rep[j] != j)
			s->hit[j] = s->hit[rep[j]];
	s->n_hit = n;
	free(map);
	free(rep);
}

#undef DOUBT

/*
 * A SCAN OBJECT WITH ITS BUDGET AND LEDGER, for a route to fill: the caller's budget with every field it left at zero
 * filled by the default for THIS object, and the one number only the caller knows (the memory allowance) as given.
 * `code_bytes` is what the object's code is, 0 for one that has none (a script: its size is its text).
 */
static struct kgenome_diag_scan *scan_new(const uint8_t *base, uint64_t size, uint64_t code_bytes,
					  const struct kgenome_budget *b, enum kgenome_status *refused)
{
	struct kgenome_diag_scan *s = calloc(1, sizeof *s);

	if (!s) {
		if (refused)
			*refused = KGENOME_NOMEM;
		KOF_TRACE("[cut] kgenome_diag_scan: scan object not allocated\n");
		return NULL;
	}
	{
		struct kgenome_budget dflt;

		kgenome_budget_default(&dflt, b && b->obj_size ? b->obj_size : size,
				       b && b->code_bytes ? b->code_bytes : code_bytes);
		s->bud = dflt;
		if (b) {
			if (b->max_bytes)
				s->bud.max_bytes = b->max_bytes;
			if (b->max_insn)
				s->bud.max_insn = b->max_insn;
			if (b->max_insn_resolve)
				s->bud.max_insn_resolve = b->max_insn_resolve;
			s->bud.insn_spent = b->insn_spent;
			if (b->max_steps)
				s->bud.max_steps = b->max_steps;
			if (b->max_nodes)
				s->bud.max_nodes = b->max_nodes;
			if (b->max_names)
				s->bud.max_names = b->max_names;
			s->bud.deadline_ms = b->deadline_ms;
		}
		/* The indexes are 16 bits: a width, not a choice (KGENOME_MAX_INDEX). */
		if (s->bud.max_nodes > KGENOME_MAX_INDEX)
			s->bud.max_nodes = KGENOME_MAX_INDEX;
		if (s->bud.max_names > KGENOME_MAX_INDEX)
			s->bud.max_names = KGENOME_MAX_INDEX;
		kgenome_ledger_init(&s->led, s->bud.max_bytes);
	}
	s->base = base;
	s->size = size;
	return s;
}

struct kgenome_diag_scan *kgenome_diag_scan_with_inputs(const struct kgenome_obj *obj,
						const uint8_t *base,
						uint64_t size, unsigned run,
						const struct kgenome_diag_inputs *in)
{
	struct kgenome_diag_scan *s;
	unsigned i, pass;

	if (!obj || !base || !size)
		return NULL;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64) {
		/*
		 * The value model reads x86 outside the syscall route; the
		 * fixed-width ports have that one only, so it is the one run.
		 */
		if (!kgenome_diag_fixed_arch(obj))
			return NULL;
		run &= KGENOME_DIAG_RUN_SYSCALL;
	}
	s = scan_new(base, size, kgenome_diag_code_bytes(obj, size), in ? in->budget : NULL,
		     in ? in->refused : NULL);
	if (!s)
		return NULL;
	s->relocs = in ? in->relocs : NULL;
	s->funcs = in ? in->funcs : NULL;
	s->walk = in ? in->walk : NULL;
	kgenome_diag_walk_bind(s->walk, &s->led);
	s->apihash = in ? in->apihash : NULL;
	s->imports = in ? in->imports : NULL;
	s->seq = in ? in->seq : NULL;
	s->n_seq = in ? in->n_seq : 0;
	s->lineage_stages = in ? in->lineage_stages : 0;
	for (pass = 0; pass < 2u; pass++) {
		for (i = 0; i < sizeof diag_scenarios / sizeof diag_scenarios[0]; i++) {
			const struct diag_scenario *d = &diag_scenarios[i];

			if (!(run & d->bit) || !d->fn || d->after_merge != (int)pass)
				continue;
			KOF_TIME_BEGIN(d->slot);
			d->fn(s, obj, base, size);
			KOF_TIME_END(d->slot);
			s->ran |= d->bit;
			if (s->halt)
				break;
		}
		if (!pass) {
			merge_sites(s);
			if (s->halt)
				break;
		}
	}
	/* A walk the scan made for itself has no other reader once the stages are done: its trace goes now
	 * (a tool that keeps a scan alive to show it must not keep an object's worth of decode with it). */
	if (s->own_walk)
		kgenome_diag_walk_trim(s->own_walk);
	return s;
}

struct kgenome_diag_scan *kgenome_diag_scan_text(const struct kgenome_diag_text_req *rq)
{
	struct kgenome_diag_scan *s;

	if (!rq || !rq->base || !rq->size)
		return NULL;
	s = scan_new(rq->base, rq->size, 0, rq->budget, rq->refused);
	if (!s)
		return NULL;
	KOF_TIME_BEGIN(KOF_T_DIAG_TEXT);
	kgenome_diag_run_text(s, rq);
	KOF_TIME_END(KOF_T_DIAG_TEXT);
	s->ran |= KGENOME_DIAG_RUN_TEXT;
	return s;
}

struct kgenome_diag_scan *kgenome_diag_scan_with(const struct kgenome_obj *obj,
					 const uint8_t *base, uint64_t size,
					 unsigned run)
{
	return kgenome_diag_scan_with_inputs(obj, base, size, run, NULL);
}

const struct kgenome_diag_apihash_set *kgenome_diag_apihash(struct kgenome_diag_scan *s,
					   const struct kgenome_obj *obj)
{
	if (!s)
		return NULL;
	if (!s->apihash && !s->apihash_done) {
		s->own |= KGENOME_DIAG_OWN_APIHASH;
		s->own_apihash = kgenome_diag_apihash_run(obj, s->base, s->size,
						 kgenome_diag_imports(s, obj), &s->bud);
		s->apihash = s->own_apihash;
		/* NULL is an answer too - not asked for again */
		s->apihash_done = 1;
	}
	return s->apihash;
}

/*
 * THE FUNCTIONS, ONE SET. The scanner's, when it handed one over; otherwise built
 * on first use from the object this scan was given and kept - the same two
 * shapes the relocation table has, and for the same reason: a route must not
 * care who produced what it reads, and nobody lists them twice.
 */
/*
 * THE FUNCTIONS OF AN OBJECT: its symbols' extents, and - only when it has none -
 * the ones its code enters, found by the wrapper analysis's own walk. One call
 * for the scanner, the diagnose routes and the viewer, so the answer cannot
 * differ between them.
 */
void kgenome_diag_funcs_with_walk(const struct kgenome_obj *obj, const uint8_t *data,
			      uint64_t data_n, struct kgenome_diag_walk *walk,
			      int want_trace, struct kgenome_func_set *out)
{
	struct kgenome_diag_walk *own = NULL;
	const uint64_t *ent;
	uint32_t n;

	if (!out)
		return;
	if (!obj) {
		memset(out, 0, sizeof *out);
		out->status = KGENOME_BAD_INPUT;
		return;
	}
	kgenome_funcs_build(obj->format, data, data_n, obj->file_header, out);
	if (out->n || out->status != KGENOME_OK || obj->format != KGENOME_FMT_ELF || !obj->file_header)
		return;
	if (!walk)
		walk = own = kgenome_diag_walk_new();
	/* KNOWN DEFECT WP9-F9 (2026-10-25, M) [sev M]: kgenome_diag_funcs_with_walk ignores a failed
	 * kgenome_diag_walk_ensure (no else branch). Trigger: allocation refused in the walk while the function
	 * table of a stripped ELF is built. Effect: the table comes back short with out->status OK (struct
	 * kgenome_func_set.status exists for NOMEM). Reproducer: tests/lib/genome/diag_bin_oom.c KNOWN-MISS F9
	 * (funcs). Fix: add `else out->status = KGENOME_NOMEM;`. */
	if (kgenome_diag_walk_ensure(walk, obj, data, data_n, want_trace)) {
		ent = kgenome_diag_walk_entries(walk, &n);
		if (n)
			kgenome_elf_funcs_from_entries(kof_buf_make(data, data_n),
						   obj->file_header, obj->entry_off,
						   ent, n, out);
	}
	kgenome_diag_walk_free(own);
}

void kgenome_diag_funcs_of(const struct kgenome_obj *obj, const uint8_t *data,
		       uint64_t data_n, struct kgenome_func_set *out)
{
	kgenome_diag_funcs_with_walk(obj, data, data_n, NULL, 0, out);
}

/*
 * THE FUNCTIONS OF A NORMALISED VIEW - the parent's, found again in the view's
 * bytes. One call for every tool that lists or scores the view's units, so the
 * sequence (the parent's own functions, then kgenome_funcs_remap over the view) is
 * written once. `parent_funcs` is the parent's set when the caller already
 * holds it; NULL builds it here.
 */
void kgenome_diag_funcs_of_view(const struct kgenome_obj *parent_obj, kof_buf parent,
			    const struct kgenome_func_set *parent_funcs, kof_buf view,
			    struct kgenome_func_set *out)
{
	struct kgenome_func_set own;

	memset(out, 0, sizeof *out);
	if (!parent_obj || !parent.p || !view.p)
		return;
	memset(&own, 0, sizeof own);
	if (!parent_funcs) {
		kgenome_diag_funcs_of(parent_obj, parent.p, parent.n, &own);
		parent_funcs = &own;
	}
	kgenome_funcs_remap(parent.p, parent.n, parent_funcs, view.p, view.n, out);
	kgenome_funcs_free(&own);
}

const struct kgenome_func_set *kgenome_diag_funcs(struct kgenome_diag_scan *s,
					  const struct kgenome_obj *obj)
{
	if (!s->funcs) {
		if (obj && obj->file_header) {
			s->own |= KGENOME_DIAG_OWN_FUNCS;
			kgenome_diag_funcs_with_walk(obj, s->base, s->size,
						 kgenome_diag_scan_walk(s), 0,
						 &s->own_funcs);
			/* The set is built by the part that knows the object, so it is
			 * charged when it is done: past the allowance the scan says
			 * KGENOME_OVER_BUDGET (the set is kept - it is the answer the
			 * routes read - and the caller's budget is what to raise). */
			(void)kgenome_ledger_charge(&s->led, (uint64_t)s->own_funcs.n *
						    sizeof *s->own_funcs.v);
			if (s->own_funcs.status != KGENOME_OK)
				kgenome_diag_note(s, s->own_funcs.status);
		}
		s->funcs = &s->own_funcs;
	}
	return s->funcs;
}

const struct kgenome_elf_relocs *kgenome_diag_relocs(struct kgenome_diag_scan *s,
					     const struct kgenome_obj *obj,
					     unsigned kind)
{
	const struct kgenome_elf_info *ei = obj && obj->format == KGENOME_FMT_ELF
					? kgenome_obj_elf(obj) : NULL;
	kof_buf f;

	f.p = s->base;
	f.n = s->size;
	if (kind == KGENOME_ELF_RELOC_DATA) {
		if (!s->data_ready) {
			if (ei && ei->valid) {
				(void)kgenome_elf_reloc_table(f, ei, KGENOME_ELF_RELOC_DATA,
							  &s->data_relocs);
				kgenome_diag_note(s, s->data_relocs.status);
			}
			s->data_ready = 1;
		}
		return &s->data_relocs;
	}
	if (!s->relocs) {
		if (ei && ei->valid) {
			s->own |= KGENOME_DIAG_OWN_RELOCS;
			(void)kgenome_elf_reloc_table(f, ei, KGENOME_ELF_RELOC_CODE,
						  &s->own_relocs);
			kgenome_diag_note(s, s->own_relocs.status);
		}
		/* an empty table is still the answer, and is not asked for again */
		s->relocs = &s->own_relocs;
	}
	return s->relocs;
}

struct rcall_gather {
	struct kgenome_diag_rcall *v;
	uint32_t n, cap;
	int oom;
};

static void rcall_put(void *user, uint64_t at, uint64_t target, const char *name)
{
	struct rcall_gather *g = user;
	struct kgenome_diag_rcall *r;

	if (g->n == g->cap) {
		/* KNOWN DEFECT REV-D8p (2026-10-25, Inference) [sev L]: rcall_put (diag_scan.c) doubles a uint32 capacity (relocation calls)
		 * with no overflow guard and no ledger charge. Trigger: 2^31 or more relocation calls in a relocatable object; the engine caps an object at 512 MiB,
		 * so only a host using the lib directly. Effect: the doubled capacity wraps to a smaller one and the table
		 * is overrun. Reproducer: none (read). Fix: use kof_tab_grow (kofcore/tabgrow.h) or test cap against
		 * UINT32_MAX / 2 before doubling. */
		uint32_t nc = g->cap ? g->cap * 2u : 64u;
		struct kgenome_diag_rcall *nv = realloc(g->v, (size_t)nc * sizeof *nv);

		if (!nv) {
			g->oom = 1;
			return;
		}
		g->v = nv;
		g->cap = nc;
	}
	r = &g->v[g->n++];
	r->at = at;
	r->target = target;
	/* An internal call names a capability only by accident. */
	r->cap = (target || !name) ? (uint16_t)KGENOME_NUCLEO_NONE
				   : kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, name);
	r->name = r->cap != KGENOME_NUCLEO_NONE ? kgenome_nucleo_name_id(KGENOME_NUCLEO_T_ELF, name) : 0u;
}

const struct kgenome_diag_rcall *kgenome_diag_relcalls(struct kgenome_diag_scan *s,
						   const struct kgenome_obj *obj,
						   uint32_t *n)
{
	if (!s->rcall_done) {
		const struct kgenome_elf_info *ei = obj && obj->format == KGENOME_FMT_ELF
						? kgenome_obj_elf(obj) : NULL;
		struct rcall_gather g;
		enum kgenome_status rst = KGENOME_OK;
		kof_buf f;

		f.p = s->base;
		f.n = s->size;
		memset(&g, 0, sizeof g);
		s->rcall_done = 1;
		if (ei && ei->valid) {
			kgenome_elf_relcalls(f, ei, kgenome_diag_relocs(s, obj, KGENOME_ELF_RELOC_CODE),
					     rcall_put, &g, &rst);
			/* a name cut at the symbol bound is a name not whole */
			kgenome_diag_note(s, rst);
		}
		if (g.oom) {
			s->halt = 1;
			kgenome_diag_note(s, KGENOME_NOMEM);
		}
		s->rcall = g.v;
		s->n_rcall = g.n;
		(void)kgenome_ledger_charge(&s->led, (uint64_t)g.n * sizeof *g.v);
	}
	*n = s->n_rcall;
	return s->rcall;
}

struct kgenome_diag_scan *kgenome_diag_scan(const struct kgenome_obj *obj,
				    const uint8_t *base, uint64_t size)
{
	return kgenome_diag_scan_with(obj, base, size, KGENOME_DIAG_RUN_DEFAULT);
}

unsigned kgenome_diag_scan_own(const struct kgenome_diag_scan *s)
{
	return s ? s->own : 0;
}

unsigned kgenome_diag_scan_ran(const struct kgenome_diag_scan *s)
{
	return s ? s->ran : 0u;
}

uint32_t kgenome_diag_scan_count(const struct kgenome_diag_scan *s)
{
	return s ? s->n_hit : 0u;
}

const struct kgenome_diag_hit *kgenome_diag_scan_at(const struct kgenome_diag_scan *s,
					    uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : NULL;
}

enum kgenome_status kgenome_diag_scan_status(const struct kgenome_diag_scan *s)
{
	if (!s)
		return KGENOME_BAD_INPUT;
	return kgenome_status_merge(s->status, s->led.status);
}

uint32_t kgenome_diag_scan_refused(const struct kgenome_diag_scan *s)
{
	return s ? s->n_str_refused : 0u;
}

uint32_t kgenome_diag_scan_eval_cut(const struct kgenome_diag_scan *s)
{
	return s ? s->eval_cut : 0u;
}

uint64_t kgenome_diag_scan_bytes(const struct kgenome_diag_scan *s, uint64_t *peak)
{
	if (peak)
		*peak = s ? s->led.peak : 0;
	return s ? s->led.used : 0;
}

/* THIN WRAPPER over kgenome_diag_scan_status - see diag_scan.h. */
int kgenome_diag_scan_full(const struct kgenome_diag_scan *s)
{
	return s && kgenome_diag_scan_status(s) != KGENOME_OK;
}

/*
 * HOW MANY DISTINCT NAMES ARE KEPT - kgenome_budget.max_names: max(1024, the
 * node limit), at most 65534 (the table's 16-bit index). The fixed 1024 was a
 * bound on a result: it sat above anything a module declares (0 to ~25) but
 * below what a big object's call sites read, and the 1025th name was dropped.
 * It scales with the nodes now, because a name is read at a call site and an
 * object cannot have more of them than it has nodes. Reaching it is a bound on
 * cost, not a statement about the object, and it is not silent: the name is
 * counted (kgenome_diag_scan_refused), the status is KGENOME_TRUNCATED, and a
 * caller reading a list must check it before it says "none".
 */

void kgenome_diag_scan_free(struct kgenome_diag_scan *s)
{
	if (!s)
		return;
	free(s->str_tab);
	free(s->str);
	free(s->adj_head);
	free(s->adj_edge);
	free(s->wrap);
	free(s->wrap_sorted);
	/* The walk may outlive this scan (it is the object's): let go of the ledger
	 * it was charging before the ledger is gone. */
	kgenome_diag_walk_bind(s->walk, NULL);
	kgenome_diag_apihash_free(s->own_apihash);
	kgenome_pe_imptab_free(&s->own_imports);
	kgenome_elf_reloc_table_free(&s->own_relocs);
	kgenome_funcs_free(&s->own_funcs);
	kgenome_diag_walk_free(s->own_walk);
	kgenome_elf_reloc_table_free(&s->data_relocs);
	free(s->rcall);
	free(s->oblig);
	free(s->noret_at);
	free(s->hit);
	free(s);
}
