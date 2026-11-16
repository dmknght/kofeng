/*
 * diag_hit.c - the hits of a scan: adding one, the roles of a call's arguments, and what is noted on a hit.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"
#include "diag_oatab.h"

/*
 * A SLOT FOR ONE MORE NODE. When the table is full - the node index space (kgenome_diag_node_limit) or what the ledger grants - the node is
 * REFUSED and counted (drops.refused), and the scan goes on: the walk keeps its other nodes and the lineage still runs, where a halt here
 * used to end every route and the lineage with them (the whole graph lost for one node too many). What the table keeps is then decided by
 * the keep rule (kgenome_diag_nodes_keep), after the lineage, when the links are known.
 *
 * TODO(owner): decision 1b of fix_lgtab/owner_decisions.txt - a node refused HERE, while the routes run, is refused first-come: its links do
 * not exist yet (the lineage links after every route), so it cannot be weighed by the keep rule. Default implemented: refuse it, count it,
 * go on, and apply the rule after the lineage. Alternative: a second walk - run the lineage on what fits, compact by the rule, then run the
 * rest of the routes into the room made - which changes the scan's order (diag_scenarios) and its cost.
 */
static int hit_room(struct kgenome_diag_scan *s)
{
	struct kgenome_diag_hit *nv;
	uint32_t nc;

	if (s->n_hit < s->cap_hit)
		return 1;
	if (s->n_hit >= kgenome_diag_node_limit(s))
		goto full;
	nc = s->cap_hit ? s->cap_hit * 2u : 64u;
	if (nc > kgenome_diag_node_limit(s))
		nc = kgenome_diag_node_limit(s);
	if (!kgenome_ledger_charge(&s->led, (uint64_t)(nc - s->cap_hit) * sizeof *nv))
		goto full;              /* (the ledger noted KGENOME_OVER_BUDGET) */
	nv = realloc(s->hit, nc * sizeof *nv);
	if (!nv) {
		kgenome_ledger_release(&s->led, (uint64_t)(nc - s->cap_hit) * sizeof *nv);
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto full;
	}
	s->hit = nv;
	s->cap_hit = nc;
	return 1;
full:
	s->nodes_full = 1;
	s->drops.refused++;
	kgenome_diag_note(s, KGENOME_TRUNCATED);        /* a node was not kept: said, and counted by class */
	return 0;
}

struct kgenome_diag_hit *kgenome_diag_hit_add(struct kgenome_diag_scan *s, uint64_t at,
				    uint16_t cap, uint16_t flags)
{
	struct kgenome_diag_hit *h;

	if (!hit_room(s))
		return NULL;
	h = &s->hit[s->n_hit++];
	memset(h, 0, sizeof *h);
	h->at = at;
	h->cap = cap;
	h->flags = flags;
	h->nr_from = KGENOME_DIAG_ORG_NONE;     /* (a number's producer: none until the lineage stage names one) */
	return h;
}

void kgenome_diag_hit_nonblock(struct kgenome_diag_scan *s, uint64_t at, uint16_t open_idx)
{
	struct kgenome_diag_hit *n = kgenome_diag_hit_add(s, at, KGENOME_NUCLEO_FD_NONBLOCK, 0);

	if (n)
		kgenome_diag_note_in(s, n, open_idx, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED);
}

/* ---- where a value came from ---------------------------------------------
 *
 * A SHADOW BESIDE celllysis's CONSTANT MAP, not a replacement for it. The two
 * answer different questions and neither covers the other: the constant map
 * says WHAT NUMBER a register holds, this says WHICH NODE it came out of. A
 * pointer stays a pointer through a push and a pop whether or not anyone
 * knows its address, and a number can be known while coming from nowhere.
 */

/* ---- the walk ------------------------------------------------------------ */

/*
 * THE ARGUMENT REGISTERS, per ABI, in order.
 *
 * Taken from nucleo's kgenome_nucleo_abi rather than written again here - a second copy
 * of "rdi, rsi, rdx, r10, r8, r9" is a second thing to get wrong when a
 * port is added, and the sweep that had its own copy is the reason this
 * rule exists.
 */
int kgenome_diag_arg_regs(const struct kgenome_obj *obj, const uint8_t **out)
{
	static const uint8_t x64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t x86[] = { KGENOME_CELL_REG_BX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI, KGENOME_CELL_REG_BP };

	if (obj->arch == KGENOME_ARCH_X86_64) {
		*out = x64;
		return (int)(sizeof x64 / sizeof x64[0]);
	}
	if (obj->arch == KGENOME_ARCH_X86) {
		*out = x86;
		return (int)(sizeof x86 / sizeof x86[0]);
	}
	*out = NULL;
	return 0;
}

/*
 * ONE SYSCALL SITE.
 *
 * The number comes out of the constant map, which is why this file needs
 * celllysis at all. When it is not there the node is still emitted, as
 * KGENOME_NUCLEO_NONE with KGENOME_DIAG_H_OPAQUE set - see the note on that flag. A
 * site dropped because its number could not be read is a site that makes
 * two different programs look alike.
 */

/*
 * ---- WHICH INPUT OF A CALL EACH ARGUMENT IS, by its capability ----------
 *
 * THE CAPABILITY'S SHAPE (celllysis/nucleo_capshape.c), for a call that has no row of its own - a system call, a route that knows
 * only the capability. This was the switch that held the answer; the answer is a column of the vocabulary's shapes now, with the
 * per-API rows beside it (kgenome_nucleo_call_role: CreateProcessA's command line is argument 1, ShellExecuteA's file argument 2,
 * which no per-capability answer can say). A reader that holds a NODE asks kgenome_nucleo_call_role(h->cap, h->row, i) - the row is
 * carried by the node (kgenome_diag_hit.row) - and one that holds only a capability asks kgenome_nucleo_cap_role. This function stays
 * because the module ABI names it (kofsig.h, kof_diag_role_of_arg); the two system call routes diag_site.c and diag_wrapper_calls.c
 * still call it (a capability alone, the same answer: files of other work packages on 2026-11-15, to move to kgenome_nucleo_cap_role).
 *
 * AND THE ROLES OF ONE CALL MUST BE DISTINCT, which is not a style rule but the invariant kgenome_diag_note_in rests on (it refuses
 * a link whose (parent, role, kind) it already holds; two arguments wearing one role make two relations one - measured on a hooked
 * getdents, where copy_to_user's two buffers were both `buffer` and one vanished). The generator refuses a shape that repeats a role
 * (tools/gen_nucleo_index.py) and tests/lib/genome/diag_roles.c walks every capability and every row.
 */
uint8_t kgenome_diag_role_of_arg(uint16_t cap, unsigned i)
{
	return kgenome_nucleo_cap_role(cap, i);
}

struct kgenome_diag_hit *kgenome_diag_hit_of(struct kgenome_diag_scan *s, uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : 0;
}

void kgenome_diag_note_in(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
		      uint16_t from, uint8_t role, uint8_t kind)
{
	kgenome_diag_note_in_how(s, h, from, role, kind, KGENOME_DIAG_LINK_PROVEN);
}

/* ---- EVERY INPUT OF A NODE: the view in[] and the scan's table of the rest (see diag_scan.h, struct kgenome_diag_xin) ---- */

static uint32_t xin_key(const struct kgenome_diag_xin *x)
{
	uint64_t h = ((uint64_t)x->hit << 32) | ((uint64_t)x->in.from << 16) | ((uint64_t)x->in.role << 8) | x->in.kind;

	return kgenome_oatab_fold(h * KGENOME_OATAB_K);
}

static uint32_t xin_slot_hash(void *ctx, const void *slot)
{
	const struct kgenome_diag_scan *s = ctx;

	return xin_key(&s->xin[*(const uint32_t *)slot - 1u]);
}

/* The table's entry of (node, from, role, kind), or NULL. */
static struct kgenome_diag_in *xin_find(const struct kgenome_diag_scan *s, uint32_t hit, uint16_t from, uint8_t role, uint8_t kind)
{
	struct kgenome_diag_xin k;
	uint32_t i;

	if (!s->xin_tcap)
		return NULL;
	memset(&k, 0, sizeof k);
	k.hit = hit;
	k.in.from = from;
	k.in.role = role;
	k.in.kind = kind;
	for (i = xin_key(&k) & (s->xin_tcap - 1u); s->xin_tab[i]; i = kgenome_oatab_next(i, s->xin_tcap)) {
		struct kgenome_diag_xin *x = &s->xin[s->xin_tab[i] - 1u];

		if (x->hit == hit && x->in.from == from && x->in.role == role && x->in.kind == kind)
			return &x->in;
	}
	return NULL;
}

/* Rebuild the hash of every entry (after their nodes were renumbered). 0 when memory was refused (the repeat test then misses: said). */
int kgenome_diag_links_rehash(struct kgenome_diag_scan *s)
{
	uint32_t i, k;

	if (s->xin_tab)
		memset(s->xin_tab, 0, (size_t)s->xin_tcap * sizeof *s->xin_tab);
	s->xin_tn = 0;
	for (i = 0; i < s->n_xin; i++) {
		if (!s->xin_tcap)
			return 0;
		for (k = xin_key(&s->xin[i]) & (s->xin_tcap - 1u); s->xin_tab[k]; k = kgenome_oatab_next(k, s->xin_tcap))
			;
		s->xin_tab[k] = i + 1u;
		s->xin_tn++;
	}
	return 1;
}

/* One more input of node `hit` in the table, charged to the ledger: 0 when the ledger or memory refused it. */
static int xin_add(struct kgenome_diag_scan *s, uint32_t hit, const struct kgenome_diag_in *in)
{
	uint32_t k, nc;

	if (s->n_xin == s->cap_xin) {
		struct kgenome_diag_xin *nv;

		nc = kgenome_grow_cap(s->cap_xin, 64u);
		if (!nc || !kgenome_ledger_charge(&s->led, (uint64_t)(nc - s->cap_xin) * sizeof *nv))
			return 0;
		nv = realloc(s->xin, (size_t)nc * sizeof *nv);
		if (!nv) {
			kgenome_ledger_release(&s->led, (uint64_t)(nc - s->cap_xin) * sizeof *nv);
			kgenome_diag_note(s, KGENOME_NOMEM);
			return 0;
		}
		s->xin = nv;
		s->cap_xin = nc;
	}
	nc = kgenome_oatab_want(s->xin_tn, s->xin_tcap, 64u);
	if (nc) {
		const uint32_t oc = s->xin_tcap;

		if (!kgenome_ledger_charge(&s->led, (uint64_t)nc * sizeof *s->xin_tab))
			return 0;
		if (!kgenome_oatab_rehash((void **)&s->xin_tab, &s->xin_tcap, nc, sizeof *s->xin_tab, xin_slot_hash, s, NULL)) {
			kgenome_ledger_release(&s->led, (uint64_t)nc * sizeof *s->xin_tab);
			kgenome_diag_note(s, KGENOME_NOMEM);
			return 0;
		}
		if (oc)
			kgenome_ledger_release(&s->led, (uint64_t)oc * sizeof *s->xin_tab);
	}
	s->xin[s->n_xin].hit = hit;
	s->xin[s->n_xin].in = *in;
	for (k = xin_key(&s->xin[s->n_xin]) & (s->xin_tcap - 1u); s->xin_tab[k]; k = kgenome_oatab_next(k, s->xin_tcap))
		;
	s->xin_tab[k] = s->n_xin + 1u;
	s->xin_tn++;
	s->n_xin++;
	return 1;
}

/* Put the table in order by node, once the routes have stopped adding to it (and again after the nodes were renumbered). Without the
 * memory for it the readers search the table as it is: slower, the same answers. */
void kgenome_diag_links_settle(struct kgenome_diag_scan *s)
{
	uint32_t i;

	if (s->xin_ord)
		kgenome_ledger_release(&s->led, (uint64_t)s->n_xin_ord * sizeof *s->xin_ord);
	s->n_xin_ord = 0;
	free(s->xin_ord);
	s->xin_ord = NULL;
	if (!s->n_xin || !kgenome_ledger_charge(&s->led, (uint64_t)s->n_xin * sizeof *s->xin_ord))
		return;
	s->xin_ord = malloc((size_t)s->n_xin * sizeof *s->xin_ord);
	if (!s->xin_ord) {
		kgenome_ledger_release(&s->led, (uint64_t)s->n_xin * sizeof *s->xin_ord);
		return;
	}
	for (i = 0; i < s->n_xin; i++)
		s->xin_ord[i] = i;
	/* by node, then by index: an insertion sort over runs that arrive mostly in order (no qsort_r in C11) */
	for (i = 1; i < s->n_xin; i++) {
		const uint32_t v = s->xin_ord[i];
		uint32_t j = i;

		while (j > 0 && s->xin[s->xin_ord[j - 1u]].hit > s->xin[v].hit) {
			s->xin_ord[j] = s->xin_ord[j - 1u];
			j--;
		}
		s->xin_ord[j] = v;
	}
	s->n_xin_ord = s->n_xin;
}

/* The first position in the order of node `hit`'s entries, and how many. */
static uint32_t xin_run(const struct kgenome_diag_scan *s, uint32_t hit, uint32_t *n)
{
	uint32_t lo = 0, hi = s->n_xin_ord, e;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (s->xin[s->xin_ord[mid]].hit < hit)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (e = lo; e < s->n_xin_ord && s->xin[s->xin_ord[e]].hit == hit; e++)
		;
	*n = e - lo;
	return lo;
}

uint32_t kgenome_diag_in_count(const struct kgenome_diag_scan *s, uint32_t node)
{
	uint32_t n = 0, i;

	if (!s || node >= s->n_hit)
		return 0;
	if (s->n_xin_ord == s->n_xin)
		(void)xin_run(s, node, &n);
	else
		for (i = 0; i < s->n_xin; i++)
			n += s->xin[i].hit == node;
	return s->hit[node].n_in + n;
}

const struct kgenome_diag_in *kgenome_diag_in_at(const struct kgenome_diag_scan *s, uint32_t node, uint32_t k)
{
	uint32_t n, lo, i;

	if (!s || node >= s->n_hit)
		return NULL;
	if (k < s->hit[node].n_in)
		return &s->hit[node].in[k];
	k -= s->hit[node].n_in;
	if (s->n_xin_ord == s->n_xin) {
		lo = xin_run(s, node, &n);
		return k < n ? &s->xin[s->xin_ord[lo + k]].in : NULL;
	}
	for (i = 0; i < s->n_xin; i++)
		if (s->xin[i].hit == node && !k--)
			return &s->xin[i].in;
	return NULL;
}

/* The input (from, role, kind) of the node, wherever it is kept, or NULL. */
static struct kgenome_diag_in *in_find(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h, uint16_t from, uint8_t role, uint8_t kind)
{
	uint8_t i;

	for (i = 0; i < h->n_in; i++)
		if (h->in[i].from == from && h->in[i].role == role && h->in[i].kind == kind)
			return &h->in[i];
	return xin_find(s, (uint32_t)(h - s->hit), from, role, kind);
}

/*
 * A LINK THE RUN SAW ARRIVE. The run (the emulate route) and the code-only routes can find the same relation,
 * and kgenome_diag_note_in_how keeps the FIRST statement of it: a sweep that said MAY (two arms joined, or a
 * callee that was not read) would keep the run's proof out. A link the run demonstrated is PROVEN, and
 * replaces a MAY that is already there. The fold of two nodes at one site asks for it (merge_sites, where
 * the run's node meets the sweep's), and so does the lineage stage for a link it proved on every path
 * (diag_lineage.c); a route recording its own links keeps the first statement, as the script route's oracle
 * (tests/lib/genome/diag_text_sum_gen.c) holds.
 */
int kgenome_diag_note_in_seen(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			      uint16_t from, uint8_t role, uint8_t kind)
{
	struct kgenome_diag_in *e;

	if (h && from != KGENOME_DIAG_ORG_NONE && (e = in_find(s, h, from, role, kind)) != NULL) {
		e->how = KGENOME_DIAG_LINK_PROVEN;
		return 0;
	}
	return kgenome_diag_note_in_how(s, h, from, role, kind, KGENOME_DIAG_LINK_PROVEN);
}

/*
 * ONE INPUT OF A NODE. THE SAME LINK TWICE IS ONE LINK: (parent, role, KIND) - two relations between one pair of nodes are two links (see
 * enum kgenome_diag_kind), and only a repeat of all three is the loop arriving again (MEASURED before the test was here: meter1's retry loop
 * produced ten copies of one link).
 *
 * WHERE IT IS KEPT. The first four inputs of the roles a pack can name are the node's view (in[]): the graph block a module reads holds two a
 * record and its builder reports the rest as a cut (kof_diag_graph_build), the matcher reads them there. Every other input - a fifth, and a
 * system call's NUMBER, which no pack names - is the scan's table, as many as the program gives the node: the fixed four dropped a fifth
 * and said KGENOME_TRUNCATED, which was a cap deleting evidence (CLAUDE.md rule 4: 98 links in 21 of 356 files). The ledger bounds the
 * table; a refusal loses the input and says so. 1 when the input was lost.
 */
int kgenome_diag_note_in_how(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			  uint16_t from, uint8_t role, uint8_t kind, uint8_t how)
{
	struct kgenome_diag_in in;

	if (!h || from == KGENOME_DIAG_ORG_NONE)
		return 0;
	if (in_find(s, h, from, role, kind))
		return 0;
	memset(&in, 0, sizeof in);      /* (its padding byte too: an input is compared whole by readers that copy it) */
	in.from = from;
	in.role = role;
	in.how = how;
	in.kind = kind;
	if (h->n_in < 4u && role != KGENOME_DIAG_ROLE_NUMBER) {
		h->in[h->n_in++] = in;
		return 0;
	}
	if (!xin_add(s, (uint32_t)(h - s->hit), &in)) {
		kgenome_diag_note(s, KGENOME_TRUNCATED);        /* the ledger refused (it noted OVER_BUDGET) or memory did: the input is lost */
		return 1;
	}
	if (s->xin_ord) {               /* the order is made again when the routes are done (kgenome_diag_links_settle) */
		kgenome_ledger_release(&s->led, (uint64_t)s->n_xin_ord * sizeof *s->xin_ord);
		free(s->xin_ord);
		s->xin_ord = NULL;
	}
	s->n_xin_ord = 0;
	return 0;
}

/* ---- THE KEEP RULE: what the table keeps when it was full ---- */

void kgenome_diag_scan_drops(const struct kgenome_diag_scan *s, struct kgenome_diag_drops *out)
{
	if (!out)
		return;
	if (!s) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = s->drops;
}

/* Does a loaded diagnose name this capability (exactly, or as its group). */
static int cap_named(const struct kgenome_diag_scan *s, uint16_t cap)
{
	const uint16_t g = kgenome_nucleo_cap_generic(cap);
	uint32_t i;

	for (i = 0; i < s->n_keep_caps; i++)
		if (s->keep_caps[i] == cap || s->keep_caps[i] == g)
			return 1;
	return 0;
}

/*
 * THE KEEP RULE (owner, 2026-11-15: "keep only nodes that have a link and connect to nucleo"): when the table refused a node (nodes_full),
 * the table keeps a node that is on a link (it has an input or is the producer of one) AND carries a capability; and, whatever links it, a
 * node whose capability a loaded diagnose names (keep_caps: a HEAD-only diagnose - docs/disabled/diagnoses/kernel_selfhide_00 - needs its
 * one node unlinked). Every other node is dropped and counted by class (drops.unlinked, drops.nocap): never silent. The anomaly facts are
 * links (a system call's NUMBER input, the TARGET of an exec of produced memory), so the rule keeps them (measured on msfvenom's
 * cleartext: 5 of 6 nodes kept, nanosleep - linked to nothing - dropped).
 *
 * MEASURED, the rule over the 348 executables of the 356-file set (fix_lgtab/scratch/nf.txt): 89033 nodes, 7291 kept, 70261 with a capability
 * and no link, 284 with neither - which is why it runs ONLY when the table was full, after the lineage, and not on every scan: the table
 * never filled there (26.8% of the index space at most), and the viewer and the code notes show the unlinked nodes.
 *
 * The nodes are renumbered (their links, the inputs past their views, the names read at them, the number producers and the lineage's
 * unresolved set follow); a dropped node is on no kept node's input (the producers of kept nodes are kept, AUD-6), so no link loses an end.
 *
 * TODO(owner): decision 2 of fix_lgtab/owner_decisions.txt - a node index is 16 bits (KGENOME_MAX_INDEX) in the module ABI's graph block
 * (kofmod/kofdiagtree.h kof_gr_in.from). Default implemented: no ABI change, the table is bounded by the index space and managed by this
 * rule. Alternative A: past 0xfffd nodes, per-function graphs whose local indices stay below 0xfffe and a cross-graph link table read
 * through a new accessor kof_gr_xlink (KOFMOD_ABI minor +1, old modules unaffected). Alternative B: kof_gr_in.from of 32 bits (the record
 * grows, KOFMOD_ABI major +1, every module rebuilt).
 */
void kgenome_diag_nodes_keep(struct kgenome_diag_scan *s)
{
	uint32_t *map, i, k, n = 0;
	uint8_t *on;

	if (!s || !s->nodes_full || !s->n_hit)
		return;
	map = malloc((size_t)s->n_hit * sizeof *map);
	on = calloc(s->n_hit, 1);
	if (!map || !on) {
		free(map);
		free(on);
		kgenome_diag_note(s, KGENOME_NOMEM);    /* the table stays as it is: nothing dropped, nothing lost */
		return;
	}
	/* who is on a link: every node with an input, and every producer an input names */
	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < kgenome_diag_in_count(s, i); k++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, k);

			on[i] = 1;
			if (x->from < s->n_hit)
				on[x->from] = 1;
		}
	/* on[] from here: 2 = kept by the rule, then every producer a kept node's input names (closure, below) */
	for (i = 0; i < s->n_hit; i++) {
		const struct kgenome_diag_hit *h = &s->hit[i];

		on[i] = (uint8_t)(((on[i] && h->cap != KGENOME_NUCLEO_NONE) || (h->cap != KGENOME_NUCLEO_NONE && cap_named(s, h->cap))) ? 2u : 0u);
	}
	/*
	 * A KEPT NODE'S INPUTS KEEP BOTH ENDS (audit AUD-6, 2026-11-16, M): a producer with no capability (a system call whose number was not read, an opaque
	 * call) that feeds a kept node is kept with it, and so on back. Before, it was dropped and the consumer's `from` was renumbered to (uint16_t)UINT32_MAX
	 * = 0xffff, which every reader takes for an origin that is no node: the link silently changed meaning. Map[] is the stack of the closure.
	 * TODO(owner): the alternative is to drop such a link from the consumer (counted) and the producer with it; default: keep the producer, a link is
	 * a fact between two kept nodes and the rule ("on a link that reaches the vocabulary") holds for it.
	 */
	{
		uint32_t top = 0;

		for (i = 0; i < s->n_hit; i++)
			if (on[i] == 2u)
				map[top++] = i;
		while (top) {
			const uint32_t c = map[--top];

			for (k = 0; k < kgenome_diag_in_count(s, c); k++) {
				const struct kgenome_diag_in *x = kgenome_diag_in_at(s, c, k);

				if (x->from < s->n_hit && on[x->from] != 2u) {
					on[x->from] = 2u;
					map[top++] = x->from;
				}
			}
			if (s->hit[c].nr_from < s->n_hit && on[s->hit[c].nr_from] != 2u) {    /* the producer of its number, the same */
				on[s->hit[c].nr_from] = 2u;
				map[top++] = s->hit[c].nr_from;
			}
		}
	}
	for (i = 0; i < s->n_hit; i++) {
		const struct kgenome_diag_hit *h = &s->hit[i];

		if (on[i] == 2u) {
			map[i] = n++;
			continue;
		}
		map[i] = UINT32_MAX;
		if (h->cap == KGENOME_NUCLEO_NONE)
			s->drops.nocap++;
		else
			s->drops.unlinked++;
	}
	if (n == s->n_hit) {
		free(map);
		free(on);
		return;
	}
	/* the links, the inputs past the views, the number producers: renumbered (a kept node's producer is kept: it is on a link) */
	for (i = 0; i < s->n_hit; i++) {
		struct kgenome_diag_hit *h = &s->hit[i];

		for (k = 0; k < h->n_in; k++)
			if (h->in[k].from < s->n_hit)
				h->in[k].from = (uint16_t)map[h->in[k].from];
		if (h->nr_from < s->n_hit)
			h->nr_from = (uint16_t)map[h->nr_from];
	}
	for (i = 0, k = 0; i < s->n_xin; i++) {
		if (map[s->xin[i].hit] == UINT32_MAX)
			continue;
		s->xin[k] = s->xin[i];
		s->xin[k].hit = map[s->xin[i].hit];
		if (s->xin[k].in.from < s->n_hit)
			s->xin[k].in.from = (uint16_t)map[s->xin[k].in.from];
		k++;
	}
	s->n_xin = k;
	/* the lineage's unresolved inputs go with their node */
	for (i = 0, k = 0; i < s->n_oblig; i++)
		if (s->oblig[i].node < s->n_hit && map[s->oblig[i].node] != UINT32_MAX) {
			s->oblig[k] = s->oblig[i];
			s->oblig[k++].node = map[s->oblig[i].node];
		}
	s->n_oblig = k;
	/* the names read at a node follow it, rebuilt through kgenome_diag_str_add as the fold rebuilds them (merge_sites, 3b); a name of a
	 * dropped node goes with it */
	if (s->n_str) {
		struct kgenome_diag_str *old_str = malloc((size_t)s->n_str * sizeof *old_str);
		const uint32_t old_n = s->n_str, old_hits = s->n_hit;

		if (old_str) {
			memcpy(old_str, s->str, (size_t)old_n * sizeof *old_str);
			s->n_str = 0;
			memset(s->str_tab, 0, ((size_t)s->str_tmask + 1u) * sizeof *s->str_tab);
			for (i = 0; i < old_n; i++) {
				uint16_t nd = old_str[i].node;

				if (nd < old_hits) {
					if (map[nd] == UINT32_MAX)
						continue;
					nd = (uint16_t)map[nd];
				}
				kgenome_diag_str_add(s, old_str[i].cap, nd, old_str[i].s);
			}
			free(old_str);
		} else {
			kgenome_diag_note(s, KGENOME_NOMEM);    /* the names keep the old node numbers: said */
		}
	}
	for (i = 0; i < s->n_hit; i++)
		if (map[i] != UINT32_MAX)
			s->hit[map[i]] = s->hit[i];
	s->n_hit = n;
	(void)kgenome_diag_links_rehash(s);
	kgenome_diag_links_settle(s);
	free(map);
	free(on);
}
