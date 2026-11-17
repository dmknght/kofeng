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
#include "frame.h"
#include "../celllysis/gview.h"
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
		uint32_t tm = 1u, *tab = NULL;

		while (tm < 2u * s->n_hit)
			tm <<= 1;
		tab = calloc(tm, sizeof *tab);
		tm--;
		for (i = 0; i < s->n_hit; i++) {
			const uint64_t at = s->hit[i].at;
			uint32_t hx = 0;

			if (tab && at != KGENOME_BROKEN) {
				hx = kof_hash64_slot(at ^ ((uint64_t)s->hit[i].cap << 48)) & tm;
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
	 * (the inputs past a node's view too, and their hash, whose keys hold the producers.) TODAY A NO-OP, AND KEPT: no test can tell it from
	 * its absence (mutant M25, lineage3), because no route makes an input past a view before this fold that names a node the fold moves. The
	 * argument: the nodes are appended route by route in the order of diag_scenarios (sweep, symbol, emulate, apihash), the only duplicates
	 * the fold removes are the emulate route's (its nodes meet the sweep's at the same site), so every folded node comes after every node of
	 * the sweep and the symbol route, and map[f] == f below it; an input past a view exists before the fold only where a route gave one
	 * node five inputs - the sweep (a main producer and KGENOME_DIAG_ORG_ALT = 3 alternates per role, two roles) or the symbol route - and
	 * those name their own route's nodes; the emulate route gives each of its nodes one input a role. A route that folds earlier nodes, or
	 * links past a view into later ones, makes this line the one that keeps the producers right.
	 */
	for (j = 0; j < s->n_xin; j++)
		if (s->xin[j].in.from < s->n_hit)
			s->xin[j].in.from = map[s->xin[j].in.from];
	(void)kgenome_diag_links_rehash(s);
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
		/* and those past its view (copied: noting one may grow the table under the loop) */
		{
			const uint32_t nx = s->n_xin;

			for (j = 0; j < nx; j++) {
				struct kgenome_diag_in fi;

				if (s->xin[j].hit != i)
					continue;
				fi = s->xin[j].in;
				if (fi.how == KGENOME_DIAG_LINK_PROVEN)
					(void)kgenome_diag_note_in_seen(s, h, fi.from, fi.role, fi.kind);
				else
					(void)kgenome_diag_note_in_how(s, h, fi.from, fi.role, fi.kind, fi.how);
			}
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
	/* 4. close the gaps; an input past a view goes with its node, and one of a node folded away was noted on its representative above */
	{
		uint32_t w = 0;

		for (j = 0; j < s->n_xin; j++) {
			const uint32_t o = s->xin[j].hit;

			if (o >= s->n_hit || rep[map[o]] != o)
				continue;
			s->xin[w] = s->xin[j];
			s->xin[w++].hit = map[o];
		}
		s->n_xin = w;
	}
	for (j = 0; j < n; j++)
		if (rep[j] != j)
			s->hit[j] = s->hit[rep[j]];
	s->n_hit = n;
	(void)kgenome_diag_links_rehash(s);
	kgenome_diag_links_settle(s);
	free(map);
	free(rep);
}

#undef DOUBT

/*
 * A DESCRIPTOR CALL'S WORD FROM WHAT ITS DESCRIPTOR IS - run once, after every route and stage has linked (the links are final).
 *
 * A route names the CALL: read(2), write(2), ReadFile, the libc `read`. The word is then the generic one (mem-read, mem-write),
 * because what is read from is the descriptor's object, and that is known only when the descriptor's producer is linked. Once it
 * is, the word is the vocabulary's case of it (kgenome_nucleo_cap_on_handle: a socket's read is net-recv, an opened file's is
 * file-read). Every route's nodes, one rule, decided here and nowhere else; a reader shows the word.
 *
 * ONLY ON PROOF. Every descriptor input of the node must be PROVEN (one producer on every path), PRODUCED, from a node, and every
 * one of them must give the same case: a MAY, an UNKNOWN, a descriptor from the stack or a constant (no input at all), two
 * producers of different kinds, or a producer the vocabulary has no case for (a heap pointer, a memfd, dup2's number) keeps the
 * generic word - never a narrower word than was shown. A rule that names the generic word still matches (kofdiag.c cap_is walks
 * kgenome_nucleo_cap_generic). The node's (site, capability) is folded before this runs (merge_sites), so no fold sees two words.
 */
static void caps_settle(struct kgenome_diag_scan *s)
{
	uint32_t i, q;

	for (i = 0; i < s->n_hit; i++) {
		struct kgenome_diag_hit *h = &s->hit[i];
		const uint32_t nin = kgenome_diag_in_count(s, i);
		uint16_t want = KGENOME_NUCLEO_NONE;
		uint32_t nfd = 0;
		int ok = 1;

		if (h->cap != KGENOME_NUCLEO_MEM_READ && h->cap != KGENOME_NUCLEO_MEM_WRITE)
			continue;
		for (q = 0; q < nin && ok; q++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, q);
			uint16_t c;

			if (!x || x->role != KGENOME_DIAG_ROLE_FD)
				continue;
			nfd++;
			if (x->how != KGENOME_DIAG_LINK_PROVEN || x->kind != KGENOME_DIAG_KIND_PRODUCED || x->from >= s->n_hit) {
				ok = 0;
				break;
			}
			c = kgenome_nucleo_cap_on_handle(h->cap, s->hit[x->from].cap);
			if (c == KGENOME_NUCLEO_NONE || (want != KGENOME_NUCLEO_NONE && c != want))
				ok = 0;
			want = c;
		}
		if (ok && nfd)
			h->cap = want;
	}
}

/* one writer of a region: the region's producer and the node whose BUFFER input it is */
struct exec_writer {
	uint16_t region, node;
};

static int exec_writer_cmp(const void *a, const void *b)
{
	const struct exec_writer *x = a, *y = b;

	if (x->region != y->region)
		return x->region < y->region ? -1 : 1;
	return x->node < y->node ? -1 : x->node > y->node;
}

/* Is input `x` a PROVEN, PRODUCED link of role `role` from a node (not the stack, not a node that does not exist). */
static int exec_proven_from(const struct kgenome_diag_scan *s, const struct kgenome_diag_in *x, uint8_t role)
{
	return x && x->role == role && x->how == KGENOME_DIAG_LINK_PROVEN && x->kind == KGENOME_DIAG_KIND_PRODUCED && x->from < s->n_hit;
}

/*
 * WRITTEN, THEN EXECUTED (KGENOME_DIAG_ROLE_CONTENT) - run once, after every route and stage has linked (the links are final), for every route.
 *
 * An exec of memory (KGENOME_NUCLEO_EXEC_REG) whose TARGET is PROVEN to be the value of producer P (an mmap's region), and a node whose BUFFER input
 * (the memory it writes, diag_vocab.h) is PROVEN to be the same P: the bytes the exec runs are what that node wrote. The exec gets an input from the
 * writer, role CONTENT, kind SHARED (neither made the region: they share it), PROVEN. Nothing weaker makes one: a MAY or UNKNOWN on either side, a
 * region from the stack, two different producers - no link (the same rule as caps_settle: never a statement stronger than the links it is read off).
 * LIMIT: the link says the two touch ONE region; it does not say the write comes first on every path (no order is read). Next: the lineage solve's
 * path order between the two sites.
 * The writers are listed once and sorted by region, so the cost is the inputs, not exec nodes x writers. A refused allocation makes no link and says
 * so (KGENOME_TRUNCATED).
 */
static void exec_content_settle(struct kgenome_diag_scan *s)
{
	struct exec_writer *wr;
	uint32_t i, q, n = 0, k, added = 0;
	int any_exec = 0;

	for (i = 0; i < s->n_hit && !any_exec; i++)
		any_exec = s->hit[i].cap == KGENOME_NUCLEO_EXEC_REG && !(s->hit[i].bits & KGENOME_DIAG_H_SUPERSEDED);
	if (!any_exec)
		return;
	for (i = 0; i < s->n_hit; i++)
		if (!(s->hit[i].bits & KGENOME_DIAG_H_SUPERSEDED))
			for (q = 0; q < kgenome_diag_in_count(s, i); q++)
				n += (uint32_t)exec_proven_from(s, kgenome_diag_in_at(s, i, q), KGENOME_DIAG_ROLE_BUFFER);
	if (!n)
		return;
	if (!kgenome_ledger_charge(&s->led, (uint64_t)n * sizeof *wr)) {
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return;
	}
	wr = malloc((size_t)n * sizeof *wr);
	if (!wr) {
		kgenome_ledger_release(&s->led, (uint64_t)n * sizeof *wr);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return;
	}
	n = 0;
	for (i = 0; i < s->n_hit; i++)
		if (!(s->hit[i].bits & KGENOME_DIAG_H_SUPERSEDED))
			for (q = 0; q < kgenome_diag_in_count(s, i); q++) {
				const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, q);

				if (exec_proven_from(s, x, KGENOME_DIAG_ROLE_BUFFER) && x->from != i) {
					wr[n].region = x->from;
					wr[n++].node = (uint16_t)i;
				}
			}
	qsort(wr, n, sizeof *wr, exec_writer_cmp);
	for (i = 0; i < s->n_hit; i++) {
		const uint32_t nin = kgenome_diag_in_count(s, i);

		if (s->hit[i].cap != KGENOME_NUCLEO_EXEC_REG || (s->hit[i].bits & KGENOME_DIAG_H_SUPERSEDED))
			continue;
		for (q = 0; q < nin; q++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, q);
			uint32_t lo = 0, hi = n;
			uint16_t region;

			if (!exec_proven_from(s, x, KGENOME_DIAG_ROLE_TARGET))
				continue;
			region = x->from;
			while (lo < hi) {
				const uint32_t mid = lo + (hi - lo) / 2u;

				if (wr[mid].region < region)
					lo = mid + 1u;
				else
					hi = mid;
			}
			/* noting an input past the view goes to the scan's table, never to the node's in[] read here: `x` of a later q is re-read */
			for (k = lo; k < n && wr[k].region == region; k++)
				if (wr[k].node != i) {
					(void)kgenome_diag_note_in_how(s, &s->hit[i], wr[k].node, KGENOME_DIAG_ROLE_CONTENT, KGENOME_DIAG_KIND_SHARED,
								       KGENOME_DIAG_LINK_PROVEN);
					added++;
				}
		}
	}
	kgenome_ledger_release(&s->led, (uint64_t)n * sizeof *wr);
	free(wr);
	if (added)
		kgenome_diag_links_settle(s);
}

/* ---- THE USE CHAIN of one value ---- */

/* The class of value a role names, for the use chain: 1 a descriptor, 2 a region (written, read from, or jumped into); 0: not chained (a number, a path,
 * a script's value, the content link). */
static unsigned use_class(uint8_t role)
{
	switch (role) {
	case KGENOME_DIAG_ROLE_FD:      return 1u;
	case KGENOME_DIAG_ROLE_BUFFER:
	case KGENOME_DIAG_ROLE_SOURCE:
	case KGENOME_DIAG_ROLE_TARGET:  return 2u;
	default:                        return 0u;
	}
}

struct use_ent {
	uint64_t at;            /* the consumer's site */
	uint16_t prod, node;    /* the producer; the consumer */
	uint16_t k;             /* the index of the input (kgenome_diag_in_at order) */
	uint8_t  cls, role;
};

static int use_ent_cmp(const void *a, const void *b)
{
	const struct use_ent *x = a, *y = b;

	if (x->prod != y->prod)
		return x->prod < y->prod ? -1 : 1;
	if (x->cls != y->cls)
		return x->cls < y->cls ? -1 : 1;
	if (x->at != y->at)
		return x->at < y->at ? -1 : 1;
	if (x->node != y->node)
		return x->node < y->node ? -1 : 1;
	return x->k < y->k ? -1 : x->k > y->k;
}

/* The dominators of the frames asked so far (one function's per entry, a handful per object: the chain is between consumers of one value). */
struct use_dom {
	uint32_t fi;
	const struct kgenome_frame *fr;
	struct kgenome_dom d;
	enum kgenome_status st;
};

struct use_ctx {
	struct kgenome_diag_scan *s;
	const struct kgenome_func_set *fs;
	struct kgenome_frame_src src;
	struct use_dom *dom;
	uint32_t n_dom, cap_dom;
};

/*
 * Does block b hold a call or system call that never returns (exit, abort: the scan's list, kgenome_diag_site_noreturn - the one the lineage solve ends a
 * path at)? Its successors are then no path: the frame's graph lets an exit block fall into the next one (msfvenom's stagers put the exit just above the
 * code after the loop), which would make every consumer after it reachable around the loop. LIMIT: the list is the routes' (the sweep reads a number in
 * address order); the lineage solve also asks its own state that the number is a constant, which is not kept after the solve.
 */
static int use_block_exits(const struct kgenome_diag_scan *s, const struct kgenome_frame *fr, uint32_t b)
{
	const uint64_t lo = fr->off + fr->cfg.b[b].at, hi = b + 1u < fr->cfg.n_all ? fr->off + fr->cfg.b[b + 1u].at : fr->off + fr->len;
	uint32_t l = 0, h = s->n_noret;

	while (l < h) {
		const uint32_t mid = l + (h - l) / 2u;

		if (s->noret_at[mid] < lo)
			l = mid + 1u;
		else
			h = mid;
	}
	return l < s->n_noret && s->noret_at[l] < hi;
}

static const struct use_dom *use_dom_of(struct use_ctx *c, uint32_t fi)
{
	const struct kgenome_frame *fr;
	struct kgenome_dom_edge *ed;
	struct use_dom *u;
	uint32_t i, b, m = 0;

	for (i = 0; i < c->n_dom; i++)
		if (c->dom[i].fi == fi)
			return &c->dom[i];
	if (c->n_dom == c->cap_dom) {
		const uint32_t nc = c->cap_dom ? 2u * c->cap_dom : 8u;
		struct use_dom *nv = realloc(c->dom, (size_t)nc * sizeof *nv);

		if (!nv)
			return NULL;
		c->dom = nv;
		c->cap_dom = nc;
	}
	u = &c->dom[c->n_dom++];
	memset(u, 0, sizeof *u);
	u->fi = fi;
	u->st = KGENOME_BAD_INPUT;
	fr = kgenome_frame_get(kgenome_diag_frames(c->s), &c->src, fi);
	if (!fr || fr->state != KGENOME_FRAME_OK || !fr->cfg.n_all)
		return u;
	for (b = 0; b < fr->cfg.n_all; b++) {
		if (fr->cfg.b[b].term == KGENOME_CFG_T_SWITCH)
			return u;       /* its edges are not in succ[]: a dominator read without them could claim a path that is not the only one */
		m += fr->cfg.b[b].out_deg;
	}
	ed = malloc(((size_t)m + 1u) * sizeof *ed);
	if (!ed)
		return u;
	m = 0;
	kgenome_diag_noret_settle(c->s);
	for (b = 0; b < fr->cfg.n_all; b++)
		for (i = 0; i < 2u && !use_block_exits(c->s, fr, b); i++)
			if (fr->cfg.b[b].succ[i] != KGENOME_CFG_NONE && fr->cfg.b[b].succ[i] < fr->cfg.n_all) {
				ed[m].from = b;
				ed[m++].to = fr->cfg.b[b].succ[i];
			}
	u->st = kgenome_dom_make(&(const struct kgenome_dom_req){ .n = fr->cfg.n_all, .entry = 0, .m = m, .edge = ed, .stride = sizeof *ed }, &u->d);
	u->fr = fr;
	free(ed);
	return u;
}

/* The block of the frame that holds file offset `at`, or KGENOME_CFG_NONE. */
static uint32_t use_block(const struct kgenome_frame *fr, uint64_t at)
{
	uint32_t lo = 0, hi = fr->cfg.n_all;
	uint64_t rel;

	if (at < fr->off || at - fr->off >= fr->len)
		return KGENOME_CFG_NONE;
	rel = at - fr->off;
	while (lo < hi) {               /* the last block whose start is at or before `rel` */
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fr->cfg.b[mid].at <= rel)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo ? lo - 1u : KGENOME_CFG_NONE;
}

/* 1: the site of node a runs before the site of node b on every path into b (same function; a's block dominates b's, or one block and a first). 0: not
 * established (another function, no frame, a switch, a block the entry does not reach, the dominators not computed). */
static int use_dominates(struct use_ctx *c, uint32_t a, uint32_t b)
{
	const uint64_t xa = c->s->hit[a].at, xb = c->s->hit[b].at;
	const uint32_t fa = kgenome_funcs_at(c->fs, xa), fb = kgenome_funcs_at(c->fs, xb);
	const struct use_dom *u;
	uint32_t ba, bb;

	if (fa == KGENOME_FUNCS_NONE || fa != fb || xa >= xb)
		return 0;
	u = use_dom_of(c, fa);
	if (!u || !u->fr || u->st != KGENOME_OK)
		return 0;
	ba = use_block(u->fr, xa);
	bb = use_block(u->fr, xb);
	if (ba == KGENOME_CFG_NONE || bb == KGENOME_CFG_NONE || !u->fr->cfg.b[ba].reach || !u->fr->cfg.b[bb].reach)
		return 0;
	return ba == bb || kgenome_dom_dominates(&u->d, ba, bb);
}

/* Does node `to` already have an input from `from` that is drawn for the same relation (the role, or the content link)? */
static int use_has_link(const struct kgenome_diag_scan *s, uint32_t to, uint32_t from, uint8_t role)
{
	uint32_t q;

	for (q = 0; q < kgenome_diag_in_count(s, to); q++) {
		const struct kgenome_diag_in *x = kgenome_diag_in_at(s, to, q);

		if (x && x->from == from && (x->role == role || x->role == KGENOME_DIAG_ROLE_CONTENT))
			return 1;
	}
	return 0;
}

/*
 * THE USE CHAIN (owner, 2026-11-17: "socket -> connect -> recv, as alloc -> recv -> exec") - run once, after every link is final (after exec_content_settle).
 *
 * Several consumers of ONE value - the same producer, PROVEN and PRODUCED, a role of one class (a descriptor; a region) - are put in program order. Each
 * consumer after the first whose previous consumer DOMINATES it (runs before it on every path into it: the function's frame, kgenome_dom_make) is
 * drawn from that previous consumer: it gets an input from it (kind SHARED - they share the value -, its own role, PROVEN) unless it already has one for
 * that relation (the content link), and its direct link from the producer is kept as a fact with KGENOME_DIAG_IN_UNDRAWN. A consumer the previous one does
 * not dominate (another arm, another function, no frame) keeps its direct link drawn. Nothing is deleted: the rows list every link.
 * The scripts' route has no frame: its links are not chained (limit; next: the text route's own statement order).
 */
static void use_chain_settle(struct kgenome_diag_scan *s, const struct kgenome_obj *obj)
{
	struct use_ctx c;
	struct use_ent *v;
	uint32_t i, q, n = 0, j, added = 0;

	if (!obj || !s->n_hit)
		return;
	for (i = 0; i < s->n_hit; i++)
		for (q = 0; q < kgenome_diag_in_count(s, i); q++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, q);

			n += x && use_class(x->role) && x->how == KGENOME_DIAG_LINK_PROVEN && x->kind == KGENOME_DIAG_KIND_PRODUCED && x->from < s->n_hit;
		}
	if (n < 2u)
		return;
	if (!kgenome_ledger_charge(&s->led, (uint64_t)n * sizeof *v)) {
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return;
	}
	v = malloc((size_t)n * sizeof *v);
	if (!v) {
		kgenome_ledger_release(&s->led, (uint64_t)n * sizeof *v);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return;
	}
	n = 0;
	for (i = 0; i < s->n_hit; i++)
		for (q = 0; q < kgenome_diag_in_count(s, i); q++) {
			const struct kgenome_diag_in *x = kgenome_diag_in_at(s, i, q);

			if (!x || !use_class(x->role) || x->how != KGENOME_DIAG_LINK_PROVEN || x->kind != KGENOME_DIAG_KIND_PRODUCED || x->from >= s->n_hit ||
			    x->from == i || (s->hit[i].bits & KGENOME_DIAG_H_SUPERSEDED))
				continue;
			v[n].at = s->hit[i].at;
			v[n].prod = x->from;
			v[n].node = (uint16_t)i;
			v[n].k = (uint16_t)q;
			v[n].cls = (uint8_t)use_class(x->role);
			v[n++].role = x->role;
		}
	qsort(v, n, sizeof *v, use_ent_cmp);
	memset(&c, 0, sizeof c);
	c.s = s;
	c.fs = kgenome_diag_funcs(s, obj);
	c.src = (struct kgenome_frame_src){ .obj = obj, .base = s->base, .size = s->size, .fs = c.fs, .wk = s->walk };
	/* first the bits (the inputs' order is what kgenome_diag_in_at reads; the links added below go after every one of them) */
	for (j = 1; j < n; j++) {
		const struct use_ent *p = &v[j - 1u], *e = &v[j];

		if (p->prod != e->prod || p->cls != e->cls || p->node == e->node || !c.fs)
			continue;
		if (use_dominates(&c, p->node, e->node))
			(void)kgenome_diag_in_flag(s, e->node, e->k, KGENOME_DIAG_IN_UNDRAWN);
		else
			v[j - 1u].cls = 0;      /* not chained: said to the second pass by the pair's class */
	}
	for (j = 1; j < n; j++) {
		const struct use_ent *p = &v[j - 1u], *e = &v[j];

		if (!p->cls || p->prod != e->prod || p->cls != e->cls || p->node == e->node || !c.fs)
			continue;
		if (!use_has_link(s, e->node, p->node, e->role)) {
			(void)kgenome_diag_note_in_how(s, &s->hit[e->node], p->node, e->role, KGENOME_DIAG_KIND_SHARED, KGENOME_DIAG_LINK_PROVEN);
			added++;
		}
	}
	for (i = 0; i < c.n_dom; i++)
		kgenome_dom_free(&c.dom[i].d, NULL);
	free(c.dom);
	kgenome_ledger_release(&s->led, (uint64_t)n * sizeof *v);
	free(v);
	if (added)
		kgenome_diag_links_settle(s);
}

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
	s->frames = in ? in->frames : NULL;
	s->funcs_fn = in ? in->funcs_fn : NULL;
	s->funcs_user = in ? in->funcs_user : NULL;
	kgenome_diag_walk_bind(s->walk, &s->led);
	s->apihash = in ? in->apihash : NULL;
	s->imports = in ? in->imports : NULL;
	s->seq = in ? in->seq : NULL;
	s->n_seq = in ? in->n_seq : 0;
	s->lineage_stages = in ? in->lineage_stages : 0;
	s->keep_caps = in ? in->keep_caps : NULL;
	s->n_keep_caps = in ? in->n_keep_caps : 0;
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
			kgenome_diag_wrapper_param_settle(s);
			if (s->halt)
				break;
		}
	}
	/* A walk the scan made for itself has no other reader once the stages are done: its trace goes now
	 * (a tool that keeps a scan alive to show it must not keep an object's worth of decode with it). */
	if (s->own_walk)
		kgenome_diag_walk_trim(s->own_walk);
	kgenome_diag_links_settle(s);
	caps_settle(s);
	exec_content_settle(s);
	use_chain_settle(s, obj);
	kgenome_diag_nodes_keep(s);     /* (only when the table refused a node) */
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
	kgenome_diag_links_settle(s);
	caps_settle(s);
	exec_content_settle(s);
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
/* THE FUNCTIONS OF AN OBJECT: kgenome_diag_funcs_with_walk, fntab_build.c (the function table, built once, case by case). */
void kgenome_diag_funcs_of(const struct kgenome_obj *obj, const uint8_t *data,
		       uint64_t data_n, struct kgenome_func_set *out)
{
	kgenome_diag_funcs_with_walk(obj, data, data_n, NULL, out);
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
	if (!s->funcs && s->funcs_fn)
		s->funcs = s->funcs_fn(s->funcs_user);        /* the caller's own table, made now that someone reads it */
	if (!s->funcs) {
		if (obj && obj->file_header) {
			s->own |= KGENOME_DIAG_OWN_FUNCS;
			kgenome_diag_funcs_with_walk(obj, s->base, s->size,
						 kgenome_diag_scan_walk(s),
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

/* The allocator of the frames a scan makes for itself: every byte is charged to the scan's ledger, refused (NULL) when it does not fit - the function then has no frame, said. */
static void *frame_alloc(void *user, size_t n)
{
	struct kgenome_diag_scan *s = user;
	void *p;

	if (!kgenome_ledger_charge(&s->led, n))
		return NULL;
	p = malloc(n);
	if (!p)
		kgenome_ledger_release(&s->led, n);
	return p;
}

static void frame_release(void *user, void *p, size_t n)
{
	struct kgenome_diag_scan *s = user;

	if (p) {
		kgenome_ledger_release(&s->led, n);
		free(p);
	}
}

struct kgenome_frame_cache *kgenome_diag_frames(struct kgenome_diag_scan *s)
{
	if (!s->frames) {
		if (!s->own_frames)
			s->own_frames = kgenome_frame_cache_new(&(const struct kgenome_cfg_mem){ frame_alloc, frame_release, s },
								kgenome_ledger_room(&s->led) / 4u);
		s->frames = s->own_frames;
		s->own |= KGENOME_DIAG_OWN_FRAMES;
	}
	return s->frames;
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
		uint32_t nc = kgenome_grow_cap(g->cap, 64u);
		struct kgenome_diag_rcall *nv = nc ? realloc(g->v, (size_t)nc * sizeof *nv) : NULL;

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
	free(s->param_site);
	/* The walk may outlive this scan (it is the object's): let go of the ledger
	 * it was charging before the ledger is gone. */
	kgenome_diag_walk_bind(s->walk, NULL);
	kgenome_diag_apihash_free(s->own_apihash);
	kgenome_pe_imptab_free(&s->own_imports);
	kgenome_elf_reloc_table_free(&s->own_relocs);
	kgenome_funcs_free(&s->own_funcs);
	kgenome_diag_walk_free(s->own_walk);
	kgenome_frame_cache_free(s->own_frames);
	kgenome_elf_reloc_table_free(&s->data_relocs);
	free(s->rcall);
	free(s->oblig);
	free(s->noret_at);
	free(s->xin);
	free(s->xin_tab);
	free(s->xin_ord);
	free(s->hit);
	free(s);
}
