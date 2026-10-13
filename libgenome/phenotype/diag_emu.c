/*
 * diag_emu.c - the link between two nodes, established by RUNNING the code
 * between them instead of modelling it.
 *
 * WHY A SECOND ROUTINE AND NOT A BETTER FIRST ONE.
 *
 * The static walk carries a value in a register and loses it everywhere else.
 * That is not a bug to fix; it is what reading forwards without executing can
 * honestly claim. MEASURED, on two ELFs identical but for one instruction:
 *
 *     p = mmap(RWX); read(fd, p, n); jmp p;         3 nodes, 2 links
 *     p = mmap(RWX); v = p; read(fd, v, n); jmp v;  2 nodes, 0 links
 *
 * One local variable. The same program, the same behaviour, and the diagnose
 * stops matching - the read loses its buffer link and the jump stops being a
 * node at all, because the register it branches through carries nothing.
 *
 * THE VARIABLE IS NOT A NODE. It is a step on a LINK: nothing happens at it,
 * no capability is exercised, and a model that needs a word for it has the
 * wrong shape. What is needed is not more node kinds but a link that survives
 * a trip through memory - and the cheapest correct way to follow a value
 * through memory is to put the value in memory and look.
 *
 * WHAT IT COSTS, measured here: 16.2 M instructions a second against 16.9 for
 * decoding the same stream and doing nothing with it. Interpreting is 1.04x
 * the price of reading, so which to use is not a question about speed.
 *
 *
 * ---- A LOOP MUST NOT PRODUCE A SECOND NODE, OR A SECOND LINK --------------
 *
 * The first version of this read the emulator's syscall LOG, which records
 * what was called and not where from. MEASURED on meter1_x86, which retries
 * connect ten times before giving up: thirty nodes, for three sites. Those
 * are not findings, they are the same finding counted again, and an analyzer
 * that reports them has stopped describing the program.
 *
 * A NODE IS A SITE. The instruction is at one file offset however many times
 * control reaches it; running it twice is a fact about the run, not about the
 * program. So this stops AT each syscall, takes rip, and keys the node on the
 * offset - which is also what lets a node from a run and a node from the
 * static sweep be recognised as the same node later.
 *
 * A LINK IS A TRIPLE. (child, parent, role) seen again is the same link.
 * kgenome_diag_note_in is told once.
 *
 *
 * ---- STATIC STEERS, THE RUN RESOLVES --------------------------------------
 *
 * The two routines are not two attempts at one job. The sweep reads the file
 * and says WHERE the interesting places are - every syscall site, at a file
 * offset, on every path including the ones no run takes. The run says WHICH
 * VALUE REACHED WHICH PLACE, which is the one question reading cannot answer
 * once a value goes through memory.
 *
 * SO NOTHING HERE RECOGNISES AN INSTRUCTION BY ITS BYTES. An earlier version
 * of the handover test listed the encodings of jmp and call through a
 * register and of ret - sixteen forms plus the prefixed ones - and that list
 * is a list of the ways we happen to know about. An author who hands over
 * some other way is not in it, and nothing says so. What is used instead is
 * the behaviour: control arrived inside a region an allocation handed back.
 * Whatever instruction took it there, and whether we have heard of that
 * instruction, does not enter into it.
 *
 * ---- STEERING, AND WHY IT CANNOT LIE --------------------------------------
 *
 * A run goes where its values take it. meter1 retries connect to
 * 127.0.0.1:9999 and exits; with nothing listening the run never reaches the
 * read or the jump that make it a stager, while the static sweep sees both
 * because layout does not care which arm executes.
 *
 * So when a call fails, this substitutes a success. NOT to assert that it
 * succeeded - to walk the path on which it did, which is the path the
 * diagnose is about.
 *
 * AND THAT CANNOT MANUFACTURE A LINK. A link is recorded only when a value
 * IS in an argument register at a real call site; steering decides which
 * code runs, never what a register holds. A wrong steer costs a wasted run
 * and cannot produce a finding - which is why the heuristic here is allowed
 * to be crude, and why the same crudeness in a static model would not be.
 *
 *
 * ---- WHAT IT STILL CANNOT DO ----------------------------------------------
 *
 * ONE PATH PER RUN. Choosing the success arm covers the branch that turns on
 * a call's result, which is the common one. A branch on a payload byte or a
 * counter is not steered and the other arm is not seen. The static sweep is
 * the complement, and neither is a fallback for the other.
 *
 * IT PROVES PRESENCE. A link it did not see is not a link that is not there.
 */

#include "diag_emu_private.h"

/* What the run of a linked program holds from one syscall stop to the next. */
struct route {
	struct kgenome_diag_scan *s;
	const struct kgenome_obj *obj;
	struct kgenome_emu *em;
	unsigned bits;
	const unsigned *areg;
	/* GROWN WITH THE RUN. Fixed at 64 each, a program that made a 65th
	 * distinct call lost it from the table and its links with it. */
	struct kgenome_diag_emu_site *sites;
	struct kgenome_diag_emu_made *made;
	unsigned cap_site, cap_made;
	unsigned n_site, n_made, n_fd;
	/* Every stop identity the run has made, harmless call or not: the PROGRESS
	 * of the run, see route_progress. An open-addressing set of the stop's
	 * identity (route_identity, never zero: zero is an empty slot). */
	uint64_t *seen;
	unsigned cap_seen, n_seen;
	int fresh;              /* the stop just made was not one seen before: see route_identity */
	int full;               /* the set is at KGENOME_DIAG_EMU_SITES and said so */
};

/*
 * THE IDENTITY OF A STOP: where it is AND WHO REACHED IT.
 *
 * An address alone is the wrong identity for "no progress". A libc syscall wrapper is ONE
 * address however many places call it, and each call from a different place is new work - a
 * program making three hundred different calls through one wrapper is going somewhere. What a
 * poll is, is the SAME call site reaching the SAME instruction again and again. So the identity
 * is the stop address and the two call instructions that most recently ran
 * (kgenome_emu_last_calls: the interpreter's own record, the one the API-call log keys on). Two,
 * because a wrapper that calls an inner one makes the newest the same for every caller.
 *
 * A direct `syscall` in a loop has the same address and the same call history every lap, so it
 * is a repeat from the third visit on (the first two can differ while the history fills).
 */
static uint64_t route_identity(const struct route *R, uint64_t rip)
{
	uint64_t c[2], k;

	kgenome_emu_last_calls(R->em, c);
	k = (rip + 1u) * 0x9e3779b97f4a7c15ull;
	k = (k ^ (k >> 29) ^ c[0]) * 0xbf58476d1ce4e5b9ull;
	k = (k ^ (k >> 31) ^ c[1]) * 0x94d049bb133111ebull;
	k ^= k >> 32;
	return k ? k : 1u;
}

/*
 * IS THIS STOP ONE THE RUN HAS NOT MADE BEFORE - the run's progress.
 *
 * A stop is evidence only the first time: a node is a site, so the second arrival
 * at it from the same place adds nothing (see the note on loops at the top) and a loop
 * that polls one syscall is the same stop counted again. What is NEW is a syscall instruction
 * not yet reached, or one reached from a call site not yet seen - a node when the call is one a
 * diagnose names, and when it is not (a getpid, a gettimeofday: no node, so route_node does
 * not remember it) still ground the run has covered. The run is for reaching the sites; a run
 * that keeps reaching new ones is going somewhere, and one that stops at the old ones is
 * turning round. See KGENOME_DIAG_EMU_QUIET in diag_emu_private.h for what ends it.
 *
 * Returns 1 for a new identity, 0 for one seen, and -1 when the set is full
 * (KGENOME_DIAG_EMU_SITES: a DoS bound on a program that makes new stops
 * without end) or memory is - which the caller reports.
 */
static int route_progress(struct route *R, uint64_t key)
{
	unsigned h, mask;

	if (R->n_seen >= KGENOME_DIAG_EMU_SITES)
		return -1;
	if (R->n_seen * 2u >= R->cap_seen) {
		unsigned nc = R->cap_seen ? R->cap_seen * 2u : 256u, i;
		uint64_t *ns = calloc(nc, sizeof *ns);

		if (!ns)
			return -1;
		for (i = 0; i < R->cap_seen; i++) {
			unsigned k;

			if (!R->seen[i])
				continue;
			for (k = (unsigned)((R->seen[i] * 0x9e3779b97f4a7c15ull) >> 40) & (nc - 1u);
			     ns[k]; k = (k + 1u) & (nc - 1u))
				;
			ns[k] = R->seen[i];
		}
		free(R->seen);
		R->seen = ns;
		R->cap_seen = nc;
	}
	mask = R->cap_seen - 1u;
	for (h = (unsigned)((key * 0x9e3779b97f4a7c15ull) >> 40) & mask; R->seen[h]; h = (h + 1u) & mask)
		if (R->seen[h] == key)
			return 0;
	R->seen[h] = key;
	R->n_seen++;
	return 1;
}

/* What the node step decided about this stop. */
enum route_node_act { ROUTE_GO, ROUTE_SKIP, ROUTE_STOP };

/* Where the run begins: a short way before the first node. */
static void route_aim(struct route *R)
{

/*
 * ---- START AT THE NODES, NOT AT THE ENTRY -------------------------
 *
 * This ran the program from its entry point, which is running the
 * whole file to reach the part that matters. Two things were wrong
 * with it and both were measured:
 *
 *   IT NEVER ARRIVES ON A REAL PROGRAM. 100 dynamically linked and 5
 *   statically linked binaries from /usr/bin yielded zero nodes: the
 *   run ends in the runtime's startup, hundreds of thousands of
 *   instructions before any of the program's own calls.
 *   IT IS THE WRONG QUESTION. What is wanted is not "what does this
 *   program do" but "does the value this call produced reach that
 *   call" - a relation between two places the static routines have
 *   ALREADY located, at file offsets, without running anything.
 *
 * So the run begins a short way before the FIRST node the static
 * routines found, with just enough lead-in to execute the
 * instructions that set that call's arguments up. Everything before
 * it - the loader, the runtime, the startup - is not executed because
 * it is not part of any relation being asked about.
 *
 * THE LEAD-IN IS THE SAME 256 BYTES the static window uses, and for
 * the same measured reason: msfvenom's longest argument set-up is 41.
 */
	uint64_t first = (uint64_t)-1, va;
	uint32_t q;

	for (q = 0; q < kgenome_diag_scan_count(R->s); q++) {
		uint64_t a = kgenome_diag_scan_at(R->s, q)->at;

		if (a != KGENOME_BROKEN && a < first)
			first = a;
	}
	if (first != (uint64_t)-1) {
		uint64_t lo = first > KGENOME_DIAG_EMU_LEAD
			      ? first - KGENOME_DIAG_EMU_LEAD : 0;

		/*
		 * AND NOT BEFORE THE ENTRY POINT, which is the one
		 * offset in the object certainly at an instruction
		 * boundary. An executable segment usually begins at
		 * file offset zero and therefore CONTAINS THE ELF
		 * HEADER: a lead-in that runs back into it starts the
		 * machine on `7f E L F 02 01 01` and faults at once.
		 * MEASURED - meter1's first node is at 0x8d, so 256
		 * bytes of lead-in reached 0 and the run died before
		 * its first instruction.
		 */
		if (lo < R->obj->entry_off)
			lo = R->obj->entry_off;
		va = kgenome_image_off_to_addr(R->obj, lo);
		if (va != KGENOME_BROKEN)
			kgenome_emu_set_rip(R->em, va);
	}
}

/* i386's socketcall keeps its arguments in memory: read them. */
static void route_socketcall(struct route *R, uint64_t nr, uint64_t *arg)
{
	/*
	 * ---- i386's socketcall KEEPS ITS ARGUMENTS IN MEMORY ------
	 *
	 * Every socket operation on i386 goes through one syscall,
	 * 102, with the operation in ebx and A POINTER TO THE REAL
	 * ARGUMENTS in ecx. Reading registers gives that demux pair
	 * and nothing else, so a connect has no descriptor and the
	 * network half of an i386 stager has nodes and no edges -
	 * measured on meter1_x86, where every node is present and
	 * net-connect has no parent.
	 *
	 * AFTER THE DEMUX, NOT BEFORE. The first attempt overwrote
	 * arg[] where it stood, which is where kgenome_nucleo_cap_of_syscall
	 * reads arg[0] to learn WHICH socket call this is - so the
	 * operation was gone before it was used.
	 */
	if (R->bits == 32u && nr == 102u) {
		uint64_t vec = arg[1];
		unsigned ai;

		for (ai = 0; ai < 6u; ai++) {
			uint8_t w[4];

			if (!kgenome_emu_read(R->em, vec + ai * 4u, w,
					  sizeof w))
				break;
			arg[ai] = kof_ld_le32(w);
		}
	}
}

/* The node for this stop - an existing one for a site seen before, a new one
 * otherwise - and the hit that holds it. */
static enum route_node_act route_node(struct route *R, uint64_t off,
				      uint16_t cap, uint8_t fl,
				      uint16_t *node_out,
				      struct kgenome_diag_hit **h_out)
{
	struct kgenome_diag_hit *h;
	uint16_t node;
	unsigned i;

	/*
	 * THE SAME SITE IS THE SAME NODE, however many times the run
	 * arrives - see the note on loops at the top.
	 */
	node = 0xffffu;
	for (i = 0; i < R->n_site; i++)
		if (R->sites[i].off == off) {
			node = R->sites[i].node;
			break;
		}
	if (node == 0xffffu) {
		if (cap == KGENOME_NUCLEO_NONE)
			return ROUTE_SKIP;   /* no word for it; not a node */
		h = kgenome_diag_hit_add(R->s, off, cap, fl);
		if (!h)
			return ROUTE_STOP;
		node = (uint16_t)(R->s->n_hit - 1u);
		if (R->n_site == R->cap_site) {
			unsigned nc = R->cap_site ? R->cap_site * 2u : 64u;
			struct kgenome_diag_emu_site *ns = realloc(R->sites, nc * sizeof *ns);

			if (!ns) {
				R->s->halt = 1;
				kgenome_diag_note(R->s, KGENOME_NOMEM);
				return ROUTE_STOP;
			}
			R->sites = ns;
			R->cap_site = nc;
		}
		R->sites[R->n_site].off = off;
		R->sites[R->n_site].node = node;
		R->n_site++;
	} else {
		h = kgenome_diag_hit_of(R->s, node);
	}
	*node_out = node;
	*h_out = h;
	return ROUTE_GO;
}

/* An argument that is a value an earlier call handed back is a link. */
static void route_link_args(struct route *R, struct kgenome_diag_hit *h,
			    uint16_t cap, const uint64_t *arg)
{
	unsigned i, k;

	/*
	 * AND THE LINKS. An argument that IS a value an earlier call
	 * handed back is a link, and it is one the run demonstrated:
	 * the bytes travelled there, through whatever the program put
	 * in between. kgenome_diag_note_in ignores a repeat, so a loop
	 * records the link once.
	 */
	for (k = 0; k < 6u && h; k++) {
		uint8_t role = kgenome_diag_role_of_arg(cap, k);

		if (role == KGENOME_DIAG_ROLE_NONE)
			continue;
		for (i = R->n_made; i-- > 0; )
			if (R->made[i].val == arg[k]) {
				kgenome_diag_note_in(R->s, h, R->made[i].node, role,
						 KGENOME_DIAG_KIND_PRODUCED);
				break;
			}
	}
}

/* A failed call's result, replaced by the success the walk wants. */
static uint64_t route_force(struct route *R, uint16_t cap,
			    const uint64_t *arg, uint64_t ret)
{
	/*
	 * FAILED. Walk the path on which it did not - see the note on
	 * success above. Nothing about the real world is asserted by
	 * doing so, and no link can come of it.
	 */
	if ((int64_t)ret < 0 && (int64_t)ret > -4096) {
		switch (kgenome_diag_emu_cap_force_kind(cap)) {
		case KGENOME_DIAG_EMU_FORCE_ZERO:
			ret = 0;
			break;
		case KGENOME_DIAG_EMU_FORCE_HANDLE:
			ret = KGENOME_DIAG_EMU_FD0 + R->n_fd++;
			break;
		case KGENOME_DIAG_EMU_FORCE_COUNT:
			ret = arg[2];
			/*
			 * A READ THAT SUCCEEDED PUT BYTES SOMEWHERE,
			 * and saying it returned n without writing n
			 * is a state no real machine is ever in. It
			 * also loses the finding: a stager's jump
			 * into its mapping is recorded as a hop only
			 * when the page has been WRITTEN, so a
			 * mapping that was never filled is one the
			 * run can enter without anything noticing.
			 *
			 * THE CONTENT IS OURS AND NOTHING MAY READ
			 * IT AS THE PROGRAM'S. Nops, so that control
			 * entering the region runs forward to its
			 * end rather than into whatever an
			 * uninitialised page decodes as. Nothing
			 * downstream looks at these bytes - a link
			 * comes from a register at a call site, not
			 * from memory - and if anything ever does,
			 * it will be reading this routine's writing.
			 */
			/* The buffer is NOT written - see the note on
			 * KGENOME_DIAG_EMU_FILL_ON. */
#if KGENOME_DIAG_EMU_FILL_ON
			kgenome_diag_emu_fill_buffer(R->em, arg[1], arg[2]);
#endif
			break;
		default:
			break;
		}
		if (kgenome_diag_emu_cap_force_kind(cap) != KGENOME_DIAG_EMU_FORCE_NONE)
			kgenome_emu_set_reg(R->em, KGENOME_DIAG_EMU_RET, ret);
	}
	return ret;
}

/* A value a call handed back, remembered with the node that made it. */
static void route_remember(struct route *R, uint16_t cap, uint64_t nr,
			   uint64_t ret, const uint64_t *arg, uint16_t node)
{
	unsigned i;

	/*
	 * THE NAME, because mmap and mprotect are one capability and
	 * only the first hands a mapping back - see kgenome_nucleo_hands_on.
	 * Without it this route linked everything after an mprotect
	 * to its status value.
	 */
	if (kgenome_diag_emu_cap_hands_on_value(cap, kgenome_nucleo_sys_name(R->bits, (uint32_t)nr)) &&
	    kgenome_diag_emu_ret_is_carryable(ret)) {
		for (i = 0; i < R->n_made; i++)
			if (R->made[i].node == node)
				break;
		if (i == R->n_made && R->n_made == R->cap_made) {
			unsigned nc = R->cap_made ? R->cap_made * 2u : 64u;
			struct kgenome_diag_emu_made *nm = realloc(R->made, nc * sizeof *nm);

			if (nm) {
				R->made = nm;
				R->cap_made = nc;
			} else {
				R->s->halt = 1;
				kgenome_diag_note(R->s, KGENOME_NOMEM);
			}
		}
		if (i == R->n_made && R->n_made < R->cap_made)
			R->n_made++;
		if (i < R->n_made) {
			R->made[i].val = ret;
			/* An allocation's second argument is its
			 * length on every spelling of mmap this
			 * targets. A handle has no extent and gets
			 * zero, which is what keeps a descriptor
			 * from "containing" an address. */
			R->made[i].len = (cap == KGENOME_NUCLEO_ALLOC ||
				       cap == KGENOME_NUCLEO_ALLOC_EXEC ||
				       cap == KGENOME_NUCLEO_HEAP)
				      ? arg[1] : 0u;
			R->made[i].node = node;
			/*
			 * AND ASK THE INTERPRETER TO NOTICE IF
			 * CONTROL EVER ARRIVES HERE.
			 *
			 * This is what makes KGENOME_NUCLEO_EXEC_REG
			 * findable by a run: the jump into a mapping
			 * is not a syscall and nothing else would
			 * stop on it. The range is declared the
			 * moment the call hands it back, which is
			 * the only moment it is known - a region is
			 * not in the file and cannot be registered
			 * before the run.
			 */
			if (R->made[i].len)
				kgenome_emu_hop_add(R->em, ret,
						ret + R->made[i].len, 0);
		}
	}
}

/* One stop at a syscall. Zero ends the run. */
static int route_stop(struct route *R)
{
	enum kgenome_emu_stop st = kgenome_emu_run(R->em);
	uint64_t rip, off, arg[6], nr, ret;
	struct kgenome_diag_hit *h;
	uint16_t cap, node;
	uint8_t fl = 0;
	unsigned i;

	if (st != KGENOME_EMU_STOP_INSN) {
		kgenome_diag_emu_stop_status(R->s, st);      /* exited, faulted, or ran out */
		return 0;
	}

	rip = kgenome_emu_get_rip(R->em);
	off = kgenome_image_addr_to_off(R->obj, rip);
	switch (route_progress(R, route_identity(R, rip))) {
	case 1:
		R->fresh = 1;
		break;
	case -1:
		R->full = 1;
		break;
	default:
		break;
	}

	/* The NUMBER is in the result register before the call and the
	 * RESULT is in it after, so it has to be taken now. */
	nr = kgenome_emu_get_reg(R->em, KGENOME_DIAG_EMU_RET);
	for (i = 0; i < 6u; i++)
		arg[i] = kgenome_emu_get_reg(R->em, R->areg[i]);


	/*
	 * LET THE EMULATOR MAKE THE CALL. Stepping rather than
	 * inventing a result: mmap has to return a mapping the
	 * program can then write into, and only the emulator's own
	 * implementation gives one out. kgenome_emu_step exists because
	 * the watch pauses BEFORE the instruction and resuming would
	 * pause on it again.
	 */
	kgenome_emu_step(R->em);
	ret = kgenome_emu_get_reg(R->em, KGENOME_DIAG_EMU_RET);

	cap = kgenome_nucleo_cap_of_syscall(R->bits, (uint32_t)nr, arg, &fl);

	route_socketcall(R, nr, arg);

	switch (route_node(R, off, cap, fl, &node, &h)) {
	case ROUTE_STOP:
		return 0;
	case ROUTE_SKIP:
		return 1;
	default:
		break;
	}

	route_link_args(R, h, cap, arg);
	ret = route_force(R, cap, arg, ret);
	route_remember(R, cap, nr, ret, arg, node);
	return 1;
}

/* Where control went: a hop into a region one of the calls produced. */
static void route_hops(struct route *R)
{
/*
 * ---- AND WHERE CONTROL WENT ------------------------------------
 *
 * The jump into the mapping is not a syscall, so nothing above sees
 * it. The interpreter records a HOP whenever control enters a page
 * the run wrote, and a hop that lands inside a region one of these
 * calls produced is the whole of KGENOME_NUCLEO_EXEC_REG: code that was
 * fetched, written, and then entered.
 *
 * ATTRIBUTED BY RANGE AND NOT BY GUESS. base+k belongs to the call
 * that returned base and to no other, which is why `len` is kept.
 * A hop into a page the run wrote that is NOT inside such a region -
 * a stub relocating itself, a decoder rewriting its own body - is
 * not this and is left alone.
 *
 * ONLY THE FIRST AND THE LAST are available without turning on the
 * instruction trace, which emu.h says is a diagnostic and never
 * something a scan runs with. For a stager there is one hop that
 * matters and both report it; a run with many is one this routine
 * under-reports rather than one it gets wrong.
 *
 * hop_count is how many ARRIVALS there were, not how many ranges are
 * watched - zero means control never entered one of them.
 */
	uint64_t hop[2] = { 0, 0 };
	uint32_t n_hop = 0;
	unsigned q;

	kgenome_emu_first_hop(R->em, &(uint64_t){ 0 }, &hop[0]);
	kgenome_emu_last_hop(R->em, &hop[1], &n_hop);
	for (q = 0; q < 2u && n_hop; q++) {
		unsigned i;

		if (!hop[q])
			continue;
		if (q == 1u && hop[1] == hop[0])
			break;          /* one hop, reported twice */
		for (i = 0; i < R->n_made; i++) {
			struct kgenome_diag_hit *h;
			uint64_t off;

			if (!R->made[i].len ||
			    hop[q] < R->made[i].val ||
			    hop[q] - R->made[i].val >= R->made[i].len)
				continue;
			/*
			 * THE SITE IS NOT IN THE FILE, and saying it
			 * is would be the lie. Control is executing
			 * bytes the run produced; kgenome_image_addr_to_off
			 * answers KGENOME_BROKEN for them, which is the
			 * engine's word for "applies, could not be
			 * determined" and is the truth here.
			 */
			off = kgenome_image_addr_to_off(R->obj, hop[q]);
			h = kgenome_diag_hit_add(R->s, off,
					     KGENOME_NUCLEO_EXEC_REG, 0);
			if (h)
				kgenome_diag_note_in(R->s, h, R->made[i].node,
						 KGENOME_DIAG_ROLE_TARGET,
						 KGENOME_DIAG_KIND_PRODUCED);
			break;
		}
	}
}

void kgenome_diag_run_emulate(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size)
{
	static const uint8_t pat_syscall[2] = { 0x0f, 0x05 };
	static const uint8_t pat_int80[2]   = { 0xcd, 0x80 };
	const struct kgenome_elf_info *ei;
	struct kgenome_emu_unp_report rep;
	struct route R;
	unsigned stops = 0;


	/*
	 * AN ELF WITH A PROGRAM HEADER, because that is what there is an image
	 * builder for - see kgenome_emu_unp_build. A raw payload has no segments
	 * to map and no entry to start at; the static routine reads those and
	 * has already run.
	 */
	if (!obj || obj->format != KGENOME_FMT_ELF)
		return;
	ei = kgenome_obj_elf(obj);
	if (!ei || !ei->valid)
		return;
	R.bits = obj->arch == KGENOME_ARCH_X86_64 ? 64u : 32u;
	R.areg = R.bits == 64u ? kgenome_diag_emu_arg_reg64 : kgenome_diag_emu_arg_reg32;

	/*
	 * A RELOCATABLE OBJECT TAKES THE OTHER PATH ENTIRELY - there is no
	 * entry point to start from and no syscall to stop at. See
	 * kgenome_diag_emu_run_rel_gaps.
	 */
	if (!ei->seg_count) {
		kgenome_diag_emu_run_rel_gaps(s, obj, ei, base, size);
		return;
	}

	memset(&rep, 0, sizeof rep);
	{
		struct kgenome_budget eb;

		memset(&eb, 0, sizeof eb);
		eb.max_insn = s->bud.max_insn;
		eb.max_bytes = kgenome_diag_emu_pages_charge(s) * KGENOME_EMU_PAGE;
		R.em = kgenome_emu_unp_build(base, size, ei, &eb, &rep);
	}
	if (!R.em) {
		kgenome_diag_emu_pages_release(s);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return;
	}
	if (s->bud.deadline_ms)
		kgenome_emu_set_deadline(R.em, s->bud.deadline_ms);

	R.s = s;
	R.obj = obj;
	R.sites = NULL;
	R.made = NULL;
	R.cap_site = 0;
	R.cap_made = 0;
	R.n_site = 0;
	R.n_made = 0;
	R.n_fd = 0;
	R.seen = NULL;
	R.cap_seen = 0;
	R.n_seen = 0;
	R.fresh = 0;
	R.full = 0;

	route_aim(&R);


	/*
	 * STOP BEFORE EVERY WAY INTO THE KERNEL. Both encodings, because i386
	 * reaches it through a software interrupt and amd64 through an
	 * instruction, and a stager is one or the other.
	 */
	kgenome_emu_watch_insn(R.em, pat_syscall, sizeof pat_syscall);
	kgenome_emu_watch_insn(R.em, pat_int80, sizeof pat_int80);

	{
		/* The run ends when KGENOME_DIAG_EMU_QUIET stops in a row reached no
		 * address it had not reached before - see the note there. */
		unsigned quiet = 0;
		int ended = 0;

		for (;;) {
			stops++;
			R.fresh = 0;
			if (!route_stop(&R)) {
				ended = 1;
				break;
			}
			if (R.fresh)
				quiet = 0;
			else if (++quiet >= KGENOME_DIAG_EMU_QUIET)
				break;
			if (R.full)
				break;
		}
		/* THE CAP BIT, and the run was not over: the stops it would have made
		 * next are unseen, so the answer says it is partial. */
		if (!ended)
			kgenome_diag_note(s, KGENOME_TRUNCATED);
	}

	route_hops(&R);

	kgenome_emu_free(R.em);
	kgenome_diag_emu_pages_release(s);
	free(R.sites);
	free(R.made);
	free(R.seen);
}
