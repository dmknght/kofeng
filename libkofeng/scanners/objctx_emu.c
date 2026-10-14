/*
 * objctx_emu.c - the interpreter a module asks the engine to drive.
 *
 * WHAT THIS SERVES: an unpacker or a heuristic that wants a program RUN - to
 * decrypt itself, to reveal what it calls - asks the engine, because only the
 * engine owns the budget, the memory ceiling and the machine that outlives the
 * module call. This unit builds the run (kof_scan_emu_unpack), gathers what it
 * produced into regions, and answers the module's questions about the machine
 * (registers, memory, resume, take).
 *
 * OPEN, with what was measured so it is not re-derived:
 *  - the PE image-diff filter (IMG_DIFF_DEN) and the written-memory fallback
 *    (`any = built`, the stop-reason list) are family policy that belongs in a
 *    declared driver. On pe300, 27 image builds: 18 identical to the parent (the
 *    drop is exact), 9 changed 64..61043 bytes, none past the filter. Handing
 *    over only the changed spans was tried: +6 objects and the parent's
 *    Heur:WriteExec on pe300/005 vanished, because scan.c drops a parent's
 *    heuristic findings whenever it has a produced child (n_kids > n_views +
 *    n_carved) and a formatless region says nothing. Fix that rule first.
 *  - EMU_IDLE_DECLARED and EMU_INSN_PER_BYTE carry MPRESS/Themida/UPX numbers in
 *    generic constants.
 */

/* Before any include, and _GNU_SOURCE rather than _POSIX_C_SOURCE, for the
 * reason dbloader.c gives at length: kofplatform.h's POSIX branch has an inline
 * kof_memmem whose body calls memmem, which glibc declares only under this
 * macro - and _POSIX_C_SOURCE actively suppresses it. */
#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"   /* kof_write_all - the spill file below */
#include "objctx_int.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <genotype/image/elf_rebuild.h>

/* The script folding pass and the lexical table it is driven from - see
 * kof_scan_script_forms below. */
/*
 * The one format header the scan path includes, and it is not a shortcut.
 *
 * BCJ2 is not a coding that happens to appear in 7z - it IS a 7z folder shape.
 * Which packed stream carries the code, which carries the call targets, which the
 * jump targets, and which the range coder is stated by the folder's bind pairs and
 * nowhere else. A general "multi stream coding" hook in the module ABI would be an
 * abstraction with exactly one user, invented to avoid naming the thing it is for.
 */


#include "../analyzers/genome_obj.h"
#include <phenotype/diag_scan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind);

/* ---- the last resort ------------------------------------------------------
 *
 * See kof_scan_emu_unpack in scan.h.
 */

/*
 * THE INSTRUCTION BUDGET, DERIVED FROM THE OBJECT RATHER THAN CHOSEN.
 *
 * A fixed five million was the single thing most wrong with this stage, and it
 * did not look wrong: runs ended tidily at the ceiling having written
 * something, so they read as "the emulator got partway" when they were "the
 * emulator was interrupted mid-decompression". Measured over the seventeen
 * objects in the malware corpus that no unpacker could open, the work is
 * proportional to the PACKED SIZE and the constant is remarkably steady:
 *
 *     NRV (UPX method 14)          ~57 instructions per input byte
 *     LZMA (UPX method 14 + LZMA)  ~250-330 instructions per input byte
 *
 * and the totals ran from 2.7 million to 253 million. At five million, two of
 * the seventeen finished; with the budget below, fifteen do - the same code,
 * the same design, a ceiling that was two orders of magnitude under what
 * decompression costs.
 *
 * 512 per byte leaves headroom over the worst measured ratio. The floor keeps a
 * tiny object from getting a budget too small to leave its own entry code; the
 * cap is what a caller who asked for --heur 2 can be expected to tolerate on
 * one object, at the ten million instructions a second this interprets.
 */
#define EMU_INSN_PER_BYTE  512ull
#define EMU_INSN_MIN       (16ull << 20)
#define EMU_INSN_MAX       (256ull << 20)

/* The stall ceiling for a child a module asked to have run - see the call. */
#define EMU_IDLE_DECLARED  (128ull << 20)

static uint64_t emu_insn(uint64_t obj_size)
{
	/* Saturating, like the budget's own ratio a few functions up: the
	 * operand is a file size and the product is not checked anywhere
	 * after this. Wrapping would floor the budget instead of capping it,
	 * which is a run that fails for a reason nobody could read off the
	 * size. */
	uint64_t n = obj_size > UINT64_MAX / EMU_INSN_PER_BYTE
		   ? UINT64_MAX : obj_size * EMU_INSN_PER_BYTE;

	if (n < EMU_INSN_MIN)
		n = EMU_INSN_MIN;
	if (n > EMU_INSN_MAX)
		n = EMU_INSN_MAX;
	return n;
}

/*
 * THE TREE'S INTERPRETER ALLOWANCE - the bound the per-object numbers above cannot be.
 *
 * Every limit above follows ONE object, and a floor makes a small object's limit larger
 * than its size: a 1 KB PE whose code is `jmp $` runs 16 Mi instructions (0.25 s). A
 * limit that restarts for each child multiplies by the number of children, which a file
 * chooses: a zip of 100 of them (18.9 KB) took 26 s, with a loop that decodes 85 s
 * (tests/unit/hunt_emu_tree.c). A child's bytes are produced from the root, so its size
 * is no new allowance either (a decompression bomb must not buy emulation time): the
 * tree gets one account, from the ROOT's size alone.
 *
 *   allowance = 64 Mi + 512 per root byte, at most 4 Gi instructions
 *
 * 512 is EMU_INSN_PER_BYTE: every byte of the file may be the packed input of one run,
 * once. 64 Mi is four floors (EMU_INSN_MIN), what a file too small to scale gets. 4 Gi is
 * about a minute at the 70 million instructions a second this interpreter runs (a spin
 * loop, release build), the DoS bound for a root of any size. A host sets its own with
 * kof_scan_option.max_emu_insn.
 *
 * WHAT A RUN GETS is the smaller of its per-object limit and what is left. Degradation
 * is in the order of rule 4: the emulating routes of the diagnose scan and the
 * API-resolution run are OPTIONAL evidence and are skipped (oc_emu_afford) once less
 * than EMU_OPT_MIN is left; an unpack run is given what is left while that is its
 * floor (EMU_INSN_MIN, or its limit when smaller); and the FIRST KOF_SCAN_EMU_FLOOR_RUNS runs of
 * the tree - the root's and the first four children's - get that floor even when
 * nothing is left, so a packed file that is the whole tree is never denied its unpack.
 * Past that the run is not made, the object reads KOF_BROKEN_LIMIT, limit_hits and
 * emu_budget_denied move. Nothing is silent.
 *
 * MEASURED (build/release, spin-loop PE of 1025 bytes): 16.7 Mi instructions = 0.24 s,
 * 70 Mi/s. Legitimate packed files need far less than the floor: see
 * tests/unit/emu_tree_budget.c for the unpack runs of the corpus (UPX, PECompact,
 * Themida samples) against the allowance.
 */
#define EMU_TREE_MIN    (4ull * EMU_INSN_MIN)
#define EMU_TREE_MAX    (4096ull << 20)
#define EMU_OPT_MIN     (1ull << 20)

uint64_t oc_emu_tree_insn(uint64_t root_size, uint64_t host_max)
{
	uint64_t n;

	if (host_max)
		return host_max;
	n = root_size > UINT64_MAX / EMU_INSN_PER_BYTE ? UINT64_MAX
						       : root_size * EMU_INSN_PER_BYTE;
	n = n > UINT64_MAX - EMU_TREE_MIN ? UINT64_MAX : n + EMU_TREE_MIN;
	return n > EMU_TREE_MAX ? EMU_TREE_MAX : n;
}

/* The tree's allowance ran out on this object: said once for the object. */
static void emu_denied(struct kof_scanner *sc)
{
	if (sc->obj.emu.refused)
		return;
	sc->obj.emu.refused = 1;
	sc->st.emu_budget_denied++;
	OC_LIMIT(sc, "the tree's interpreter allowance is spent");
}

/*
 * What an OPTIONAL emulation may execute: `own` (its per-object limit) or what is left
 * if that is less, and 0 - denied and said - when less than EMU_OPT_MIN is left.
 */
uint64_t oc_emu_afford(struct kof_scanner *sc, uint64_t own)
{
	const uint64_t left = sc->ledger.emu_insn_left;

	if (left >= own)
		return own;
	if (left >= (own < EMU_OPT_MIN ? own : EMU_OPT_MIN))
		return left;
	emu_denied(sc);
	return 0;
}

/* Take `insn` executed instructions from the tree's allowance. */
void oc_emu_charge(struct kof_scanner *sc, uint64_t insn)
{
	sc->st.emu_insn += insn;
	sc->ledger.emu_insn_left = insn > sc->ledger.emu_insn_left
				   ? 0u : sc->ledger.emu_insn_left - insn;
}

/*
 * THE DIAGNOSE SCAN'S EMULATING ROUTES, under the tree's allowance. They are optional
 * evidence: with less than EMU_OPT_MIN left they are not run (`run` loses them), the
 * object is said to be cut, and the scan the other routes make is noted incomplete so a
 * diagnose that needed them reads "could not say" and not "no" (oc_emu_diag_end).
 */
void oc_emu_diag_begin(struct kof_scanner *sc, struct oc_emu_diag *acct,
		       struct kgenome_budget *kb, unsigned *run)
{
	const unsigned routes = KGENOME_DIAG_RUN_EMULATE | KGENOME_DIAG_RUN_APIHASH;

	acct->spent = 0;
	acct->skipped = 0;
	if (*run & routes) {
		const uint64_t grant = oc_emu_afford(sc, kb->max_insn);

		if (grant) {
			kb->max_insn = grant;
			if (kb->max_insn_resolve > grant)
				kb->max_insn_resolve = grant;
		} else {
			*run &= ~routes;
			acct->skipped = 1;
		}
	}
	kb->insn_spent = &acct->spent;
}

void oc_emu_diag_end(struct kof_scanner *sc, const struct oc_emu_diag *acct,
		     struct kgenome_diag_scan *ds)
{
	oc_emu_charge(sc, acct->spent);
	if (ds && acct->skipped)
		kgenome_diag_note(ds, KGENOME_OVER_BUDGET);
}

/*
 * THE PE'S API-RESOLUTION PRODUCT, made under the tree's allowance: the resolver's run
 * may execute what the tree has left (oc_emu_afford), and NULL - said - when it has
 * nothing. The product is also what the symbol view and the graph read.
 */
struct kgenome_diag_apihash_set *oc_emu_apihash(struct kof_scanner *sc,
		const struct kgenome_obj *gobj, kof_buf b, const struct kgenome_pe_imptab *imports)
{
	struct kgenome_budget kb;
	struct kgenome_diag_apihash_set *a;
	uint64_t spent = 0;

	kgenome_budget_default(&kb, b.n, kgenome_diag_code_bytes(gobj, b.n));
	kb.max_bytes = oc_scan_room(sc);
	kb.max_insn_resolve = oc_emu_afford(sc, kb.max_insn_resolve);
	if (!kb.max_insn_resolve)
		return NULL;
	kb.insn_spent = &spent;
	a = kgenome_diag_apihash_run(gobj, b.p, b.n, imports, &kb);
	oc_emu_charge(sc, spent);
	return a;
}

/*
 * What an UNPACK run may execute: `own`, or what is left while that is at least its
 * floor, or the floor itself for one of the tree's first KOF_SCAN_EMU_FLOOR_RUNS runs, else 0.
 * `commit` says the run is starting (the run counts toward the floor runs); a probe
 * (oc_emu_run, before it counts the ask) does not.
 */
static uint64_t emu_grant(struct kof_scanner *sc, uint64_t own, int commit)
{
	const uint64_t left = sc->ledger.emu_insn_left;
	const uint64_t floor = own < EMU_INSN_MIN ? own : EMU_INSN_MIN;
	const int protect = sc->ledger.emu_floor_left != 0;

	if (commit && protect)
		sc->ledger.emu_floor_left--;
	if (left >= own)
		return own;
	if (left >= floor)
		return left;
	return protect ? floor : 0u;
}

/* A run's total so far, charged to the tree for what it did since the last call. */
static void emu_spend(struct kof_scanner *sc, uint64_t total)
{
	oc_emu_charge(sc, total > sc->obj.emu.spent ? total - sc->obj.emu.spent : 0u);
	sc->obj.emu.spent = total;
}

/*
 * THE INTERPRETER AND THE SCAN'S OWN MEMORY CEILING.
 *
 * A caller who set max_resident_bytes did so to bound what this scan holds at any
 * instant, and an interpreter allocating outside that number would make the
 * setting a lie. So the guest's memory is charged to the scan's ledger - but AS IT
 * IS TAKEN (emu_account, which the machine calls for its table, its private pages
 * in chunks, its snapshots), not as it might be: this was a page cap taken from
 * half of what the ceiling had left, floored at 4 MiB and capped at 128 MiB, which
 * made the same object map a different amount of address space under a different
 * allowance and left the memory it really took out of the ledger altogether.
 *
 * The cap that remains is the machine's own bound, the same under every
 * allowance: EMU_PAGES_MAX of guest address space (what an unlimited caller always
 * got). What an allowance cuts is reported - the machine says
 * KGENOME_EMU_HIT_MEM, the refusal marks the object incomplete (oc_scan_limit).
 */
#define EMU_PAGES_MAX   (128u << 20)

static uint64_t emu_pages(const struct kof_scanner *sc)
{
	(void)sc;
	return EMU_PAGES_MAX / KGENOME_EMU_PAGE;
}

/* The machine asks before it takes memory and tells what it gives back. */
static int emu_account(void *user, int64_t bytes)
{
	struct kof_scanner *sc = user;

	if (bytes < 0) {
		const uint64_t back = (uint64_t)-bytes;

		oc_scan_release(sc, back);
		sc->emu.charged = back > sc->emu.charged ? 0u : sc->emu.charged - back;
		return 1;
	}
	if ((uint64_t)bytes > oc_scan_room(sc)) {
		/* The answer of this run is shorter than the object's: said. */
		oc_scan_limit(sc);
		return 0;
	}
	scan_charge(sc, (uint64_t)bytes);
	sc->emu.charged += (uint64_t)bytes;
	return 1;
}

/*
 * THE INTERPRETER'S BUDGET, as kgenome takes it: the engine's two numbers above
 * (the instruction budget `insn`, which the caller may have cut to a slice, and
 * the address space emu_pages gives it) carried in the struct kgenome_budget the
 * lib reads and nothing else - the lib never goes looking for them in engine
 * state. The values are unchanged; this is only where they are written down.
 */
static struct kgenome_budget emu_budget(struct kof_scanner *sc,
					uint64_t obj_size, uint64_t insn)
{
	struct kgenome_budget kb;

	kgenome_budget_default(&kb, obj_size, 0);
	kb.max_insn = insn;
	kb.max_bytes = emu_pages(sc) * KGENOME_EMU_PAGE;
	kb.account = emu_account;
	kb.account_user = (void *)sc;
	return kb;
}


int oc_emit_exact(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n)
{
	return oc_emit_all(ctx, p, n) == n;
}


uint32_t kof_scan_emu_unpack(const struct kof_obj_ctx *ctx, int force)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu *e;
	kof_buf b;
	int is_pe;

	if (!sc || !sc->cur.src || !ctx->file_header)
		return 0;
	/*
	 * TWO FORMATS NOW, and the PE half arrived long after the ELF one.
	 *
	 * This read `ctx->format != KOF_FMT_ELF`, which was right when the
	 * bridge could only build an ELF process image. emu_unpack.h carries
	 * the argument for running a PE with no Windows API behind it; what
	 * matters here is that the two are the same shape from this side - a
	 * gate, a run, and a set of written pages to harvest - so the only
	 * thing that forks is which pair is called.
	 */
	if (ctx->format != KOF_FMT_ELF && ctx->format != KOF_FMT_PE)
		return 0;
	if (!oc_can_produce(sc))
		return 0;
	is_pe = ctx->format == KOF_FMT_PE;
	b = kof_src_buf(sc->cur.src);
	if (is_pe) {
		const struct kgenome_pe_info *info = kof_pe(ctx);

		struct kgenome_obj gobj;

		kof_genome_obj(ctx, &gobj);
		if (!force && kgenome_emu_unp_gate_pe(&gobj, info, b.p, b.n) ==
			      KGENOME_EMU_UNP_NO)
			return 0;
		{
			struct kgenome_emu_oep oep[KGENOME_EMU_EXEC_WATCH];
			unsigned k;

			for (k = 0; k < sc->cur.n_xw; k++) {
				oep[k].rva = sc->cur.xw[k].rva;
				oep[k].len = sc->cur.xw[k].len;
			}
			KOF_TRACE("[emu] oep ranges=%u\n", sc->cur.n_xw);
			{
				/* See emu_nolimit_ms in emu_unpack_*.c: the
				 * experiment switch, which replaces every work
				 * bound with a wall clock. 2 GB of guest pages
				 * is what "bounded by RAM" means here. */
				uint64_t bi = emu_grant(sc, emu_insn(b.n), 1);
				uint64_t idle = 0;
				unsigned ext = force ? KGENOME_EMU_EXTEND_MAX : 0u;
				struct kgenome_budget kb;

				if (!bi) {
					emu_denied(sc);
					return 0;
				}

				/* An extension is another slice of the run's own limit, so
				 * it must fit in the tree's allowance too. */
				if (bi && ext && sc->ledger.emu_insn_left > bi) {
					const uint64_t more = (sc->ledger.emu_insn_left - bi) / bi;

					if (more < ext)
						ext = (unsigned)more;
				} else if (ext) {
					ext = 0u;
				}

				/*
				 * AND A SLICE, WHEN THE MODULE ASKED FOR ONE -
				 * see `emu_slice`. The real ceiling is kept so
				 * that a stop at the slice can be told from a
				 * stop at the budget, which are opposite
				 * answers: one means "look and carry on", the
				 * other means "this is all there will be".
				 */
				sc->obj.emu.full = bi;
				if (sc->obj.emu.slice && sc->obj.emu.slice < bi)
					bi = sc->obj.emu.slice;
				KOF_TRACE("[emu] budget full=%llu slice=%llu use=%llu\n",
						(unsigned long long)sc->obj.emu.full,
						(unsigned long long)sc->obj.emu.slice,
						(unsigned long long)bi);

				/*
				 * A MODULE THAT ASKED FOR THE INTERPRETER GETS
				 * A LONGER LEASH, and only it does.
				 *
				 * The stall ceiling ends a run that has not
				 * touched a new page for four million
				 * instructions, which is the right answer for
				 * an object nothing recognised: a decoder fed
				 * junk spins to the budget and costs the scan
				 * every second of it. It is the wrong answer
				 * for a child a packer module produced and
				 * declared it wants run - measured, an MPRESS
				 * child computes for 84623471 instructions
				 * without a new page and then decrypts strings
				 * that are in neither the packed file nor the
				 * static unpacker's output, and a Themida one
				 * needs 5930463.
				 *
				 * So the raise is attached to the declaration
				 * rather than to the constant: a file no
				 * module claimed is bounded exactly as before.
				 */
				/*
				 * ASKED FOR, BY WHOEVER ASKED. `force` is set
				 * when a producer declared KOF_ENG_USE_EMU on
				 * this child and when a heuristic rule asked
				 * for the object in front of it; it is clear
				 * when nothing asked and the engine is trying
				 * the interpreter on its own guess. Reading
				 * cur_want instead covered only the first of
				 * those, so a rule that recognised a protector
				 * got the short ceiling.
				 */
				if (force)
					idle = EMU_IDLE_DECLARED;
				kb = emu_budget(sc, b.n, bi);
				e = kgenome_emu_unp_run_pe(&(const struct kgenome_emu_unp_pe_req){
						.file = b.p,
						.n = b.n,
						.info = info,
						.imports = oc_pe_imports(sc, ctx),
						.bud = &kb,
						.idle = idle,
						.hand_back = sc->obj.emu.slice != 0,
						.extensions = ext,
						.oep = oep,
						.n_oep = sc->cur.n_xw,
						.decl = &sc->pend.decl,
						.rep = &rep,
					});
			}
		}
	} else {
		const struct kgenome_elf_info *info = kof_elf(ctx);

		struct kgenome_obj gobj;

		kof_genome_obj(ctx, &gobj);
		if (!force && kgenome_emu_unp_gate(&gobj, info, b.p, b.n) ==
			      KGENOME_EMU_UNP_NO)
			return 0;
		{
			const uint64_t grant = emu_grant(sc, emu_insn(b.n), 1);
			struct kgenome_budget kb;

			if (!grant) {
				emu_denied(sc);
				return 0;
			}
			kb = emu_budget(sc, b.n, grant);
			e = kgenome_emu_unp_run(b.p, b.n, info, &kb, &rep);
		}
	}
	emu_spend(sc, e ? kgenome_emu_insn_count(e) : rep.insn);
	/*
	 * A SLICE THAT EXPIRED IS A PAUSE, NOT AN END - see `emu_slice`. The
	 * guest is mid-decryption and the module asked to be shown that; the
	 * machine stays alive exactly as it does for an instruction watch.
	 */
	if (e && rep.stop == KGENOME_EMU_STOP_BUDGET && sc->obj.emu.slice &&
	    kgenome_emu_insn_count(e) < sc->obj.emu.full)
		rep.stop = KGENOME_EMU_STOP_INSN;
	if (e && rep.stop == KGENOME_EMU_STOP_INSN) {
		/*
		 * PAUSED, NOT FINISHED. Nothing is gathered yet - the guest is
		 * mid-stub and whatever it has written so far is a snapshot of
		 * a decryptor at work. The module reads the machine, decides,
		 * and resumes. See `emu_resume` in kofsig.h.
		 */
		sc->emu.live = e;
		if (!sc->emu.rep_p)
			sc->emu.rep_p = calloc(1, sizeof *sc->emu.rep_p);
		if (sc->emu.rep_p)
			*sc->emu.rep_p = rep;
		else
			OC_LIMIT(sc, "emulator report of a paused run not kept");
		sc->emu.paused = 1;
		return 0;
	}
	return oc_emu_gather(ctx, sc, e, rep);
}


/*
 * The machine, and the regions that point into it, let go.
 *
 * Called when the module that asked for a run returns - see unpack_object.
 * Nothing a module kept a pointer to survives this, which is the point: a
 * region is valid for exactly as long as the call that asked for it.
 */
void kof_scan_emu_release(struct kof_scanner *sc)
{
	if (!sc)
		return;
	if (sc->emu.live) {
		kgenome_emu_free(sc->emu.live);
		sc->emu.live = NULL;
	}
	free(sc->emu.own);
	sc->emu.own = NULL;
	{
		uint32_t i;

		for (i = 0; i < sc->emu.n_rgn; i++) {
			free(sc->emu.rgn[i].own);
			sc->emu.rgn[i].own = NULL;
			sc->emu.rgn[i].p = NULL;
		}
	}
	sc->emu.n_rgn = 0;
	oc_scan_release(sc, sc->emu.held);
	sc->emu.held = 0;
}

/*
 * ---- WHAT A MODULE SEES OF A RUN ------------------------------------------
 *
 * The interpreter gathers and these hand the gathering over. Nothing here
 * creates an object: that is the unpack module's job, through the same
 * declarations every other producer uses.
 */
uint32_t oc_emu_run(const struct kof_obj_ctx *ctx, uint32_t vouch)
{
	/* A vouch is honoured from the --heur level the module named, and a
	 * scan with heuristics off honours none - see vouch_level. */
	int vouched;

	struct kof_scanner *sc = kof_scan_of(ctx);

	/*
	 * THE HOST'S REFUSALS, IN ONE PLACE.
	 *
	 * A module asks; whether it may is the host's answer, because every
	 * one of these is a budget - how deep through packers, how many runs
	 * this scan has already spent, whether an interpreter is allowed at
	 * all. See QUALITY_AUDIT.txt I.A.
	 */
	/*
	 * WHY A RUN DID NOT HAPPEN, on request.
	 *
	 * Every refusal below is silent and there are six of them, so a module
	 * that asked and got nothing back could not tell "the interpreter ran
	 * and the program wrote nothing" from "the host never started it" -
	 * which are opposite problems. Same argument, and same switch, as the
	 * stop-reason trace further down.
	 */
	vouched = sc && vouch && sc->cur.heur_lvl >= vouch;
	if (sc)
		KOF_TRACE("[emu] ask: vouched=%d live=%d stance=%d packed=%d spent=%llu\n",
			vouched, sc->emu.live ? 1 : 0, (int)sc->obj.emu.stance,
			sc->obj.open.packed_here, (unsigned long long)sc->st.heur_emu);
	if (!sc || sc->emu.live)
		return 0;               /* one run at a time */
	/*
	 * AND ONE PER OBJECT. The machine is released the moment the module
	 * that drove it returns, so emu_live is clear again by the time the
	 * next module is offered the same object - and without this every
	 * module that declines it in turn would pay for a run of its own.
	 */
	if (sc->obj.emu.ran)
		return 0;
	/* --emu never, and the packer-depth ceiling. Neither is a budget and
	 * neither yields to a vouch - see emu_stance in scan.h. */
	if (sc->obj.emu.stance == KOF_EMU_STANCE_BANNED)
		return 0;
	/* A packer already opened this, so the payload is in hand and running
	 * it as well is peeling it and then running it anyway. Under
	 * KOF_EMU_ONLY the interpreter stands in for the packer modules, so
	 * that is not a refusal. */
	if (sc->obj.open.packed_here && !kof_emu_stance_only(sc->obj.emu.stance))
		return 0;
	/*
	 * NOBODY SPOKE FOR IT AND UNASKED RUNS ARE OFF. A module that vouches
	 * and a database that asked both get past this; what does not is the
	 * generic receiver guessing, in a mode whose caller wants no
	 * interpreter unless something argued for one.
	 */
	if (!vouched && sc->obj.emu.stance == KOF_EMU_STANCE_NOBODY)
		return 0;
	/* The scan's own ceiling on how many runs it will spend - see
	 * KOF_SCAN_EMU_MAX. */
	if (!sc->ledger.emu_left) {
		/* The tree has had its runs. Refused AND SAID, once for this object:
		 * what the interpreter would have shown of it is not in the answer. */
		if (!sc->obj.emu.refused) {
			sc->obj.emu.refused = 1;
			oc_scan_limit(sc);
		}
		return 0;
	}
	/* The tree's instruction allowance (see emu_grant): an ELF or PE that would be run
	 * and cannot be is refused here, before the ask is counted as a run. */
	if ((ctx->format == KOF_FMT_ELF || ctx->format == KOF_FMT_PE) && sc->cur.src &&
	    !emu_grant(sc, emu_insn(kof_src_buf(sc->cur.src).n), 0)) {
		emu_denied(sc);
		return 0;
	}
	sc->ledger.emu_left--;
	sc->st.heur_emu++;
	sc->obj.emu.ran = 1;
	sc->obj.emu.run_by = sc->mod.cur;   /* the one carrier: see kid_push */
	/*
	 * VOUCHED BY THE MODULE, OR SPOKEN FOR BY THE DATABASE.
	 *
	 * A family module vouches because it recognised its packer. The generic
	 * receiver cannot, and what speaks for its object is a rule that
	 * declared KOF_ENG_USE_EMU or a producer that said its output needs
	 * running - both resolved in unpack_object, both invisible from a
	 * module. Either way `force` means the same thing to the run: skip the
	 * entropy gate, which is an estimate about objects nobody spoke for.
	 */
	return kof_scan_emu_unpack(ctx, vouched || kof_emu_stance_asked(sc->obj.emu.stance));
}

int oc_emu_region(const struct kof_obj_ctx *ctx, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind)
{
	return kof_scan_emu_region(kof_scan_of(ctx), i, va, len, kind);
}

/*
 * The bytes of a gathered region, which are a SNAPSHOT - see
 * `emu_region_read` in kofsig.h for why that is not the same as emu_read.
 */
uint32_t oc_emu_region_read(const struct kof_obj_ctx *ctx, uint32_t i,
				  uint64_t off, uint8_t *out, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_emu_rgn *r;

	if (!sc || !out || !n || i >= sc->emu.n_rgn)
		return 0;
	r = &sc->emu.rgn[i];
	if (!r->p || off >= r->n)
		return 0;
	if ((uint64_t)n > r->n - off)
		n = (uint32_t)(r->n - off);
	memcpy(out, r->p + off, n);
	return n;
}

/*
 * ---- CHANGING A PAUSED MACHINE ------------------------------------------
 *
 * See `emu_set_reg` in kofsig.h for why a module needs this. All three refuse
 * unless the run is PAUSED: a running machine belongs to the interpreter and a
 * finished one has already gone to the gather.
 */
void oc_emu_set_reg(const struct kof_obj_ctx *ctx, uint32_t gpr,
			  uint64_t value)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.paused || !sc->emu.live)
		return;
	if (gpr == KUNP_REG_IP)
		kgenome_emu_set_rip(sc->emu.live, value);
	else
		kgenome_emu_set_reg(sc->emu.live, gpr, value);
}

void oc_emu_set_ip(const struct kof_obj_ctx *ctx, uint64_t va)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc && sc->emu.paused && sc->emu.live)
		kgenome_emu_set_rip(sc->emu.live, va);
}

uint32_t oc_emu_write(const struct kof_obj_ctx *ctx, uint64_t va,
			    const uint8_t *bytes, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.paused || !sc->emu.live || !bytes || !n)
		return 0;
	/* All or nothing, like every other span this engine hands a module: a
	 * half-written patch is a machine nobody can reason about. */
	return kgenome_emu_write(sc->emu.live, va, bytes, n) ? n : 0u;
}

/*
 * THE ASSEMBLED IMAGE, HANDED TO THE CHILD INSTEAD OF COPIED INTO IT.
 *
 * The run's rebuilt image (sc->emu.own) is the engine's own allocation and the
 * child's image (oc_image) is another of the same size, which the take then filled
 * with a copy: one PE's bytes twice, for the length of the take. When the child's
 * extent is the fresh zeroed one oc_image made and the cursor is at its start,
 * the answer of a copy is the image followed by zeroes - which is the image buffer
 * grown to the extent's size with its tail zeroed. So it is taken over: the
 * extent's own memory goes, the image's takes its place, and the region says it
 * has no bytes any more (a module reads a region it has taken only through
 * oc_emu_region_read, which then answers 0; emu_harvest.h does not).
 *
 * Only when the extent is provably what oc_image made: fixed, in memory, nothing
 * spilled, the cursor at 0, and every byte of it still zero - a module that has
 * written into it first gets the copy, which preserves what it wrote beyond the
 * image. 0 means "not handed over": the caller copies.
 */
static int emu_adopt(struct kof_scanner *sc, struct kof_emu_rgn *r)
{
	size_t k;
	uint8_t *m;

	if (!sc->emu.own || r->p != sc->emu.own || r->own || !r->n)
		return 0;
	if (!sc->sink.fixed || sc->sink.fd >= 0 || sc->sink.spilled || sc->sink.at != 0 ||
	    !sc->sink.mem || r->n > sc->sink.cap)
		return 0;
	for (k = 0; k < sc->sink.cap; k++)
		if (sc->sink.mem[k])
			return 0;
	m = sc->emu.own;
	if (sc->sink.cap > r->n) {
		m = realloc(m, sc->sink.cap);
		if (!m)
			return 0;       /* the image is still where it was */
		memset(m + r->n, 0, sc->sink.cap - (size_t)r->n);
	}
	free(sc->sink.mem);
	sc->sink.mem = m;
	sc->sink.at = (size_t)r->n;
	if (sc->sink.at > sc->sink.len)
		sc->sink.len = sc->sink.at;
	sc->emu.own = NULL;
	r->p = NULL;
	sc->st.emu_adopted++;
	oc_scan_release(sc, r->n);      /* the extent is charged already (oc_image) */
	sc->emu.held = r->n > sc->emu.held ? 0u : sc->emu.held - r->n;
	return 1;
}

/* One region into the child being built, at the cursor. */
int oc_emu_take(const struct kof_obj_ctx *ctx, uint32_t i)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || i >= sc->emu.n_rgn || !sc->emu.rgn[i].p)
		return 0;
	if (emu_adopt(sc, &sc->emu.rgn[i]))
		return 1;
	return oc_emit_exact(ctx, sc->emu.rgn[i].p, sc->emu.rgn[i].n);
}

/* Whether anything has already opened this object. */
int oc_opened_already(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	return sc && (sc->child.n || sc->obj.open.packed_here);
}

static int kof_scan_emu_region(const struct kof_scanner *sc, uint32_t i,
			uint64_t *va, uint64_t *len, uint32_t *kind)
{
	if (!sc || i >= sc->emu.n_rgn)
		return 0;
	if (va)
		*va = sc->emu.rgn[i].va;
	if (len)
		*len = sc->emu.rgn[i].n;
	if (kind)
		*kind = sc->emu.rgn[i].kind;
	return 1;
}


/*
 * A child that is already a contiguous range of this object.
 *
 * No copy and no budget: nothing was produced, the parent's mapping is simply seen
 * through a different offset. What bounds it is the child count and the depth,
 * because a window can still be a way of pointing an object at itself.
 */
void oc_emu_watch(const struct kof_obj_ctx *ctx, uint64_t rva,
			uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !len)
		return;
	if (sc->pend.n_xw >= KGENOME_EMU_EXEC_WATCH) {
		/* A range the table has no room for is a range not watched: said. */
		oc_scan_limit(sc);
		return;
	}
	sc->pend.xw[sc->pend.n_xw].rva = rva;
	sc->pend.xw[sc->pend.n_xw].len = len;
	sc->pend.n_xw++;
}

/* This object is a wrapper - see `supersede` in kofsig.h. */
/*
 * A register, and guest memory, of the machine the last run left.
 *
 * Both answer nothing when no machine is alive, which is the honest answer for
 * a module that never asked for a run or whose run the host refused.
 */
uint64_t oc_emu_reg(const struct kof_obj_ctx *ctx, uint32_t gpr)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.live)
		return 0;
	if (gpr == KUNP_REG_IP)
		return kgenome_emu_get_rip(sc->emu.live);
	return kgenome_emu_get_reg(sc->emu.live, gpr);
}

uint32_t oc_emu_read(const struct kof_obj_ctx *ctx, uint64_t va,
			   uint8_t *out, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || !sc->emu.live || !out || !n)
		return 0;
	/* The interpreter answers all-or-nothing for a span, which is the
	 * right shape here too: a partial read of a structure is a structure
	 * nobody can check. */
	return kgenome_emu_read(sc->emu.live, va, out, n) ? n : 0u;
}


/*
 * The instructions a module wants the run paused on, and carrying on from a
 * pause - see `emu_watch_insn` in kofsig.h.
 */
void oc_emu_watch_insn(const struct kof_obj_ctx *ctx,
			     const uint8_t *bytes, uint32_t n, uint32_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc)
		return;
	/* No bytes disarms - see kgenome_emu_watch_insn. Applied to a LIVE machine
	 * too, because that is when a module gives up on pausing and wants the
	 * run to finish. */
	if (!bytes || !n) {
		sc->pend.decl.n_iw = 0;
		sc->pend.decl.iw_len = 0;
		if (sc->emu.live)
			kgenome_emu_watch_insn(sc->emu.live, NULL, 0);
		return;
	}
	if (n > sizeof sc->pend.decl.iw[0].b)
		return;
	/* As many as the emulator will take, not the eight its table starts with; one
	 * past that is a pattern not watched, and said. */
	if (sc->pend.decl.n_iw >= KGENOME_EMU_INSN_WATCH_MAX) {
		oc_scan_limit(sc);
		return;
	}
	memcpy(sc->pend.decl.iw[sc->pend.decl.n_iw].b, bytes, n);
	sc->pend.decl.iw[sc->pend.decl.n_iw].n = (uint8_t)n;
	sc->pend.decl.n_iw++;
	sc->pend.decl.iw_len = len;
}

/*
 * WHAT THE MACHINE IS TOLD BEFORE IT STARTS - see `emu_api_returns` and
 * `emu_patch` in kofsig.h. Both only record: the run has not been built yet,
 * and the declaration travels to it in sc->pend.decl. Both answer 0 when the
 * declaration was not kept (full, or malformed) so a module can tell.
 */
uint32_t oc_emu_api_returns(const struct kof_obj_ctx *ctx, const char *name,
			    uint64_t ret)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu_decl *d;
	size_t l;

	if (!sc || !name)
		return 0;
	d = &sc->pend.decl;
	l = strlen(name);
	if (!l || l >= KGENOME_EMU_SHIM_NAME)
		return 0;
	{
		uint32_t k;

		for (k = 0; k < d->n_shim; k++)
			if (!strcmp(d->shim[k].name, name)) {
				d->shim[k].ret = ret;
				return 1;
			}
	}
	if (d->n_shim >= KGENOME_EMU_SHIM_MAX)
		return 0;
	memcpy(d->shim[d->n_shim].name, name, l + 1u);
	d->shim[d->n_shim].ret = ret;
	d->n_shim++;
	return 1;
}

uint32_t oc_emu_patch(const struct kof_obj_ctx *ctx, const uint8_t *find,
		      const uint8_t *rep, uint32_t n)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu_decl *d;

	if (!sc || !find || !rep || !n || n > KGENOME_EMU_PATCH_LEN)
		return 0;
	d = &sc->pend.decl;
	if (d->n_patch >= KGENOME_EMU_PATCH_MAX)
		return 0;
	memcpy(d->patch[d->n_patch].find, find, n);
	memcpy(d->patch[d->n_patch].rep, rep, n);
	d->patch[d->n_patch].n = (uint8_t)n;
	d->n_patch++;
	return 1;
}

/*
 * End a paused run where it stands and gather what it left - see `emu_stop`
 * in kofsig.h for the measurement that made this necessary.
 *
 * THE SAME HAND-OVER AS A FINISHED RUN. oc_emu_gather takes ownership of the
 * machine, so emu_live is cleared here exactly as oc_emu_resume clears it; a
 * module that stops is not holding anything afterwards that one which ran to
 * the end would not be.
 */



/*
 * How far a run may go before handing control back - see `emu_slice`.
 * Recorded and not acted on here: the run itself reads it, because the
 * ceiling has to be in place before the machine starts.
 */
void oc_emu_slice(const struct kof_obj_ctx *ctx, uint64_t insn)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (sc)
		sc->obj.emu.slice = insn;
}

uint32_t oc_emu_stop(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu *e;

	if (!sc || !sc->emu.paused || !sc->emu.live || !sc->emu.rep_p)
		return 0;
	e = sc->emu.live;
	sc->emu.rep_p->insn = kgenome_emu_insn_count(e);
	sc->emu.paused = 0;
	sc->emu.live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu.rep_p);
}

uint32_t oc_emu_resume(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	struct kgenome_emu *e;
	enum kgenome_emu_stop st;

	if (!sc || !sc->emu.paused || !sc->emu.live || !sc->emu.rep_p)
		return 0;
	e = sc->emu.live;
	/*
	 * Another slice, if the module asked for slices - see `emu_slice`.
	 *
	 * AND THE WRITTEN PAGES ARE SNAPSHOTTED FIRST, which is not optional.
	 * emu_unpack_pe_dump.c's own extension loop does exactly this between slices,
	 * with the reason beside it: what a slice earned is kept before the
	 * next one is risked. Resuming without it threw away everything the
	 * previous slices had decrypted - measured, detection fell from three
	 * samples of four to one.
	 */
	if (sc->obj.emu.slice) {
		uint64_t at = kgenome_emu_insn_count(e);
		uint64_t to = at + sc->obj.emu.slice;

		kgenome_emu_snap_written(e);
		kgenome_emu_set_max_insn(e, to < sc->obj.emu.full ? to : sc->obj.emu.full);
	}
	KOF_TIME_BEGIN(KOF_T_EMU);
	st = kgenome_emu_run(e);
	KOF_TIME_END(KOF_T_EMU);
	if (st == KGENOME_EMU_STOP_BUDGET && sc->obj.emu.slice &&
	    kgenome_emu_insn_count(e) < sc->obj.emu.full)
		st = KGENOME_EMU_STOP_INSN;
	sc->emu.rep_p->stop = st;
	sc->emu.rep_p->insn = kgenome_emu_insn_count(e);
	emu_spend(sc, sc->emu.rep_p->insn);
	if (st == KGENOME_EMU_STOP_INSN)
		return 0;               /* paused again */
	/*
	 * Finished. The machine goes to the gather, which takes ownership of it
	 * exactly as it does on the path with no pause - so emu_live is cleared
	 * here and set again there.
	 */
	sc->emu.paused = 0;
	sc->emu.live = NULL;
	return oc_emu_gather(ctx, sc, e, *sc->emu.rep_p);
}
