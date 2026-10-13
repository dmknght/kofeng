/*
 * diag_emu_image.c - an image for a relocatable object, its relocations, and names read out of guest memory.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_int.h for what the
 * files share.
 */
#include "diag_emu_int.h"

/*
 * ---- AN IMAGE FOR A RELOCATABLE OBJECT -----------------------------------
 *
 * A .ko has no program header, so kgenome_emu_unp_build has nothing to lay out
 * and the routine above never reaches a kernel module at all. What it has is
 * SECTIONS, and for a run that starts between two known call sites that is
 * enough: map every allocatable one where the file holds it, at the offset
 * the file holds it at.
 *
 * THE FILE IS THE ADDRESS SPACE, which is not a convenience but the only
 * coherent reading. sh_addr in an ET_REL is zero - the linker has not placed
 * anything - and kgenome_elf_relcalls reports its sites as file offsets, so the
 * decoder, the relocation table and this mapping all speak the same numbers.
 * cell_off_to_va makes the same choice for the same reason.
 *
 * RELOCATIONS ARE NOT APPLIED, and that is the boundary of what this can do.
 * A call to an import is `e8 00 00 00 00`, so it is never EXECUTED here - the
 * run stops before it, and the routine supplies the result. A RIP-relative
 * data reference is also a hole, and one in the span between two sites sends
 * a load or a store to the wrong address; the run faults, the span yields
 * nothing, and nothing wrong is reported. Diamorphine's give_root has no such
 * reference between its two calls. Its init_module does - `mov %rax,.bss+0x3c`
 * - and that span is one this cannot read yet.
 */
/*
 * ---- APPLYING THE RELOCATIONS ---------------------------------------------
 *
 * Without this every pointer the module loads is the hole the linker was
 * supposed to fill, so two calls handed the same object both receive zero and
 * nothing can tell they were handed the same thing. It is the single reason
 * the kprobe pair, list_del's THIS_MODULE and the syscall table reads were
 * all invisible.
 *
 * ONLY THE FOUR THAT PLACE AN ADDRESS, and only for a symbol this object
 * defines. PLT32 is a call, which this routine steps over rather than takes;
 * an undefined symbol is a promise to the loader and there is nothing here to
 * point at, so its hole is left as a hole and the span that needs it ends
 * quietly.
 *
 * THE PATCH GOES INTO THE EMULATOR'S MEMORY, not into the caller's file. The
 * object on disk is evidence and is never written to - see the note in
 * CLAUDE.md on scans that repair in place.
 */
struct relapply { struct kgenome_emu *em; uint64_t size; };

/*
 * IS THERE A PRINTABLE, NUL-TERMINATED NAME AT THIS OFFSET.
 *
 * A symbol name, not a string in general: short, printable, and ending. The
 * bound is what the kernel's own symbol table allows, and the floor keeps a
 * stray byte that happens to be followed by a NUL from being read as a name.
 */
#define DIAG_NAME_MIN 3u
#define DIAG_NAME_MAX 64u

/*
 * ---- A C STRING OUT OF THE GUEST'S MEMORY ---------------------------------
 *
 * Read from the emulator, and never from the file. A name an object hands a
 * kernel resolver may be built at run time, or sit in the file encoded and be
 * decoded in place before the call - and in both cases the bytes that matter
 * exist only in the guest, after the code in front of the call has run. The
 * file's copy is the encoding, or nothing.
 *
 * ONE BYTE AT A TIME because a name may end a page short of an unmapped one,
 * and a read of a fixed length that crosses it fails whole - see the note on
 * kgenome_emu_read. The bound is a symbol's length, so the cost is a few reads per
 * candidate and this runs at a handful of call sites.
 *
 * Returns the length, or 0 when what is there is not a symbol name - the same
 * charset the file-side check used: letters, digits, underscore, and the dot
 * and dollar the kernel and the linker really use. A compiler version string
 * lands on a register by accident and is not accepted for it.
 */
unsigned kgenome_diag_emu_guest_name(struct kgenome_emu *em, uint64_t va, char *out)
{
	unsigned i;

	if (!va)
		return 0;
	for (i = 0; i <= KGENOME_DIAG_STR_MAX; i++) {
		uint8_t c;

		if (!kgenome_emu_read(em, va + i, &c, 1u))
			return 0;
		if (!c) {
			out[i] = 0;
			return i >= DIAG_NAME_MIN ? i : 0;
		}
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '.' ||
		      c == '$'))
			return 0;
		if (i < KGENOME_DIAG_STR_MAX)
			out[i] = (char)c;
	}
	return 0;               /* too long to be a symbol */
}

/*
 * HOW MANY WORDS OF AN OBJECT ARE LOOKED AT for a pointer to a name. This is
 * a bound on COST and it is deliberately far past any probe or resolver
 * argument that exists - struct kprobe is about 0x70 bytes - because the
 * layout is a fact about a kernel build and the bound must not be what
 * decides whether a name is found.
 */
#define DIAG_NAME_OBJ_WORDS 32u

/*
 * THE NAMES A CALL WAS GIVEN, kept in the scan. See kgenome_flow_name_arg for
 * where the vocabulary says to look; this does the looking.
 *
 * An OBJECT is read word by word and every word that points at a symbol name
 * is kept - never one particular field. The probe's own link pointers, its
 * handlers and its resolved address are pointers too, and none of them point
 * at a run of identifier characters ending in a zero.
 */
void kgenome_diag_emu_capture_names(struct kgenome_diag_scan *s, struct kgenome_emu *em,
			  uint16_t cap, uint16_t node)
{
	unsigned arg, kind = kgenome_flow_name_arg(cap, &arg);
	uint64_t a;
	char nm[KGENOME_DIAG_STR_MAX + 1u];

	if (!kind)
		return;
	a = kgenome_emu_get_reg(em, kgenome_diag_sysv_arg[arg]);
	if (kind == KGENOME_NAME_DIRECT) {
		if (kgenome_diag_emu_guest_name(em, a, nm))
			kgenome_diag_str_add(s, cap, node, nm);
		return;
	}
	{
		unsigned w;

		for (w = 0; w < DIAG_NAME_OBJ_WORDS; w++) {
			uint8_t q[8];
			uint64_t p = 0;
			unsigned b;

			if (!kgenome_emu_read(em, a + (uint64_t)w * 8u, q, 8u))
				break;
			for (b = 0; b < 8u; b++)
				p |= (uint64_t)q[b] << (8u * b);
			if (kgenome_diag_emu_guest_name(em, p, nm))
				kgenome_diag_str_add(s, cap, node, nm);
		}
	}
}

static int apply_reloc(void *user, uint64_t where, uint32_t type,
		       uint64_t sym, int defined, int64_t addend,
		       uint64_t nameoff)
{
	(void)nameoff;          /* this one is making the image runnable */

	struct relapply *a = user;
	uint64_t p = KGENOME_DIAG_REL_BASE + where;
	uint64_t s = KGENOME_DIAG_REL_BASE + sym;
	uint8_t b[8];
	unsigned n = 0, i;
	uint64_t v = 0;

	if (!defined || where + 4u > a->size)
		return 1;
	switch (type) {
	case 1u:                                /* R_X86_64_64   S + A      */
		v = s + (uint64_t)addend; n = 8u; break;
	case 2u:                                /* R_X86_64_PC32 S + A - P  */
		v = s + (uint64_t)addend - p; n = 4u; break;
	case 10u:                               /* R_X86_64_32   S + A      */
	case 11u:                               /* R_X86_64_32S  S + A      */
		v = s + (uint64_t)addend; n = 4u; break;
	default:
		return 1;
	}
	if (where + n > a->size)
		return 1;
	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(v >> (8u * i));
	kgenome_emu_write(a->em, p, b, n);
	return 1;             /* an image needs every one of them */
}

/*
 * THE PAGES A RUN MAY TOUCH, charged to the scan's ledger before the emulator
 * is made: the emulator's own default (KGENOME_EMU_DEF_PAGES) or what the
 * allowance has left, whichever is less, and at least one. A run is charged for
 * the most it may take and not for what it takes, so the ledger can refuse it
 * before it exists. Released when the emulator is freed.
 */
uint64_t kgenome_diag_emu_emu_pages_charge(struct kgenome_diag_scan *s)
{
	uint64_t pg = kgenome_ledger_room(&s->led) / KGENOME_EMU_PAGE;

	if (pg > KGENOME_EMU_DEF_PAGES)
		pg = KGENOME_EMU_DEF_PAGES;
	if (!pg) {
		kgenome_diag_note(s, KGENOME_OVER_BUDGET);
		pg = 1;
	}
	if (kgenome_ledger_charge(&s->led, pg * KGENOME_EMU_PAGE))
		s->emu_charged += pg * KGENOME_EMU_PAGE;
	return pg;
}

/* The run is over (its emulator freed): give its pages back. */
void kgenome_diag_emu_emu_pages_release(struct kgenome_diag_scan *s)
{
	kgenome_ledger_release(&s->led, s->emu_charged);
	s->emu_charged = 0;
}

/* The relocatable image could not be built - a map the emulator refused, for
 * want of pages or memory. The run does not happen, and the scan says why. */
static void rel_image_fail(struct kgenome_diag_scan *s, struct kgenome_emu *em)
{
	kgenome_emu_free(em);
	kgenome_diag_emu_emu_pages_release(s);
	kgenome_diag_note(s, KGENOME_NOMEM);
}

/*
 * WHY A RUN ENDED, as a status. The ordinary endings - the guest exits, hands
 * off, or faults where a stager would - say nothing; the three that mean the
 * answer is partial because of a limit or a gap in the emulator do:
 *
 *   BUDGET       the instruction budget was spent - KGENOME_OVER_BUDGET, the
 *                caller's number to raise
 *   STALLED      the run waited on something that cannot happen, or touched no
 *                new page for KGENOME_EMU_IDLE instructions - KGENOME_TRUNCATED
 *   UNSUPPORTED  an instruction this build does not carry - KGENOME_UNSUPPORTED
 */
void kgenome_diag_emu_emu_stop_status(struct kgenome_diag_scan *s, enum kgenome_emu_stop st)
{
	if (st == KGENOME_EMU_STOP_BUDGET)
		kgenome_diag_note(s, KGENOME_OVER_BUDGET);
	else if (st == KGENOME_EMU_STOP_STALLED)
		kgenome_diag_note(s, KGENOME_TRUNCATED);
	else if (st == KGENOME_EMU_STOP_UNSUPPORTED)
		kgenome_diag_note(s, KGENOME_UNSUPPORTED);
}

struct kgenome_emu *kgenome_diag_emu_build_rel_image(struct kgenome_diag_scan *s,
				       const struct kgenome_obj *obj,
				       const uint8_t *base, uint64_t size)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *em;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = s->bud.max_insn;
	cfg.max_pages = kgenome_diag_emu_emu_pages_charge(s);
	cfg.bits = obj->arch == KGENOME_ARCH_X86_64 ? 64u : 32u;
	em = kgenome_emu_new(&cfg);
	if (!em) {
		kgenome_diag_emu_emu_pages_release(s);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	if (s->bud.deadline_ms)
		kgenome_emu_set_deadline(em, s->bud.deadline_ms);

	/*
	 * THE WHOLE FILE AS ONE REGION, AT ZERO.
	 *
	 * NOT SECTION BY SECTION, which was the first attempt and mapped
	 * nothing: a section's file offset is aligned to eight or sixteen
	 * bytes, never to a page, and a mapping has to start on one. Every
	 * call failed, the image came back empty, and the routine returned
	 * without a word - the symptom was that gap emulation added exactly
	 * zero links and looked like it had simply found nothing.
	 *
	 * Mapping the file whole is also the honest shape. The address space
	 * of a relocatable object IS its file - sh_addr is zero, the
	 * relocation table reports file offsets, and cell_off_to_va makes the
	 * same identity. One region keeps all three agreeing, and a section
	 * table that disagrees with itself cannot send a step somewhere the
	 * file does not reach.
	 *
	 * THE SLACK IS FOR .bss, which holds no bytes in the file and is
	 * written to all the same.
	 *
	 * AND IT IS NOT AT ZERO. The identity the file enjoys is with OFFSETS,
	 * and offset zero is the null page - a mapping there is refused, which
	 * is right and was the second thing to make the image come back empty.
	 * The region sits at KGENOME_DIAG_REL_BASE and this routine adds it on the way
	 * in and takes it off on the way out; nothing outside sees the bias.
	 */
	if (!kgenome_emu_map(em, KGENOME_DIAG_REL_BASE, base, size,
			 (size + KGENOME_DIAG_REL_SLACK + KGENOME_EMU_PAGE - 1u) &
			 ~(uint64_t)(KGENOME_EMU_PAGE - 1u),
			 KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X)) {
		rel_image_fail(s, em);
		return 0;
	}

	/*
	 * AND AN ARENA FOR THE TOKENS, because a token is dereferenced.
	 *
	 * prepare_creds hands back a struct the caller then WRITES into -
	 * `movq $0x0,0x8(%rax)`, four times, zeroing the uid and gid fields.
	 * A token that is merely a distinctive number is an unmapped address
	 * the moment that happens, and the span dies three instructions in.
	 * MEASURED: every gap faulted at step 3 or 4 until this was here.
	 *
	 * ONE PAGE PER PRODUCER, so a value can be attributed to the call it
	 * came from, and so that a program adding a field offset to it stays
	 * inside that page and stays attributable.
	 */
	if (!kgenome_emu_map(em, KGENOME_DIAG_TOK_BASE, 0, 0,
			 KGENOME_DIAG_TOK_SPAN * KGENOME_EMU_PAGE,
			 KGENOME_EMU_R | KGENOME_EMU_W)) {
		rel_image_fail(s, em);
		return 0;
	}

	/* A stack, high and away from anything the file occupies. */
	if (!kgenome_emu_map(em, KGENOME_DIAG_REL_STACK - 0x10000u, 0, 0, 0x10000u,
			 KGENOME_EMU_R | KGENOME_EMU_W)) {
		rel_image_fail(s, em);
		return 0;
	}
	kgenome_emu_set_reg(em, KGENOME_EMU_RSP, KGENOME_DIAG_REL_STACK - 0x8000u);
	kgenome_emu_set_reg(em, KGENOME_EMU_RBP, KGENOME_DIAG_REL_STACK - 0x8000u);

	/*
	 * AND SOMEWHERE FOR %gs TO POINT, which kernel code reads in its
	 * third instruction.
	 *
	 * Every function compiled with the stack protector begins
	 * `mov %gs:0x0(%rip),%rdi`, and the per-cpu area lives there too.
	 * With the base left at zero that is a read of address zero and the
	 * span dies before it has done anything - MEASURED, Diamorphine's
	 * init_module got three instructions in, 157 bytes short of the
	 * `mov cr0` the walk had been opened for.
	 *
	 * The page is scratch and its contents are not read as the program's:
	 * what comes back is a guard value the code only ever compares
	 * against itself.
	 */
	if (kgenome_emu_map(em, KGENOME_DIAG_REL_PERCPU, 0, 0, KGENOME_EMU_PAGE * 16u,
			KGENOME_EMU_R | KGENOME_EMU_W))
		kgenome_emu_set_seg_base(em, 5u, KGENOME_DIAG_REL_PERCPU);

	{
		struct relapply ra;
		unsigned kind;

		ra.em = em;
		ra.size = size;
		/* BOTH KINDS: an image is made runnable by its code AND by the
		 * pointers its data holds - see struct kgenome_elf_reloc. The code table
		 * is the one the other routes read; the data table is built here and
		 * for nothing else. */
		for (kind = KGENOME_ELF_RELOC_CODE; kind <= KGENOME_ELF_RELOC_DATA; kind <<= 1) {
			const struct kgenome_elf_relocs *t = kgenome_diag_relocs(s, obj, kind);
			uint32_t i;

			for (i = 0; i < t->n; i++)
				(void)apply_reloc(&ra, t->v[i].where, t->v[i].type,
						  t->v[i].sym, t->v[i].defined,
						  t->v[i].addend, t->v[i].nameoff);
		}
	}
	return em;
}
