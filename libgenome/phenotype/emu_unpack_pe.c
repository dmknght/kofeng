#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_pe.c - the PE run: patches to the image, then the run itself.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and emu_unpack_private.h for what the
 * files share.
 */
#include "emu_unpack_private.h"

/*
 * The image with the declared patches applied, as a private copy - or NULL when
 * there is nothing to apply or no memory for a copy, in which case the run goes
 * ahead on the unpatched bytes rather than not at all. Every occurrence inside
 * a section's file bytes is replaced (a pattern that matches twice is two
 * places the same check lives), in section order, and a pattern is looked for
 * only INSIDE a section: a match straddling two is not code.
 */
static uint8_t *apply_patches(const uint8_t *file, uint64_t n,
			      const struct kgenome_pe_info *info,
			      const struct kgenome_emu_decl *decl)
{
	uint8_t *c = malloc((size_t)n);
	uint32_t k, i;
	int hit = 0;

	if (!c)
		return NULL;
	memcpy(c, file, (size_t)n);
	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];
		uint64_t off = s->file_off, len = s->file_size, at;

		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (k = 0; k < decl->n_patch && k < KGENOME_EMU_PATCH_MAX; k++) {
			const struct kgenome_emu_patch *p = &decl->patch[k];

			if (!p->n || p->n > KGENOME_EMU_PATCH_LEN || len < p->n)
				continue;
			for (at = 0; at + p->n <= len; at++)
				if (c[off + at] == p->find[0] &&
				    !memcmp(c + off + at, p->find, p->n)) {
					memcpy(c + off + at, p->rep, p->n);
					at += p->n - 1u;
					hit = 1;
				}
		}
	}
	if (!hit) {
		free(c);
		return NULL;
	}
	return c;
}

/*
 * THE STEPS OF kgenome_emu_unp_run_pe, in the order it takes them. Each is the
 * statements that used to sit inline, moved whole: nothing here is asked twice
 * and the order is the order the run depends on (the stack before the thread
 * block before the libraries before the import table; the watches before the
 * seeding; what a module asked to be paused on, last).
 */

/* Step 1: the headers and the sections, or the flat map when none could be. 0: nothing mapped. */
static int pe_map_image(struct kgenome_emu *e, const uint8_t *img, uint64_t n,
			const struct kgenome_pe_info *info, uint64_t base,
			struct kgenome_emu_unp_map *m)
{
	uint32_t i;

	/*
	 * THE HEADERS ARE MAPPED, and that is not tidiness.
	 *
	 * A PE is mapped from its first byte: the MZ header, the NT headers
	 * and the section table are all readable at ImageBase in a real
	 * process, and stubs read them. The ones that matter here walk their
	 * own section table to find the compressed stream - the PE analogue of
	 * the AT_PHDR trick the ELF path had to be taught - and a stub that
	 * finds zeros where its section table should be unpacks nothing, with
	 * no fault and no message.
	 */
	if (info->size_of_headers && info->size_of_headers <= n) {
		struct kgenome_emu_unp_extent x;

		memset(&x, 0, sizeof x);
		x.va = base;
		x.file_size = x.mem_size = info->size_of_headers;
		x.perm = KGENOME_EMU_R;
		(void)kgenome_emu_unp_map_extent(e, m, img, n, &x);
	}

	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];
		struct kgenome_emu_unp_extent x;

		if (!s->mem_rva && !s->file_size)
			continue;
		memset(&x, 0, sizeof x);
		x.va = base + s->mem_rva;
		x.off = s->file_off;
		x.file_size = s->file_size;
		x.code = kgenome_pe_sec_is_code(s);
		/*
		 * VirtualSize governs the MAPPING and SizeOfRawData the
		 * CONTENT, and a packer's output is where they differ most:
		 * the section its payload decompresses into has a large
		 * VirtualSize and no file bytes at all. Mapping only the raw
		 * size would leave the stub writing into nothing.
		 */
		x.mem_size = s->mem_size;
		/*
		 * EXECUTABLE WHATEVER THE SECTION SAYS.
		 *
		 * A section's characteristics describe what the LOADER sets,
		 * and a packed image's stub changes it the moment it runs -
		 * every one of them calls VirtualProtect on the section it
		 * decompresses into. Enforcing the file's word about it buys
		 * nothing and costs runs: measured, a VMProtect stub jumps
		 * from its entry point into a section this engine had
		 * reconstructed as data, and the run ended there after 22
		 * instructions. The section flags of a REBUILT image are a
		 * reconstruction anyway - they are this engine's guess about
		 * content, not the original loader's word about permission.
		 *
		 * The execute check in the interpreter is still worth having,
		 * and still fires where it was written for: the fabricated
		 * library images, whose headers a guest reaches only by
		 * resolving an export this build does not have.
		 */
		x.perm = kgenome_emu_unp_perm_of_pe(s->perm) | KGENOME_EMU_X;
		(void)kgenome_emu_unp_map_extent(e, m, img, n, &x);
	}

	/*
	 * THE FAIL-SAFE, and the reasoning is the ELF one unchanged - see
	 * kgenome_emu_unp_map_flat.
	 */
	if (!m->mapped && !kgenome_emu_unp_map_flat(e, m, base, img, n))
		return 0;
	return 1;
}

/* Step 2: the entry point, or the reason there is none (rep->refused). 0: refuse. */
static int pe_entry_point(const struct kgenome_pe_info *info, uint64_t base,
			  struct kgenome_emu_unp_map *m, struct kgenome_emu_unp_report *rep,
			  uint64_t *out)
{
	/* The rules are the ELF image's word for word - see
	 * kgenome_emu_unp_map_entry; a PE's flat map is held to the range it
	 * mapped, which an ELF's is not. */
	return kgenome_emu_unp_map_entry(m, info->entry_rva ? base + info->entry_rva : 0,
					 0, "the image declares no entry point", rep, out);
}

/* Step 3: the stack, the thread block, the libraries and the import table. 0: the run is not worth starting. */
static int pe_build_guest(struct kgenome_emu *e, const uint8_t *file, uint64_t n,
			  const struct kgenome_pe_info *info,
			  const struct kgenome_pe_imptab *imports,
			  uint64_t base, unsigned bits)
{
	struct kgenome_pe_imptab own;

	if (!kgenome_emu_unp_build_stack_pe(e, bits)) {
		return 0;
	}
	/*
	 * AND THE THREAD BLOCK, which the stack alone is not. See kgenome_emu_unp_build_teb_pe
	 * for the measurement that says this belongs here; a failure to map it
	 * is a failure of the run, because a guest that reads gs:[0x30] against
	 * a base of zero faults on data the host chose not to provide rather
	 * than on anything the file did.
	 */
	if (!kgenome_emu_unp_build_teb_pe(e, bits, base,
			  (bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP) -
			  (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE,
			  bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP)) {
		return 0;
	}
	/*
	 * AND THE ONE LIBRARY, AND THE THUNKS THAT POINT INTO IT.
	 *
	 * In that order, because the thunks are filled with addresses inside
	 * the image the line above maps. Neither is fatal to skip - a guest
	 * that never asks for kernel32 never notices either - but a failure
	 * here means the host could not map two pages, and a run under that
	 * much memory pressure is not one worth starting.
	 */
	{
		unsigned mi;

		kgenome_emu_win_setup(e, base);
		/*
		 * kernel32 must map or the run is pointless - it is what every
		 * stub asks for. The rest are best effort: a library that
		 * could not be mapped is one the guest is told it does not
		 * have, which is a true answer and a visible one.
		 */
		for (mi = 0; mi < kgenome_emu_win_mod_count(); mi++)
			if (!kgenome_emu_unp_build_module_pe(e, bits, mi) &&
			    mi == KGENOME_EMU_WIN_MOD_K32) {
				return 0;
			}
		{
			unsigned nf;

			/*
			 * THE IMPORT TABLE IS THE OBJECT'S, handed over, and
			 * not walked again. One built from a different buffer
			 * is not read - its offsets would index the wrong
			 * bytes - so a caller with none, or the wrong one,
			 * gets a table from the same builder that makes the
			 * scanner's, for this run only.
			 */
			memset(&own, 0, sizeof own);
			if (!kgenome_pe_imptab_is_of(imports,
						 kof_buf_make(file, n))) {
				kgenome_pe_imptab_build(kof_buf_make(file, n),
						    info, &own);
				imports = &own;
			}
			nf = kgenome_emu_unp_fill_iat_pe(e, imports, kof_buf_make(file, n),
					 info, base, bits);
			kgenome_pe_imptab_free(&own);

			KOF_TRACE("[emu] iat filled=%u dir=%#llx\n", nf,
					(unsigned long long)
					info->dir[KGENOME_PE_DIR_IMPORT].rva);
		}
	}
	return 1;
}

/* Step 4: where the program will be when the loader is done: the watches. */
static void pe_watch_handover(struct kgenome_emu *e, const struct kgenome_pe_info *info,
			      uint64_t base, const struct kgenome_emu_oep *oep,
			      unsigned n_oep)
{
	uint32_t i;

	/*
	 * AND WHERE THE PROGRAM WILL BE WHEN THE LOADER IS DONE.
	 *
	 * A section with a VirtualSize and no SizeOfRawData is a region the
	 * file declares and does not supply - so nothing but the run can put
	 * code in it, and a fetch from one is the loader handing over. See
	 * kgenome_emu_watch_exec, which carries the argument and the attribution
	 * for where the idea came from.
	 *
	 * NOT THE SECTION THE ENTRY POINT IS IN, even when that one is hollow
	 * too: the run starts there, so watching it would stop on the first
	 * instruction.
	 */
	/*
	 * ONLY WHEN THE HOLLOW SECTIONS ARE THE PROGRAM, which is not every
	 * file that has one.
	 *
	 * The shape this is for puts the whole image inside the section the
	 * entry point is in and leaves the originals with a size and no bytes:
	 * then a fetch from one of them is the loader handing over. The other
	 * shape - SecureEngine's - is the reverse. Its `.themida` is the
	 * hollow one and it holds the LOADER, while the program sits in the
	 * sections that do have bytes, encrypted. Watching hollow sections
	 * there stops the run on the loader's first instruction, which is the
	 * opposite of the intent.
	 *
	 * The discriminator is where the file's raw bytes are: in the first
	 * shape the entry section holds almost all of them, in the second it
	 * does not. That is the same test bases/unp/hollow_pe.c is built on.
	 */
	/*
	 * WHAT THE MODULE SAID, FIRST, because it knows the container and this
	 * file does not. The structural rule below is the fallback for an
	 * object no module spoke for.
	 */
	for (i = 0; i < n_oep; i++)
		if (oep[i].len) {
			kgenome_emu_watch_exec(e, base + oep[i].rva,
					   base + oep[i].rva + oep[i].len);
			/*
			 * AND THE SAME RANGES WATCHED FOR WRITES.
			 *
			 * A module naming these is saying "the program will be
			 * here", and for a protector that means two different
			 * things at two different times: the loader DECRYPTS
			 * into them and only then JUMPS into them. The exec
			 * watch catches the jump; this catches the decryption,
			 * which happens first and happens even when the jump
			 * never does. See kgenome_emu_watch_write.
			 */
			kgenome_emu_watch_write(e, base + oep[i].rva,
					    base + oep[i].rva + oep[i].len);
		}

	if (!n_oep)
	{
		uint64_t raw_other = 0, raw_entry = 0;

		for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
			if (i == info->entry_sec)
				raw_entry = info->sec[i].file_size;
			else
				raw_other += info->sec[i].file_size;
		}
		if (raw_entry && raw_other * 20u <= raw_entry)
			for (i = 0; i < info->sec_count &&
				    i < KGENOME_PE_MAX_SECTIONS; i++) {
				const struct kgenome_pe_sec *s = &info->sec[i];

				if (i == info->entry_sec || s->file_size ||
				    !s->mem_size)
					continue;
				kgenome_emu_watch_exec(e, base + s->mem_rva,
						   base + s->mem_rva +
						   s->mem_size);
			}
	}
}

/* Step 5: the run's own state: the image, the stack range, the stages, rip and the seeds. */
static void pe_set_run_state(struct kgenome_emu *e, const uint8_t *file, uint64_t n,
			     const struct kgenome_pe_info *info, uint64_t base,
			     unsigned bits, uint64_t idle, uint64_t entry)
{
	uint32_t i;

	kgenome_emu_set_self(e, file, n);
	if (idle)
		kgenome_emu_set_idle(e, idle);
	kgenome_emu_count_mod_reads(e, 1);
	/* The stub's own section, so a jump it makes inside itself is not read
	 * as a handover - see kgenome_emu_set_stub_range. */
	if (info->entry_sec < info->sec_count) {
		const struct kgenome_pe_sec *es = &info->sec[info->entry_sec];

		kgenome_emu_set_stub_range(e, base + es->mem_rva,
				       base + es->mem_rva + es->mem_size);
	}
	/* And the image itself, so the run can dump it at the handover rather
	 * than at its end - see the write-then-execute snapshot in emu_interp.c. */
	{
		uint64_t hi = 0;
		uint32_t si;

		for (si = 0; si < info->sec_count &&
			     si < KGENOME_PE_MAX_SECTIONS; si++) {
			uint64_t end = info->sec[si].mem_rva +
				       info->sec[si].mem_size;

			if (end > hi)
				hi = end;
		}
		if (hi) {
			kgenome_emu_set_image_range(e, base, base + hi);
			/* And the handover test, which needs that range - see
			 * kgenome_emu_set_oep_watch. */
			kgenome_emu_set_oep_watch(e, 1);
		}
	}
	{
		uint64_t top = bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP;

		kgenome_emu_set_stack_range(e,
			top - (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE, top);
	}
	/*
	 * EVERY SECTION IS A STAGE TO WATCH, and the entry point's is marked
	 * as already seen because the run begins in it. See kgenome_emu_hop_add.
	 */
	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *hs = &info->sec[i];

		if (!hs->mem_size)
			continue;
		kgenome_emu_hop_add(e, base + hs->mem_rva,
				base + hs->mem_rva + hs->mem_size,
				i == info->entry_sec);
	}
	kgenome_emu_set_rip(e, entry);

	/*
	 * The same seeding as the ELF path and for the same family of decoders
	 * that index off whatever register the caller left pointing at them.
	 * RSP and RBP are excluded: kgenome_emu_unp_build_stack_pe just set them.
	 */
	{
		static const unsigned seed[] = {
			KGENOME_EMU_RAX, KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_RBX,
			KGENOME_EMU_RSI, KGENOME_EMU_RDI
		};
		unsigned k;

		for (k = 0; k < sizeof seed / sizeof seed[0]; k++)
			kgenome_emu_set_reg(e, seed[k], entry);
	}
}

/* Step 6: what a module asked to be paused on, set last. */
static void pe_declare_watches(struct kgenome_emu *e, const struct kgenome_emu_decl *decl)
{
	unsigned k;

	/*
	 * AND WHAT A MODULE ASKED TO BE PAUSED ON, set last so that everything
	 * the setup does is behind it - see kgenome_emu_watch_insn.
	 */
	if (!decl)
		return;
	for (k = 0; k < decl->n_iw; k++)
		kgenome_emu_watch_insn(e, decl->iw[k].b, decl->iw[k].n);
	if (decl->n_iw)
		kgenome_emu_watch_insn_len(e, decl->iw_len);
	for (k = 0; k < decl->n_shim; k++)
		(void)kgenome_emu_shim_api(e, decl->shim[k].name, decl->shim[k].ret);
}

/* Step 7 is the run (kgenome_emu_unp_emu_run_while_producing); step 8: what it says about itself. */
static void pe_report(struct kgenome_emu *e, struct kgenome_emu_unp_report *rep,
		      enum kgenome_emu_stop st, uint64_t entry, int improvised)
{
	uint64_t xl = 0, xb = kgenome_emu_exc_scratch(e, &xl);
	uint32_t it = 0, k = 0;
	uint64_t va, len;
	const uint8_t *bytes;

	if (rep) {
		rep->stop = st;
		/* Where the host wrote the exception records, so the
		 * harvest can skip them. See kgenome_emu_unp_report. */
		rep->exc_lo = xb;
		rep->exc_hi = xb ? xb + xl : 0;
		rep->insn = kgenome_emu_insn_count(e);
		rep->entry = entry;
		rep->improvised = improvised;
		rep->detail = kgenome_emu_stop_detail(e);
		/*
		 * A fault at the sentinel is the stub RETURNING, which
		 * is how a PE entry point finishes - see
		 * kgenome_emu_unp_report.returned. Read off rip rather
		 * than out of `detail`, because a number is a fact and
		 * a message is a sentence somebody may reword.
		 */
		rep->returned = st == KGENOME_EMU_STOP_FAULT &&
				kgenome_emu_rip(e) == KGENOME_EMU_UNP_PE_RET_MAGIC;
		for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes,
						   &len); )
			k++;
		rep->images = k;
		for (it = 0, k = 0;
		     kgenome_emu_next_written(e, &it, &va, &bytes, &len); )
			k++;
		rep->written = k;
	}
}

struct kgenome_emu *kgenome_emu_unp_run_pe(const struct kgenome_emu_unp_pe_req *rq)
{
	const uint8_t *file = rq->file;
	const uint64_t n = rq->n;
	const struct kgenome_pe_info *info = rq->info;
	const struct kgenome_pe_imptab *imports = rq->imports;
	const struct kgenome_budget *bud = rq->bud;
	const uint64_t idle = rq->idle;
	const int hand_back = rq->hand_back;
	const unsigned extensions = rq->extensions;
	const struct kgenome_emu_oep *oep = rq->oep;
	const unsigned n_oep = rq->n_oep;
	const struct kgenome_emu_decl *decl = rq->decl;
	struct kgenome_emu_unp_report *rep = rq->rep;
	struct kgenome_emu_cfg cfg;
	uint8_t *patched = NULL;
	const uint8_t *img;
	struct kgenome_emu *e;
	uint64_t base, entry = 0;
	struct kgenome_emu_unp_map m;

	if (rep)
		memset(rep, 0, sizeof *rep);
	if (!file || !n || !info || !info->valid)
		return NULL;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = bud ? bud->max_insn : 0;
	cfg.max_pages = bud ? (bud->max_bytes + KGENOME_EMU_PAGE - 1u) / KGENOME_EMU_PAGE : 0;
	/*
	 * The width comes from the FILE, exactly as on the ELF side: PE32
	 * holds i386 code and PE32+ holds amd64, and the parser has already
	 * decided which magic this carries.
	 */
	cfg.bits = info->pe32_plus ? 64u : 32u;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;

	img = file;
	if (decl && decl->n_patch) {
		patched = apply_patches(file, n, info, decl);
		if (patched)
			img = patched;
	}

	base = info->image_base ? info->image_base
			        : (cfg.bits == 64 ? KGENOME_EMU_UNP_PE_BASE_64 : KGENOME_EMU_UNP_PE_BASE_32);

	kgenome_emu_unp_map_init(&m, ~0ull);
	if (!pe_map_image(e, img, n, info, base, &m)) {
		free(patched);
		kgenome_emu_free(e);
		return NULL;
	}

	/* The pages own their bytes now; the patched copy has done its job. */
	free(patched);
	patched = NULL;

	if (!pe_entry_point(info, base, &m, rep, &entry)) {
		kgenome_emu_free(e);
		return NULL;
	}

	if (rep) {
		uint64_t top = cfg.bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP;

		rep->stack_hi = top;
		rep->stack_lo = top - (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE;
	}
	if (!pe_build_guest(e, file, n, info, imports, base, cfg.bits)) {
		kgenome_emu_free(e);
		return NULL;
	}
	pe_watch_handover(e, info, base, oep, n_oep);
	pe_set_run_state(e, file, n, info, base, cfg.bits, idle, entry);
	pe_declare_watches(e, decl);
	pe_report(e, rep, kgenome_emu_unp_emu_run_while_producing(e, bud ? bud->max_insn : 0, hand_back, extensions), entry, m.improvised);
	return e;
}
