#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_gate.c - the gate: whether an object hides its code (entropy, loader blobs), for an ELF and for a PE.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and emu_unpack_private.h for what the
 * files share.
 */
#include "emu_unpack_private.h"

/*
 * The threshold, in eighths of a bit, over PT_LOAD|PF_X.
 *
 * Eighths rather than a float: this runs inside the engine, and an integer
 * comparison cannot round differently on a different build.
 */
#define DENSE_EIGHTHS  60u             /* 7.5 bits per byte */
#define DENSE_MIN      512u            /* below this the estimate is noise */

/*
 * The loader test: a ciphertext block in a non-code segment, and an import
 * that can make memory executable. See KGENOME_EMU_UNP_WHY_LOADER.
 *
 * The window is 512 bytes because entropy measured over fewer is not stable:
 * 256 uniformly random bytes score only ~7.1 bits, below the threshold, purely
 * from the finite sample. At 512 the estimate settles - random and ciphertext
 * read ~7.5, ordinary code reads ~4.9 - so the two separate cleanly. The size
 * threshold is what earns the near-zero false positives: measured over 846
 * clean binaries, 16 KB of contiguous high-entropy in a non-code segment beside
 * the import fires on one - git-lfs, whose embedded assets are genuinely that
 * big - where 8 KB fires on three. The cost of the threshold is reach: an
 * encrypted payload smaller than 16 KB, a short stager most of all, slips under
 * it. That is the deliberate trade - a block this size is what a stray
 * high-entropy field cannot reach and a real staged payload clears easily - and
 * it means the signal is for the LARGE encrypted payload, not the small stager.
 */
#define LOADER_EIGHTHS 57u             /* 7.125 bits per byte, over a window */
#define LOADER_WINDOW  512u            /* the entropy is measured this wide */
#define LOADER_BLOB    16384u          /* and this many high bytes in a row */

/* ---- the gate ------------------------------------------------------------ */

/*
 * The longest run of high-entropy windows anywhere in a non-executable
 * PT_LOAD, in bytes. Windows are stepped by their own width, so the answer is
 * a multiple of LOADER_WINDOW; that is deliberate, because a payload straddling
 * a window boundary still fills whole windows on either side of it.
 */
static uint64_t loader_blob(const struct kgenome_elf_info *info,
			    const uint8_t *file, uint64_t n)
{
	uint64_t best = 0, i;

	for (i = 0; i < info->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		const struct kgenome_elf_seg *s = &info->seg[i];
		uint64_t off = s->file_off, len = s->file_size, at, run = 0;

		if (s->type != KGENOME_EMU_UNP_PT_LOAD_TYPE || kgenome_elf_seg_is_code(s) || !len)
			continue;
		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (at = 0; at + LOADER_WINDOW <= len; at += LOADER_WINDOW) {
			uint32_t hist[256];

			memset(hist, 0, sizeof hist);
			kentropy_count(hist, file + off + at, LOADER_WINDOW);
			if (kentropy_hist(hist, LOADER_WINDOW) >= LOADER_EIGHTHS) {
				run += LOADER_WINDOW;
				if (run > best)
					best = run;
			} else {
				run = 0;
			}
		}
	}
	return best;
}

/*
 * Does the file import a way to make memory executable? The name lives in the
 * dynamic string table, which is loaded and so is somewhere in the file's
 * bytes; a substring search finds it without a second parse and without
 * depending on section headers a hostile object may have stripped. A benign
 * mention in .rodata would match too, but only in concert with an 8 KB
 * ciphertext block, and that pair is what the measurement cleared.
 *
 * A NAME DECIDES HERE, AND IS LEFT: the two spellings are libc's own import names (fixed by
 * the loader for a dynamic file), so renaming a symbol of the program does not hide them -
 * but a static build carries neither string, and the same fact is in its code as a syscall
 * number (10 and 319 on x86-64). The structural form is the syscall-number sweep the diagnose
 * already runs; moving the gate onto it changes which objects reach the emulator, so it needs
 * its own measurement (docs/silent_loss_audit.txt, SECTION 5, "names").
 */
static int loader_imports_exec(const uint8_t *file, uint64_t n)
{
	static const char *const want[] = { "mprotect", "memfd_create" };
	unsigned w;

	for (w = 0; w < sizeof want / sizeof want[0]; w++) {
		uint64_t m = strlen(want[w]) + 1;   /* include the NUL: a symbol
						     * name, not a random hit */

		if (m > n)
			continue;
		/*
		 * kof_memmem AND NOT A COMPARE PER POSITION.
		 *
		 * This walked every offset of the object and ran a memcmp at
		 * each - a naive O(n*m) substring search over a whole file,
		 * twice. The host already has the right tool: memmem, which is
		 * Two-Way inside glibc and vectorised, and on Windows the KMP
		 * fallback in kofplatform.h. Same answer, same bound, one call.
		 */
		if (kof_memmem(file, (size_t)n, want[w], (size_t)m))
			return 1;
	}
	return 0;
}

enum kgenome_emu_unp_why kgenome_emu_unp_gate(const struct kgenome_obj *obj,
				      const struct kgenome_elf_info *info,
				      const uint8_t *file, uint64_t n)
{
	static const uint64_t unloadable =
		KGENOME_ELF_ANOM_NO_LOAD_SEGMENT | KGENOME_ELF_ANOM_PHOFF_PAST_EOF |
		KGENOME_ELF_ANOM_PHENTSIZE_ODD   | KGENOME_ELF_ANOM_TRUNCATED_HEADER |
		KGENOME_ELF_ANOM_ENTRY_UNMAPPED  | KGENOME_ELF_ANOM_ENTRY_ZEROFILL |
		KGENOME_ELF_ANOM_ENTRY_NOT_EXEC;
	uint32_t hist[256];
	uint64_t total = 0;
	uint32_t i;

	if (!obj || !info || !info->valid || !file)
		return KGENOME_EMU_UNP_NO;
	/*
	 * x86 AND x86-64, since the emulator learned a 32-bit mode - see
	 * kgenome_emu_cfg.bits. It was amd64 only because the interpreter was, and
	 * the note that used to stand here said the measurement supported that:
	 * every one of the 294 dense objects in the clean-corpus run was amd64.
	 * That is still true of the DENSE gate and says nothing about the
	 * others - the shape rule in bases/heur/shellcode_00.c fires on 32-bit
	 * payloads and asks for the emulator on them, and until now the ask
	 * arrived here and was refused.
	 *
	 * Everything else is still refused: the decoder decodes these two and an
	 * ARM object would be started and stopped on its first instruction,
	 * which costs a page table and teaches nothing.
	 */
	if (obj->arch != KGENOME_ARCH_X86_64 && obj->arch != KGENOME_ARCH_X86)
		return KGENOME_EMU_UNP_NO;

	/*
	 * Broken first, because it is the stronger statement. A file whose
	 * header cannot be loaded has already defeated every module that needs
	 * structure, and the density test would not even find its code.
	 */
	if (info->anomalies & unloadable)
		return KGENOME_EMU_UNP_WHY_BROKEN;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < info->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		const struct kgenome_elf_seg *s = &info->seg[i];
		uint64_t off, len;

		if (!kgenome_elf_seg_is_code(s))
			continue;
		len = kgenome_elf_seg_extent(s, n, &off);
		if (!len)
			continue;
		kentropy_count(hist, file + off, len);
		total += len;
	}
	if (total >= DENSE_MIN &&
	    kentropy_hist(hist, total) >= DENSE_EIGHTHS)
		return KGENOME_EMU_UNP_WHY_DENSE;

	/*
	 * The code is ordinary, so nothing above fired - but a ciphertext block
	 * in a non-code segment beside an import that can execute memory is the
	 * C-loader carrying an encrypted payload. Last because it is the
	 * narrowest statement and the most work: two passes over the file that
	 * the two cheaper tests above did not need.
	 */
	if (loader_blob(info, file, n) >= LOADER_BLOB &&
	    loader_imports_exec(file, n))
		return KGENOME_EMU_UNP_WHY_LOADER;

	return KGENOME_EMU_UNP_NO;
}

/* ---- building a process image -------------------------------------------- */

/*
 * The longest run of high-entropy windows ANYWHERE in the file - not per
 * section, which is the point of it.
 *
 * loader_blob asks the same question of one segment at a time because on ELF
 * the interesting statement is WHICH segment holds the ciphertext. Here the
 * statement has already been made by the entry point sitting in an appended
 * section, and where the packer then parked its compressed original - a
 * section, the overlay, past the last section header - is its own business.
 * Asking per section would have missed exactly the case this exists for.
 */
static uint64_t blob_anywhere(const uint8_t *file, uint64_t n)
{
	uint64_t best = 0, run = 0, at;

	for (at = 0; at + LOADER_WINDOW <= n; at += LOADER_WINDOW) {
		uint32_t hist[256];

		memset(hist, 0, sizeof hist);
		kentropy_count(hist, file + at, LOADER_WINDOW);
		if (kentropy_hist(hist, LOADER_WINDOW) >= LOADER_EIGHTHS) {
			run += LOADER_WINDOW;
			if (run > best)
				best = run;
		} else {
			run = 0;
		}
	}
	return best;
}

enum kgenome_emu_unp_why kgenome_emu_unp_gate_pe(const struct kgenome_obj *obj,
					 const struct kgenome_pe_info *info,
					 const uint8_t *file, uint64_t n)
{
	/*
	 * THE ANOMALIES THAT MEAN "THIS CANNOT BE LOADED AS WRITTEN" - the PE
	 * half of `unloadable`, and deliberately not the whole anomaly list.
	 * Most of the twenty-seven are notes about a file that loads perfectly
	 * well. These are the ones where the header has stopped describing the
	 * image, which is when an interpreter - needing only somewhere to
	 * start - is the only reader left.
	 */
	static const uint64_t unloadable =
		KGENOME_PE_ANOM_SECTAB_PAST_EOF | KGENOME_PE_ANOM_SEC_PAST_EOF |
		KGENOME_PE_ANOM_ENTRY_UNMAPPED  | KGENOME_PE_ANOM_ENTRY_ZEROFILL |
		KGENOME_PE_ANOM_ENTRY_NOT_EXEC  | KGENOME_PE_ANOM_NSEC_ZERO;
	uint32_t hist[256];
	uint64_t total = 0;
	uint32_t i;

	if (!obj || !info || !info->valid || !file)
		return KGENOME_EMU_UNP_NO;
	/*
	 * the decoder decodes x86 and x86-64 and nothing else, so an ARM64 PE is
	 * refused HERE rather than started and left to fault on its first
	 * instruction - which would spend a budget to learn something the
	 * machine field said for free.
	 */
	if (obj->arch != KGENOME_ARCH_X86_64 && obj->arch != KGENOME_ARCH_X86)
		return KGENOME_EMU_UNP_NO;

	if (info->anomalies & unloadable)
		return KGENOME_EMU_UNP_WHY_BROKEN;

	/*
	 * ONE MERGED HISTOGRAM OVER THE CODE SECTIONS' DECLARED BYTES - and not
	 * the scanner's memoised obj->content->region_entropy(KGENOME_SCAN_PE_CODE),
	 * although both answer "how dense is the code". They are the same number
	 * only for an image whose sections do not overlap and which is not .NET:
	 * the region is the CLAIMED partition (an overlapped byte counts once, in
	 * the earlier section) with the CLR heaps cut out, where this counts every
	 * declared byte of every code section, heaps included. A managed
	 * assembly carrying an encrypted resource inside .text is dense here and
	 * not there, and which of the two the emulator should be asked about is a
	 * behaviour question this change was not asked to move. Said at the
	 * definition so the next reader does not "unify" it unmeasured.
	 *
	 * It also runs only when a rule or a vouch has asked for the emulator, so
	 * the pass it costs is not on the path of an ordinary scan - none of the
	 * 100 PEs of the 300-file subset reach it.
	 */
	memset(hist, 0, sizeof hist);
	for (i = 0; i < info->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
		const struct kgenome_pe_sec *s = &info->sec[i];
		uint64_t off, len;

		if (!kgenome_pe_sec_is_code(s))
			continue;
		len = kgenome_pe_sec_extent(s, n, &off);
		if (!len)
			continue;
		kentropy_count(hist, file + off, len);
		total += len;
	}
	/*
	 * THE SAME 7.5 BITS PER BYTE AS THE ELF SIDE, and measured to be in
	 * the same place. Over those 2678 clean PEs the executable sections
	 * fall almost entirely between 6.0 and 7.0 bits - 1669 of them - and
	 * only 4 files reach 7.0 at all. One clears 7.5. Compiled code simply
	 * is not this dense, and something that is has written its own code
	 * before running it.
	 */
	if (total >= DENSE_MIN &&
	    kentropy_hist(hist, total) >= DENSE_EIGHTHS)
		return KGENOME_EMU_UNP_WHY_DENSE;

	/*
	 * AND THE PACKER THAT LEFT ITS COMPRESSED DATA SOMEWHERE DENSE CANNOT
	 * LOOK - see KGENOME_EMU_UNP_WHY_APPENDED for the measurement.
	 *
	 * Two sections at least, so "the LAST section" is a statement about an
	 * arrangement rather than a tautology about a file that has only one.
	 */
	if (info->sec_count >= 2u &&
	    info->entry_rva &&
	    info->entry_sec == info->sec_count - 1u &&
	    blob_anywhere(file, n) >= LOADER_BLOB)
		return KGENOME_EMU_UNP_WHY_APPENDED;

	return KGENOME_EMU_UNP_NO;
}
