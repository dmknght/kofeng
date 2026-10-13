/*
 * ksb_build.c - --module, the compiler and linker: run the tools, produce the
 *    raw blob.
 */

#include "ksb.h"

/*
 * ---------------------------------------------------------------------------
 * RUNNING THE COMPILER AND THE LINKER, WITHOUT A SHELL.
 *
 * These two cannot be removed - there is no compiling C without a compiler -
 * but the SHELL that ran them can be, and that is the one a Windows host does
 * not have. Everything else the build did with grep, sed, awk, nm, readelf,
 * size and objcopy is already inside this program; this is what lets the last
 * of it move too.
 *
 * The argument vector is passed as a vector on both systems. On Windows that
 * means building a command line and quoting it by the documented rule, because
 * CreateProcess takes one string and the child is what splits it again - a
 * signature source under a path with a space in it would otherwise arrive as
 * two arguments.
 * ---------------------------------------------------------------------------
 */

static int run_tool(const char *const *argv)
{
#ifdef _WIN32
	char cmd[8192];
	size_t at = 0;
	int i;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	DWORD code = 1;

	for (i = 0; argv[i]; i++) {
		const char *a = argv[i];
		size_t j;

		if (at + 3u >= sizeof cmd)
			return -1;
		if (i)
			cmd[at++] = ' ';
		cmd[at++] = '"';
		for (j = 0; a[j]; j++) {
			size_t bs = 0;

			while (a[j] == '\\') { bs++; j++; }
			if (!a[j]) {
				bs *= 2u;
				while (bs-- && at + 2u < sizeof cmd)
					cmd[at++] = '\\';
				break;
			}
			if (a[j] == '"')
				bs = bs * 2u + 1u;
			while (bs-- && at + 2u < sizeof cmd)
				cmd[at++] = '\\';
			if (at + 2u >= sizeof cmd)
				return -1;
			cmd[at++] = a[j];
		}
		if (at + 2u >= sizeof cmd)
			return -1;
		cmd[at++] = '"';
	}
	cmd[at] = 0;
	memset(&si, 0, sizeof si);
	si.cb = sizeof si;
	memset(&pi, 0, sizeof pi);
	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL,
			    &si, &pi))
		return -1;
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (int)code;
#else
	pid_t pid = fork();
	int status = 0;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		union { const char *const *c; char *const *v; } u;

		u.c = argv;
		execvp(argv[0], u.v);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}

/*
 * THE RAW BLOB - the bytes the database stores and the loader jumps into.
 *
 * Two routes here, and they arrive at the same bytes rather than at two
 * answers: module.ld places everything in .blob at address zero and discards
 * the rest, and the image has just been checked to carry no other section. So
 * "the allocatable sections laid out by address", which is what --oformat
 * binary writes, is the contents of .blob and nothing besides it.
 *
 * The linker is asked wherever the linker can answer, so on every host that
 * has built a database so far the bytes still come from where they always
 * came from. Two hosts cannot answer. GNU ld's AArch64 backend refuses the
 * request outright - "cannot change output format whilst linking AArch64
 * binaries". lld in its link flavour has no --oformat at all, which is why
 * the Windows build used to reach for llvm-objcopy --dump-section instead.
 * Both take the bytes out of the image this build has already linked, parsed
 * and validated - which is also what removes objcopy from what a Windows
 * build has to have installed.
 *
 * Chosen by which host this is, not by running the link and reading its exit
 * code: a refusal to change output format and a link that genuinely went
 * wrong both come back as failure, and a fallback that cannot tell them apart
 * would turn a real error into a silently different blob.
 */
static int emit_raw(const char *ld, const char *lds, const char *obj,
		    const char *img, const char *raw,
		    const struct img_facts *f)
{
#if defined(_WIN32) || defined(__aarch64__) || defined(_M_ARM64)
	uint8_t *buf;
	size_t len;
	FILE *out;
	int ok;

	(void)ld;
	(void)lds;
	(void)obj;

	buf = (uint8_t *)ksb_slurp(img, &len);
	if (!buf) {
		fprintf(stderr, "FAIL: cannot re-read the linked image\n");
		return 0;
	}
	/* The offsets come from this same file, but they are still checked
	 * against its real length before either is believed. */
	if (f->blob_off > (uint64_t)len ||
	    f->blob_len > (uint64_t)len - f->blob_off) {
		fprintf(stderr, "FAIL: .blob lies outside the image\n");
		free(buf);
		return 0;
	}
	out = fopen(raw, "wb");
	if (!out) {
		fprintf(stderr, "FAIL: cannot write %s\n", raw);
		free(buf);
		return 0;
	}
	ok = fwrite(buf + f->blob_off, 1, (size_t)f->blob_len, out) ==
	     (size_t)f->blob_len;
	if (fclose(out) != 0)
		ok = 0;
	free(buf);
	if (!ok) {
		fprintf(stderr, "FAIL: writing %s\n", raw);
		return 0;
	}
	return 1;
#else
	const char *cmd[] = { ld, "-T", lds, "--gc-sections",
			      "--oformat", "binary",
			      obj, "-o", raw, NULL };
	int rc;

	(void)img;
	(void)f;

	rc = run_tool(cmd);
	if (rc != 0) {
		fprintf(stderr, "FAIL: raw link returned %d\n", rc);
		return 0;
	}
	return 1;
#endif
}

/* Compile the module to an object, and check on the OBJECT that it holds no
 * writable state. */
static int build_compile(struct ksb_ctx *ksb, const char *src, const char *pat,
			 const char *obj, struct img_facts *f)
{
	const char *cc = ksb->opt.cc;
	const char *incdir = ksb->opt.include;
	char inc[1024];
	int rc;

	if (!cc || !cc[0])
		cc = "cc";
	snprintf(inc, sizeof inc, "-I%s",
		 incdir && incdir[0] ? incdir : ".");

	/*
	 * WHICH MACHINE THE BLOB IS FOR, said out loud rather than inherited.
	 *
	 * Without this the module compile is whatever `cc` defaults to, which
	 * is the machine the compiler was built for and not necessarily the
	 * one this database is being built for. The pack's own machine field
	 * comes from KOF_PACK_MACH_HOST - a property of the build that made
	 * ksigbuilder - so the two are set by different things and can
	 * disagree.
	 *
	 * They did. On an ARM64 Windows host building the x86_64 default, the
	 * tools were cross-compiled to x86_64 and stamped the pack x86_64,
	 * while every blob came out AArch64 because `cc` here is native. That
	 * database loads without a complaint - the machine field says exactly
	 * what the engine is - and then the scanner enters the first module
	 * and dies on STATUS_ILLEGAL_INSTRUCTION.
	 *
	 * Empty means "whatever cc targets", which is right for a native
	 * build and is what the Linux side uses.
	 */
	{
		const char *triple = ksb->opt.triple;
		char targ[256];
		const char *flags[] = {
			"-std=c11", "-Os",
			"-ffreestanding", "-fno-builtin", "-nostdlib",
			"-fno-asynchronous-unwind-tables",
			"-fno-unwind-tables",
			"-fno-ident", "-g0",
			"-fno-stack-protector", "-fno-jump-tables",
			"-ffunction-sections", "-fdata-sections",
#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_WIN32)
			/*
			 * REACHING THE BLOB'S OWN RODATA, ON A HOST WHERE
			 * PC-RELATIVE MEANS PAGE-RELATIVE.
			 *
			 * A blob is linked at address zero and then copied to
			 * wherever the arena has room, and nothing relocates
			 * it - which works because every reference inside it
			 * is PC-relative. On x86-64 that is RIP-relative and
			 * counts in BYTES, so any load address will do.
			 *
			 * AArch64's default is adrp+add, and adrp counts in
			 * 4KB PAGES: it yields the page the instruction is
			 * in, and the add carries the link-time offset within
			 * that page. The two agree only when the blob is
			 * loaded at the same page offset it was linked at,
			 * and the loader aligns a blob to KOF_PACK_BLOB_ALIGN
			 * - sixteen bytes. So a module reading a const table
			 * of its own read whatever happened to sit at that
			 * offset from a page boundary instead.
			 *
			 * Measured before this flag: ten of the sixty-two
			 * modules in bases/ emitted adrp, and every one of
			 * them was silently reading the wrong bytes - no
			 * fault, no refusal, just a module that never
			 * matched. tests/unit/msf_xor.c is the one that
			 * noticed.
			 *
			 * -mcmodel=tiny emits adr instead, which is
			 * PC-relative in bytes and therefore correct at any
			 * load address. Its cost is a 1MB reach from the
			 * instruction to what it names; a signature module is
			 * a few kilobytes, and a blob that ever outgrew that
			 * fails at link time with a relocation overflow
			 * rather than by reading the wrong address.
			 *
			 * ELF only, and not by choice: clang refuses the tiny
			 * model for a COFF target outright - "tiny code model
			 * is only supported on ELF". AArch64 Windows has the
			 * same adrp and therefore the same bug waiting, and
			 * it needs a different remedy - most likely giving a
			 * blob a page-aligned home in the arena rather than
			 * the sixteen bytes KOF_PACK_BLOB_ALIGN promises.
			 * Nothing here is affected by that yet, because the
			 * COFF half of this function is not written.
			 */
			"-mcmodel=tiny",
#endif
#ifdef _WIN32
			/*
			 * Windows grows a stack a page at a time and has the
			 * function ask for it, by calling __chkstk once its
			 * frame passes a threshold. That is a CRT symbol, and
			 * a module links against no CRT - so a signature with
			 * a large enough local buffer fails to link, naming a
			 * function nobody wrote a call to.
			 *
			 * Raised past anything a module's own locals can
			 * plausibly need. It is not a licence to use a
			 * megabyte of stack: a module runs on whatever stack
			 * the host was already on, and the modules here budget
			 * in kilobytes. It only stops the compiler from
			 * reaching for a runtime that is not there.
			 */
			"-mstack-probe-size=1000000",
#endif
			"-Wall", "-Wextra", "-Werror",
			inc, "-include", pat, "-c", src, "-o", obj,
			NULL
		};
		const char *cmd[8 + sizeof flags / sizeof flags[0]];
		unsigned n = 0, k;

		cmd[n++] = cc;
		if (triple && triple[0]) {
			snprintf(targ, sizeof targ, "--target=%s", triple);
			cmd[n++] = targ;
		}
		for (k = 0; flags[k]; k++)
			cmd[n++] = flags[k];
		cmd[n] = NULL;

		rc = run_tool(cmd);
		if (rc != 0) {
			fprintf(stderr, "FAIL: compile returned %d\n",
				rc);
			return 0;
		}
	}

	/* No writable state, checked on the OBJECT where the sections
	 * are still separate and attributable. */
#ifdef _WIN32
	if (!ksb_coff_read(obj, f)) {
#else
	if (!ksb_img_read(obj, NULL, f)) {
#endif
		fprintf(stderr, "FAIL: cannot read the compiled "
				"object\n");
		return 0;
	}
	if (f->data_bytes || f->bss_bytes) {
		fprintf(stderr, "FAIL: module has writable data "
				"(.data=%llu .bss=%llu)\n"
				"      modules must hold no state; use "
				"locals or ask the host\n",
			(unsigned long long)f->data_bytes,
			(unsigned long long)f->bss_bytes);
		return 0;
	}

	return 1;
}

/* Link the object into the image. */
static int build_link(const char *ld, const char *lds, const char *obj,
		      const char *img)
{
	int rc;

#ifdef _WIN32
	/*
	 * COFF has no linker script, so what module.ld does for the
	 * ELF side is done with flags here.
	 *
	 * -dll -noentry: nothing is ever loaded as a PE image, so the
	 * header's own entry field is read by nobody - the host copies
	 * raw bytes into its arena and enters them by offset. -dll is
	 * only what -noentry has to be paired with; it sets a header
	 * bit nothing reads.
	 *
	 * The three -merge flags are the part that matters. Without
	 * them .rdata lands in its own separately page-aligned
	 * section, and the PC-relative loads reaching it are correct
	 * only at that gap - so dumping .text alone would carry code
	 * whose data references point past the end of what was
	 * copied. Merging first makes the linker resolve every
	 * reference assuming byte-for-byte adjacency, which is what
	 * leaves one section that is self-contained at any address.
	 */
	char outarg[1024];
	const char *cmd[] = { ld, "-flavor", "link",
			      "-dll", "-noentry",
			      "-subsystem:native", "-nodefaultlib",
			      "-merge:.rdata=.text",
			      "-merge:.data=.text",
			      "-merge:.bss=.text",
			      obj, outarg, NULL };

	(void)lds;
	snprintf(outarg, sizeof outarg, "-out:%s", img);
#else
	const char *cmd[] = { ld, "-T", lds, "--gc-sections",
			      obj, "-o", img, NULL };
#endif

	rc = run_tool(cmd);
	if (rc != 0) {
		fprintf(stderr, "FAIL: link returned %d\n", rc);
		return 0;
	}

	return 1;
}

/* Read the linked image back and refuse what a module may not be. */
static int build_check_image(const char *img, struct img_facts *f)
{
#ifdef _WIN32
	{
		/*
		 * Two files, two questions - see ksb_coff_read. The object has
		 * already answered which entry point this module exports and
		 * whether it reaches outside itself; the image answers what it
		 * alone can, and those answers are laid over the object's
		 * rather than replacing them.
		 */
		struct img_facts im;

		if (!ksb_pe_image_read(img, &im)) {
			fprintf(stderr, "FAIL: cannot read the linked "
					"image\n");
			return 0;
		}
		f->have_reloc = im.have_reloc;
		snprintf(f->extra_sec, sizeof f->extra_sec, "%s", im.extra_sec);
		f->blob_off = im.blob_off;
		f->blob_len = im.blob_len;
	}
#else
	if (!ksb_img_read(img, ".blob", f)) {
		fprintf(stderr, "FAIL: cannot read the linked image\n");
		return 0;
	}
#endif
	if (f->have_reloc) {
		fprintf(stderr, "FAIL: relocations remain (%s)\n",
			f->extra_sec);
		return 0;
	}
	if (f->undef[0]) {
		fprintf(stderr, "FAIL: undefined symbol (module "
				"reached outside its blob): %s\n",
			f->undef);
		return 0;
	}
	if (f->extra_sec[0]) {
		fprintf(stderr, "FAIL: unexpected section in image: "
				"%s\n", f->extra_sec);
		return 0;
	}
	if (f->n_entry != 1) {
		fprintf(stderr, "FAIL: image exports %d of kof_scan, "
				"kof_unpack, kof_heur; a module is one "
				"kind\n", f->n_entry);
		return 0;
	}
	if (f->entry_off != 0) {
		fprintf(stderr, "FAIL: entry point is at 0x%llx, expected 0; "
				"check module.ld (ELF) or the .text$0 "
				"forcing (COFF)\n",
			(unsigned long long)f->entry_off);
		return 0;
	}

	return 1;
}

/*
 * Compile, link, validate and emit one module. Non-zero on success, with
 * *entry_out naming the entry point the image exports.
 *
 * The compiler and the linker are the only programs a build still runs, and
 * they are run from here rather than from a shell - which is what lets this
 * work on a host that has neither bash nor the GNU binutils.
 */
int ksb_do_build(struct ksb_ctx *ksb, const char *src, const char *pat,
		 const char *obj, const char *img, const char *raw,
		 const char *lds, const char **entry_out)
{
	const char *ld = ksb->opt.ld;
	struct img_facts f;

	if (!ld || !ld[0])
		ld = "ld";
	if (!build_compile(ksb, src, pat, obj, &f))
		return 0;
	if (!build_link(ld, lds, obj, img))
		return 0;
	if (!build_check_image(img, &f))
		return 0;

	/* Last, and only once the image above has been read and accepted -
	 * one of the two routes in emit_raw takes its bytes out of exactly
	 * that image, so nothing is written before there is something worth
	 * writing. */
	if (!emit_raw(ld, lds, obj, img, raw, &f))
		return 0;

	ksb->kept.cure = f.have_cure ? f.cure_off : 0u;
	snprintf(ksb->kept.entry, sizeof ksb->kept.entry, "%.31s", f.entry_name);
	*entry_out = ksb->kept.entry;
	return 1;
}
