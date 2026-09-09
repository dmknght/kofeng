/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kofmemscan - scan what is running, rather than what is on the disk.
 *
 * WHAT THIS IS FOR, since a file scanner already exists and finds most of it.
 *
 * Everything a loaded module holds in memory is also in the file it was loaded
 * from. Scanning the memory finds what scanning the file would have found, so
 * the value of a memory scan is entirely in the DELTA - bytes that are in a
 * process and are in no file:
 *
 *   - a reflectively loaded DLL, which was never written to disk at all;
 *   - a payload unpacked in place, whose file on disk is a packer;
 *   - a module whose pages have been written to since the loader mapped them:
 *     an inline hook, a blown-away AMSI stub, a hollowed image.
 *
 * And a machine that was compromised before the sensor was installed produces a
 * perfectly clean event stream, because everything that mattered happened
 * before anything was watching. This is the half of the answer that needs no
 * history - see the top of wproc.h.
 *
 *
 * TWO LEVELS, AND THE DIFFERENCE IS NOT A THOROUGHNESS DIAL.
 *
 * LEVEL 1 SCANS. Every object it hands the engine is bytes already present in a
 * process, presented as what they are, with the engine at its cheap settings -
 * no interpreter, first finding wins. The cost is bounded by what is mapped and
 * a walk of four hundred processes finishes. This is what a real-time sweep
 * runs.
 *
 * LEVEL 2 GATHERS, then analyses. Three things it does that level 1 cannot:
 *
 *   - UN-MAPS a mapped image back into a PE file, undoing the loader's base
 *     relocations, so the file corpus applies to bytes that only ever existed
 *     in memory. See pe_unmap.h: without this a signature whose literal crosses
 *     a relocated pointer matches the file and not the image, and the miss
 *     looks exactly like a clean result.
 *   - DIFFS a module against the file it was mapped from, and scans what
 *     differs. That difference is the only part of a loaded module that
 *     scanning the file did not already cover, and it is where an inline hook,
 *     a blown-away AMSI stub and a hollowed section live.
 *   - Turns the expensive engine settings ON: the interpreter, the full
 *     heuristic, every match rather than the first, and deeper recursion.
 *
 * It costs a file read per module and an image-sized allocation per mapped
 * image, so it is asked for - `--level 2` - and never the default.
 *
 *
 * WHY IT SCANS THE FILE FOR AN ORDINARY MODULE.
 *
 * A module's pages are shared with every process that mapped the same file, and
 * they are shared BECAUSE they are identical to it. Reading eight thousand
 * mappings out of processes to reach an answer that fifty file reads already
 * give is what makes a memory scan take an hour. So a module is scanned as its
 * FILE, the answer is remembered against the file's identity - see koffridge.h,
 * and note that identity is not the path - and only the parts of a process that
 * are in NO file are read out of it.
 *
 *
 * EVERY SIGNATURE THAT ALREADY EXISTS APPLIES, and that is not an accident.
 *
 * There is no memory format and no memory region vocabulary. A hand-mapped
 * image is declared to the engine as a PE in the layout the loader produces, so
 * every PE rule in the database runs on it with its regions resolved to the
 * right bytes; anything else goes over as unidentified bytes, exactly like any
 * object no format claims. A new format would have REPLACED the rules that
 * exist rather than adding to them - see enum kof_pe_layout, and the note in
 * wproc.h on why this enum is a scan policy and not a partition.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofeng.h"
#include <kofmod/pe.h>
#include "kofunpack/pe_unmap.h"
#include <binaries/pe_parse.h>
#include "wproc.h"
#include "koffridge.h"

/*
 * Never copy more than this out of one allocation.
 *
 * A committed private region can be gigabytes - a GC heap, a database's buffer
 * pool, a VM's guest memory - and level one has no business pulling one across.
 * Separate from kofw_pmem_option.max_region, which bounds what the walk
 * EXAMINES; this bounds what is COPIED and scanned.
 */
#define MEM_MAX_READ (32u * 1024u * 1024u)

struct opt {
	const char *db;
	uint32_t only_pid;
	int level;          /* 1 scans, 2 gathers and analyses */
	int scan_heap;
	int no_files;
	int verbose;
};

struct run {
	kof_scanner *sc;
	struct koffridge *fridge;
	struct opt o;

	uint8_t *buf;             /* one read buffer, reused */
	size_t   cap;

	uint64_t procs, refused;
	uint64_t modules, files_scanned, files_cached;
	uint64_t regions_seen, regions_scanned;
	uint64_t bytes_read;
	uint64_t findings;

	/* level 2 */
	uint64_t unmapped;        /* images turned back into files */
	uint64_t relocs_undone;
	uint64_t patched_modules; /* modules whose bytes differ from their file */
	uint64_t patched_bytes;
};

/*
 * THE ENGINE'S SETTINGS, IN ONE PLACE, because the level is only a policy about
 * these and scattering them is how two call sites end up at different levels.
 *
 * Level 1 takes what a memset gives - no interpreter, stop at the first
 * finding - and adds only a recursion depth, because an object inside an object
 * is still level-1 work.
 *
 * Level 2 turns on what costs: KOF_EMU_AUTO interprets an object no unpacker
 * would take, which is the largest thing a scan can do and is measured in tens
 * of millions of instructions; the full heuristic; every match rather than the
 * first, because a report wants the list and an on-access hook only ever wanted
 * to know whether to block.
 */
static void engine_opt(const struct run *r, struct kof_scan_option *so)
{
	memset(so, 0, sizeof *so);
	so->max_depth = 4;
	if (r->o.level < 2)
		return;
	so->max_depth = 8;
	so->all_matches = 1;
	so->emu_use = KOF_EMU_AUTO;
	so->heur_level = KOF_HEUR_LEVEL_MAX;
}

/* --------------------------------------------------------------- reporting */

/*
 * One scan's worth of findings, collected so the cache can be told what the
 * whole scan came to.
 *
 * The engine reports per OBJECT and a file may hold several - an archive, a
 * packer and its payload - so what is remembered about the file is the worst
 * thing found anywhere under it. Remembering only the top-level object's
 * verdict would cache "clean" for an archive with a trojan in it.
 */
struct sink {
	struct run *r;
	struct kof_result worst;
	int rank;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct sink *s = user;
	uint32_t i;

	(void)bytes;
	(void)len;
	for (i = 0; i < res->n; i++) {
		int rk = kof_level_rank(res->v[i].level);

		printf("  MALICIOUS  %-44s %s\n", res->v[i].name, name);
		s->r->findings++;
		if (rk > s->rank) {
			s->rank = rk;
			s->worst.v[0] = res->v[i];
			s->worst.n = 1;
		}
	}
	if (res->broken && !s->worst.broken)
		s->worst.broken = res->broken;
	return 0;
}

static void sink_init(struct sink *s, struct run *r)
{
	memset(s, 0, sizeof *s);
	s->r = r;
	s->rank = -1;
}

/* ------------------------------------------------------- a file's identity */

/*
 * NOT ITS PATH. The volume and file index are the kernel's own name for a file;
 * the size and write time move whenever it is replaced. A cache keyed on the
 * path says "System32\foo.dll was clean an hour ago" about a file that has been
 * swapped since. See koffridge.h for what this bargain does and does not buy.
 *
 * Zero on failure, and then the caller scans WITHOUT caching rather than
 * caching under a key it could not establish.
 */
static int file_identity(const char *path, struct koffridge_fileid *out)
{
	BY_HANDLE_FILE_INFORMATION bi;
	HANDLE h;

	memset(out, 0, sizeof *out);
	h = CreateFileA(path, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	if (!GetFileInformationByHandle(h, &bi)) {
		CloseHandle(h);
		return 0;
	}
	CloseHandle(h);
	out->volume = bi.dwVolumeSerialNumber;
	out->index  = ((uint64_t)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
	out->size   = ((uint64_t)bi.nFileSizeHigh  << 32) | bi.nFileSizeLow;
	out->mtime  = ((uint64_t)bi.ftLastWriteTime.dwHighDateTime << 32) |
		      bi.ftLastWriteTime.dwLowDateTime;
	return 1;
}

static void scan_module_file(struct run *r, const char *path)
{
	struct koffridge_fileid id;
	struct koffridge_verdict v;
	struct kof_scan_option so;
	struct sink s;
	int have_id;

	if (r->o.no_files || !path || !path[0])
		return;

	have_id = file_identity(path, &id);
	if (have_id && koffridge_get(r->fridge, &id, sizeof id, &v)) {
		/*
		 * A CACHED ENTRY HOLDS THE VERDICT, NOT THE REPORT - one name,
		 * because the level-1 engine stops at the first finding and
		 * there is only ever one. Level 2 asks for every match, so a
		 * file that produced several is re-scanned rather than reported
		 * as one of them: the cache is there to skip the CLEAN ones,
		 * which is where all the work is, and an object that is already
		 * known to be bad is rare enough to pay for twice.
		 */
		if (!(r->o.level >= 2 && v.findings > 1)) {
			r->files_cached++;
			if (v.findings)
				printf("  MALICIOUS  %-44s %s (cached)\n",
				       v.name, path);
			return;
		}
	}

	sink_init(&s, r);
	engine_opt(r, &so);
	(void)kof_scan_path(r->sc, path, &so, on_object, &s);
	r->files_scanned++;

	if (have_id)
		(void)koffridge_put(r->fridge, &id, sizeof id, &s.worst);
}

/* ----------------------------------------------------------- memory objects */

static int grow(struct run *r, size_t n)
{
	uint8_t *p;

	if (n <= r->cap)
		return 1;
	p = realloc(r->buf, n);
	if (!p)
		return 0;
	r->buf = p;
	r->cap = n;
	return 1;
}

/*
 * LEVEL 2: put a mapped image back into the shape its file had, and scan that
 * too.
 *
 * Not INSTEAD of scanning the image. The image is what is actually executing
 * and a rule may be written for exactly that; the un-mapped file is what the
 * corpus was written against. They are two objects and both are offered.
 *
 * `mapped_at` is what makes the relocations undoable - see pe_unmap.h - and it
 * is the allocation base, which is where the image's own base sits.
 */
static void unmap_and_scan(struct run *r, const uint8_t *img, uint64_t len,
			   uint64_t mapped_at, const char *parent)
{
	struct kof_pe_unmap_info ui;
	struct kof_scan_option so;
	struct sink s;
	uint8_t *back = NULL;
	uint64_t back_len = 0;
	char name[224];

	if (!kof_pe_unmap(kof_buf_make(img, len), mapped_at, MEM_MAX_READ,
			  &back, &back_len, &ui))
		return;
	r->unmapped++;
	r->relocs_undone += ui.relocs_undone;

	if (r->o.verbose)
		printf("  unmapped %s -> %llu bytes, %u reloc(s) undone, "
		       "delta 0x%llx\n", parent, (unsigned long long)back_len,
		       ui.relocs_undone,
		       (unsigned long long)(uint64_t)ui.delta);

	snprintf(name, sizeof name, "%s//unmapped", parent);
	sink_init(&s, r);
	engine_opt(r, &so);
	(void)kof_scan_bytes(r->sc, back, back_len, name, &so, on_object, &s);
	free(back);
}

/*
 * Scan one span of a process's memory.
 *
 * `is_pe` says the allocation begins with a PE header, which wproc worked out
 * and which is the whole reason the declaration below can be made. A span that
 * is not one goes over undeclared: the sniff chain gets it, refuses it, and it
 * reaches the modules written for unidentified bytes - which is where the
 * shellcode heuristic lives.
 */
static void scan_span(struct run *r, struct kofw_pmem *m, uint32_t pid,
		      const char *who, uint64_t base, uint64_t size, int is_pe)
{
	struct kof_scan_option so;
	struct kof_pe_info hint;
	struct sink s;
	char name[192];
	size_t want, got;

	if (!size)
		return;
	want = size > MEM_MAX_READ ? MEM_MAX_READ : (size_t)size;
	if (!grow(r, want))
		return;

	/*
	 * SHORT IS NORMAL AND IS NOT AN ERROR. A guard page in the way, a
	 * module unloaded mid-walk, a page decommitted between the query and
	 * the read - kofw_pmem_read stops at the first refusal and returns what
	 * it got, and thirty-nine pages of forty are still worth scanning.
	 */
	got = kofw_pmem_read(m, base, r->buf, want);
	if (!got)
		return;
	r->bytes_read += got;
	r->regions_scanned++;

	snprintf(name, sizeof name, "mem//%lu//%s//0x%llx",
		 (unsigned long)pid, who ? who : "?",
		 (unsigned long long)base);

	sink_init(&s, r);
	engine_opt(r, &so);
	if (is_pe) {
		/*
		 * DECLARED, because the bytes cannot say it. A PE laid out by
		 * the loader states both its file offsets and its virtual
		 * addresses in the same section table, and resolving the scan
		 * regions from the wrong pair points every one of them at other
		 * sections' bytes - no error, no anomaly, and no rule matches.
		 *
		 * The whole view is passed rather than a prefix: `layout` sits
		 * at the end of it, where adding a field cannot move the fields
		 * a database compiled earlier reads by offset.
		 */
		memset(&hint, 0, sizeof hint);
		hint.layout   = KOF_PE_LAYOUT_MAPPED;
		so.as_format  = KOF_FMT_PE;
		so.as_view    = &hint;
		so.as_view_len = (uint32_t)sizeof hint;
	}
	(void)kof_scan_bytes(r->sc, r->buf, (uint64_t)got, name, &so,
			     on_object, &s);

	if (is_pe && r->o.level >= 2)
		unmap_and_scan(r, r->buf, (uint64_t)got, base, name);
}

/* ------------------------------------------ level 2: the image against its file */

static unsigned char *slurp(const char *path, uint64_t *len)
{
	FILE *f = fopen(path, "rb");
	unsigned char *b;
	long n;

	*len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	n = ftell(f);
	if (n <= 0 || (uint64_t)n > MEM_MAX_READ) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	b = malloc((size_t)n);
	if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
		free(b);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (uint64_t)n;
	return b;
}

#define SCN_MEM_WRITE   0x80000000u
#define SCN_MEM_DISCARD 0x02000000u

/* How far apart two differing bytes can be and still be called one patch. A
 * hook is five bytes and a detour trampoline is a few more; a gap larger than
 * this is two separate things and reporting them as one hides the second. */
#define PATCH_GAP 16u

/* Enough bytes around a patch that a rule has something to match. A five-byte
 * jmp on its own is not a signature and never will be; what is worth scanning
 * is the code it was written over and whatever was put there. */
#define PATCH_CONTEXT 128u

/* Past this many per module, the module is the finding and the list is not. */
#define PATCH_MAX 8u

/*
 * LEVEL 2: does this module still say what its file says.
 *
 * THE COMPARISON IS AGAINST THE UN-MAPPED IMAGE, not against the raw one. The
 * loader itself changes bytes on the way in - it applies base relocations - so
 * a raw comparison reports every relocated pointer in the module and buries the
 * one write that matters. Undoing them first is what leaves only what SOMEBODY
 * ELSE wrote.
 *
 * WHAT IS DELIBERATELY NOT COMPARED, because it changes for honest reasons:
 *
 *   writable sections   .data is the program's working memory. Every process
 *                       differs there from its file within microseconds of
 *                       starting, and always will.
 *   the IAT             the loader fills it with addresses that exist in this
 *                       process only. pe_unmap does not restore it - see its
 *                       header - so it is excluded here instead.
 *
 * AND WHAT IS STILL EXPECTED TO BE NOISY, said plainly rather than discovered:
 * an image with no IAT directory keeps its import thunks somewhere this cannot
 * find without walking the import descriptors, and those will be reported. A
 * hot-patched or self-modifying module will be reported too, and is a true
 * statement rather than a finding. This reports a DIFFERENCE; what it means is
 * the operator's call.
 */
static void diff_module(struct run *r, struct kofw_pmem *m,
			const struct kofw_module *md, const char *who,
			uint32_t pid)
{
	struct kof_pe_info info;
	struct kof_obj_ctx ctx;
	struct kof_pe_unmap_info ui;
	unsigned char *file = NULL;
	uint8_t *back = NULL;
	uint64_t back_len = 0, flen = 0, iat_lo = 0, iat_hi = 0;
	uint32_t i, patches = 0;
	size_t got;

	if (!md->path[0] || !md->size || md->size > MEM_MAX_READ)
		return;
	if (!grow(r, (size_t)md->size))
		return;

	got = kofw_pmem_read(m, md->base, r->buf, (size_t)md->size);
	if (got < 0x400u)
		return;
	r->bytes_read += got;

	if (!kof_pe_unmap(kof_buf_make(r->buf, (uint64_t)got), md->base,
			  MEM_MAX_READ, &back, &back_len, &ui))
		return;
	r->unmapped++;
	r->relocs_undone += ui.relocs_undone;

	file = slurp(md->path, &flen);
	if (!file) {
		free(back);
		return;
	}

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);
	if (!kof_pe_parse(kof_buf_make(file, flen), &info, &ctx) ||
	    !info.valid) {
		free(file);
		free(back);
		return;
	}
	if (info.n_dirs > KOF_PE_DIR_IAT && info.dir[KOF_PE_DIR_IAT].size) {
		uint64_t o = kof_pe_rva_to_off(&info,
					       info.dir[KOF_PE_DIR_IAT].rva);

		if (o != KOF_BROKEN) {
			iat_lo = o;
			iat_hi = o + info.dir[KOF_PE_DIR_IAT].size;
		}
	}

	for (i = 0; i < info.sec_count && patches < PATCH_MAX; i++) {
		uint64_t off = info.sec[i].file_off;
		uint64_t len = info.sec[i].file_size;
		uint64_t at, run_lo = 0, run_hi = 0;
		int in_run = 0;

		if (!len || (info.sec[i].characteristics &
			     (SCN_MEM_WRITE | SCN_MEM_DISCARD)))
			continue;
		if (off + len > flen || off + len > back_len)
			continue;

		for (at = off; at <= off + len; at++) {
			int differs = at < off + len &&
				      !(at >= iat_lo && at < iat_hi) &&
				      back[at] != file[at];

			if (differs) {
				if (!in_run) {
					run_lo = at;
					in_run = 1;
				}
				run_hi = at + 1;
				continue;
			}
			if (!in_run)
				continue;
			/* Still inside the gap that joins one patch. */
			if (at < run_hi + PATCH_GAP && at < off + len)
				continue;

			r->patched_bytes += run_hi - run_lo;
			if (patches == 0)
				r->patched_modules++;
			if (patches < PATCH_MAX) {
				struct kof_scan_option so;
				struct sink s;
				char name[256];
				uint64_t lo, hi;

				printf("  PATCHED    %s [%lu %s] %.8s"
				       " +0x%llx  %llu byte(s) differ from the"
				       " file\n", md->path, (unsigned long)pid,
				       who, info.sec[i].name,
				       (unsigned long long)(run_lo - off),
				       (unsigned long long)(run_hi - run_lo));

				lo = run_lo > PATCH_CONTEXT ?
				     run_lo - PATCH_CONTEXT : 0;
				hi = run_hi + PATCH_CONTEXT;
				if (hi > back_len)
					hi = back_len;
				snprintf(name, sizeof name,
					 "mem//%lu//%s//%s//patch@0x%llx",
					 (unsigned long)pid, who,
					 md->path, (unsigned long long)run_lo);
				sink_init(&s, r);
				engine_opt(r, &so);
				(void)kof_scan_bytes(r->sc, back + lo, hi - lo,
						     name, &so, on_object, &s);
			}
			patches++;
			in_run = 0;
		}
	}

	free(file);
	free(back);
}

/*
 * Walk one process.
 *
 * The two walks are run together for the reason wproc.h gives: the module list
 * is the loader's own and is exactly as honest as the loader, so a module
 * unlinked from it is invisible there and still shows up as a region.
 */
/*
 * WHERE A MODULE'S PAGES HAVE STOPPED BEING SHARED.
 *
 * An image's pages are shared with every process that mapped the same file, and
 * a page that has stopped being shared is one somebody WROTE. The region walk
 * reports that as KOFW_RGF_DIRTY_IMAGE, one query per region, and it is the
 * cheap way to know which modules are worth reading out of the process at all.
 *
 * A fixed set, because it is small by construction - a process with more than a
 * few dozen written-to modules is not a process this list would help with - and
 * because a level-2 sweep must not start allocating per process.
 */
#define DIRTY_MAX 64u

struct dirty {
	uint64_t base[DIRTY_MAX];
	uint32_t n;
	uint32_t over;      /* more than the set could hold */
};

static void dirty_add(struct dirty *d, uint64_t base)
{
	uint32_t i;

	for (i = 0; i < d->n; i++)
		if (d->base[i] == base)
			return;
	if (d->n == DIRTY_MAX) {
		d->over++;
		return;
	}
	d->base[d->n++] = base;
}

static int dirty_has(const struct dirty *d, uint64_t base)
{
	uint32_t i;

	for (i = 0; i < d->n; i++)
		if (d->base[i] == base)
			return 1;
	return 0;
}

/*
 * Walk one process.
 *
 * REGIONS FIRST, THEN MODULES, and the order is load-bearing at level 2: the
 * region walk is what says which modules have been written to, and the module
 * walk is what can then read them and say what changed. The two iterators are
 * independent, so this costs nothing.
 *
 * They are both walked at every level for the reason wproc.h gives: the module
 * list is the loader's own and is exactly as honest as the loader, so a module
 * unlinked from it is invisible there and still shows up as a region.
 */
static void one_process(struct run *r, const struct kofw_proc *p)
{
	struct kofw_pmem_option po;
	struct kofw_pmem *m;
	struct kofw_module md;
	struct kofw_region rg;
	struct dirty dirty;
	uint64_t span_base = 0, span_end = 0;
	int span_pe = 0, have_span = 0;
	char who[64];
	int err = 0;

	/* Never itself: the database is in this address space, and a scanner
	 * that scans its own pattern tables reports every family it knows. */
	if (p->flags & KOFW_PF_SELF)
		return;

	memset(&dirty, 0, sizeof dirty);
	memset(&po, 0, sizeof po);
	po.want = KOFW_MW_PATHS | KOFW_MW_DIRTY | KOFW_MW_EXEC_ONLY;
	if (r->o.scan_heap)
		po.want = (po.want & ~(uint32_t)KOFW_MW_EXEC_ONLY) |
			  KOFW_MW_HEAP;

	m = kofw_pmem_open(p->pid, p->create_time, &po, &err);
	if (!m) {
		r->refused++;
		if (r->o.verbose)
			printf("  [%lu %s] %s\n", (unsigned long)p->pid,
			       p->image, kofw_err_name(err));
		return;
	}
	r->procs++;

	{
		const char *b = strrchr(p->image, '\\');

		snprintf(who, sizeof who, "%s", b ? b + 1 : p->image);
	}

	/*
	 * REGIONS ARE GROUPED BACK INTO ALLOCATIONS.
	 *
	 * One hand-mapped DLL comes back as four or five runs - header
	 * read-only, .text RX, .data RW - because the walk reports runs of
	 * identical protection. Scanning each run separately would scan a
	 * payload's header apart from its code, report it several times, and
	 * hand the PE parser a fragment that starts nowhere near a PE header.
	 *
	 * The walk is in address order, so a run whose alloc_base differs from
	 * the one being accumulated ends the span.
	 */
	while (kofw_pmem_next_region(m, &rg)) {
		int want_it;

		r->regions_seen++;
		if (rg.flags & KOFW_RGF_DIRTY_IMAGE)
			dirty_add(&dirty, rg.alloc_base);

		/*
		 * WHAT IS WORTH READING, and the default set is small on
		 * purpose. Unbacked executable memory is where a reflective
		 * loader, a manually mapped module and plain shellcode all end
		 * up. Executable memory behind a file mapped as DATA is module
		 * stomping and is not something a compiler or a JIT produces.
		 *
		 * A dirty image region is NOT read here. At level 2 the module
		 * walk below reads the whole module and compares it against its
		 * file, which is the only reading of "this page changed" that
		 * says WHAT changed; reading the run on its own would scan
		 * bytes that are almost entirely identical to the file that was
		 * scanned already.
		 */
		want_it = (rg.use == KOFW_USE_CODE) ||
			  (rg.flags & KOFW_RGF_DATA_EXEC) ||
			  (r->o.scan_heap && rg.use == KOFW_USE_HEAP);
		if (rg.flags & KOFW_RGF_GUARD)
			want_it = 0;

		if (have_span && rg.alloc_base != span_base) {
			scan_span(r, m, p->pid, who, span_base,
				  span_end - span_base, span_pe);
			have_span = 0;
		}
		if (!want_it)
			continue;

		if (!have_span) {
			span_base = rg.alloc_base;
			span_end = rg.base + rg.size;
			span_pe = (rg.flags & KOFW_RGF_PE) != 0;
			have_span = 1;
		} else {
			if (rg.base + rg.size > span_end)
				span_end = rg.base + rg.size;
			span_pe |= (rg.flags & KOFW_RGF_PE) != 0;
		}
	}
	if (have_span)
		scan_span(r, m, p->pid, who, span_base, span_end - span_base,
			  span_pe);

	if (dirty.over && r->o.verbose)
		printf("  [%lu %s] more than %u modules have written-to pages;"
		       " %u not followed\n", (unsigned long)p->pid, who,
		       DIRTY_MAX, dirty.over);

	while (kofw_pmem_next_module(m, &md)) {
		r->modules++;
		if (md.flags & (KOFW_MDF_UNNAMED | KOFW_MDF_NO_FILE)) {
			/*
			 * NO FILE BEHIND IT. At level 1 there is nothing to do
			 * - the region walk already scanned whatever of it is
			 * executable. At level 2 the mapped copy is the ONLY
			 * copy, so it is un-mapped into a file and scanned as
			 * one, which is what makes the file corpus reach a
			 * module that was never written to disk.
			 */
			if (r->o.verbose)
				printf("  [%lu %s] module at 0x%llx has no file"
				       " behind it\n", (unsigned long)p->pid,
				       who, (unsigned long long)md.base);
			if (r->o.level >= 2 && md.size &&
			    md.size <= MEM_MAX_READ &&
			    grow(r, (size_t)md.size)) {
				size_t got = kofw_pmem_read(m, md.base, r->buf,
							    (size_t)md.size);
				char nm[160];

				if (got >= 0x400u) {
					r->bytes_read += got;
					snprintf(nm, sizeof nm,
						 "mem//%lu//%s//0x%llx",
						 (unsigned long)p->pid, who,
						 (unsigned long long)md.base);
					unmap_and_scan(r, r->buf,
						       (uint64_t)got, md.base,
						       nm);
				}
			}
			continue;
		}

		scan_module_file(r, md.path);
		if (r->o.level >= 2 && dirty_has(&dirty, md.base))
			diff_module(r, m, &md, who, p->pid);
	}

	kofw_pmem_close(m);
}

/* ---------------------------------------------------------------- the tool */

static void usage(const char *me)
{
	printf("usage: %s [--db DIR] [--level 1|2] [--pid N] [--heap]"
	       " [--no-files] [-v]\n"
	       "\n"
	       "  --db DIR     the signature database (default databases/)\n"
	       "  --level N    1 (default) scans what is mapped, at the\n"
	       "               engine's cheap settings.\n"
	       "               2 also un-maps every image back into a PE file\n"
	       "               (undoing the loader's relocations, so the file\n"
	       "               corpus applies), compares each written-to module\n"
	       "               against the file it came from, and turns on the\n"
	       "               interpreter, the full heuristic and all matches.\n"
	       "               It costs a file read per changed module and an\n"
	       "               image-sized allocation per image.\n"
	       "  --pid N      just this process\n"
	       "  --heap       also read writable private memory. Off by\n"
	       "               default: every byte a process ever read passes\n"
	       "               through there, so a match says it TOUCHED them\n"
	       "               and not that it made them.\n"
	       "  --no-files   skip the module-file half; memory only\n"
	       "  -v           say what was refused and why\n", me);
}

int main(int argc, char **argv)
{
	struct run r;
	struct kofw_plist_option lo;
	struct kofw_plist *l;
	struct kofw_proc p;
	struct kof_db_version dv;
	kof_engine *eng;
	char line[160];
	int i, err = 0;

	memset(&r, 0, sizeof r);
	r.o.db = "databases";
	r.o.level = 1;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--db") && i + 1 < argc)
			r.o.db = argv[++i];
		else if (!strcmp(argv[i], "--level") && i + 1 < argc) {
			r.o.level = atoi(argv[++i]);
			if (r.o.level < 1 || r.o.level > 2) {
				usage(argv[0]);
				return 2;
			}
		} else if (!strcmp(argv[i], "--pid") && i + 1 < argc)
			r.o.only_pid = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--heap"))
			r.o.scan_heap = 1;
		else if (!strcmp(argv[i], "--no-files"))
			r.o.no_files = 1;
		else if (!strcmp(argv[i], "-v"))
			r.o.verbose = 1;
		else {
			usage(argv[0]);
			return 2;
		}
	}

	eng = kof_engine_open(r.o.db);
	if (!eng) {
		fprintf(stderr, "%s: cannot load a database from %s\n",
			argv[0], r.o.db);
		return 2;
	}
	memset(&dv, 0, sizeof dv);
	kof_engine_db_version(eng, &dv);

	r.sc = kof_scanner_new(eng);
	/*
	 * The cache is keyed on the database as well as on the file, because a
	 * verdict is only true of the rules that produced it. Nothing in this
	 * process can mix two, but any on-disk form of the cache must check it
	 * before it trusts a single entry.
	 */
	r.fridge = koffridge_open(0, dv.build);
	if (!r.sc || !r.fridge) {
		fprintf(stderr, "%s: out of memory\n", argv[0]);
		return 2;
	}

	memset(&lo, 0, sizeof lo);
	lo.want = KOFW_PW_BASIC | KOFW_PW_PATH;
	lo.only_pid = r.o.only_pid;

	l = kofw_plist_open(&lo, &err);
	if (!l) {
		fprintf(stderr, "%s: cannot list processes: %s\n", argv[0],
			kofw_err_name(err));
		return 2;
	}
	while (kofw_plist_next(l, &p))
		one_process(&r, &p);
	kofw_plist_close(l);

	printf("\nlevel %d: %llu process(es) walked, %llu refused"
	       " - a refusal is a process NOT looked at, not a clean one\n",
	       r.o.level,
	       (unsigned long long)r.procs, (unsigned long long)r.refused);
	printf("%llu module(s) -> %llu file scan(s), %llu served from cache\n",
	       (unsigned long long)r.modules,
	       (unsigned long long)r.files_scanned,
	       (unsigned long long)r.files_cached);
	printf("%llu region(s) seen, %llu span(s) read (%.1f MB)\n",
	       (unsigned long long)r.regions_seen,
	       (unsigned long long)r.regions_scanned,
	       (double)r.bytes_read / 1048576.0);
	if (r.o.level >= 2) {
		printf("%llu image(s) un-mapped, %llu relocation(s) undone\n",
		       (unsigned long long)r.unmapped,
		       (unsigned long long)r.relocs_undone);
		printf("%llu module(s) differ from their file (%llu byte(s))"
		       " - a difference, not a verdict\n",
		       (unsigned long long)r.patched_modules,
		       (unsigned long long)r.patched_bytes);
	}
	koffridge_describe(r.fridge, line, sizeof line);
	printf("%s\n", line);
	printf("%llu finding(s)\n", (unsigned long long)r.findings);

	koffridge_close(r.fridge);
	kof_scanner_free(r.sc);
	kof_engine_close(eng);
	return r.findings != 0;
}
