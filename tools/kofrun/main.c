/*
 * kofrun - load signature blobs and run them against files.
 *
 *   kofrun <blob-or-sigdir> <file>...
 *
 * The point of the loader is how little there is: no relocation, no symbol
 * resolution, no format parsing of the blob. ld did that once at build time, so what
 * remains is map, copy, protect, call.
 *
 * One arena shared by every blob. Scattering each module into its own mmap costs a
 * syscall and an mprotect per module - measured at 3.35us each, plus 2.61us for the
 * three file opens - which at ten thousand modules is sixty milliseconds of syscall
 * before a byte is scanned.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>

#include "../../libkofeng/kofparser/elf/elf_parse.h"
#include "../../libkofeng/kofmatch/kofmatch.h"

typedef void (*kof_scan_fn)(const struct kof_obj_ctx *);

/* A blob is raw code with no header yet, so there is nothing to validate
 * properly; that comes with the database, where a per-module record has to
 * carry length, entry offset and integrity anyway. Until then, two guards for
 * the mistake that actually happens: handing over an intermediate instead of
 * the blob. Everything else about the file has to be taken on trust, which is
 * acceptable only because this is a development tool. */
#define KOF_BLOB_MAX_CODE (4u * 1024u * 1024u)

static int blob_plausible(const uint8_t *p, size_t len, const char *path)
{
	if (len == 0 || len > KOF_BLOB_MAX_CODE) {
		fprintf(stderr, "kofrun: %s: implausible blob size %zu\n",
			path, len);
		return 0;
	}
	/* The intermediates are an .o and a linked .elf. Copying either into
	 * executable memory and jumping to offset 0 executes an ELF header. */
	if (len >= 4 && memcmp(p, "\177ELF", 4) == 0) {
		fprintf(stderr, "kofrun: %s looks like an ELF image, not a "
				"blob; use build/sig/<name>.blob\n", path);
		return 0;
	}
	return 1;
}

struct arena {
	uint8_t *base;
	size_t   cap;
	size_t   used;
};

static long page_size_of(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	return ps > 0 ? ps : 4096;
}

static size_t round_up(size_t v, size_t a)
{
	return (v + a - 1) / a * a;
}

/*
 * Reserve the arena writable. Blobs are copied in, then the whole arena is
 * flipped to read plus execute in one step; no page is ever writable and
 * executable at the same time.
 */
static int arena_open(struct arena *a, size_t cap)
{
	size_t ps = (size_t)page_size_of();
	a->cap  = round_up(cap, ps);
	a->used = 0;
	a->base = mmap(NULL, a->cap, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (a->base == MAP_FAILED) {
		a->base = NULL;
		return 0;
	}
	return 1;
}

static int arena_seal(struct arena *a)
{
	return mprotect(a->base, a->cap, PROT_READ | PROT_EXEC) == 0;
}

/*
 * Release the arena.
 *
 * Only used on the failure paths during load. Once modules are live there is
 * nothing to gain from unmapping: function pointers into the arena are held in the
 * module table, so tearing it down early would turn a clean exit into a use after
 * free with no benefit.
 */
static void arena_close(struct arena *a)
{
	if (a->base)
		munmap(a->base, a->cap);
	a->base = NULL;
}

/* Copy one blob in and return its offset. Blobs are kept 16 byte aligned so an
 * entry point is never misaligned for the target's calling convention. */
static long arena_add(struct arena *a, const uint8_t *blob, size_t len)
{
	size_t off = round_up(a->used, 16);
	if (off > a->cap || len > a->cap - off)
		return -1;
	memcpy(a->base + off, blob, len);
	a->used = off + len;
	return (long)off;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	FILE *f;

	/* stat() rather than fstat(fileno()): fileno is POSIX, and the tools are
	 * built as strict ISO C11 so that the parser stays portable. */
	if (stat(path, &st) != 0 || st.st_size <= 0)
		return NULL;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*out_len = (size_t)st.st_size;
	return buf;
}

/*
 * The byte level accessors handed to a module.
 *
 * Each takes the context and recovers the host state from ctx->priv rather than
 * reading a global, so two threads can scan two objects through the same table.
 * Every one of them is bounds checked: this is the whole untrusted surface, six
 * functions audited once, instead of bounds arithmetic repeated in every module.
 */
/*
 * Host state behind ctx->priv: what the accessors need, plus whatever the module
 * reported. The module cannot hold state, so a finding has to land here.
 */
struct host_state {
	struct kof_match_ctx m;

	uint32_t rep_level;
	uint32_t rep_name_id;
	int      rep_valid;
	int      rep_cont;

	/*
	 * Cumulative scan cost, summed out of m after each file because
	 * kof_match_begin clears it per object.
	 *
	 * Here rather than left to a profiler because it answers a question timing
	 * cannot: how many bytes a module actually asked to have searched. Wall
	 * time over a warm corpus mixes that up with page cache and with the parse;
	 * this is the number that says whether a signature's region mask is doing
	 * any work, and it is what to compare between two ways of writing the same
	 * detection.
	 */
	uint64_t tot_bytes;
	uint64_t tot_calls;
	uint64_t tot_memo;
	uint64_t files_run;
	uint64_t files_bytes;
	uint64_t n_gram_skips;

	/* Which module is currently running. find_str is reached from inside a
	 * module, and the string and range ids it passes are module local, so the
	 * host has to know whose they are. */
	const struct module *cur_mod;
};

static struct host_state *host_of(const struct kof_obj_ctx *ctx)
{
	return (struct host_state *)(void *)(uintptr_t)ctx->priv;
}

static struct kof_match_ctx *mctx_of(const struct kof_obj_ctx *ctx)
{
	return &host_of(ctx)->m;
}

/*
 * Take a finding. Only the last one is kept, which is all a single-verdict
 * interface can express; when a scan needs to report several findings per object
 * this becomes a list and nothing in a module changes.
 */
static void c_report(const struct kof_obj_ctx *ctx, uint32_t level,
		     uint32_t name_id)
{
	struct host_state *h = host_of(ctx);
	h->rep_level   = level;
	h->rep_name_id = name_id;
	h->rep_valid   = 1;
}

static void c_cont(const struct kof_obj_ctx *ctx)
{
	host_of(ctx)->rep_cont = 1;
}

/* The outcome is what the module reported, not what it returned: it returns
 * nothing, so that a module with nothing to say can simply end. */
static const char *outcome_str(const struct host_state *h)
{
	if (h->rep_cont)
		return "CONTINUE";
	if (!h->rep_valid)
		return "CLEAN";
	return h->rep_level == KOF_LVL_INFECT ? "MATCH" : "SUSPECT";
}

#define GRAM_BITS 24
#define GRAM_SLOTS (1u << GRAM_BITS)

/*
 * Below this many declared strings the presence set is not built.
 *
 * The threshold is a guess pending measurement of where the crossover actually is.
 * What is not a guess is that there is one: the build cost is fixed per object while
 * the saving scales with how many string queries there are to answer.
 */
#define GRAM_MIN_STRINGS 32

static uint16_t *gram_stamp;
static uint16_t  gram_gen;

static int gram_enabled(void)
{
	return gram_stamp != NULL;
}

/* Multiplicative hash of the four bytes, folded to the table width. The constant is
 * the usual odd 32-bit Knuth multiplier; taking the high bits after multiplying
 * mixes all four input bytes into the index, which matters because the low bytes of
 * a gram in text or code are far from uniform. */
static uint32_t gram_hash(uint32_t v)
{
	return (v * 2654435761u) >> (32 - GRAM_BITS);
}

static uint32_t load32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Detection names, loaded from the table the build emitted beside the blob.
 *
 * Deliberately not inside the blob. A family gets renamed on reclassification far
 * more often than its detection logic changes, and a name in .rodata would make
 * that a recompile. Resolving through a table also fails visibly: a table out of
 * step with the blob yields "unknown", never a different family's name.
 */
struct name_ent {
	uint32_t id;
	char     text[192];
};

/*
 * One loaded module.
 *
 * Everything except fn is a precondition or a name table - that is, everything the
 * host needs in order to decide *not* to call fn. Which is the point: at database
 * scale the interesting number is how many modules can be ruled out per object
 * without being entered, so the record has to carry enough to rule them out.
 *
 * The preconditions come from the build: target and size and arch are declared in
 * the source, and scan_mask is derived from the searches the module contains. None
 * of them requires reading the blob.
 */
struct module {
	kof_scan_fn fn;
	const char *path;

	uint32_t target_mask;
	uint32_t scan_mask;     /* 0: names no region, so cannot be skipped this way */
	uint64_t size_min;      /* 0: no minimum. There is no maximum by design;
				 * see KOF_FILESIZE_MIN in kofsig.h. */
	uint32_t arch_mask;     /* 0: any architecture */

	/* Slice of the shared name table, not an array of its own. Inline arrays
	 * were tried and were a mistake worth recording: at 64 entries of 196 bytes
	 * each, the table cost 12.5KB per module whether or not the module had two
	 * names, so a database of eight thousand would have spent 100MB on name
	 * storage alone. That would have been the dominant term in any memory
	 * measurement - the measurement would have been measuring the bug. */
	uint32_t name_base;
	uint32_t n_names;

	/* Slices of the shared tables, in declaration order - which is the order the
	 * generated identifiers index. */
	uint32_t str_base;
	uint32_t n_str;
	uint32_t rng_base;
	uint32_t n_rng;
};

/*
 * One declared string, as the host needs it.
 *
 * The literal lives here and not in the blob, which is what allows the host to
 * search on the module's behalf - and therefore to answer many modules' strings in
 * one pass rather than each module scanning for itself.
 */
#define KOF_STR_MAX_LEN 512

struct str_ent {
	uint8_t  icase;
	uint8_t  fullword;
	uint16_t len;
	uint32_t gram;        /* hash of the first four bytes, 0 if shorter */
	int      has_gram;
	uint8_t  bytes[KOF_STR_MAX_LEN];
};

static struct str_ent *str_tab;
static uint32_t n_str_tab, cap_str_tab;

/* Declared ranges. Just a mask, but named, so a call site can refer to it by an
 * identifier the build can turn into an index. */
static uint32_t *rng_tab;
static uint32_t n_rng_tab, cap_rng_tab;

static struct module *mods;
static uint32_t n_mods;

/*
 * One name table for every module, grown as they load.
 *
 * This is also how the database has to hold them: names are per detection, not per
 * module, and most modules have one or two. A shared table means the cost is the
 * number of names that exist rather than a per-module reservation for names that
 * do not.
 */
static struct name_ent *name_tab;
static uint32_t n_name_tab, cap_name_tab;

static int name_tab_push(uint32_t id, const char *text)
{
	if (n_name_tab == cap_name_tab) {
		uint32_t nc = cap_name_tab ? cap_name_tab * 2 : 256;
		struct name_ent *nv = realloc(name_tab, nc * sizeof *nv);
		if (!nv)
			return 0;
		name_tab = nv;
		cap_name_tab = nc;
	}
	name_tab[n_name_tab].id = id;
	snprintf(name_tab[n_name_tab].text, sizeof name_tab[n_name_tab].text,
		 "%s", text);
	n_name_tab++;
	return 1;
}

static const char *name_of(const struct module *m, uint32_t id)
{
	uint32_t i;
	for (i = 0; i < m->n_names; i++)
		if (name_tab[m->name_base + i].id == id)
			return name_tab[m->name_base + i].text;
	return 0;
}

/* Swap ".blob" for another extension. */
static int sibling_path(const char *blob_path, const char *ext, char *out,
			size_t cap)
{
	size_t n = strlen(blob_path);
	if (n < 5 || n - 5 + strlen(ext) + 1 > cap)
		return 0;
	memcpy(out, blob_path, n - 5);
	memcpy(out + n - 5, ext, strlen(ext) + 1);
	return 1;
}

static void names_load(struct module *m, const char *blob_path)
{
	char path[4096];
	char line[256];
	FILE *f;

	m->name_base = n_name_tab;
	m->n_names   = 0;

	if (!sibling_path(blob_path, ".names", path, sizeof path))
		return;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "kofrun: no name table at %s; "
				"detections will report as unknown\n", path);
		return;
	}
	while (fgets(line, sizeof line, f)) {
		char *tab = strchr(line, '\t');
		char *nl;
		if (!tab)
			continue;
		*tab++ = 0;
		nl = strchr(tab, '\n');
		if (nl)
			*nl = 0;
		if (!name_tab_push((uint32_t)strtoul(line, 0, 10), tab))
			break;
		m->n_names++;
	}
	fclose(f);
}

/*
 * Load the declared strings.
 *
 * Tab separated: index, region mask, icase, fullword, length, then the literal
 * last, so nothing in the literal has to be escaped to keep the columns parseable.
 */
static int str_tab_push(const struct str_ent *e)
{
	if (n_str_tab == cap_str_tab) {
		uint32_t nc = cap_str_tab ? cap_str_tab * 2 : 128;
		struct str_ent *nv = realloc(str_tab, nc * sizeof *nv);
		if (!nv)
			return 0;
		str_tab = nv;
		cap_str_tab = nc;
	}
	str_tab[n_str_tab++] = *e;
	return 1;
}

static int rng_tab_push(uint32_t mask)
{
	if (n_rng_tab == cap_rng_tab) {
		uint32_t nc = cap_rng_tab ? cap_rng_tab * 2 : 128;
		uint32_t *nv = realloc(rng_tab, nc * sizeof *nv);
		if (!nv)
			return 0;
		rng_tab = nv;
		cap_rng_tab = nc;
	}
	rng_tab[n_rng_tab++] = mask;
	return 1;
}

static void strs_load(struct module *m, const char *blob_path)
{
	char path[4096];
	char line[KOF_STR_MAX_LEN + 128];
	FILE *f;

	m->str_base = n_str_tab;
	m->n_str    = 0;
	m->rng_base = n_rng_tab;
	m->n_rng    = 0;

	if (!sibling_path(blob_path, ".strs", path, sizeof path))
		return;
	f = fopen(path, "r");
	if (!f)
		return;                 /* a module may declare neither */

	while (fgets(line, sizeof line, f)) {
		char *p = line, *tab;

		if (p[0] == 'r' && p[1] == '\t') {
			/* r <idx> <mask> */
			unsigned long mask;
			p += 2;
			tab = strchr(p, '\t');
			if (!tab)
				continue;
			mask = strtoul(tab + 1, 0, 10);
			if (!rng_tab_push((uint32_t)mask))
				break;
			m->n_rng++;
			continue;
		}
		if (p[0] == 's' && p[1] == '\t') {
			/* s <idx> <icase> <fullword> <len> <literal> */
			struct str_ent e;
			unsigned long v[4];
			int i;
			size_t len;

			memset(&e, 0, sizeof e);
			p += 2;
			for (i = 0; i < 4; i++) {
				tab = strchr(p, '\t');
				if (!tab)
					break;
				*tab = 0;
				v[i] = strtoul(p, 0, 10);
				p = tab + 1;
			}
			if (i != 4)
				continue;   /* malformed row: skip it, not the file */

			len = strlen(p);
			while (len && (p[len - 1] == '\n' || p[len - 1] == '\r'))
				p[--len] = 0;
			/* The recorded length is authoritative: it is what the
			 * generator measured, and trusting strlen would silently
			 * truncate a literal containing a NUL once escapes exist. */
			if (v[3] != len || len == 0 || len > KOF_STR_MAX_LEN)
				continue;

			e.icase    = (uint8_t)v[1];
			e.fullword = (uint8_t)v[2];
			e.len      = (uint16_t)len;
			memcpy(e.bytes, p, len);
			if (len >= 4) {
				e.gram = gram_hash(load32(e.bytes));
				e.has_gram = 1;
			}
			if (!str_tab_push(&e))
				break;
			m->n_str++;
		}
	}
	fclose(f);
}

/*
 * Preconditions, read from the table the build emitted beside the blob.
 *
 * A missing or empty field means unconstrained, and that is the safe direction: an
 * unconstrained module gets run, so a stale or absent record costs time rather than
 * detections. Getting this backwards - defaulting to a constraint - would silently
 * stop running modules, which no test would notice.
 */
static void meta_load(struct module *m, const char *blob_path)
{
	char path[4096];
	char line[128];
	FILE *f;

	m->target_mask = 0xffffffffu;
	m->scan_mask   = 0;
	m->size_min    = 0;
	m->arch_mask   = 0;

	if (!sibling_path(blob_path, ".meta", path, sizeof path))
		return;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "kofrun: no precondition table at %s; "
				"assuming the module applies to everything\n", path);
		return;
	}
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "target=", 7) == 0)
			m->target_mask = (uint32_t)strtoul(line + 7, 0, 10);
		else if (strncmp(line, "scan_mask=", 10) == 0)
			m->scan_mask = (uint32_t)strtoul(line + 10, 0, 10);
		else if (strncmp(line, "size_min=", 9) == 0)
			m->size_min = strtoull(line + 9, 0, 10);
		else if (strncmp(line, "arch_mask=", 10) == 0)
			m->arch_mask = (uint32_t)strtoul(line + 10, 0, 10);
	}
	fclose(f);
	if (m->target_mask == 0)
		m->target_mask = 0xffffffffu;
}

static const char *fmt_str(uint8_t t)
{
	switch (t) {
	case KOF_FMT_ELF:    return "ELF";
	case KOF_FMT_PE:     return "PE";
	case KOF_FMT_MACHO:  return "MachO";
	case KOF_FMT_SCRIPT: return "Script";
	case KOF_FMT_TEXT:   return "Text";
	default:            return "Unknown";
	}
}

static const char *arch_name(uint8_t a)
{
	switch (a) {
	case KOF_ARCH_X86:     return "x86";
	case KOF_ARCH_X86_64:  return "x86_64";
	case KOF_ARCH_ARM:     return "arm";
	case KOF_ARCH_ARM64:   return "arm64";
	case KOF_ARCH_RISCV64: return "riscv64";
	case KOF_ARCH_MIPS:    return "mips";
	case KOF_ARCH_PPC64:   return "ppc64";
	default:               return "any";
	}
}

/*
 * Build the string a finding is reported as: <format>.<arch>.<authored family>.
 *
 * The prefix is composed rather than authored. It removes the chance of a module
 * naming a format it was not run against, and it means one authored name covers
 * every architecture instead of being written out once per combination.
 *
 * The operating system is absent on purpose. ELF does not say it - os_abi reads
 * SYSV on essentially everything - so putting "Linux" here would be a guess
 * wearing the clothes of a fact.
 */
static void finding_str(const struct kof_obj_ctx *ctx, const struct module *m,
			const struct host_state *h, char *out, size_t cap)
{
	const char *nm;

	if (!h->rep_valid) {
		snprintf(out, cap, "-");
		return;
	}
	nm = name_of(m, h->rep_name_id);
	snprintf(out, cap, "%s.%s.%s", fmt_str(ctx->format),
		 arch_name(ctx->arch), nm ? nm : "unknown");
}

static uint8_t c_rd8(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint8_t v = 0;
	kof_rd_u8(mctx_of(ctx)->data, off, &v);
	return v;
}

static uint16_t c_rd16(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint16_t v = 0;
	kof_rd_u16(mctx_of(ctx)->data, off, 0, &v);
	return v;
}

static uint32_t c_rd32(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint32_t v = 0;
	kof_rd_u32(mctx_of(ctx)->data, off, 0, &v);
	return v;
}

static uint64_t c_rd64(const struct kof_obj_ctx *ctx, uint64_t off)
{
	uint64_t v = 0;
	kof_rd_u64(mctx_of(ctx)->data, off, 0, &v);
	return v;
}

static int c_memeq(const struct kof_obj_ctx *ctx, uint64_t off,
		   const void *pat, uint32_t len)
{
	kof_buf s = kof_slice(mctx_of(ctx)->data, off, len);
	if (s.n != len || len == 0)
		return 0;
	return memcmp(s.p, pat, len) == 0;
}

static uint32_t c_csum(const struct kof_obj_ctx *ctx, uint64_t off,
		       uint32_t len)
{
	kof_buf s = kof_slice(mctx_of(ctx)->data, off, len);
	if (s.n != len)
		return 0;
	return kof_crc32(s.p, s.n);
}


/* Outcomes the host can report without the module having run. */
enum {
	RUN_SKIP  = -1, /* could not be opened or mapped */
	RUN_NA    = -2  /* module's target does not cover this object */
};

/*
 * Why modules were not run, counted. This is the measurement the whole
 * precondition idea stands or falls on: a filter that rules nothing out is
 * overhead, and the only way to know which is to count.
 */
struct prefilter_stats {
	uint64_t considered;
	uint64_t by_target;
	uint64_t by_size;
	uint64_t by_arch;
	uint64_t by_region;
	uint64_t ran;
	uint64_t gram_bytes;   /* cost of building the presence sets */
};

/*
 * Which four-byte sequences occur in the object under scan.
 *
 * The point is what it is not: it does not grow with the database. One fixed table
 * answers "is this sequence present" for any number of modules, built in a single
 * pass over the object rather than once per module. That is O(bytes + modules)
 * instead of O(modules x bytes), and the second is where this was heading - 4000
 * modules read every byte 1954 times.
 *
 * An automaton over every pattern would also collapse the passes and would be exact,
 * but its size is the database's size. This trades exactness for a fixed footprint: a
 * collision makes a module run that need not have, which costs time. Absence is never
 * wrong, and absence is what gets acted on.
 *
 * Generation stamps rather than a bitmap that gets cleared, so a new object is a
 * counter increment and the table is wiped only when the counter wraps.
 */
/*
 * Allocated only when it will be used.
 *
 * Below GRAM_MIN_STRINGS there is nothing to amortise the build over, and mapping
 * the table anyway is not free even though calloc is lazy: gram_build writes
 * scattered stamps, so the pages get touched for real. Measured on one module over
 * one sample directory, building it unconditionally cost 4.37s and 53MB against
 * 2.74s and 5MB - the table answering two questions that two direct searches would
 * have answered.
 */
static int gram_init(uint32_t n_strings)
{
	gram_gen = 0;
	if (n_strings < GRAM_MIN_STRINGS)
		return 1;
	gram_stamp = calloc(GRAM_SLOTS, sizeof *gram_stamp);
	return gram_stamp != NULL;
}

/*
 * Record every four-byte sequence of the object.
 *
 * Built over the whole object rather than per region, and that is the safe
 * direction: a sequence that occurs in a part of the file no module searches makes
 * the filter admit a module it could have excluded, which costs a scan. Building
 * per region would be tighter and would cost a pass per region, which is the thing
 * being avoided.
 */
static void gram_build(kof_buf b, struct prefilter_stats *st)
{
	uint64_t i;

	if (!gram_enabled())
		return;
	if (++gram_gen == 0) {
		/* Wrapped: every slot still holds a stamp from 65535 objects ago,
		 * which would now read as current. */
		memset(gram_stamp, 0, (size_t)GRAM_SLOTS * sizeof *gram_stamp);
		gram_gen = 1;
	}
	if (b.n < 4)
		return;
	for (i = 0; i + 4 <= b.n; i++)
		gram_stamp[gram_hash(load32(b.p + i))] = gram_gen;
	st->gram_bytes += b.n;
}

static int gram_present(uint32_t h)
{
	return gram_stamp[h] == gram_gen;
}

/*
 * Which regions this object actually has, as a mask of region bits.
 *
 * Computed once per object, not once per module. That distinction is the whole
 * value: resolving a region walks the segment and section tables and sorts the
 * result, so doing it per module would cost more than running the cheap modules it
 * is supposed to save. Done once, the per-module test is a single AND.
 *
 * This is the same shape as the prefix-checksum tables in the old engine - pay for
 * a small per-object precomputation so that each of very many records can be
 * decided with one instruction.
 */
static uint32_t regions_present(const struct kof_obj_ctx *ctx)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t present = 0, bit;

	if (ctx->obj_size)
		present |= KOF_SCAN_ALL;
	if (!ctx->resolve_scan)
		return present;

	/* Bit 0 is KOF_SCAN_ALL, already handled; the rest belong to the format. */
	for (bit = 1; bit < 16; bit++)
		if (ctx->resolve_scan(ctx, 1u << bit, ext, KOF_SCAN_MAX_EXTENTS))
			present |= 1u << bit;
	return present;
}

/*
 * Search one declared string over one range.
 *
 * Region resolution and the matcher are the same ones a module used to reach through
 * the content table; the only change is who calls them. Fullword is applied here
 * rather than inside the matcher because it depends on the bytes either side of a
 * match, and the edge of an extent counts as a boundary - a property of the range,
 * not of the pattern.
 */
static int is_word_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

static int search_str(const struct kof_obj_ctx *ctx, struct host_state *h,
		      const struct str_ent *e, uint32_t scan_mask)
{
	struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	uint32_t n = 0, i;

	if (scan_mask & KOF_SCAN_ALL) {
		ext[0].off = 0;
		ext[0].len = ctx->obj_size;
		n = ctx->obj_size ? 1 : 0;
	} else if (ctx->resolve_scan) {
		n = ctx->resolve_scan(ctx, scan_mask, ext, KOF_SCAN_MAX_EXTENTS);
		if (n > KOF_SCAN_MAX_EXTENTS)
			n = KOF_SCAN_MAX_EXTENTS;
	}

	for (i = 0; i < n; i++) {
		uint64_t base = ext[i].off, span = ext[i].len, from = 0, hit;

		while (span > from &&
		       kof_match_find(&h->m, base + from, span - from,
				      e->bytes, e->len, e->icase, &hit)) {
			if (!e->fullword)
				return 1;
			{
				uint64_t end = hit + e->len;
				int lok = (hit == base) ||
					  !is_word_byte(h->m.data.p[hit - 1]);
				int rok = (end >= base + span) ||
					  !is_word_byte(h->m.data.p[end]);
				if (lok && rok)
					return 1;
			}
			from = (hit - base) + 1;
		}
	}
	return 0;
}

/*
 * Does any case variant of this gram occur?
 *
 * A case insensitive string still filters, which is worth having: the presence set
 * holds the object's bytes as they are, so "gLiB" has to be looked up as every case
 * combination its letters allow. Four bytes means at most sixteen lookups into a
 * table that is already warm, against a pass over the object - so folding costs
 * nothing here.
 */
static int gram_present_folded(const uint8_t *b)
{
	uint8_t letter[4], base[4];
	int nl = 0, i, comb;

	for (i = 0; i < 4; i++) {
		uint8_t c = b[i];
		base[i] = c;
		letter[i] = 0;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			letter[i] = 1;
			nl++;
			base[i] = (uint8_t)(c | 0x20);
		}
	}
	for (comb = 0; comb < (1 << nl); comb++) {
		uint8_t v[4];
		int bit = 0;
		for (i = 0; i < 4; i++) {
			v[i] = base[i];
			if (letter[i]) {
				if (comb & (1 << bit))
					v[i] = (uint8_t)(base[i] & ~0x20u);
				bit++;
			}
		}
		if (gram_present(gram_hash(load32(v))))
			return 1;
	}
	return 0;
}

/*
 * The module facing search, in two stages.
 *
 * The presence set says whether the string's first four bytes occur anywhere in the
 * object; only then is a search run. So a marker that is absent - nearly every marker
 * for nearly every object - costs one table lookup and no scan. That first stage does
 * not depend on the range, so absence answers every range at once.
 *
 * Answers are memoised per (string, range), so a module asking twice pays once and a
 * batched pass can fill the same table ahead of time. That is where batching will go:
 * the surviving strings of every module about to run, searched together, one pass per
 * range.
 */
#define MEMO_UNKNOWN 0
#define MEMO_ABSENT  1
#define MEMO_PRESENT 2

static uint8_t *str_memo;          /* n_str_tab rows of n_rng_tab, reset per object */
static uint32_t str_memo_stride;

static int c_find_str(const struct kof_obj_ctx *ctx, uint32_t str_id,
		      uint32_t range_id)
{
	struct host_state *h = host_of(ctx);
	const struct module *m = h->cur_mod;
	const struct str_ent *e;
	uint32_t si, ri;
	uint8_t *slot;
	int found;

	if (!m || str_id >= m->n_str || range_id >= m->n_rng)
		return 0;
	si = m->str_base + str_id;
	ri = m->rng_base + range_id;
	e = &str_tab[si];

	slot = &str_memo[(size_t)si * str_memo_stride + ri];
	if (*slot != MEMO_UNKNOWN)
		return *slot == MEMO_PRESENT;

	if (e->has_gram && gram_enabled()) {
		int maybe = e->icase ? gram_present_folded(e->bytes)
				     : gram_present(e->gram);
		if (!maybe) {
			h->n_gram_skips++;
			*slot = MEMO_ABSENT;
			return 0;
		}
	}
	found = search_str(ctx, h, e, rng_tab[ri]);
	*slot = found ? MEMO_PRESENT : MEMO_ABSENT;
	return found;
}

static const struct kof_content content_vtable = {
	c_rd8, c_rd16, c_rd32, c_rd64, c_memeq, c_find_str, c_csum
};

/*
 * Can this module be ruled out for this object without calling it?
 *
 * Every test here reads a field of the module's record against a fact the collector
 * already produced. None of them touches the blob, which is what makes this a
 * pre-use filter rather than the same conditions written inside the module - those
 * are correct and save nothing, because reaching them costs the call.
 *
 * Absent constraints mean unconstrained, so a module with an empty record runs. The
 * default has to fall that way: over-running costs time, under-running costs
 * detections and would not show up as a failure anywhere.
 */
static int prefilter(const struct module *m, const struct kof_obj_ctx *ctx,
		     uint32_t present, struct prefilter_stats *st)
{
	st->considered++;

	if (!(m->target_mask & (1u << ctx->format))) {
		st->by_target++;
		return 0;
	}
	if (ctx->obj_size < m->size_min) {
		st->by_size++;
		return 0;
	}
	if (m->arch_mask) {
		/* Architectures outside the bit width cannot be named by a mask, so
		 * a module that constrains architecture does not cover them. */
		if (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))) {
			st->by_arch++;
			return 0;
		}
	}
	/*
	 * A module that names regions cannot match if none of them exist here: every
	 * search it performs would be over an empty range. A module that names none -
	 * scalar only - has nothing to be excused by, and runs.
	 */
	if (m->scan_mask && !(m->scan_mask & present)) {
		st->by_region++;
		return 0;
	}

	st->ran++;
	return 1;
}

/*
 * Map the target read only, collect facts, and decide whether this module
 * applies before calling it.
 *
 * The applicability test lives here rather than inside the module, because it is
 * the host that chose to make the call. A module asked about an object it was
 * never written for has nothing useful to say, and having every module open with
 * the same two guards means the same condition is evaluated once per module per
 * object instead of once per object.
 *
 * The predicate is hardcoded to ELF for now. It becomes a lookup of the target
 * mask carried by the module's record, which is also where the ABI version it
 * was built against will live; today module and host come out of the same make
 * invocation, so neither can drift from the other.
 */
/*
 * Scan one object with every loaded module.
 *
 * Mapped once, parsed once, regions resolved once - then N modules are filtered
 * against that one set of facts. This is the shape the design has been arguing for
 * all along: the expensive part is per object, and per module there is only a
 * handful of integer comparisons for the ones that get ruled out.
 *
 * The applicability test lives here rather than inside the modules, because it is
 * the host that chose to make the call. It is also what makes the format cast in a
 * module sound: kof_elf() casts ctx->file_header, and that is safe only because a
 * module is never entered for an object its declared target does not cover.
 */
static int scan_file(const char *path, struct kof_elf_info *info,
		     struct host_state *h, struct prefilter_stats *st,
		     char *name_out, size_t name_cap, uint32_t *hit_mod)
{
	struct kof_obj_ctx ctx;
	struct stat sb;
	void *map = NULL;
	kof_buf buf;
	uint32_t present, i;
	int fd, rc = RUN_NA;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return RUN_SKIP;
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return RUN_SKIP;
	}
	if (sb.st_size > 0) {
		map = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE,
			   fd, 0);
		if (map == MAP_FAILED) {
			close(fd);
			return RUN_SKIP;
		}
	}
	close(fd);

	memset(&ctx, 0, sizeof ctx);
	ctx.content = &content_vtable;
	ctx.report  = c_report;
	ctx.cont    = c_cont;
	ctx.priv    = h;

	buf = kof_buf_make(map, (uint64_t)sb.st_size);
	kof_match_begin(&h->m, buf);
	kof_elf_parse(buf, info, &ctx);
	present = regions_present(&ctx);
	gram_build(buf, st);
	/* Answers are per object, so the memo is cleared per object. One byte per
	 * (string, range) pair across the whole database - small next to the tables
	 * themselves, and a clear beats keeping a generation stamp for something this
	 * size. */
	if (str_memo)
		memset(str_memo, MEMO_UNKNOWN,
		       (size_t)n_str_tab * str_memo_stride);

	h->files_bytes += (uint64_t)sb.st_size;

	for (i = 0; i < n_mods; i++) {
		if (!prefilter(&mods[i], &ctx, present, st))
			continue;

		h->rep_valid = 0;
		h->rep_cont  = 0;
		/* Every string this module declared, answered before it is entered. */
		h->cur_mod = &mods[i];
		mods[i].fn(&ctx);
		h->cur_mod = NULL;
		h->files_run++;

		if (h->rep_valid) {
			finding_str(&ctx, &mods[i], h, name_out, name_cap);
			*hit_mod = i;
			rc = 1;
			/* First finding wins. Whether to keep going is a host
			 * policy, not something a module gets to decide. */
			break;
		}
		rc = 0;   /* at least one module ran and said nothing */
	}

	/* Accumulate before the per-file counters are reset by the next
	 * kof_match_begin. */
	h->tot_bytes += h->m.n_bytes_scanned;
	h->tot_calls += h->m.n_calls;
	h->tot_memo  += h->m.n_memo_hits;

	if (map)
		munmap(map, (size_t)sb.st_size);
	return rc;
}

/*
 * Load every blob into one arena.
 *
 * One mapping and one mprotect for the whole set, not one per module. Measured on
 * this machine, the per-module model costs 3.35us in mmap+copy+mprotect plus 2.61us
 * in the three file opens; at ten thousand modules that is sixty milliseconds of
 * syscall before a single byte is scanned. Sharing the arena removes the first part
 * of that, and a packed container removes the rest, which is the next step.
 */
/* File scope, not allocated: the arena outlives every function here by design,
 * since the module table holds function pointers into it for the life of the
 * process. Making that lifetime explicit also keeps the leak checker quiet about a
 * mapping that is deliberately never released. */
static struct arena code_arena;

static int modules_load(char **paths, int n)
{
	struct arena *arena = &code_arena;
	size_t total = 0;
	int i;

	mods = calloc((size_t)n, sizeof *mods);
	if (!mods)
		return 0;

	for (i = 0; i < n; i++) {
		struct stat sb;
		if (stat(paths[i], &sb) == 0)
			total += (size_t)sb.st_size + 64;
	}
	if (!arena_open(arena, total ? total : 4096)) {
		fprintf(stderr, "kofrun: cannot reserve arena\n");
		return 0;
	}

	for (i = 0; i < n; i++) {
		uint8_t *blob;
		size_t len;
		long off;

		blob = read_file(paths[i], &len);
		if (!blob) {
			fprintf(stderr, "kofrun: cannot read blob %s\n", paths[i]);
			continue;
		}
		if (!blob_plausible(blob, len, paths[i])) {
			free(blob);
			continue;
		}
		off = arena_add(arena, blob, len);
		free(blob);
		if (off < 0) {
			fprintf(stderr, "kofrun: arena full at %s\n", paths[i]);
			break;
		}
		mods[n_mods].path = paths[i];
		/* Entry offset is zero within each blob; build.sh asserts it. */
		mods[n_mods].fn = (kof_scan_fn)(void *)(arena->base + off);
		names_load(&mods[n_mods], paths[i]);
		meta_load(&mods[n_mods], paths[i]);
		strs_load(&mods[n_mods], paths[i]);
		n_mods++;
	}

	if (!arena_seal(arena)) {
		fprintf(stderr, "kofrun: cannot make the arena executable\n");
		arena_close(arena);
		return 0;
	}
	return n_mods > 0;
}

/* Collect *.blob from a directory, so a whole signature set can be named at once. */
static int collect_blobs(const char *dir, char ***out)
{
	char **v = NULL;
	size_t cap = 0, n = 0;
	struct dirent *de;
	DIR *d = opendir(dir);

	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char *p;
		if (l < 6 || strcmp(de->d_name + l - 5, ".blob") != 0)
			continue;
		if (n == cap) {
			size_t nc = cap ? cap * 2 : 64;
			char **nv = realloc(v, nc * sizeof *nv);
			if (!nv)
				break;
			v = nv;
			cap = nc;
		}
		p = malloc(strlen(dir) + l + 2);
		if (!p)
			break;
		sprintf(p, "%s/%s", dir, de->d_name);
		v[n++] = p;
	}
	closedir(d);
	*out = v;
	return (int)n;
}

int main(int argc, char **argv)
{
	struct kof_elf_info *info;
	struct host_state host;
	struct prefilter_stats st;
	struct stat sb;
	char **sigs = NULL;
	int nsigs = 0, first_target, i, matched = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <blob-or-sigdir> <file>...\n", argv[0]);
		return 2;
	}

	memset(&host, 0, sizeof host);
	memset(&st, 0, sizeof st);

	/* First argument names either one blob or a directory of them. A directory
	 * is how a set large enough for the filter to matter gets named. */
	if (stat(argv[1], &sb) == 0 && S_ISDIR(sb.st_mode)) {
		nsigs = collect_blobs(argv[1], &sigs);
		if (nsigs <= 0) {
			fprintf(stderr, "kofrun: no .blob files in %s\n", argv[1]);
			return 2;
		}
	} else {
		sigs = &argv[1];
		nsigs = 1;
	}
	first_target = 2;

	if (!modules_load(sigs, nsigs)) {
		fprintf(stderr, "kofrun: no modules loaded\n");
		return 2;
	}
	/* The vector is done with, but not the strings in it: each module holds the
	 * pointer to its own path for reporting. */
	if (sigs != &argv[1])
		free(sigs);
	printf("loaded %u module(s), %u string(s)\n", n_mods, n_str_tab);

	/* After loading, because the decision depends on how many strings there are. */
	if (!gram_init(n_str_tab)) {
		fprintf(stderr, "kofrun: cannot allocate the presence table\n");
		return 2;
	}

	/* One row per declared string, one column per declared range. Allocated once
	 * the tables are known, because until then there is no size. */
	str_memo_stride = n_rng_tab ? n_rng_tab : 1;
	if (n_str_tab) {
		str_memo = calloc((size_t)n_str_tab * str_memo_stride, 1);
		if (!str_memo) {
			fprintf(stderr, "kofrun: out of memory\n");
			return 2;
		}
	}

	/* One instance, reused for every file: the struct carries the segment and
	 * section arrays inline, so per-file allocation would mean a fresh 11KB
	 * and a free on each one. */
	info = malloc(sizeof *info);
	if (!info) {
		fprintf(stderr, "kofrun: out of memory\n");
		return 2;
	}

	for (i = first_target; i < argc; i++) {
		char found[224] = "-";
		uint32_t hit = 0;
		switch (scan_file(argv[i], info, &host, &st, found,
				  sizeof found, &hit)) {
		case RUN_SKIP:
			printf("%-10s %s\n", "SKIP", argv[i]);
			break;
		case RUN_NA:
			/* Reported distinctly from CLEAN: "no module was asked" and
			 * "the modules said no" are different facts, and conflating
			 * them hides how much of a corpus is actually covered. */
			printf("%-10s %s\n", "N/A", argv[i]);
			break;
		default:
			printf("%-10s %-40s %s\n", outcome_str(&host), found,
			       argv[i]);
			if (host.rep_valid && host.rep_level == KOF_LVL_INFECT)
				matched++;
			break;
		}
	}

	printf("matched %d of %d\n", matched, argc - first_target);

	/*
	 * How much the preconditions actually removed. The number that decides
	 * whether declaring them was worth anything: a filter that rules nothing out
	 * is pure overhead, and only the counts can say which it is.
	 */
	if (st.considered) {
		printf("prefilter: %llu considered, %llu ran (%.2f%%)\n",
		       (unsigned long long)st.considered,
		       (unsigned long long)st.ran,
		       100.0 * (double)st.ran / (double)st.considered);
		printf("  skipped by  target=%llu  size=%llu  arch=%llu  region=%llu\n",
		       (unsigned long long)st.by_target,
		       (unsigned long long)st.by_size,
		       (unsigned long long)st.by_arch,
		       (unsigned long long)st.by_region);
		/* The string filter is not a module-level skip any more: the module
		 * runs and its searches are answered, so what is counted here is
		 * searches avoided rather than modules avoided. Reported separately
		 * because it is the number that says whether the presence set is
		 * earning the pass it costs. */
		printf("  searches answered from the presence set: %llu\n",
		       (unsigned long long)host.n_gram_skips);
		printf("  presence sets built over %.2f MB (one pass per object)\n",
		       (double)st.gram_bytes / 1048576.0);
	}

	/*
	 * Scan cost. Printed always, because the whole design rests on a module
	 * being cheap for the objects it does not detect, and a number nobody looks
	 * at is a number nobody keeps honest.
	 *
	 * "of object bytes" is the ratio worth watching: it is how much of the
	 * material a module chose to read. A scalar-gated module lands near zero, a
	 * KOF_SCAN_ALL module near one per pattern, and a region-scoped one in
	 * between at a share set by its mask.
	 */
	if (host.files_bytes) {
		/* Extent searches, not kof_find_str calls: one authored search over a
		 * mask resolving to three ranges counts three. That is the right
		 * unit here, since it is what the matcher was actually entered for. */
		printf("scan cost: %llu extent searches, %llu memo hits, "
		       "%.2f MB searched over %.2f MB of objects (%.2fx)\n",
		       (unsigned long long)host.tot_calls,
		       (unsigned long long)host.tot_memo,
		       (double)host.tot_bytes / 1048576.0,
		       (double)host.files_bytes / 1048576.0,
		       (double)host.tot_bytes / (double)host.files_bytes);
	}

	free(info);
	/* The arena is deliberately not unmapped: the process is about to exit, and
	 * tearing down an executable mapping while function pointers into it are
	 * still reachable buys nothing. */
	return 0;
}
