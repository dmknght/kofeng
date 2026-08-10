/*
 * kofdb.c - load packed databases into an immutable engine.
 *
 * A database is one or more .ksig packs. Each is mapped read only, validated, and
 * its tables copied into the engine's; the mapping is released once the copy is
 * done, so nothing outlives the load but the engine itself.
 *
 * Copying rather than pointing into the mapping is a deliberate first step. The
 * format is laid out so that a reader could use it in place - that is what the
 * fixed strides are for - but doing so means the engine's tables become per pack
 * and the scan path has to reach through one more level. That change is worth
 * measuring before it is made; this one is not, because the cost it removes is
 * already the whole of the problem:
 *
 *     4000 modules as loose artefacts: 16000 files, 83463 syscalls, 47ms per
 *     process with a warm page cache - none of it I/O, all of it syscall and
 *     parse, and all of it linear in the number of modules.
 *
 * Reading N packs is N opens and N mmaps whatever they contain.
 *
 * The validation order below is the one kofpack.h specifies, and the order is the
 * point: every step runs before anything it checks is dereferenced, and no step
 * trusts a value a later step has not yet bounded. Every bound comes from the
 * length fstat reported, never from a length the file states about itself.
 */

/* Before any include, not after: open, mmap and opendir are POSIX, and a feature
 * test macro placed after the first include has no effect at all. */
#define _POSIX_C_SOURCE 200809L

#include "kofdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

static size_t page_size_of(void)
{
	long ps = sysconf(_SC_PAGESIZE);

	return ps > 0 ? (size_t)ps : 4096u;
}

/* ---- validation ------------------------------------------------------------- */

/*
 * Is this mapping a pack, and does every offset in it stay inside the mapping?
 *
 * One function rather than checks scattered through the loader, so the rule that
 * nothing is dereferenced before it is bounded can be read in one place instead
 * of reconstructed from the order of statements.
 */
static int pack_valid(const void *map, uint64_t len, const char *path)
{
	const struct kof_pack_hdr *h = map;
	uint64_t i;

#define REFUSE(...)                                                            \
	do {                                                                   \
		fprintf(stderr, "kofdb: %s: ", path);                          \
		fprintf(stderr, __VA_ARGS__);                                  \
		fputc('\n', stderr);                                           \
		return 0;                                                      \
	} while (0)

	if (len < sizeof *h)
		REFUSE("smaller than a pack header");
	if (h->magic != KOF_PACK_MAGIC)
		REFUSE("not a pack");
	if (h->version != KOF_PACK_VERSION)
		REFUSE("pack version %u, this engine reads %u", h->version,
		       KOF_PACK_VERSION);
	/* A pack holds native code, so one built for another machine is refused
	 * loudly rather than entered. */
	if (h->machine != KOF_PACK_MACH_HOST)
		REFUSE("built for machine %u, this is %u", h->machine,
		       (unsigned)KOF_PACK_MACH_HOST);
	/* The kind is the ABI. kof_scan_fn is the only entry point this engine
	 * knows how to call, so a pack of unpackers is refused here rather than
	 * entered through the wrong signature - which is the point of one kind per
	 * pack. */
	if (h->kind != KOF_PACK_DETECT)
		REFUSE("holds kind %u; this engine runs detectors only", h->kind);
	/* Before any offset inside is believed: truncation is caught here. */
	if (h->file_len != len)
		REFUSE("declares %llu bytes, the file has %llu",
		       (unsigned long long)h->file_len, (unsigned long long)len);
	if (kof_crc32((const uint8_t *)map + KOF_PACK_CRC_FROM,
		      len - KOF_PACK_CRC_FROM) != h->crc32)
		REFUSE("checksum does not match its contents");

	for (i = 0; i < KOF_SEC_COUNT; i++) {
		uint64_t off = h->sec[i].off, n = h->sec[i].len;
		uint64_t align = (i == KOF_SEC_CODE) ? KOF_PACK_CODE_ALIGN
						     : KOF_PACK_SEC_ALIGN;

		if (off > len || n > len - off)
			REFUSE("section %llu runs outside the file",
			       (unsigned long long)i);
		if (off % align)
			REFUSE("section %llu is misaligned",
			       (unsigned long long)i);
	}

	/*
	 * Exactly, not at most. A section longer than its count means the writer
	 * and this reader disagree about the stride, and that is not a pack to
	 * load however plausible the rest of it looks.
	 *
	 * The parameter is not called `sec`: it is substituted into h->sec[...],
	 * and a macro parameter shadowing the member it indexes expands to
	 * nonsense.
	 */
#define STRIDE(id_, count_, unit_)                                             \
	if (h->sec[id_].len != (uint64_t)(count_) * (unit_))                   \
		REFUSE("section %s is %llu bytes for %u entries of %u", #id_,  \
		       (unsigned long long)h->sec[id_].len,                    \
		       (unsigned)(count_), (unsigned)(unit_))

	STRIDE(KOF_SEC_PRE_TARGET, h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_SCAN,   h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_ARCH,   h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_SIZE,   h->n_mods,  8);
	STRIDE(KOF_SEC_MODS,       h->n_mods,  sizeof(struct kof_pack_mod));
	STRIDE(KOF_SEC_STR_DESC,   h->n_str,   sizeof(struct kof_pack_str));
	STRIDE(KOF_SEC_NAME_DESC,  h->n_names, sizeof(struct kof_pack_name));
	STRIDE(KOF_SEC_RANGE,      h->n_rng,   4);
#undef STRIDE

	/*
	 * Per module and per descriptor, arithmetic only: no syscall, no
	 * allocation, a few compares each. This is the one per-module loop at load
	 * and it is what lets the scan path do no bounds checking at all - that
	 * path is hot and runs per object per module, so paying there for what can
	 * be settled once here is the wrong trade.
	 */
	{
		const uint8_t *base = map;
		const struct kof_pack_mod *m =
			(const void *)(base + h->sec[KOF_SEC_MODS].off);
		const struct kof_pack_str *s =
			(const void *)(base + h->sec[KOF_SEC_STR_DESC].off);
		const struct kof_pack_name *nm =
			(const void *)(base + h->sec[KOF_SEC_NAME_DESC].off);
		const char *np = (const char *)base +
				 h->sec[KOF_SEC_NAME_POOL].off;
		uint64_t code_len = h->sec[KOF_SEC_CODE].len;
		uint64_t spool = h->sec[KOF_SEC_STR_POOL].len;
		uint64_t npool = h->sec[KOF_SEC_NAME_POOL].len;
		uint32_t k;

		for (k = 0; k < h->n_mods; k++) {
			if ((uint64_t)m[k].code_off + m[k].code_len > code_len)
				REFUSE("module %u names code outside the arena", k);
			if ((uint64_t)m[k].str_first + m[k].n_str > h->n_str ||
			    (uint64_t)m[k].rng_first + m[k].n_rng > h->n_rng ||
			    (uint64_t)m[k].name_first + m[k].n_names > h->n_names)
				REFUSE("module %u names a table slice that is "
				       "not there", k);
			if (m[k].code_off % KOF_PACK_BLOB_ALIGN)
				REFUSE("module %u is not aligned for a call", k);
		}
		for (k = 0; k < h->n_str; k++) {
			if ((uint64_t)s[k].off + s[k].len > spool)
				REFUSE("string %u lies outside its pool", k);
			if (s[k].len == 0 || s[k].len > KOF_STR_MAX_LEN)
				REFUSE("string %u has length %u", k, s[k].len);
		}
		for (k = 0; k < h->n_names; k++) {
			uint64_t o = nm[k].off, j;
			int terminated = 0;

			if (o >= npool)
				REFUSE("name %u lies outside its pool", k);
			for (j = o; j < npool; j++)
				if (np[j] == 0) {
					terminated = 1;
					break;
				}
			if (!terminated)
				REFUSE("name %u is not terminated inside its pool",
				       k);
		}
	}
	return 1;
#undef REFUSE
}

/* ---- mapping ---------------------------------------------------------------- */

/* A pack while it is being read. Alive only for the length of one load. */
struct mapped {
	void  *map;
	size_t len;
};

static int map_pack(struct mapped *mp, const char *path)
{
	struct stat st;
	void *map;
	int fd;

	mp->map = NULL;
	mp->len = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "kofdb: cannot open %s\n", path);
		return 0;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return 0;
	}
	/* The descriptor is closed at once: a mapping keeps the file alive on its
	 * own, and holding one open per pack would spend a descriptor per pack for
	 * nothing. */
	map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		fprintf(stderr, "kofdb: cannot map %s\n", path);
		return 0;
	}
	if (!pack_valid(map, (uint64_t)st.st_size, path)) {
		munmap(map, (size_t)st.st_size);
		return 0;
	}
	mp->map = map;
	mp->len = (size_t)st.st_size;
	return 1;
}

static void unmap_pack(struct mapped *mp)
{
	if (mp->map)
		munmap(mp->map, mp->len);
	mp->map = NULL;
	mp->len = 0;
}

/* ---- the code arena --------------------------------------------------------- */

/*
 * One arena for every pack, not one per pack: per-pack mapping costs an mmap and
 * an mprotect each, and the arena is written once then flipped to read plus
 * execute in a single step, so no page is ever writable and executable at once.
 */
static int arena_open(struct kof_engine *e, size_t want)
{
	size_t ps = page_size_of();

	e->code_cap = (want + ps - 1) / ps * ps;
	if (e->code_cap == 0)
		e->code_cap = ps;
	e->code = mmap(NULL, e->code_cap, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (e->code == MAP_FAILED) {
		e->code = NULL;
		e->code_cap = 0;
		return 0;
	}
	return 1;
}

/* ---- collecting packs -------------------------------------------------------- */

/* Collect *.ksig from a directory so a whole database can be named at once. */
static const char **collect_packs(const char *dir, uint32_t *out_n)
{
	static const char ext[] = ".ksig";
	DIR *d = opendir(dir);
	struct dirent *de;
	const char **v = NULL;
	uint32_t n = 0, cap = 0;

	*out_n = 0;
	if (!d)
		return NULL;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name), need;
		char *p;

		if (l < sizeof ext ||
		    strcmp(de->d_name + l - (sizeof ext - 1), ext) != 0)
			continue;
		if (n == cap) {
			uint32_t nc = cap ? cap * 2 : 16;
			const char **nv = realloc(v, nc * sizeof *nv);
			if (!nv)
				break;
			v = nv;
			cap = nc;
		}
		need = strlen(dir) + l + 2;
		p = malloc(need);
		if (!p)
			break;
		snprintf(p, need, "%s/%s", dir, de->d_name);
		v[n++] = p;
	}
	closedir(d);
	*out_n = n;
	return v;
}

/* ---- copying one pack into the engine ---------------------------------------- */

/*
 * Append a pack's tables to the engine's.
 *
 * Every index a module carries is rebased as it is copied: a module's string
 * slice is written as an offset into the engine's table, not the pack's, so
 * nothing on the scan path has to know which pack a module came from.
 */
static void absorb(struct kof_engine *e, const struct mapped *mp,
		   size_t code_at)
{
	const uint8_t *base = mp->map;
	const struct kof_pack_hdr *h = mp->map;
	const uint32_t *pt = (const void *)(base + h->sec[KOF_SEC_PRE_TARGET].off);
	const uint32_t *ps = (const void *)(base + h->sec[KOF_SEC_PRE_SCAN].off);
	const uint32_t *pa = (const void *)(base + h->sec[KOF_SEC_PRE_ARCH].off);
	const uint64_t *pz = (const void *)(base + h->sec[KOF_SEC_PRE_SIZE].off);
	const struct kof_pack_mod *pm =
		(const void *)(base + h->sec[KOF_SEC_MODS].off);
	const struct kof_pack_str *pstr =
		(const void *)(base + h->sec[KOF_SEC_STR_DESC].off);
	const struct kof_pack_name *pname =
		(const void *)(base + h->sec[KOF_SEC_NAME_DESC].off);
	const uint8_t *spool = base + h->sec[KOF_SEC_STR_POOL].off;
	const char *npool = (const char *)base + h->sec[KOF_SEC_NAME_POOL].off;
	const uint32_t *prng = (const void *)(base + h->sec[KOF_SEC_RANGE].off);

	uint32_t str0 = e->n_str, rng0 = e->n_rng, name0 = e->n_name;
	uint32_t i;

	memcpy(e->code + code_at, base + h->sec[KOF_SEC_CODE].off,
	       (size_t)h->sec[KOF_SEC_CODE].len);

	for (i = 0; i < h->n_str; i++) {
		struct kof_str_ent *d = &e->str_tab[e->n_str++];

		d->icase    = pstr[i].icase;
		d->fullword = pstr[i].fullword;
		d->len      = pstr[i].len;
		memcpy(d->bytes, spool + pstr[i].off, pstr[i].len);
	}
	for (i = 0; i < h->n_rng; i++)
		e->rng_tab[e->n_rng++] = prng[i];
	for (i = 0; i < h->n_names; i++) {
		struct kof_name_ent *d = &e->name_tab[e->n_name++];

		d->id = pname[i].id;
		snprintf(d->text, sizeof d->text, "%s", npool + pname[i].off);
	}

	for (i = 0; i < h->n_mods; i++) {
		struct kof_module *m = &e->mods[e->n_mods++];

		/* Entry offset is zero within each blob; the compiler asserts it,
		 * so the blob's place in the arena is the entry point. */
		m->fn = (kof_scan_fn)(void *)(e->code + code_at + pm[i].code_off);

		m->target_mask = pt[i];
		m->scan_mask   = ps[i];
		m->arch_mask   = pa[i];
		m->size_min    = pz[i];

		m->str_base  = str0  + pm[i].str_first;
		m->n_str     = pm[i].n_str;
		m->rng_base  = rng0  + pm[i].rng_first;
		m->n_rng     = pm[i].n_rng;
		m->name_base = name0 + pm[i].name_first;
		m->n_names   = pm[i].n_names;

		m->memo_base = e->memo_size;
		e->memo_size += m->n_str * m->n_rng;

		e->scan_mask |= m->scan_mask;
	}
}

/* ---- the database ------------------------------------------------------------ */

const char *kof_db_name(const struct kof_engine *e, const struct kof_module *m,
			uint32_t name_id)
{
	uint32_t i;

	for (i = 0; i < m->n_names; i++)
		if (e->name_tab[m->name_base + i].id == name_id)
			return e->name_tab[m->name_base + i].text;
	return NULL;
}

struct kof_engine *kof_db_load(const char *path)
{
	struct kof_engine *e = NULL;
	struct mapped *mp = NULL;
	struct stat sb;
	const char **paths = NULL;
	const char *single[1];
	uint32_t n_paths = 0, n_ok = 0, i;
	uint64_t n_mods = 0, n_str = 0, n_rng = 0, n_name = 0, code = 0, memo = 0;
	size_t at = 0;
	int owned = 0;

	if (!path)
		return NULL;

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		paths = collect_packs(path, &n_paths);
		owned = 1;
		if (!paths || n_paths == 0) {
			fprintf(stderr, "kofdb: no .ksig packs in %s\n", path);
			free(paths);
			return NULL;
		}
	} else {
		single[0] = path;
		paths = single;
		n_paths = 1;
	}

	mp = calloc(n_paths, sizeof *mp);
	if (!mp)
		goto out;

	/*
	 * Map and validate everything first, then allocate once from the totals.
	 * Growing the tables while reading would mean reallocating four arrays per
	 * pack, and the counts are already in the headers - there is nothing to
	 * discover by growing.
	 *
	 * A pack that will not load is refused and the rest are still read: one
	 * corrupt file in a directory should not take the whole database with it.
	 */
	for (i = 0; i < n_paths; i++) {
		const struct kof_pack_hdr *h;

		if (!map_pack(&mp[n_ok], paths[i]))
			continue;
		h = mp[n_ok].map;
		n_mods += h->n_mods;
		n_str  += h->n_str;
		n_rng  += h->n_rng;
		n_name += h->n_names;
		memo   += h->memo_slots;
		/* Each pack's blobs keep the offsets its own header gives them, so
		 * its code section is placed whole and aligned. */
		code = (code + KOF_PACK_BLOB_ALIGN - 1) / KOF_PACK_BLOB_ALIGN
		     * KOF_PACK_BLOB_ALIGN;
		code += h->sec[KOF_SEC_CODE].len;
		n_ok++;
	}
	if (n_ok == 0)
		goto out;
	/*
	 * In 64 bits, then refused if a total does not fit the engine's uint32.
	 *
	 * Not defensive politeness: every one of these is an index into a table
	 * allocated from it. A wrapped memo total in particular allocates a memo
	 * smaller than the slots the modules address, and the matcher's bounds check
	 * turns that into every search past the wrap answering "absent" - a database
	 * that loads, scans, and quietly detects nothing.
	 */
	if (n_mods > 0xffffffffu || n_str > 0xffffffffu ||
	    n_rng > 0xffffffffu || n_name > 0xffffffffu || memo > 0xffffffffu) {
		fprintf(stderr, "kofdb: %s: more entries than an index can hold\n",
			path);
		goto out;
	}

	e = calloc(1, sizeof *e);
	if (!e)
		goto out;
	e->mods     = calloc(n_mods ? n_mods : 1, sizeof *e->mods);
	e->str_tab  = calloc(n_str  ? n_str  : 1, sizeof *e->str_tab);
	e->rng_tab  = calloc(n_rng  ? n_rng  : 1, sizeof *e->rng_tab);
	e->name_tab = calloc(n_name ? n_name : 1, sizeof *e->name_tab);
	if (!e->mods || !e->str_tab || !e->rng_tab || !e->name_tab ||
	    !arena_open(e, (size_t)code)) {
		kof_db_free(e);
		e = NULL;
		goto out;
	}

	for (i = 0; i < n_ok; i++) {
		const struct kof_pack_hdr *h = mp[i].map;

		at = (at + KOF_PACK_BLOB_ALIGN - 1) / KOF_PACK_BLOB_ALIGN
		   * KOF_PACK_BLOB_ALIGN;
		absorb(e, &mp[i], at);
		at += (size_t)h->sec[KOF_SEC_CODE].len;
	}

	/* Written once, then executable. */
	if (mprotect(e->code, e->code_cap, PROT_READ | PROT_EXEC) != 0) {
		fprintf(stderr, "kofdb: cannot make the code executable\n");
		kof_db_free(e);
		e = NULL;
	}
out:
	for (i = 0; i < n_ok; i++)
		unmap_pack(&mp[i]);
	free(mp);
	if (owned) {
		for (i = 0; i < n_paths; i++)
			free((void *)(uintptr_t)paths[i]);
		free(paths);
	}
	return e;
}

void kof_db_free(struct kof_engine *e)
{
	if (!e)
		return;
	free(e->mods);
	free(e->str_tab);
	free(e->rng_tab);
	free(e->name_tab);
	if (e->code)
		munmap(e->code, e->code_cap);
	free(e);
}
