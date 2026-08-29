/*
 * kofdb.c - load packed databases into an immutable engine.
 *
 * A database is one or more .ksig packs. Each is mapped read only, validated, and
 * its tables copied into the engine's - except the detection names, which are left
 * where they are and read from the mapping when a finding needs one. The mappings
 * therefore outlive the load and belong to the engine.
 *
 * WHY NAMES ARE THE EXCEPTION AND NOTHING ELSE IS. The measurement is in
 * tests/unit/db_scale.c: with names copied, a database costs 61 resident bytes per
 * record and half of that is names. They are also the only table read exclusively on
 * the way OUT - a name is looked up when a module has already decided an object is
 * infected, which over a corpus scan is a few dozen times against however many
 * millions of records are loaded. Everything else here is read on the way in, per
 * object, and copying it buys a flat array and no indirection.
 *
 * So the general rule stands and the exception is measured: point at the mapping
 * where the data is large, cold, and only wanted after a decision; copy where it is
 * hot. The format was laid out to allow either - that is what the fixed strides are
 * for.
 *
 * Copying at all is worth defending, because the alternative was not mapping:
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
 * test macro placed after the first include has no effect at all.
 *
 * _GNU_SOURCE, not _POSIX_C_SOURCE: this file pulls in kofplatform.h (below),
 * and that header's POSIX branch defines kof_memmem as a thin wrapper around
 * the real memmem - a GNU/BSD extension, not POSIX. Whether or not this
 * specific translation unit ever calls kof_memmem, the compiler still has to
 * see memmem declared to compile that inline function's body at all, and on
 * glibc, _POSIX_C_SOURCE alone does not just fail to enable memmem, it
 * actively suppresses it (defining any of _POSIX_C_SOURCE/_XOPEN_SOURCE
 * without _GNU_SOURCE/_DEFAULT_SOURCE opts into strict-POSIX mode). Missed
 * here originally because every build so far ran on Windows, where
 * kofplatform.h's kof_memmem never touches the real memmem at all - a real
 * Linux build surfaces it immediately as "implicit declaration of function
 * 'memmem'". _GNU_SOURCE is a superset of what _POSIX_C_SOURCE 200809L gave
 * this file, so nothing else here changes. */
#define _GNU_SOURCE

#include "kofdb.h"
#include "../kofmatchers/hexprog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../core/kofplatform.h"

/* ---- validation ------------------------------------------------------------- */

/*
 * Is a compiled hex program self consistent?
 *
 * Every table it names has to lie inside it and every alternative's bytes have to
 * lie inside its data area. Checked here, once, so the matcher can walk the tables
 * without a bounds test per step - the same trade the module slices get, and for
 * the same reason: that walk runs per object per pattern.
 *
 * The caps come from hexprog.h and the compiler enforces them, but they are checked
 * again because this arrives as bytes out of a file. A program that passes here
 * cannot make the walk exceed its work bound.
 */
static int hex_prog_valid(const uint8_t *p, uint32_t len)
{
	const struct kof_hex_hdr *h = (const void *)p;
	const struct kof_hex_step *st;
	const struct kof_hex_alt *al;
	uint32_t i, seen_alts = 0;

	if (len < sizeof *h || h->total_len != len)
		return 0;
	if (h->n_steps == 0 || h->n_steps > KOF_HEX_MAX_STEPS)
		return 0;
	if (h->n_alts < h->n_steps || h->n_alts > KOF_HEX_MAX_STEPS * KOF_HEX_MAX_ALTS)
		return 0;
	if (h->anchor_len == 0 || h->anchor_step >= h->n_steps)
		return 0;
	if (h->min_span == 0 || h->max_span < h->min_span)
		return 0;
	if (h->anchor_before_max < h->anchor_before_min)
		return 0;
	if (h->anchor_before_max > h->max_span ||
	    h->anchor_len > h->max_span - h->anchor_before_max)
		return 0;
	/* The window is what the matcher iterates, so it is what has to be bounded:
	 * an unbounded one turns one anchor hit into an unbounded number of walks. */
	if (h->anchor_before_max - h->anchor_before_min > KOF_HEX_MAX_GAP_TOTAL)
		return 0;

	/*
	 * Each table has to start inside the program and fit in what is left.
	 *
	 * The "> len" half of every one of these is not redundant. Written as
	 * "count > (len - off) / stride" alone, an off past the end makes the
	 * subtraction wrap to something enormous and the test passes - which is how
	 * a mutated pack got an alternative pointing into unmapped memory and the
	 * mask scan below walked off the mapping. Establish "off <= len" first, then
	 * subtract: the same rule kofcore.h states for every read of a file.
	 */
	if (h->steps_off < sizeof *h || h->steps_off > len ||
	    h->n_steps > (len - h->steps_off) / sizeof *st)
		return 0;
	if (h->alts_off < h->steps_off + h->n_steps * sizeof *st ||
	    h->alts_off > len ||
	    h->n_alts > (len - h->alts_off) / sizeof *al)
		return 0;
	if (h->data_off < h->alts_off + h->n_alts * sizeof *al || h->data_off > len)
		return 0;

	st = (const void *)(p + h->steps_off);
	al = (const void *)(p + h->alts_off);

	for (i = 0; i < h->n_steps; i++) {
		uint32_t j;

		if (st[i].gap_max < st[i].gap_min ||
		    st[i].gap_max > KOF_HEX_MAX_GAP_TOTAL)
			return 0;
		if (st[i].n_alts == 0 || st[i].n_alts > KOF_HEX_MAX_ALTS)
			return 0;
		if (st[i].alt_first != seen_alts ||
		    (uint32_t)st[i].alt_first + st[i].n_alts > h->n_alts)
			return 0;
		for (j = 0; j < st[i].n_alts; j++) {
			const struct kof_hex_alt *a = &al[st[i].alt_first + j];
			uint32_t need = a->len;

			if (a->len == 0 || a->len > KOF_HEX_MAX_ALT_LEN)
				return 0;
			if (a->flags & ~KOF_HEX_ALT_MASKED)
				return 0;
			if (a->flags & KOF_HEX_ALT_MASKED)
				need += a->len;
			if (a->data_off < h->data_off || a->data_off > len ||
			    need > len - a->data_off)
				return 0;
		}
		seen_alts += st[i].n_alts;
	}
	if (seen_alts != h->n_alts)
		return 0;

	/*
	 * The anchor run has to lie inside the alternative it names, because the
	 * matcher reads it from there without a further check.
	 *
	 * After the loop above and not before it. Checking the anchor first reads
	 * that alternative's data_off and len while both are still whatever the
	 * file said, so a mutated pack sent the mask scan off into unmapped memory
	 * - which is what the loader is supposed to make impossible, and what the
	 * pack fuzzer found within twenty thousand rounds.
	 */
	{
		const struct kof_hex_step *as = &st[h->anchor_step];
		const struct kof_hex_alt *aa = &al[as->alt_first];

		if (h->anchor_in_alt > aa->len ||
		    h->anchor_len > (uint32_t)aa->len - h->anchor_in_alt)
			return 0;
		/* An anchor inside a masked alternative would be searched for as
		 * concrete bytes that are not concrete. */
		if (aa->flags & KOF_HEX_ALT_MASKED) {
			const uint8_t *msk = p + aa->data_off + aa->len;
			uint32_t b;

			for (b = 0; b < h->anchor_len; b++)
				if (msk[h->anchor_in_alt + b] != 0xff)
					return 0;
		}
	}
	return 1;
}

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
	/*
	 * The ABI before anything else that reads the pack's contents.
	 *
	 * A pack whose modules expect a newer vtable than this host has would call
	 * through a slot the host never filled. Nothing later in this function would
	 * notice - the layout is fine, the checksum is fine, the code loads - and the
	 * failure appears only when a module runs, as a call into whatever happens to
	 * follow the struct.
	 */
	if (h->abi_version > KOFSIG_ABI_VERSION)
		REFUSE("modules need ABI %u, this engine provides %u",
		       h->abi_version, (unsigned)KOFSIG_ABI_VERSION);
	if (h->version != KOF_PACK_VERSION)
		REFUSE("pack version %u, this engine reads %u", h->version,
		       KOF_PACK_VERSION);
	/* A pack holds native code, so one built for another machine is refused
	 * loudly rather than entered. */
	if (h->machine != KOF_PACK_MACH_HOST)
		REFUSE("built for machine %u, this is %u", h->machine,
		       (unsigned)KOF_PACK_MACH_HOST);
	/* The kind decides which list the modules go into and which point they are
	 * entered from, so a kind the engine has no list for is refused rather
	 * than guessed at. */
	if (h->kind != KOF_PACK_DETECT && h->kind != KOF_PACK_UNPACK)
		REFUSE("holds kind %u, which this engine has no dispatch for",
		       h->kind);
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

	STRIDE(KOF_SEC_PRE_TARGET,  h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_SCAN,    h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_ARCH,    h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_SIZE,    h->n_mods,  8);
	/* Appended after the others, not slotted in - see kofpack.h - and missed
	 * here for exactly that reason: absorb() reads h->n_mods entries from
	 * this section unconditionally (pk[i] below), so without this check a
	 * pack declaring a short PRE_SUBTYPE section still passes every other
	 * validation and absorb() reads past the section - and potentially past
	 * the mapping - on a merely corrupted or truncated pack file. */
	STRIDE(KOF_SEC_PRE_SUBTYPE, h->n_mods,  4);
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
			/*
			 * A pack cannot hold more distinct patterns than it holds
			 * patterns, so a uid at or past n_str is a number nobody
			 * wrote. Bounding it here is what keeps n_uid - and the
			 * memo sized from it - from being whatever a mutated file
			 * says.
			 */
			if (s[k].uid >= h->n_str)
				REFUSE("string %u has a pattern id outside the "
				       "pack", k);
			if ((uint64_t)s[k].off + s[k].len > spool)
				REFUSE("string %u lies outside its pool", k);
			if (s[k].len == 0)
				REFUSE("string %u is empty", k);
			if (s[k].kind == KOF_STR_LITERAL) {
				if (s[k].len > KOF_STR_MAX_LEN)
					REFUSE("literal %u is %u bytes", k, s[k].len);
			} else if (s[k].kind == KOF_STR_HEX) {
				if (s[k].len > KOF_HEX_MAX_PROG)
					REFUSE("hex program %u is %u bytes", k,
					       s[k].len);
				/* Read as a struct, so a misaligned one is not a
				 * slow read, it is undefined behaviour. */
				if (s[k].off % KOF_HEX_PROG_ALIGN)
					REFUSE("hex program %u is misaligned", k);
				if (!hex_prog_valid(base + h->sec[KOF_SEC_STR_POOL].off
						    + s[k].off, s[k].len))
					REFUSE("hex program %u is malformed", k);
			} else {
				REFUSE("string %u has kind %u", k, s[k].kind);
			}
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
/* The header's type, not a private twin: the array built here is handed to the
 * engine whole at the end of a successful load. */
static int map_pack(struct kof_db_pack *mp, const char *path)
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
	map = kof_map_file_ro(fd, (uint64_t)st.st_size);
	close(fd);
	if (!map) {
		fprintf(stderr, "kofdb: cannot map %s\n", path);
		return 0;
	}
	if (!pack_valid(map, (uint64_t)st.st_size, path)) {
		kof_unmap_file(map, (uint64_t)st.st_size);
		return 0;
	}
	mp->map = map;
	mp->len = (size_t)st.st_size;
	return 1;
}

static void unmap_pack(struct kof_db_pack *mp)
{
	kof_unmap_file(mp->map, mp->len);
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
	size_t ps = kof_page_size();

	e->code_cap = kof_round_up(want, ps);
	if (e->code_cap == 0)
		e->code_cap = ps;
	e->code = kof_map_anon_rw(e->code_cap);
	if (!e->code) {
		e->code_cap = 0;
		return 0;
	}
	return 1;
}

/* ---- collecting packs -------------------------------------------------------- */

/*
 * Order two pack paths. Plain byte order, which is enough because the only thing
 * being asked of it is that it be the same everywhere.
 */
static int pack_cmp(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/*
 * Collect *.ksig from a directory so a whole database can be named at once.
 *
 * SORTED, and that is a correctness requirement rather than tidiness.
 *
 * The order packs load in is the order their modules end up in, and the scan stops
 * at the first module that matches unless the caller asked for everything. So the
 * load order decides WHICH finding gets reported when an object matches more than
 * one - and readdir's order is whatever the filesystem happens to hand back, which
 * changes when the directory is rewritten.
 *
 * Measured before this was sorted, on one machine, with byte-identical .ksig files
 * and only the database rebuilt between runs: 4637, 4820, 4637 and 4682 objects
 * reported infected across four rebuilds, with the balance moving to a lower
 * severity. Same sources, same bytes, same corpus, four answers. Two machines with
 * the same database could disagree, and a rebuild could change a verdict with no
 * change to anything anybody wrote.
 */
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
	if (v && n > 1)
		qsort(v, n, sizeof *v, pack_cmp);
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
static void absorb(struct kof_engine *e, const struct kof_db_pack *mp,
		   size_t code_at, uint32_t pack_id)
{
	const uint8_t *base = mp->map;
	const struct kof_pack_hdr *h = mp->map;
	const uint32_t *pt = (const void *)(base + h->sec[KOF_SEC_PRE_TARGET].off);
	const uint32_t *ps = (const void *)(base + h->sec[KOF_SEC_PRE_SCAN].off);
	const uint32_t *pa = (const void *)(base + h->sec[KOF_SEC_PRE_ARCH].off);
	const uint32_t *pk = (const void *)(base + h->sec[KOF_SEC_PRE_SUBTYPE].off);
	const uint64_t *pz = (const void *)(base + h->sec[KOF_SEC_PRE_SIZE].off);
	const struct kof_pack_mod *pm =
		(const void *)(base + h->sec[KOF_SEC_MODS].off);
	const uint32_t *prng = (const void *)(base + h->sec[KOF_SEC_RANGE].off);

	uint32_t rng0 = e->n_rng;
	uint32_t i;
	int unpack = (h->kind == KOF_PACK_UNPACK);

	memcpy(e->code + code_at, base + h->sec[KOF_SEC_CODE].off,
	       (size_t)h->sec[KOF_SEC_CODE].len);

	e->n_str += h->n_str;
	for (i = 0; i < h->n_rng; i++)
		e->rng_tab[e->n_rng++] = prng[i];

	for (i = 0; i < h->n_mods; i++) {
		struct kof_module *m = unpack ? &e->unp[e->n_unp++]
					     : &e->mods[e->n_mods++];

		/* Entry offset is zero within each blob; the compiler asserts it,
		 * so the blob's place in the arena is the entry point. */
		m->fn = (kof_scan_fn)(void *)(e->code + code_at + pm[i].code_off);

		m->target_mask = pt[i];
		m->scan_mask   = ps[i];
		m->arch_mask   = pa[i];
		m->subtype_mask = pk[i];
		m->size_min    = pz[i];

		m->str_base  = pm[i].str_first;     /* within that pack */
		m->n_str     = pm[i].n_str;
		m->rng_base  = rng0  + pm[i].rng_first;
		m->n_rng     = pm[i].n_rng;
		m->pack_id   = pack_id;
		m->name_base = pm[i].name_first;    /* within that pack */
		m->n_names   = pm[i].n_names;
		m->family_off = pm[i].family_off;
		m->maltype    = pm[i].maltype;
		m->unp_kind   = pm[i].unp_kind;
		m->src_off    = pm[i].src_off;


		/* Only a detector's regions go into the union the scanner resolves.
		 * An unpacker runs after the searching is done, so a region it
		 * names must not make every object pay for resolving it. */
		if (!unpack)
			e->scan_mask |= m->scan_mask;
	}
}

/* ---- the database ------------------------------------------------------------ */

/*
 * The pack's string descriptor and the engine's are the same sixteen bits of layout,
 * which is what lets the descriptors be used where they lie instead of copied. If
 * either ever moves, this stops the cast rather than letting it read shifted fields.
 */
_Static_assert(sizeof(struct kof_str_ent) == sizeof(struct kof_pack_str),
	       "string descriptor layout drifted from the pack's");

const struct kof_str_ent *kof_db_str(const struct kof_engine *e,
				     const struct kof_module *m, uint32_t id,
				     const uint8_t **bytes)
{
	const struct kof_pack_hdr *h;
	const struct kof_str_ent *d;
	const uint8_t *base;
	uint64_t maplen, desc_off, pool_off, pool_len;

	if (!m || id >= m->n_str || m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	maplen = e->packs[m->pack_id].len;
	if (!base)
		return NULL;
	h = (const void *)base;

	if ((uint64_t)m->str_base + m->n_str > h->n_str)
		return NULL;
	desc_off = h->sec[KOF_SEC_STR_DESC].off;
	pool_off = h->sec[KOF_SEC_STR_POOL].off;
	pool_len = h->sec[KOF_SEC_STR_POOL].len;
	if (desc_off > maplen ||
	    (uint64_t)h->n_str * sizeof *d > maplen - desc_off)
		return NULL;
	if (pool_off > maplen || pool_len > maplen - pool_off)
		return NULL;

	d = (const struct kof_str_ent *)(const void *)(base + desc_off) +
	    m->str_base + id;
	if ((uint64_t)d->off + d->len > pool_len)
		return NULL;
	*bytes = base + pool_off + d->off;
	return d;
}

/*
 * The text a module reports, read out of the pack that carries it.
 *
 * Out of the mapping, not out of a table, because a table of every name in the
 * database would be the biggest thing the engine holds and this is the only function
 * that would ever read it - once per finding, which over a whole corpus is tens of
 * calls. The pack's own name section is already an index: descriptors sorted beside
 * a pool, addressed by the offset the module's slice gives.
 *
 * EVERY BOUND IS CHECKED HERE even though the loader checked the same ones, and that
 * is not belt and braces. The loader checked a file; what is read now is a mapping
 * of that file, and a MAP_PRIVATE mapping may or may not show writes another process
 * made since - the format's own header says so. A name that was terminated at load
 * need not still be, and this returns a pointer that the caller prints. Checking
 * costs a comparison on a path that runs when something has already been detected.
 *
 * NULL for anything that does not hold, which the callers already handle: a finding
 * with no name is reported by id, and a wrong answer here would be a name invented
 * out of whatever followed it in the file.
 */
/*
 * One of a module's names, by id or by position.
 *
 * Two questions with one body of bounds checks between them. A finding reports an
 * id and wants the text for it; a tool that lists what a module can report has no
 * id to offer and wants them in order. Splitting the two would be two copies of
 * the checks, which is the one thing this function is careful about - see the
 * note on kof_db_name for why a mapping is re-validated on every call rather than
 * trusted from load time.
 *
 * `by_index` picks which: non-zero and `key` is a position in the module's slice,
 * zero and it is the id the module reports.
 */
static const char *db_name_lookup(const struct kof_engine *e,
				  const struct kof_module *m, uint32_t key,
				  int by_index, uint32_t *id_out)
{
	const struct kof_pack_hdr *h;
	const struct kof_pack_name *pn;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len, desc_off;
	uint32_t i;

	if (m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	desc_off = h->sec[KOF_SEC_NAME_DESC].off;
	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	/* The slice the module names has to be inside the section the header
	 * names, which has to be inside the mapping. */
	if ((uint64_t)m->name_base + m->n_names > h->n_names)
		return NULL;
	if (desc_off > e->packs[m->pack_id].len ||
	    (uint64_t)h->n_names * sizeof *pn >
		    e->packs[m->pack_id].len - desc_off)
		return NULL;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pn = (const void *)(base + desc_off);
	pool = (const char *)base + pool_off;

	for (i = 0; i < m->n_names; i++) {
		const struct kof_pack_name *d = &pn[m->name_base + i];

		if (by_index ? i != key : d->id != key)
			continue;
		if (id_out)
			*id_out = d->id;
		if (d->off >= pool_len)
			return NULL;
		/* Terminated inside the pool, or it is not a string this may hand
		 * to printf. */
		if (memchr(pool + d->off, 0, (size_t)(pool_len - d->off)) == NULL)
			return NULL;
		return pool + d->off;
	}
	return NULL;
}

const char *kof_db_name(const struct kof_engine *e, const struct kof_module *m,
			uint32_t name_id)
{
	return db_name_lookup(e, m, name_id, 0, NULL);
}

const char *kof_db_name_at(const struct kof_engine *e,
			   const struct kof_module *m, uint32_t index,
			   uint32_t *id_out)
{
	return db_name_lookup(e, m, index, 1, id_out);
}

/*
 * The family KOF_TARGET_NAME declared, read the same way kof_db_name reads a
 * finding's variant - same pool, same mapping, same reason to check on every
 * call instead of trusting the load time pass (see the comment on kof_db_name).
 *
 * Simpler than kof_db_name: family_off is not a table of candidates to search
 * by id, it is the one offset this module's record carries, so there is no loop
 * here - just the same two checks kof_db_name's loop body makes for whichever
 * descriptor it found.
 */
const char *kof_db_family(const struct kof_engine *e, const struct kof_module *m)
{
	const struct kof_pack_hdr *h;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len;

	if (!m || m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pool = (const char *)base + pool_off;
	if (m->family_off >= pool_len)
		return NULL;
	if (memchr(pool + m->family_off, 0,
		   (size_t)(pool_len - m->family_off)) == NULL)
		return NULL;
	return pool + m->family_off;
}

/*
 * The source this module was written in, relative to the bases tree.
 *
 * NULL when the database does not carry one - a module compiled outside a tree,
 * or a pack built before the field existed. A caller joins it with its own idea
 * of where the tree is; the database records the path INSIDE the tree and not an
 * absolute one, because an absolute path is a fact about the machine that built
 * the database rather than about the module.
 */
const char *kof_db_source(const struct kof_engine *e, const struct kof_module *m)
{
	const struct kof_pack_hdr *h;
	const uint8_t *base;
	const char *pool;
	uint64_t pool_off, pool_len;

	if (!m || m->pack_id >= e->n_packs)
		return NULL;
	base = e->packs[m->pack_id].map;
	if (!base)
		return NULL;
	h = (const void *)base;

	pool_off = h->sec[KOF_SEC_NAME_POOL].off;
	pool_len = h->sec[KOF_SEC_NAME_POOL].len;
	if (pool_off > e->packs[m->pack_id].len ||
	    pool_len > e->packs[m->pack_id].len - pool_off)
		return NULL;

	pool = (const char *)base + pool_off;
	if (!m->src_off || m->src_off >= pool_len)
		return NULL;
	if (memchr(pool + m->src_off, 0,
		   (size_t)(pool_len - m->src_off)) == NULL)
		return NULL;
	return pool + m->src_off;
}

struct kof_engine *kof_db_load(const char *path)
{
	struct kof_engine *e = NULL;
	struct kof_db_pack *mp = NULL;
	struct stat sb;
	const char **paths = NULL;
	const char *single[1];
	uint32_t n_paths = 0, n_ok = 0, i;
	uint64_t n_mods = 0, n_str = 0, n_rng = 0, code = 0, memo = 0;
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
		memo   += h->memo_slots;
		/* Padded to the same boundary the packer used inside each pool, so
		 * an aligned offset stays aligned once the pools are concatenated. */
		/* Each pack's blobs keep the offsets its own header gives them, so
		 * its code section is placed whole and aligned. */
		code = kof_round_up(code, KOF_PACK_BLOB_ALIGN) +
		       h->sec[KOF_SEC_CODE].len;
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
	    n_rng > 0xffffffffu || memo > 0xffffffffu) {
		fprintf(stderr, "kofdb: %s: more entries than an index can hold\n",
			path);
		goto out;
	}

	e = calloc(1, sizeof *e);
	if (!e)
		goto out;
	e->mods     = calloc(n_mods ? n_mods : 1, sizeof *e->mods);
	e->unp      = calloc(n_mods ? n_mods : 1, sizeof *e->unp);
	e->rng_tab  = calloc(n_rng  ? n_rng  : 1, sizeof *e->rng_tab);
	if (!e->mods || !e->unp || !e->rng_tab ||
	    !arena_open(e, (size_t)code)) {
		kof_db_free(e);
		e = NULL;
		goto out;
	}

	for (i = 0; i < n_ok; i++) {
		const struct kof_pack_hdr *h = mp[i].map;

		at = (size_t)kof_round_up(at, KOF_PACK_BLOB_ALIGN);
		absorb(e, &mp[i], at, i);
		at += (size_t)h->sec[KOF_SEC_CODE].len;
	}

	/*
	 * Pattern ids, made unique across packs, and region masks made dense.
	 *
	 * Both are the memo's key, and both have to be settled before memo_size can
	 * be known - so this runs after every pack has been absorbed and before the
	 * scanner is ever made.
	 */
	{
		uint32_t i2, j2;

		e->n_uid = 0;
		for (i2 = 0; i2 < n_ok; i2++) {
			const struct kof_pack_hdr *ph = mp[i2].map;
			const struct kof_pack_str *ps =
				(const void *)((const uint8_t *)ph +
					       ph->sec[KOF_SEC_STR_DESC].off);
			uint32_t hi = 0;

			for (j2 = 0; j2 < ph->n_str; j2++)
				if (ps[j2].uid + 1u > hi)
					hi = ps[j2].uid + 1u;
			mp[i2].uid_base = e->n_uid;
			mp[i2].n_uid = hi;
			e->n_uid += hi;
		}

		e->rng_uid = calloc(e->n_rng ? e->n_rng : 1, sizeof *e->rng_uid);
		if (!e->rng_uid) {
			kof_db_free(e);
			e = NULL;
			goto out;
		}
		/*
		 * Against the DISTINCT masks, not against every earlier entry.
		 *
		 * rng_tab holds one entry per module per range, so it is as long as the
		 * database; the distinct values in it are one per way a module can name
		 * a region, which is a handful. Comparing against the whole table was
		 * quadratic in the database - two billion comparisons at sixty thousand
		 * modules, on the load path, to find fewer than thirty answers.
		 */
		{
			uint32_t seen[KOF_MAX_DISTINCT_MASKS];

			e->n_masks = 0;
			for (i2 = 0; i2 < e->n_rng; i2++) {
				for (j2 = 0; j2 < e->n_masks; j2++)
					if (seen[j2] == e->rng_tab[i2])
						break;
				if (j2 == e->n_masks) {
					if (e->n_masks == KOF_MAX_DISTINCT_MASKS) {
						/* More region vocabularies than any
						 * set of formats defines: refuse
						 * rather than share a slot. */
						kof_db_free(e);
						e = NULL;
						goto out;
					}
					seen[e->n_masks++] = e->rng_tab[i2];
				}
				e->rng_uid[i2] = j2;
			}
		}
		/*
		 * The memo, keyed by (pattern, mask) instead of by (module, string,
		 * range).
		 *
		 * The old key gave every module its own slots, so a pattern two
		 * families happen to share was searched for twice. This one gives it
		 * one slot however many modules name it - and because identical
		 * patterns were merged at build time, the table SHRINKS by exactly the
		 * duplication factor rather than growing.
		 */
		if (e->n_masks && e->n_uid &&
		    (uint64_t)e->n_uid * e->n_masks <= 0xffffffffu)
			e->memo_size = e->n_uid * e->n_masks;
		else
			e->memo_size = 0;
	}

	/*
	 * Give back the unpacker table nobody filled.
	 *
	 * It was allocated for n_mods because which modules unpack is not known
	 * until the packs have been walked, and one array sized for the worst case
	 * is simpler than counting twice. The worst case is also absurd - a database
	 * is detection records with a handful of unpackers beside them, so this holds
	 * eleven entries out of however many were reserved.
	 *
	 * ADDRESS SPACE, NOT RESIDENT MEMORY - measured, having first assumed
	 * otherwise. At four million records the slack is 64 bytes a record, and the
	 * quarter gigabyte that suggests never becomes resident: calloc serves a block
	 * that size from mmap, and a page of it costs nothing until something writes
	 * to it. tests/unit/db_scale.c reports the same bytes per module with this
	 * shrink and without it.
	 *
	 * It is still worth the four lines. The reservation is real at sizes the
	 * allocator serves from the heap, where the pages ARE touched, and a mapping
	 * whose size has nothing to do with its contents is a thing the next reader
	 * has to work out from scratch. What it is not is the saving it looks like.
	 *
	 * A failed shrink is not an error. realloc declining to make a block smaller
	 * leaves the original intact, which is exactly the state this started in.
	 */
	{
		struct kof_module *sm;
		size_t want = e->n_unp ? e->n_unp : 1u;

		sm = realloc(e->unp, want * sizeof *sm);
		if (sm)
			e->unp = sm;
	}

	/* Written once, then executable. */
	if (kof_mprotect_rx(e->code, e->code_cap) != 0) {
		fprintf(stderr, "kofdb: cannot make the code executable\n");
		kof_db_free(e);
		e = NULL;
	} else {
		/*
		 * The engine takes the mappings.
		 *
		 * They used to be released here, because everything had been copied
		 * out of them and nothing pointed back. Detection names are no
		 * longer copied - kof_db_name reads them from the pack - so the
		 * mappings are now part of the loaded database and outlive this
		 * function. Clearing mp is what stops the cleanup below from
		 * unmapping tables the engine is about to use.
		 */
		e->packs = mp;
		e->n_packs = n_ok;
		mp = NULL;
	}
out:
	if (mp) {
		for (i = 0; i < n_ok; i++)
			unmap_pack(&mp[i]);
		free(mp);
	}
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
	free(e->unp);
	free(e->rng_tab);
	free(e->rng_uid);
	if (e->packs) {
		uint32_t i;

		for (i = 0; i < e->n_packs; i++)
			kof_unmap_file(e->packs[i].map, e->packs[i].len);
		free(e->packs);
	}
	kof_unmap_anon(e->code, e->code_cap);
	free(e);
}
