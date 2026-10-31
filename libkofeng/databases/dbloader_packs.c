/*
 * OLD-DISEASE (owner, 2026-10-28): the parts of this file about diseases are the OLD logic - a disease as (maltype, free-text
 * behaviour path), its id and its records in the pack. The NEW disease is the pair (ACT, OBJ) of kofmod/diseaselist.h and has no
 * text. Nothing is removed yet: this is marked for review and removal in the disease rework (changing the pack layout or version is
 * the owner's decision). `grep -rn OLD-DISEASE` lists every marked place.
 */
/*
 * dbloader_packs.c - mapping a pack and reading the diagnose and disease tables beside it. Split from dbloader.c; the text is unchanged.
 */

#define _GNU_SOURCE

#include "../kofcore/kofdebug.h"
#include "dbloader_int.h"
#include "../kofcore/kofmod/kofname.h"
#include "pack/dbcrc.h"

/* ---- mapping ---------------------------------------------------------------- */

/* A pack while it is being read. Alive only for the length of one load. */
/* The header's type, not a private twin: the array built here is handed to the
 * engine whole at the end of a successful load. */
int kof_db_map_pack(struct kof_db_pack *mp, const char *path)
{
	struct stat st;
	struct kof_tail ft;
	void *map;
	uint64_t map_len;
	int fd, has;

	memset(mp, 0, sizeof *mp);
	mp->fd = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "dbloader: cannot open %s\n", path);
		return 0;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return 0;
	}
	/*
	 * Does the pack carry a tail (pack/dbkix.h): the block index, the pattern table, or both?
	 * Asked with a read of the last 64 bytes, not of the mapping: a file that is shorter than
	 * it was measured is a short read here and an engine that never faults on it.
	 *
	 * A pack WITH one maps only the part before it. That part is checked as a whole against
	 * the footer's CRC (what the header's own CRC covers is the tail too, which would be
	 * reading all of it), and the descriptor is kept for the tail's reads. A pack without
	 * one is mapped whole and checked as it always was, and the descriptor is closed at once:
	 * a mapping keeps the file alive on its own, and holding one open per pack would spend a
	 * descriptor per pack for nothing.
	 */
	has = kof_tail_probe(fd, (uint64_t)st.st_size, &ft);
	map_len = has ? ft.old_len : (uint64_t)st.st_size;
	map = kof_map_file_ro(fd, map_len);
	if (!map) {
		close(fd);
		fprintf(stderr, "dbloader: cannot map %s\n", path);
		return 0;
	}
	if (has && !kof_db_crc_holds(fd, KOF_PACK_CRC_FROM, ft.old_len, ft.old_crc)) {
		fprintf(stderr, "dbloader: %s: checksum does not match its contents\n", path);
		kof_unmap_file(map, map_len);
		close(fd);
		return 0;
	}
	if (!(has ? kof_db_pack_valid_old(map, map_len, (uint64_t)st.st_size, path)
		  : kof_db_pack_valid_fd(map, map_len, fd, path))) {
		kof_unmap_file(map, map_len);
		close(fd);
		return 0;
	}
	mp->map = map;
	mp->len = (size_t)map_len;
	mp->file_size = (uint64_t)st.st_size;
	if (has) {
		const struct kof_pack_hdr *h = map;
		char why[200];

		if (ft.has_kix) {
			struct kof_kix_loc loc;

			memset(&loc, 0, sizeof loc);
			loc.fd = fd;
			loc.file_size = (uint64_t)st.st_size;
			loc.blk_off = h->sec[KOF_SEC_MUTATION_BLK].off;
			loc.pool_off = h->sec[KOF_SEC_MUTATION_POOL].off;
			loc.n_blk = h->n_blk;
			loc.n_pool = h->n_pool;
			mp->kix = kof_kix_open_file(&loc, &ft.kix, why, sizeof why);
			if (!mp->kix) {
				/* One pack with a bad index is refused on its own; the rest still load. */
				fprintf(stderr, "dbloader: %s: %s\n", path, why);
				kof_unmap_file(map, map_len);
				close(fd);
				mp->map = NULL;
				mp->len = 0;
				return 0;
			}
			mp->has_kix = 1;
			mp->foot = ft.kix;
		}
		if (ft.has_pix) {
			if (!kof_pix_open_file(fd, (uint64_t)st.st_size, &ft.pix, &mp->pix_sl, why, sizeof why)) {
				fprintf(stderr, "dbloader: %s: %s\n", path, why);
				kof_kix_close(mp->kix);
				mp->kix = NULL;
				kof_unmap_file(map, map_len);
				close(fd);
				mp->map = NULL;
				mp->len = 0;
				return 0;
			}
			mp->has_pix = 1;
			mp->pix_foot = ft.pix;
		}
		mp->fd = fd;
		/* What checking the pack touched is not needed again soon: the hash pool alone is
		 * four bytes a hash and the check read all of it. The mapping stays good; a page
		 * comes back from the file when something reads it. */
		kof_map_drop(map, map_len);
	} else {
		/* What validating touched (the sections the checks walk) is not needed again soon; the pages
		 * come back from the file when something reads them. */
		kof_map_drop(map, map_len);
		close(fd);
	}
	return 1;
}

void kof_db_unmap_pack(struct kof_db_pack *mp)
{
	kofpix_close(mp->pix);
	mp->pix = NULL;
	kof_slices_done(&mp->pix_sl);
	kof_kix_close(mp->kix);
	mp->kix = NULL;
	if (mp->fd >= 0)
		close(mp->fd);
	mp->fd = -1;
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
int kof_db_arena_open(struct kof_engine *e, size_t want)
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
/*
 * THE DIAGNOSES: packs named diag-<kind>.kdig, beside the signature packs.
 *
 * "KDGP", a version byte, a count and a table of (offset, length), then the
 * records - the layout is written beside write_diag_packs in ksigbuilder. One
 * file per diagnose made the set a database held depend on a directory
 * listing; here the packs are read in NAME order, so the load order and nothing
 * that depends on it varies with the filesystem.
 *
 * Every number in a pack is checked against the file's own length, and a RECORD
 * that does not parse is SKIPPED WITH A WORD rather than failing the load: one
 * bad diagnose must not take the others with it, and silence would be worse than
 * either - a diagnose that quietly is not there reads, from every rule that
 * names it, as an object that does not do the thing. A header that does not add
 * up refuses the whole pack, because then no record in it can be trusted to
 * start where the table says.
 */
/*
 * NO COUNT OF PACKS AND NO SIZE FOR ONE. There were 64 files and 4 MiB a file: the
 * 65th pack of a directory was not opened and a valid pack past 4 MiB was refused,
 * each with nothing a host could read. A directory's packs are now listed without
 * a bound on how many, and the bound that remains is the ALLOWANCE - the bytes of
 * every pack of a kind it reads (the diagnose packs share one; the disease table
 * has its own). A file that does not fit what is
 * left is refused WHOLE and counted (diag_packs_refused, kdb_diag_packs_refused).
 */
#define KOF_KDIG_ALLOW ((uint64_t)256u << 20)

/*
 * A .kdig READ WHOLE, once, for the two kinds of file that share the shape: the
 * diagnose packs and the disease table. At most what is left of
 * the allowance still `*left` (one per kind of file), at least `min`, starting with `magic` and
 * version 1.
 *
 * A file that is not there says nothing - a database may have none of a kind - and
 * one that is there and wrong says which kind it is not, on stderr AND in the
 * engine's count (diag_packs_refused), and gives nothing back: refused WHOLE,
 * because no record in a file whose header does not add up can be trusted to
 * start where it says. Returns the malloc'd bytes and their count in `*got`, or
 * NULL. The bytes are charged to the allowance for the life of the load.
 */
static uint8_t *read_kdig(struct kof_engine *e, uint64_t *left, const char *p,
			  const char *magic, const char *what, long min,
			  size_t *got)
{
	uint8_t *buf;
	long len;
	FILE *f = fopen(p, "rb");

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < min ||
	    (uint64_t)len > *left || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		fprintf(stderr, "dbloader: %s is not a %s\n", p, what);
		e->diag_packs_refused++;
		return NULL;
	}
	buf = malloc((size_t)len);
	*got = buf ? fread(buf, 1, (size_t)len, f) : 0;
	fclose(f);
	if (!buf || *got != (size_t)len || memcmp(buf, magic, 4) != 0 || buf[4] != 1u) {
		free(buf);
		fprintf(stderr, "dbloader: %s is not a %s this build can read\n", p, what);
		e->diag_packs_refused++;
		return NULL;
	}
	*left -= (uint64_t)len;
	return buf;
}

/* How many records a pack with the diagnose pack's header holds: u16 count at 6,
 * then count x { u32 offset, u32 length }. `*n` is that count, and 0 is returned
 * when the table is longer than the file - which refuses the whole pack. */
static int kdig_table(const uint8_t *buf, size_t got, size_t *n)
{
	*n = (size_t)buf[6] | ((size_t)buf[7] << 8);
	return 8u + *n * 8u <= got;
}

/* Record `i` of that table, as an offset and a length; 0 when it runs outside the
 * file, which skips the one record. */
static int kdig_record(const uint8_t *buf, size_t got, size_t i, uint64_t *off,
		       uint64_t *len)
{
	const uint8_t *t = buf + 8u + i * 8u;

	*off = (uint64_t)t[0] | ((uint64_t)t[1] << 8) |
	       ((uint64_t)t[2] << 16) | ((uint64_t)t[3] << 24);
	*len = (uint64_t)t[4] | ((uint64_t)t[5] << 8) |
	       ((uint64_t)t[6] << 16) | ((uint64_t)t[7] << 24);
	return *off <= got && *len <= got - *off;
}

/*
 * THE RULES A DIAGNOSE NAMES AS ITS READERS, kept by name for the one pass that
 * marks the modules (kof_db_mark_diag_readers). The record's USERS section is a
 * count, then a length and the source name of each rule; the names are copied,
 * because the record is gone when the pack is. A name that does not fit is not
 * kept, and the module it names is simply not marked - it runs in its tier, as
 * every module did before the mark existed.
 */
static void note_users(struct kof_engine *e, const uint8_t *rec, uint64_t rl,
		       const struct kof_diag *d)
{
	uint64_t at, end;
	uint32_t k, cnt;

	if (!d->users_len || (uint64_t)d->users_off + d->users_len > rl)
		return;
	at = d->users_off;
	end = at + d->users_len;
	cnt = rec[at++];
	for (k = 0; k < cnt && at < end; k++) {
		uint32_t l = rec[at++];
		char *nm;

		if (!l || at + l > end)
			return;
		if (e->n_diag_user == e->cap_diag_user) {
			uint32_t nc = e->cap_diag_user ? e->cap_diag_user * 2u : 32u;
			char **g = realloc(e->diag_user, nc * sizeof *g);

			if (!g)
				return;
			e->diag_user = g;
			e->cap_diag_user = nc;
		}
		nm = malloc((size_t)l + 1u);
		if (!nm)
			return;
		memcpy(nm, rec + at, l);
		nm[l] = 0;
		e->diag_user[e->n_diag_user++] = nm;
		at += l;
	}
}

/*
 * THE STRING STORE OF ONE PACK'S RECORDS, one block. A string a record carries (a
 * node's symbol, a declared symbol) takes at most the bytes it was read from plus
 * its terminator, which the record's own length byte already paid for, so a store
 * of "record length + 1" per record cannot overflow - and, unlike a slot of a
 * fixed size, it does not refuse a diagnose for having a long symbol. The block is
 * kept on the engine and freed with it.
 */
/* KNOWN DEFECT MEM-6 (2026-10-29, R) [sev L]: the store is "record length + 1" for EVERY record, and a detection form (no node, no symbol) uses none of it: the whole
 * record is mostly the form's hashes. Trigger: any pack of form diagnoses. Effect: the engine holds the pack's bytes a second time for its life (780 KB of 700 forms in
 * tests/unit/mem_diag_forms.c; at most the pack's size, 256 MiB, and it counts in keng_memory_db). Reproducer: tests/unit/mem_diag_forms.c (growth pack, 779 KB, needs 0).
 * Fix: a kof_diag_needs_bound() beside kof_diag_load (the bytes of the record outside its KDIG_SEC_FORM sections) sizes each slice; the section walk stays in kofdiag.c. */
static char *diag_arena_new(struct kof_engine *e, const uint8_t *buf, size_t got,
			    size_t n_rec)
{
	uint64_t total = 0, off, rl;
	size_t i;
	char **grown, *a;

	for (i = 0; i < n_rec; i++)
		if (kdig_record(buf, got, i, &off, &rl))
			total += rl + 1u;
	grown = realloc(e->diag_arena, ((size_t)e->n_diag_arena + 1u) * sizeof *grown);
	if (!grown)
		return NULL;
	e->diag_arena = grown;
	a = calloc(1, (size_t)(total ? total : 1u));
	if (!a)
		return NULL;
	e->diag_arena[e->n_diag_arena++] = a;
	return a;
}

/*
 * THE BLOCKS OF A DIAGNOSE'S FORM, appended to the engine's table of them (dblk, dpool) and numbered after every pack's:
 * `blk_base` of the form is the number of its first block in the matcher's one set. Both arrays double as they grow and
 * a failure to grow is the caller's refusal of the record (answers 0, nothing appended). Hashes are copied: a record is
 * freed when its pack has been read.
 */
static int diag_form_blocks(struct kof_engine *e, struct kof_diag *d)
{
	struct kof_form *f = (struct kof_form *)(uintptr_t)d->form;
	uint32_t k, need_b, need_p;

	if (!f || !f->n_block)
		return 1;
	need_b = e->n_dblk + f->n_block;
	need_p = e->n_dpool + f->n_hash;
	if (need_b > e->cap_dblk) {
		uint32_t nc = e->cap_dblk ? e->cap_dblk : 16u;
		struct kof_mutation_block *g;

		while (nc < need_b)
			nc *= 2u;
		g = realloc(e->dblk, (size_t)nc * sizeof *g);
		if (!g)
			return 0;
		e->dblk = g;
		e->cap_dblk = nc;
	}
	if (need_p > e->cap_dpool) {
		uint32_t nc = e->cap_dpool ? e->cap_dpool : 256u;
		uint32_t *g;

		while (nc < need_p)
			nc *= 2u;
		g = realloc(e->dpool, (size_t)nc * sizeof *g);
		if (!g)
			return 0;
		e->dpool = g;
		e->cap_dpool = nc;
	}
	memcpy(e->dpool + e->n_dpool, f->hash, (size_t)f->n_hash * sizeof *f->hash);
	for (k = 0; k < f->n_block; k++) {
		struct kof_mutation_block *b = &e->dblk[e->n_dblk + k];

		memset(b, 0, sizeof *b);
		b->first_hash = e->n_dpool + f->block[k].first;
		b->n_hash = f->block[k].n_hash;
		b->scan_mask = f->block[k].mask;
		b->side = f->block[k].side;
	}
	/* The set reads the engine's copy (dpool, borrowed by the matcher for as long as the engine lives); the form's own is
	 * never read again, and kept it was n_hash * 4 bytes (up to 16 KiB) of a second copy for every similarity diagnose
	 * (audit_mem MEM-1: 700 forms, 640000 bytes). `n_hash` stays: diag_form_unblocks gives back that many. */
	free(f->hash);
	f->hash = NULL;
	f->hash_cap = 0;
	/* The pack blocks come first: their count is final when the diagnoses are read (db_finish). */
	f->blk_base = e->n_blk + e->n_dblk;
	KOF_TRACE("[load] form blocks: %u block(s), %u hash(es), set numbers from %u (pack blocks %u), scan_mask now %x\n",
		  (unsigned)f->n_block, (unsigned)f->n_hash, (unsigned)f->blk_base, (unsigned)e->n_blk, (unsigned)e->scan_mask);
	e->n_dblk += f->n_block;
	e->n_dpool += f->n_hash;
	return 1;
}

/* Take back the blocks the last appended form added (a diagnose that is not kept). */
static void diag_form_unblocks(struct kof_engine *e, const struct kof_diag *d)
{
	const struct kof_form *f = d->form;

	if (!f || !f->n_block)
		return;
	e->n_dblk -= f->n_block;
	e->n_dpool -= f->n_hash;
}

/* A region some block is cut from is a region the scanner must resolve for the object (sx_regions_present asks only for
 * `scan_mask`, the union of what the detectors name): left out, the feed finds no region of the parse present, credits no
 * unit, and every similarity form scores 0 on an object that holds the block whole (the run1 defect). Added only when the
 * diagnose is KEPT, after the collision test: a diagnose that is dropped (its name is another's) names no region, and
 * scan_mask is a union that cannot take one bit back (audit_mem MEM-2). */
static void diag_form_regions(struct kof_engine *e, const struct kof_diag *d)
{
	uint32_t k;

	for (k = 0; d->form && k < d->form->n_block; k++)
		/* KNOWN DEFECT DF-8 (2026-10-30, M) [sev H]: a block of region KOF_SCAN_ALL adds only the bit ALL to scan_mask, so sx_regions_present resolves no region of the parse (cause read, R).
		 * Trigger: a pack whose similarity blocks are all region ALL, on a PE or ELF. Effect: kof_scan_mutation_feed credits no unit, the block scores 0 even in .data; it scores once another block names a PE region; Raw is fine. kofregion.h says ALL means the same for every input.
		 * Reproducer: /mnt/games/normtest/fix_detacc2_fmt/defects/df_repro.c (prints "DF-8 REPRODUCED").
		 * Fix: when a block's mask has ALL, add every region of the parse that region_in_all covers (the format is known when the object is opened), or resolve them for ALL in sx_regions_present. */
		e->scan_mask |= d->form->block[k].mask;
}

static void load_diag_pack(struct kof_engine *e, uint64_t *left, const char *p)
{
	uint8_t *buf;
	size_t got, n_rec, i;
	char *arena;
	uint64_t used = 0;

	buf = read_kdig(e, left, p, "KDGP", "diagnose pack", 8, &got);
	if (!buf)
		return;
	if (!kdig_table(buf, got, &n_rec)) {
		free(buf);
		fprintf(stderr, "dbloader: %s has a table longer than the file\n", p);
		e->diag_packs_refused++;
		return;
	}
	KOF_TRACE("[load] diagnose pack %s: %zu record(s), %u diagnose(s) loaded before it\n", p, n_rec, (unsigned)e->n_diag);
	arena = diag_arena_new(e, buf, got, n_rec);
	if (!arena) {
		free(buf);
		fprintf(stderr, "dbloader: no memory for the strings of %s\n", p);
		e->diag_packs_refused++;
		return;
	}
	for (i = 0; i < n_rec; i++) {
		uint64_t off, rl;
		int loaded;

		if (e->n_diag >= e->diag_room) {
			/* A cap bounds cost and must be said (rule 4): kdb_diag_full answered it to a host that asked, and nothing
			 * told the one that did not (audit_mem MEM-8: 50000 diagnoses, 4096 loaded, no word on stderr). */
			if (!e->diag_full)
				fprintf(stderr, "dbloader: %s holds more diagnoses than the engine keeps (%u, KOF_DB_MAX_DIAG): the rest are NOT loaded (kdb_diag_full)\n",
					p, (unsigned)e->diag_room);
			e->diag_full = 1;
			break;
		}
		if (!kdig_record(buf, got, i, &off, &rl)) {
			fprintf(stderr, "dbloader: diagnose %zu runs past the end "
				"of %s\n", i, p);
			e->diag_refused++;
			continue;
		}
		{
			const struct kof_diag_store st = {
				.node = e->diag_node + (size_t)e->n_diag * KOF_DB_MAX_DIAG_NODE,
				.max_node = KOF_DB_MAX_DIAG_NODE,
				.name = e->diag_name + (size_t)e->n_diag * KOF_DB_DIAG_NAME,
				.name_cap = KOF_DB_DIAG_NAME,
				.needs = arena + used,
				.needs_cap = (uint32_t)(rl + 1u),
			};

			loaded = kof_diag_load(kof_buf_make(buf + off, rl),
					       &e->diag[e->n_diag], &st);
			/* The slice is spent whether or not the record loaded: the
			 * next one starts after it, and a refused one's strings are
			 * simply never referenced. */
			used += rl + 1u;
		}
		if (!loaded) {
			fprintf(stderr, "dbloader: diagnose %zu of %s is not one "
				"this build can read\n", i, p);
			e->diag_refused++;
			continue;
		}
		/* The blocks of a form join the similarity set; a table that cannot grow refuses the record, said. */
		if (!diag_form_blocks(e, &e->diag[e->n_diag])) {
			fprintf(stderr, "dbloader: no memory for the similarity blocks of diagnose %zu of %s\n", i, p);
			e->diag_refused++;
			kof_diag_form_free(&e->diag[e->n_diag]);
			memset(&e->diag[e->n_diag], 0, sizeof e->diag[0]);
			continue;
		}
		/*
		 * THE ID IS THE NAME'S 32-BIT HASH - see kof_diag_id32_. It was the
		 * load position: adding a record renumbered every diagnose after it,
		 * and a rule naming one had nothing stable to name. Then a 16-bit
		 * fold of the hash, and with 256 names some pair collided about four
		 * times in ten.
		 */
		e->diag[e->n_diag].id =
			kof_diag_id32_(e->diag[e->n_diag].name);
		{
			uint32_t q;

			for (q = 0; q < e->n_diag; q++)
				if (e->diag[q].id == e->diag[e->n_diag].id) {
					fprintf(stderr, "dbloader: %s and %s "
						"hash to one 32-bit diagnose id - "
						"rename one (%s is NOT "
						"loaded)\n",
						e->diag[q].name,
						e->diag[e->n_diag].name,
						e->diag[e->n_diag].name);
					e->diag_collide++;
					break;
				}
			if (q < e->n_diag) {
				/* Not loaded: its form, and the blocks it put into the set, go with it. */
				diag_form_unblocks(e, &e->diag[e->n_diag]);
				kof_diag_form_free(&e->diag[e->n_diag]);
				memset(&e->diag[e->n_diag], 0, sizeof e->diag[0]);
				continue;
			}
		}
		diag_form_regions(e, &e->diag[e->n_diag]);
		note_users(e, buf + off, rl, &e->diag[e->n_diag]);
		e->n_form += e->diag[e->n_diag].form != NULL;
		KOF_TRACE("[load] diagnose %u %s id=%08x: %s\n", (unsigned)e->n_diag, e->diag[e->n_diag].name,
			  (unsigned)e->diag[e->n_diag].id,
			  e->diag[e->n_diag].form ? (e->diag[e->n_diag].form->n_sim ? "form (similarity)" : "form (strings)")
						  : "graph diagnose");
		e->n_diag++;
	}
	KOF_TRACE("[load] diagnose pack %s done: %u diagnose(s), %u form(s), %u refused, %u collided\n", p, (unsigned)e->n_diag,
		  (unsigned)e->n_form, (unsigned)e->diag_refused, (unsigned)e->diag_collide);
	free(buf);
}

/* How many records a diagnose pack file declares, without reading the rest of
 * it: the u16 at offset 6, bounded by what the file can hold (a table entry is
 * eight bytes), so a header that lies does not size the allocation. */
static size_t pack_count(const char *p)
{
	uint8_t h[8];
	long len;
	size_t n, fit;
	FILE *f = fopen(p, "rb");

	if (!f)
		return 0;
	if (fread(h, 1, sizeof h, f) != sizeof h || memcmp(h, "KDGP", 4) != 0 ||
	    fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 8) {
		fclose(f);
		return 0;
	}
	fclose(f);
	n = (size_t)h[6] | ((size_t)h[7] << 8);
	fit = ((size_t)len - 8u) / 8u;
	return n < fit ? n : fit;
}

static int name_cmp(const void *x, const void *y)
{
	return strcmp(*(char *const *)x, *(char *const *)y);
}

void kof_db_load_diagnoses(struct kof_engine *e, const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char **names = NULL;
	uint32_t n = 0, cap_names = 0, i;
	uint64_t left = KOF_KDIG_ALLOW;

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);

		if (l > 10u && !strncmp(de->d_name, "diag-", 5u) &&
		    !strcmp(de->d_name + l - 5u, ".kdig")) {
			char *nm;

			if (n == cap_names) {
				uint32_t nc = cap_names ? cap_names * 2u : 128u;
				char **g = realloc(names, nc * sizeof *g);

				if (!g) {
					/* A pack the list has no room for is a pack not read. */
					e->diag_packs_refused++;
					continue;
				}
				names = g;
				cap_names = nc;
			}
			nm = strdup(de->d_name);
			if (!nm) {
				e->diag_packs_refused++;
				continue;
			}
			names[n++] = nm;
		}
	}
	closedir(d);
	if (!n) {
		free(names);
		return;
	}
	/*
	 * ROOM FOR WHAT THE PACKS CARRY, counted before anything is read: the
	 * tables are allocated once and the records point into them, so the count
	 * has to be known first. KOF_DB_MAX_DIAG bounds it and a database over it
	 * is marked (diag_full) instead of being cut without a word.
	 */
	qsort(names, n, sizeof names[0], name_cmp);
	{
		size_t room = 0;

		for (i = 0; i < n; i++) {
			char p[4096];

			if ((size_t)snprintf(p, sizeof p, "%s/%s", dir, names[i]) <
			    sizeof p)
				room += pack_count(p);
		}
		if (room > KOF_DB_MAX_DIAG)
			room = KOF_DB_MAX_DIAG;
		/* A pack that declares more than the bound is still read up to the
		 * bound, and says it was cut. */
		e->diag_room = (uint32_t)(room ? room : 1u);
	}
	e->diag = calloc(e->diag_room, sizeof *e->diag);
	e->diag_node = calloc((size_t)e->diag_room * KOF_DB_MAX_DIAG_NODE,
			      sizeof *e->diag_node);
	e->diag_name = calloc(e->diag_room, KOF_DB_DIAG_NAME);
	for (i = 0; i < n; i++) {
		char p[4096];

		if (e->diag && e->diag_node && e->diag_name &&
		    (size_t)snprintf(p, sizeof p, "%s/%s", dir, names[i]) <
			    sizeof p)
			load_diag_pack(e, &left, p);
		else
			e->diag_packs_refused++;
		free(names[i]);
	}
	free(names);
}

/*
 * FILES AN OLDER BUILD WROTE BESIDE THE DIAGNOSES AND THIS ONE NO LONGER READS.
 *
 * A database directory built before the verdict was made of diseases alone holds
 * `syndromes.kdig`, a pack this build has no reader for. It is refused, not taken
 * for an absent file: said on stderr and counted in diag_packs_refused
 * (kdb_diag_packs_refused), so a host sees that part of the directory it was given
 * is not in use. The only name that lives on in this tree is that file's.
 */
void kof_db_refuse_retired(struct kof_engine *e, const char *dir)
{
	static const char *const retired[] = { "syndromes.kdig" };
	size_t i;

	for (i = 0; i < sizeof retired / sizeof retired[0]; i++) {
		char p[4096];
		FILE *f;

		if ((size_t)snprintf(p, sizeof p, "%s/%s", dir, retired[i]) >= sizeof p)
			continue;
		f = fopen(p, "rb");
		if (!f)
			continue;
		fclose(f);
		fprintf(stderr, "dbloader: %s was written by an older build and is not read\n", p);
		e->diag_packs_refused++;
	}
}

/*
 * THE DISEASES' NAMES, from diseases.kdig - see ksigbuilder's write_diseases for
 * the layout. For a tool that has an id and has to show it; nothing in a scan
 * reads this. Refused whole on a header that does not add up, and on entries not
 * in ascending id order, because the lookup below is a binary search: a table
 * that is not sorted would answer for the wrong disease rather than for none.
 */
void kof_db_load_diseases(struct kof_engine *e, const char *dir)
{
	char p[4096];
	uint8_t *buf;
	size_t got, at = 12u, i, n;
	struct kof_disease_ent *tab = NULL;
	char *pool = NULL;
	size_t used = 0;
	uint32_t prev = 0;
	uint64_t left = KOF_KDIG_ALLOW;

	if ((size_t)snprintf(p, sizeof p, "%s/diseases.kdig", dir) >= sizeof p)
		return;
	buf = read_kdig(e, &left, p, "KDIS", "disease table", 12, &got);
	if (!buf)
		return;
	n = (size_t)buf[8] | ((size_t)buf[9] << 8) | ((size_t)buf[10] << 16) |
	    ((size_t)buf[11] << 24);
	/* every entry is at least six bytes: the count cannot exceed that */
	if (n > (got - 12u) / 6u) {
		free(buf);
		fprintf(stderr, "dbloader: %s has more entries than the file holds\n", p);
		return;
	}
	tab = calloc(n ? n : 1u, sizeof *tab);
	pool = malloc(got + n + 1u);
	if (!tab || !pool)
		goto bad;
	for (i = 0; i < n; i++) {
		uint32_t id;
		uint32_t L;

		if (at + 6u > got)
			goto bad;
		id = (uint32_t)buf[at] | ((uint32_t)buf[at + 1u] << 8) |
		     ((uint32_t)buf[at + 2u] << 16) | ((uint32_t)buf[at + 3u] << 24);
		L = buf[at + 5u];
		/* A type is a kof_maltype and nothing else: a name no detector declared is not in the table. */
		if (!id || (i && id <= prev) || !L || at + 6u + L > got ||
		    buf[at + 4u] >= KOF_MALTYPE_COUNT)
			goto bad;
		tab[i].id = id;
		tab[i].type = buf[at + 4u];
		memcpy(pool + used, buf + at + 6u, L);
		pool[used + L] = 0;
		tab[i].name = pool + used;
		used += L + 1u;
		at += 6u + L;
		prev = id;
	}
	e->disease = tab;
	e->disease_pool = pool;
	e->n_disease = (uint32_t)n;
	free(buf);
	return;
bad:
	fprintf(stderr, "dbloader: %s does not add up; its names are not used\n", p);
	e->diag_packs_refused++;
	free(tab);
	free(pool);
	free(buf);
}

const char **kof_db_collect_packs(const char *dir, uint32_t *out_n)
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

static int user_cmp(const void *x, const void *y)
{
	return strcmp(*(char *const *)x, *(char *const *)y);
}

/*
 * WHICH MODULES READ A DIAGNOSE, from what the database already carries: a
 * module's source (kof_db_source, written by the build) and the sources the
 * diagnoses' USERS sections name. The name a USERS entry carries is the source's
 * file name without its extension, cut to what the record holds, so that is what
 * each module's source is reduced to and compared on. Sorted once and searched,
 * so a database of a million rules costs a pass and not a pass per name. The
 * scratch is freed here, and the marks are the only thing left.
 */
void kof_db_mark_diag_readers(struct kof_engine *e)
{
	uint32_t i;

	if (e->n_diag_user) {
		qsort(e->diag_user, e->n_diag_user, sizeof *e->diag_user, user_cmp);
		for (i = 0; i < e->n_mods; i++) {
			struct kof_module *m = &e->mods[i];
			const char *src = kof_db_source(e, m), *b, *dot;
			char key[64];
			size_t l;

			if (!src)
				continue;
			b = strrchr(src, '/');
			b = b ? b + 1 : src;
			dot = strrchr(b, '.');
			l = dot ? (size_t)(dot - b) : strlen(b);
			if (!l || l >= sizeof key)
				continue;
			memcpy(key, b, l);
			key[l] = 0;
			m->reads_diag = bsearch(&(const char *){ key }, e->diag_user,
						e->n_diag_user, sizeof *e->diag_user,
						user_cmp) != NULL;
		}
	}
	for (i = 0; i < e->n_diag_user; i++)
		free(e->diag_user[i]);
	free(e->diag_user);
	e->diag_user = NULL;
	e->n_diag_user = e->cap_diag_user = 0;
}

/*
 * THE NAMES OF THE IDS, from names.kdig - the same road as the disease table above: read whole by read_kdig, kept in the engine as a sorted table
 * with its own pool, looked up by binary search, for a tool that has an id and has to show it (and for the verdict's name). Layout, little endian,
 * written by ksigbuilder (ksb_names.c):
 *     0   "KDNM"      4   version 1      5..7 zero      8   u32 rows      12  u32 CRC-32 of bytes 16..end
 *     16  rows x { u8 kind 'F' | 'V' | 'T', u64 id, u8 length 1..255, name }, ascending by (kind, id), no repeat
 * A name is checked as the catalogs' own rule checks it (a family kof_name_ok, a tag kof_tag_name_ok, a variant "<family>.<capital letters>"), because it
 * is spelled into a verdict whose separators a name must not hold. A missing file is a database that names nothing; a wrong one is refused WHOLE.
 */
#define KOF_NAMES_MAX_BYTES (16u << 20)

static int name_row_ok(uint8_t kind, const char *s, size_t l)
{
	char t[256];
	const char *dot;

	if (l >= sizeof t)
		return 0;
	memcpy(t, s, l);
	t[l] = 0;
	if (kind == 'F')
		return kof_name_ok(t);
	if (kind == 'T')
		return kof_tag_name_ok(t);
	if (kind != 'V' || !(dot = strrchr(t, '.')) || dot[1] == 0 || strlen(dot + 1u) > 5u)
		return 0;
	for (s = dot + 1; *s; s++)
		if (*s < 'A' || *s > 'Z')
			return 0;
	t[dot - t] = 0;
	return kof_name_ok(t);
}

void kof_db_load_names(struct kof_engine *e, const char *dir)
{
	char p[4096];
	uint8_t *buf;
	size_t got, at = 16u, i, n, used = 0;
	struct kof_name_ent *tab = NULL;
	char *pool = NULL;
	uint64_t left = KOF_NAMES_MAX_BYTES, prev_id = 0;
	uint8_t prev_kind = 0;
	uint32_t crc;

	if ((size_t)snprintf(p, sizeof p, "%s/names.kdig", dir) >= sizeof p)
		return;
	buf = read_kdig(e, &left, p, "KDNM", "names table", 16, &got);
	if (!buf)
		return;
	crc = (uint32_t)buf[12] | ((uint32_t)buf[13] << 8) | ((uint32_t)buf[14] << 16) | ((uint32_t)buf[15] << 24);
	if (kof_crc32_fast_cont(0u, buf + 16, got - 16u) != crc) {
		fprintf(stderr, "dbloader: %s fails its checksum; its names are not used\n", p);
		goto bad_quiet;
	}
	n = (size_t)buf[8] | ((size_t)buf[9] << 8) | ((size_t)buf[10] << 16) | ((size_t)buf[11] << 24);
	if (buf[5] || buf[6] || buf[7] || n > (got - 16u) / 11u)     /* the reserved bytes are zero, and every row is at least 11 bytes */               /* every row is at least 11 bytes */
		goto bad;
	tab = calloc(n ? n : 1u, sizeof *tab);
	pool = malloc(got + n + 1u);
	if (!tab || !pool)
		goto bad;
	for (i = 0; i < n; i++) {
		uint8_t kind;
		uint64_t id = 0;
		size_t L, k;

		if (at + 10u > got)
			goto bad;
		kind = buf[at];
		for (k = 0; k < 8u; k++)
			id |= (uint64_t)buf[at + 1u + k] << (8u * k);
		L = buf[at + 9u];
		if (id < 0x10000u || !L || at + 10u + L > got || !name_row_ok(kind, (const char *)buf + at + 10u, L) ||
		    (i && (kind < prev_kind || (kind == prev_kind && id <= prev_id))))
			goto bad;
		tab[i].id = id;
		tab[i].kind = kind;
		memcpy(pool + used, buf + at + 10u, L);
		pool[used + L] = 0;
		tab[i].name = pool + used;
		used += L + 1u;
		at += 10u + L;
		prev_id = id;
		prev_kind = kind;
	}
	if (at != got)
		goto bad;
	e->cat_name = tab;
	e->cat_name_pool = pool;
	e->n_cat_name = (uint32_t)n;
	free(buf);
	return;
bad:
	fprintf(stderr, "dbloader: %s does not add up; its names are not used\n", p);
bad_quiet:
	e->diag_packs_refused++;
	free(tab);
	free(pool);
	free(buf);
}

const char *kof_db_cat_name(const struct kof_engine *e, char kind, uint64_t id)
{
	uint32_t lo = 0, hi = e ? e->n_cat_name : 0;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		const struct kof_name_ent *m = &e->cat_name[mid];

		if (m->kind == (uint8_t)kind && m->id == id)
			return m->name;
		if (m->kind < (uint8_t)kind || (m->kind == (uint8_t)kind && m->id < id))
			lo = mid + 1u;
		else
			hi = mid;
	}
	return NULL;
}
