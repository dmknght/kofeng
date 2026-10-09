/*
 * dbloader.c - load packed databases into an immutable engine.
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
 * The validation order below is the one dbcore.h specifies, and the order is the
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

#include "dbloader.h"
#include "hexprog.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/pathogen/kofdiag.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../kofcore/kofplatform.h"

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
	/*
	 * ALIGNED, AND THE BOUNDS ARE NOT ENOUGH ON THEIR OWN.
	 *
	 * The two tables are read as arrays of structs - `st[i].n_alts`,
	 * `al[j].len` - and a struct read through a pointer that is not
	 * aligned for it is undefined. The offsets come out of a FILE, so a
	 * corrupted or hostile pack can put them anywhere, and every bound
	 * below can hold while the address is still odd.
	 *
	 * NOT A BUG THAT WAS OBSERVED, AND THAT IS WORTH SAYING. The program's
	 * own base is aligned where it really lives: dbpacker pads the string
	 * pool to KOF_HEX_PROG_ALIGN before each program and every section is
	 * laid out on KOF_PACK_SEC_ALIGN. A fuzzer that mutated 400,000
	 * compiled programs and walked the 40,778 this function accepted found
	 * no misaligned read once its own buffer was aligned the way the pack
	 * is - the misalignment it first reported was the harness's byte
	 * aligned array, not the loader.
	 *
	 * It is kept because the bounds below do not cover it: a corrupted pack
	 * can leave the program's base aligned and still put a table at an odd
	 * offset INSIDE it, and every test below would pass. It costs two
	 * instructions and refuses nothing the compiler produces.
	 */
	if (h->steps_off % 4u || h->alts_off % 4u)
		return 0;
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
			if (a->flags & ~(KOF_HEX_ALT_MASKED |
					 KOF_HEX_ALT_NEG |
					 KOF_HEX_ALT_CLASS))
				return 0;
			/*
			 * A CLASS IS ONE BYTE AND A 32-BYTE TABLE, and nothing
			 * else - see KOF_HEX_ALT_CLASS.
			 *
			 * Exclusive with the other two, because the bitmap
			 * already decides the byte and a mask beside it would
			 * be a second answer about the same position. Checked
			 * here rather than trusted, for the reason this whole
			 * function exists: the program came out of a file.
			 *
			 * The length is pinned to 1 as well. The matcher reads
			 * one byte for a class however long `len` claims to be,
			 * so a program claiming more would have the span
			 * arithmetic above describe a match longer than what is
			 * actually compared.
			 */
			if (a->flags & KOF_HEX_ALT_CLASS) {
				if (a->flags & (KOF_HEX_ALT_MASKED |
						KOF_HEX_ALT_NEG))
					return 0;
				if (a->len != 1u)
					return 0;
				need = 32u;
			} else {
				/* NEG implies MASKED: the negation array sits
				 * after the mask array, and one without the
				 * other would have the matcher read the masks
				 * as negations. */
				if ((a->flags & KOF_HEX_ALT_NEG) &&
				    !(a->flags & KOF_HEX_ALT_MASKED))
					return 0;
				if (a->flags & KOF_HEX_ALT_MASKED)
					need += a->len;
				if (a->flags & KOF_HEX_ALT_NEG)
					need += a->len;
			}
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
 * Reachable by name from the pack fuzzer, which corrupts a compiled program and
 * then walks whatever this accepts - see the note in that test. Nothing in the
 * product calls it: the validator's one caller is a few hundred lines below.
 */
int kof_hex_prog_valid_for_test(const uint8_t *p, uint32_t len);
int kof_hex_prog_valid_for_test(const uint8_t *p, uint32_t len)
{
	return hex_prog_valid(p, len);
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
		fprintf(stderr, "dbloader: %s: ", path);                          \
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
	/*
	 * AND THE FLOOR, which is the half that was missing.
	 *
	 * The ceiling above catches a module that would call a vtable slot this
	 * host does not have. It cannot catch the opposite hazard, because that
	 * one makes no call at all: a module built before a VIEW STRUCT changed
	 * shape reads `z->entry[i]` at the offset its build put there and gets
	 * whatever now lives at that address. The pack loads, the checksum is
	 * fine, every module runs - and the answers are drawn from the wrong
	 * bytes. A scanner that decides wrongly in silence is worse than one
	 * that refuses, so this refuses.
	 *
	 * Zero is a pack written before the field existed, which can only have
	 * been ABI 1 - see dbcore.h - so it is compared like any other value
	 * rather than waved through.
	 */
	if (h->abi_version < KOFSIG_ABI_MIN)
		REFUSE("built against ABI %u, which this engine no longer "
		       "reads (needs %u or newer) - rebuild the database",
		       h->abi_version, (unsigned)KOFSIG_ABI_MIN);
	/*
	 * THE THREE VERSION RULES, and they are three different rules.
	 *
	 * major is the layout: anything but an exact match reads the wrong
	 * bytes, so it is refused outright.
	 *
	 * minor is additive, so a pack older than this engine is fine and a pack
	 * NEWER is not - it may name a section this build has never heard of.
	 * That asymmetry is the whole value of having a minor at all: an engine
	 * update no longer forces every database to be rebuilt.
	 *
	 * build is not tested. It says when the pack was made and nothing about
	 * whether it can be read.
	 */
	if (h->major != KOF_PACK_MAJOR)
		REFUSE("pack layout %u, this engine reads %u",
		       (unsigned)h->major, (unsigned)KOF_PACK_MAJOR);
	if (h->minor > KOF_PACK_MINOR)
		REFUSE("pack needs format %u.%u, this engine provides %u.%u",
		       (unsigned)h->major, (unsigned)h->minor,
		       (unsigned)KOF_PACK_MAJOR, (unsigned)KOF_PACK_MINOR);
	/* A pack holds native code, so one built for another machine is refused
	 * loudly rather than entered. */
	/*
	 * A CLEARER MESSAGE, NOT A SECOND GUARD - and worth being precise about,
	 * because it looks like one.
	 *
	 * A pack from an older build that could not name its host carries zero.
	 * The comparison below already refuses it, on every host, because no
	 * host can itself be zero any more: dbcore.h makes an unrecognised
	 * build machine an #error rather than a value. So this line can never
	 * change a decision - only what the operator is told. Deleting the
	 * #error is what would give it teeth again, and then two unrecognised
	 * hosts would be running each other's native code.
	 */
	if (h->machine == KOF_PACK_MACH_NONE)
		REFUSE("pack names no machine");
	if (h->machine != KOF_PACK_MACH_HOST)
		REFUSE("built for machine %u, this is %u", h->machine,
		       (unsigned)KOF_PACK_MACH_HOST);
	/* The kind decides which list the modules go into and which point they are
	 * entered from, so a kind the engine has no list for is refused rather
	 * than guessed at. */
	if (h->kind != KOF_PACK_DETECT && h->kind != KOF_PACK_UNPACK &&
	    h->kind != KOF_PACK_HEUR)
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
		/* One alignment for every section now that the code section is
		 * not page aligned in the file - see KOF_PACK_SEC_ALIGN. Where
		 * a blob lands in MEMORY is decided by the arena rounding in
		 * kof_db_open, which is the requirement that actually exists. */
		uint64_t align = KOF_PACK_SEC_ALIGN;

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

	STRIDE(KOF_SEC_PRE_TARGET,  h->n_mods,  KOF_PRE_TARGET_STRIDE);
	STRIDE(KOF_SEC_PRE_SCAN,    h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_ARCH,    h->n_mods,  4);
	STRIDE(KOF_SEC_PRE_SIZE,    h->n_mods,  8);
	/* Appended after the others, not slotted in - see dbcore.h - and missed
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
	STRIDE(KOF_SEC_PLAGUE_BLK, h->n_blk,   sizeof(struct kof_plague_block));
	STRIDE(KOF_SEC_PLAGUE_POOL, h->n_pool, 4);
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
			    (uint64_t)m[k].name_first + m[k].n_names > h->n_names ||
			    (uint64_t)m[k].blk_first + m[k].n_blk > h->n_blk)
				REFUSE("module %u names a table slice that is "
				       "not there", k);
			if (m[k].code_off % KOF_PACK_BLOB_ALIGN)
				REFUSE("module %u is not aligned for a call", k);
		}
		for (k = 0; k < h->n_blk; k++) {
			const struct kof_plague_block *bk = (const void *)
				(base + h->sec[KOF_SEC_PLAGUE_BLK].off);

			/* A block's hashes are read with no further checking on
			 * the scan path, so the slice is settled here. */
			if ((uint64_t)bk[k].first_hash + bk[k].n_hash > h->n_pool)
				REFUSE("block %u slices hashes that are not "
				       "there", k);
			if (bk[k].n_hash < KOF_PLAGUE_MIN_HASH ||
			    bk[k].n_hash > KOF_PLAGUE_MAX_HASH)
				REFUSE("block %u has %u hashes", k, bk[k].n_hash);
			if (bk[k].norm >= KOF_PLAGUE_NORM_COUNT)
				REFUSE("block %u names normalizer %u", k,
				       bk[k].norm);
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
			uint64_t o = nm[k].off;

			if (o >= npool)
				REFUSE("name %u lies outside its pool", k);
			/* memchr, not a hand loop: db_name_lookup already reads
			 * these with memchr, and a crafted pool whose NUL is far
			 * from a name's offset turned the hand loop into an
			 * O(names x pool) scan on hostile input. */
			if (memchr(np + o, 0, (size_t)(npool - o)) == NULL)
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
		fprintf(stderr, "dbloader: cannot open %s\n", path);
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
		fprintf(stderr, "dbloader: cannot map %s\n", path);
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
#define KOF_DIAG_PACK_MAX (4u << 20)
#define KOF_DIAG_PACKS_MAX 64u

static void load_diag_pack(struct kof_engine *e, const char *p)
{
	uint8_t *buf;
	size_t got, n_rec, i;
	long len;
	FILE *f;

	f = fopen(p, "rb");
	if (!f)
		return;
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 8 ||
	    (unsigned long)len > KOF_DIAG_PACK_MAX || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		fprintf(stderr, "dbloader: %s is not a diagnose pack\n", p);
		return;
	}
	buf = malloc((size_t)len);
	got = buf ? fread(buf, 1, (size_t)len, f) : 0;
	fclose(f);
	if (!buf || got != (size_t)len || memcmp(buf, "KDGP", 4) != 0 ||
	    buf[4] != 1u) {
		free(buf);
		fprintf(stderr, "dbloader: %s is not a diagnose pack this build "
			"can read\n", p);
		return;
	}
	n_rec = (size_t)buf[6] | ((size_t)buf[7] << 8);
	if (8u + n_rec * 8u > got) {
		free(buf);
		fprintf(stderr, "dbloader: %s has a table longer than the file\n", p);
		return;
	}
	for (i = 0; i < n_rec; i++) {
		const uint8_t *t = buf + 8u + i * 8u;
		uint64_t off = (uint64_t)t[0] | ((uint64_t)t[1] << 8) |
			       ((uint64_t)t[2] << 16) | ((uint64_t)t[3] << 24);
		uint64_t rl = (uint64_t)t[4] | ((uint64_t)t[5] << 8) |
			      ((uint64_t)t[6] << 16) | ((uint64_t)t[7] << 24);

		if (e->n_diag >= KOF_DB_MAX_DIAG) {
			e->diag_full = 1;
			break;
		}
		if (off > got || rl > got - off) {
			fprintf(stderr, "dbloader: diagnose %zu runs past the end "
				"of %s\n", i, p);
			continue;
		}
		if (!kof_diag_load(buf + off, rl, &e->diag[e->n_diag],
				   e->diag_node + (size_t)e->n_diag *
						  KOF_DB_MAX_DIAG_NODE,
				   KOF_DB_MAX_DIAG_NODE,
				   e->diag_name + (size_t)e->n_diag *
						  KOF_DB_DIAG_NAME,
				   KOF_DB_DIAG_NAME,
				   e->diag_needs + (size_t)e->n_diag *
						   KOF_DB_DIAG_NEEDS,
				   KOF_DB_DIAG_NEEDS)) {
			fprintf(stderr, "dbloader: diagnose %zu of %s is not one "
				"this build can read\n", i, p);
			continue;
		}
		/*
		 * THE ID IS THE NAME'S HASH - see KOF_DIAG_ID. It was the load
		 * position: adding a record renumbered every diagnose after it,
		 * and a rule naming one had nothing stable to name.
		 */
		e->diag[e->n_diag].id =
			kof_diag_id_(e->diag[e->n_diag].name);
		{
			uint32_t q;

			for (q = 0; q < e->n_diag; q++)
				if (e->diag[q].id == e->diag[e->n_diag].id) {
					fprintf(stderr, "dbloader: %s and %s "
						"hash to one diagnose id - "
						"rename one\n",
						e->diag[q].name,
						e->diag[e->n_diag].name);
					break;
				}
			if (q < e->n_diag)
				continue;
		}
		e->n_diag++;
	}
	free(buf);
}

static int name_cmp(const void *x, const void *y)
{
	return strcmp(*(char *const *)x, *(char *const *)y);
}

static void load_diagnoses(struct kof_engine *e, const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char *names[KOF_DIAG_PACKS_MAX];
	uint32_t n = 0, i;

	if (!d)
		return;
	while ((de = readdir(d)) != NULL && n < KOF_DIAG_PACKS_MAX) {
		size_t l = strlen(de->d_name);

		if (l > 10u && !strncmp(de->d_name, "diag-", 5u) &&
		    !strcmp(de->d_name + l - 5u, ".kdig") &&
		    (names[n] = strdup(de->d_name)) != NULL)
			n++;
	}
	closedir(d);
	if (!n)
		return;
	e->diag = calloc(KOF_DB_MAX_DIAG, sizeof *e->diag);
	e->diag_node = calloc((size_t)KOF_DB_MAX_DIAG * KOF_DB_MAX_DIAG_NODE,
			      sizeof *e->diag_node);
	e->diag_name = calloc(KOF_DB_MAX_DIAG, KOF_DB_DIAG_NAME);
	e->diag_needs = calloc(KOF_DB_MAX_DIAG, KOF_DB_DIAG_NEEDS);
	qsort(names, n, sizeof names[0], name_cmp);
	for (i = 0; i < n; i++) {
		char p[4096];

		if (e->diag && e->diag_node && e->diag_name && e->diag_needs &&
		    (size_t)snprintf(p, sizeof p, "%s/%s", dir, names[i]) <
			    sizeof p)
			load_diag_pack(e, p);
		free(names[i]);
	}
}

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
/*
 * Fold one module's targets into the presence set - see any_target.
 *
 * A module with NO targets is for everything, so it sets every bit: that is
 * what KOF_FMT_ANY compiles to, and reading it as "targets nothing" would turn
 * the engine's cheapest early-out into a silent refusal to open children.
 *
 * Ids of 64 and above are not representable here and are simply not recorded.
 * The set is an OPTIMISATION - it answers "is anything interested in this
 * target at all" - so a missing bit costs a walk that finds nothing, never a
 * module that does not run. The assert beside KOF_TARGET_COUNT is what says
 * when this needs to become an array.
 */
static void any_target_add(uint64_t *set, const struct kof_module *m)
{
	uint8_t i;

	if (!m->n_target) {
		*set = ~(uint64_t)0;
		return;
	}
	for (i = 0; i < m->n_target; i++)
		if (m->target[i] < 64u)
			*set |= (uint64_t)1 << m->target[i];
}

static void absorb(struct kof_engine *e, const struct kof_db_pack *mp,
		   size_t code_at, uint32_t pack_id)
{
	const uint8_t *base = mp->map;
	const struct kof_pack_hdr *h = mp->map;
	/* Rows of bytes, not a uint32 array: a count and the ids it counts.
	 * See KOF_SEC_PRE_TARGET. */
	const uint8_t  *pt = base + h->sec[KOF_SEC_PRE_TARGET].off;
	const uint32_t *ps = (const void *)(base + h->sec[KOF_SEC_PRE_SCAN].off);
	const uint32_t *pa = (const void *)(base + h->sec[KOF_SEC_PRE_ARCH].off);
	const uint32_t *pk = (const void *)(base + h->sec[KOF_SEC_PRE_SUBTYPE].off);
	const uint64_t *pz = (const void *)(base + h->sec[KOF_SEC_PRE_SIZE].off);
	const struct kof_pack_mod *pm =
		(const void *)(base + h->sec[KOF_SEC_MODS].off);
	const uint32_t *prng = (const void *)(base + h->sec[KOF_SEC_RANGE].off);
	const struct kof_plague_block *pblk =
		(const void *)(base + h->sec[KOF_SEC_PLAGUE_BLK].off);
	const uint32_t *ppool =
		(const void *)(base + h->sec[KOF_SEC_PLAGUE_POOL].off);

	uint32_t rng0 = e->n_rng;
	uint32_t blk0 = e->n_blk, pool0 = e->n_blk_pool;
	uint32_t i;
	int unpack = (h->kind == KOF_PACK_UNPACK);
	int heur   = (h->kind == KOF_PACK_HEUR);

	memcpy(e->code + code_at, base + h->sec[KOF_SEC_CODE].off,
	       (size_t)h->sec[KOF_SEC_CODE].len);

	e->n_str += h->n_str;
	for (i = 0; i < h->n_rng; i++)
		e->rng_tab[e->n_rng++] = prng[i];
	/*
	 * The blocks and their hashes, REBASED into the engine's tables the way
	 * the packer rebased them into the pack's. Two levels of the same move,
	 * because there are two levels of pooling: a module's blocks share a
	 * pack's pool, and a pack's blocks share the engine's.
	 */
	for (i = 0; i < h->n_pool; i++)
		e->blk_pool[e->n_blk_pool++] = ppool[i];
	for (i = 0; i < h->n_blk; i++) {
		e->blk_tab[e->n_blk] = pblk[i];
		e->blk_tab[e->n_blk].first_hash += pool0;
		e->n_blk++;
	}

	for (i = 0; i < h->n_mods; i++) {
		struct kof_module *m = unpack ? &e->unp[e->n_unp++]
				     : heur ? &e->heur[e->n_heur++]
					    : &e->mods[e->n_mods++];

		/* Entry offset is zero within each blob; the compiler asserts it,
		 * so the blob's place in the arena is the entry point. */
		m->fn = (kof_scan_fn)(void *)(e->code + code_at + pm[i].code_off);
		/* Zero means the module has none - an offset of zero would be
		 * kof_scan itself, which is never a cure. */
		m->cure = pm[i].cure_off
			  ? (kof_scan_fn)(void *)(e->code + code_at +
						  pm[i].code_off +
						  pm[i].cure_off)
			  : NULL;

		/*
		 * THE COUNT IS WHAT BOUNDS THE READ, which is the whole reason
		 * it is stored beside the ids rather than derived from them.
		 * A row that claims more targets than the row holds is clamped
		 * here - the pack is a file, and a file can say anything.
		 */
		{
			const uint8_t *row = pt + (size_t)i * KOF_PRE_TARGET_STRIDE;

			m->n_target = row[0] > KOF_TARGET_LIST_MAX
				    ? (uint8_t)KOF_TARGET_LIST_MAX : row[0];
			memcpy(m->target, row + 1, m->n_target);
		}
		m->scan_mask   = ps[i];
		m->arch_mask   = pa[i];
		m->subtype_mask = pk[i];
		m->size_min    = pz[i];

		m->str_base  = pm[i].str_first;     /* within that pack */
		m->n_str     = pm[i].n_str;
		m->rng_base  = rng0  + pm[i].rng_first;
		m->n_rng     = pm[i].n_rng;
		m->block_base = blk0 + pm[i].blk_first;
		m->n_block    = pm[i].n_blk;
		m->pack_id   = pack_id;
		m->name_base = pm[i].name_first;    /* within that pack */
		m->n_names   = pm[i].n_names;
		m->family_off = pm[i].family_off;
		m->maltype    = pm[i].maltype;
		m->step       = pm[i].step;
		m->heur_phase = pm[i].heur_phase;
		/* Zero means unstated - a pack written before the field
		 * existed - and unstated is level 1, which is what every rule
		 * ran at before there was a choice. */
		m->heur_level = pm[i].heur_level ? pm[i].heur_level : 1u;
		m->heur_want  = pm[i].heur_want;
		m->heur_predict_off = pm[i].heur_predict_off;
		m->content_off = pm[i].content_off;
		m->kind       = (uint8_t)h->kind;
		m->src_off    = pm[i].src_off;


		/*
		 * Only a detector's regions go into the union the scanner
		 * resolves. An unpacker runs after the searching is done, and a
		 * heuristic reads what the parse already worked out, so a region
		 * either of them names must not make every object pay for
		 * resolving it.
		 */
		if (!unpack && !heur)
			e->scan_mask |= m->scan_mask;
		else if (heur)
			e->heur_scan_mask |= m->scan_mask;
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
	const struct kof_db_pack *p;
	const struct kof_str_ent *d;

	if (!m || id >= m->n_str || m->pack_id >= e->n_packs)
		return NULL;
	p = &e->packs[m->pack_id];
	/* Section bounds resolved when the pack was loaded - see
	 * kof_db_pack.desc for why that is both cheaper and safer. */
	if (!p->desc || !p->pool)
		return NULL;
	if ((uint64_t)m->str_base + m->n_str > p->n_desc)
		return NULL;

	d = p->desc + m->str_base + id;
	/* Still read out of the mapping, so still checked. */
	if ((uint64_t)d->off + d->len > p->pool_len)
		return NULL;
	*bytes = p->pool + d->off;
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
/*
 * A string at `off` in the module's own pack's name pool, or NULL.
 *
 * One function because three fields are stored the same way - the family, the
 * predicted family and the source path - and each is an offset that has to be
 * bounded against the pool and checked for a terminator before it is returned
 * as a C string. Three copies of that would be three places for one of the two
 * checks to go missing.
 */
static const char *db_pool_str(const struct kof_engine *e,
			       const struct kof_module *m, uint32_t off)
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
	if (off >= pool_len)
		return NULL;
	if (memchr(pool + off, 0, (size_t)(pool_len - off)) == NULL)
		return NULL;
	return pool + off;
}

const char *kof_db_family(const struct kof_engine *e, const struct kof_module *m)
{
	return db_pool_str(e, m, m ? m->family_off : 0);
}

/*
 * The family a heuristic rule PREDICTS, or NULL when it predicts nothing.
 *
 * Zero is "no prediction" and not "offset zero": the packer interns nothing for
 * a rule without KOF_HEUR_PREDICT, and offset zero in the pool belongs to
 * whatever string happened to be interned first.
 */
const char *kof_db_heur_predict(const struct kof_engine *e,
				const struct kof_module *m)
{
	if (!m || !m->heur_predict_off)
		return NULL;
	return db_pool_str(e, m, m->heur_predict_off);
}

/* Zero is "none declared", for the same reason as above. */
const char *kof_db_content(const struct kof_engine *e,
			   const struct kof_module *m)
{
	if (!m || !m->content_off)
		return NULL;
	return db_pool_str(e, m, m->content_off);
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

struct kof_engine *kof_db_load_tables(const char *path)
{
	struct kof_engine *e = NULL;
	struct kof_db_pack *mp = NULL;
	struct stat sb;
	const char **paths = NULL;
	const char *single[1];
	uint32_t n_paths = 0, n_ok = 0, i;
	uint64_t n_mods = 0, n_str = 0, n_rng = 0, code = 0;
	uint64_t n_blk = 0, n_pool = 0;
	size_t at = 0;
	int owned = 0;
	const char *dir_for_diag = NULL;

	if (!path)
		return NULL;

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		dir_for_diag = path;
		paths = collect_packs(path, &n_paths);
		owned = 1;
		if (!paths || n_paths == 0) {
			fprintf(stderr, "dbloader: no .ksig packs in %s\n", path);
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
		n_blk  += h->n_blk;
		n_pool += h->n_pool;
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
	 * allocated from it. The memo is NOT summed here - it is not the sum of
	 * the packs' memo_slots but n_uid x n_masks, derived and bounds-checked
	 * further down where those are known - so a check on the sum here would
	 * reject on a number the allocation never uses.
	 */
	if (n_mods > 0xffffffffu || n_str > 0xffffffffu ||
	    n_rng > 0xffffffffu || n_blk > 0xffffffffu ||
	    n_pool > 0xffffffffu) {
		fprintf(stderr, "dbloader: %s: more entries than an index can hold\n",
			path);
		goto out;
	}

	e = calloc(1, sizeof *e);
	if (!e)
		goto out;
	e->mods     = calloc(n_mods ? n_mods : 1, sizeof *e->mods);
	e->unp      = calloc(n_mods ? n_mods : 1, sizeof *e->unp);
	e->heur     = calloc(n_mods ? n_mods : 1, sizeof *e->heur);
	e->rng_tab  = calloc(n_rng  ? n_rng  : 1, sizeof *e->rng_tab);
	e->blk_tab  = calloc(n_blk  ? n_blk  : 1, sizeof *e->blk_tab);
	e->blk_pool = calloc(n_pool ? n_pool : 1, sizeof *e->blk_pool);
	if (!e->mods || !e->unp || !e->heur || !e->rng_tab ||
	    !arena_open(e, (size_t)code)) {
		kof_db_free_tables(e);
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

			/*
			 * And the string section as two pointers - see
			 * kof_db_pack.desc. Every bound checked here once,
			 * against the length this mapping had when it was
			 * validated.
			 */
			{
				uint64_t maplen = mp[i2].len;
				uint64_t doff = ph->sec[KOF_SEC_STR_DESC].off;
				uint64_t poff = ph->sec[KOF_SEC_STR_POOL].off;
				uint64_t plen = ph->sec[KOF_SEC_STR_POOL].len;
				const uint8_t *b = (const uint8_t *)ph;

				mp[i2].desc = NULL;
				mp[i2].n_desc = 0;
				mp[i2].pool = NULL;
				mp[i2].pool_len = 0;
				if (doff <= maplen &&
				    (uint64_t)ph->n_str *
					    sizeof(struct kof_str_ent) <=
					    maplen - doff &&
				    poff <= maplen && plen <= maplen - poff) {
					mp[i2].desc = (const struct kof_str_ent *)
						(const void *)(b + doff);
					mp[i2].n_desc = ph->n_str;
					mp[i2].pool = b + poff;
					mp[i2].pool_len = plen;
				}
			}
		}

		e->rng_uid = calloc(e->n_rng ? e->n_rng : 1, sizeof *e->rng_uid);
		if (!e->rng_uid) {
			kof_db_free_tables(e);
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
						kof_db_free_tables(e);
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

	/*
	 * The per-format index, once the module array is final.
	 *
	 * A counting sort: count the bits, run the counts into offsets, place.
	 * Failure is not fatal - mod_by_target NULL means the scan walks the
	 * flat array as it always did, which is slower and identical.
	 */
	{
		/* `m` rather than `i`: it indexes modules, and an `i` here
		 * shadowed the loader's own. */
		uint32_t b, m, total = 0, *fill;

		for (b = 0; b <= KOF_TARGET_COUNT; b++)
			e->mod_at[b] = 0;
		for (m = 0; m < e->n_mods; m++)
			for (b = 0; b < KOF_TARGET_COUNT; b++)
				if (kof_module_targets(&e->mods[m], (uint8_t)b))
					e->mod_at[b + 1u]++;
		for (b = 0; b < KOF_TARGET_COUNT; b++)
			e->mod_at[b + 1u] += e->mod_at[b];
		total = e->mod_at[KOF_TARGET_COUNT];

		fill = calloc(KOF_TARGET_COUNT, sizeof *fill);
		e->mod_by_target = total ? calloc(total, sizeof *e->mod_by_target)
					 : NULL;
		if (fill && (e->mod_by_target || !total)) {
			for (m = 0; m < e->n_mods; m++)
				for (b = 0; b < KOF_TARGET_COUNT; b++)
					if (kof_module_targets(&e->mods[m],
							       (uint8_t)b))
						e->mod_by_target[e->mod_at[b] +
								 fill[b]++] = m;
		} else {
			free(e->mod_by_target);
			e->mod_by_target = NULL;
		}
		free(fill);

		/*
		 * AND WITHIN EACH FORMAT, THE CHEAP QUESTIONS FIRST.
		 *
		 * The scan loop stops at the first module that reports, so the
		 * order inside a bucket decides what a verdict costs. A module
		 * is sorted by THE KIND OF DATA IT ASKS FOR, which is the one
		 * thing the loader knows without running it:
		 *
		 *   0  neither markers nor blocks - it reads what the parse
		 *      already established, so it needs no pass over the bytes
		 *   1  blocks - it needs the similarity feed
		 *   2  markers - it needs the multi-pattern sweep, the most
		 *      expensive of the three
		 *
		 * Paired with the deferred passes in the scanner (see
		 * need_multi and need_plague there), this is what makes a
		 * structural verdict cost no sweep at all: the module that
		 * answers first is the one that asked for least.
		 *
		 * STABLE WITHIN A TIER, so two modules that ask for the same
		 * data keep the order the database gave them and a rebuild of
		 * the same packs cannot reshuffle which of them reports.
		 *
		 * Best effort: without the scratch the index is simply left in
		 * database order, which is what it was before this existed.
		 */
		if (e->mod_by_target && total) {
			uint32_t *tmp = calloc(total, sizeof *tmp);

			if (tmp) {
				for (b = 0; b < KOF_TARGET_COUNT; b++) {
					uint32_t lo = e->mod_at[b];
					uint32_t hi = e->mod_at[b + 1u];
					uint32_t n = 0, t, k;

					for (t = 0; t < 3u; t++)
						for (k = lo; k < hi; k++) {
							const struct kof_module *md =
								&e->mods[e->mod_by_target[k]];
							uint32_t tier = md->n_str ? 2u
								      : (md->n_block ? 1u : 0u);

							if (tier == t)
								tmp[n++] = e->mod_by_target[k];
						}
					for (k = 0; k < n; k++)
						e->mod_by_target[lo + k] = tmp[k];
				}
				free(tmp);
			}
		}
	}

	/*
	 * AND HOW MANY MARKERS EACH REGION COULD HAVE, PER FORMAT - see
	 * live_cap. Summed here because it cannot change once the module list
	 * is final, and multi_prepass was recomputing it for every object.
	 *
	 * All three arrays, because all three run against an object and share
	 * its memo - the same reason multi_prepass walks all three.
	 */
	{
		const struct kof_module *arr[3];
		uint32_t cnt[3], ai, mi, t, r, b;

		arr[0] = e->mods; cnt[0] = e->n_mods;
		arr[1] = e->unp;  cnt[1] = e->n_unp;
		arr[2] = e->heur; cnt[2] = e->n_heur;

		e->live_cap = calloc((size_t)KOF_TARGET_COUNT *
				     KOF_MULTIMATCH_BITS, sizeof *e->live_cap);
		if (e->live_cap) {
			for (ai = 0; ai < 3u; ai++)
				for (mi = 0; mi < cnt[ai]; mi++) {
					const struct kof_module *m =
						&arr[ai][mi];
					uint32_t bits = 0;

					if (!m->n_str)
						continue;
					for (r = 0; r < m->n_rng; r++) {
						if (m->rng_base + r >= e->n_rng)
							break;
						bits |= e->rng_tab[m->rng_base + r];
					}
					/*
					 * ONLY THE BITS THIS TABLE HAS ROOM
					 * FOR. A scan mask may name regions
					 * past KOF_MULTIMATCH_BITS - the symbol
					 * halves are the case - and the loop
					 * this replaced dropped them by only
					 * ever counting b below that bound.
					 * Iterating the set bits instead has to
					 * say so, or a high bit indexes off the
					 * end of live_cap.
					 */
					bits &= (KOF_MULTIMATCH_BITS >= 32u)
						? 0xffffffffu
						: ((1u << KOF_MULTIMATCH_BITS) - 1u);
					if (!bits)
						continue;
					/*
					 * THE TARGETS IT NAMES, NOT ALL OF
					 * THEM - and the bits that are set,
					 * not all thirty.
					 *
					 * Written as two full sweeps this is
					 * n_mods * KOF_TARGET_COUNT *
					 * KOF_MULTIMATCH_BITS, which at 200 000
					 * modules is 174 million rounds to add
					 * a handful of numbers. A module names
					 * one target and one or two regions;
					 * walking what it declared is the same
					 * sum in a fraction of the steps.
					 *
					 * n_target of zero still means "every
					 * format", so that case keeps the full
					 * walk - see kof_module_targets.
					 */
					if (m->n_target) {
						uint8_t ti;

						for (ti = 0; ti < m->n_target &&
						     ti < KOF_TARGET_LIST_MAX;
						     ti++) {
							uint32_t tv =
								m->target[ti];
							uint32_t rest = bits;

							if (tv >= KOF_TARGET_COUNT)
								continue;
							while (rest) {
								b = (uint32_t)
								  __builtin_ctz(rest);
								rest &= rest - 1u;
								e->live_cap[tv *
								  KOF_MULTIMATCH_BITS
								  + b] += m->n_str;
							}
						}
					} else {
						for (t = 0; t < KOF_TARGET_COUNT;
						     t++) {
							uint32_t rest = bits;

							while (rest) {
								b = (uint32_t)
								  __builtin_ctz(rest);
								rest &= rest - 1u;
								e->live_cap[t *
								  KOF_MULTIMATCH_BITS
								  + b] += m->n_str;
							}
						}
					}
				}
		}
	}

	/* Written once, then executable. */
	if (kof_mprotect_rx(e->code, e->code_cap) != 0) {
		fprintf(stderr, "dbloader: cannot make the code executable\n");
		kof_db_free_tables(e);
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

		/*
		 * And what this database has business with - see any_target.
		 *
		 * Here rather than as each pack is walked, because it is the
		 * union over what was LOADED: a pack that failed to map
		 * contributes no modules and must contribute no targets
		 * either, or the engine would open children for rules it does
		 * not have.
		 */
		{
			uint32_t j;

			e->any_target = 0;
			for (j = 0; j < e->n_mods; j++)
				any_target_add(&e->any_target, &e->mods[j]);
			for (j = 0; j < e->n_unp; j++)
				any_target_add(&e->any_target, &e->unp[j]);
			for (j = 0; j < e->n_heur; j++)
				any_target_add(&e->any_target, &e->heur[j]);
		}
		/*
		 * AND THE DIAGNOSES, from the same directory. A database
		 * with none is an ordinary database - they are new, and
		 * nothing yet depends on there being any.
		 */
		if (dir_for_diag)
			load_diagnoses(e, dir_for_diag);
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

void kof_db_free_tables(struct kof_engine *e)
{
	if (!e)
		return;
	free(e->mods);
	free(e->mod_by_target);
	free(e->live_cap);
	free(e->unp);
	free(e->heur);
	free(e->rng_tab);
	free(e->rng_uid);
	free(e->blk_tab);
	free(e->blk_pool);
	free(e->diag);
	free(e->diag_node);
	free(e->diag_name);
	free(e->diag_needs);
	if (e->packs) {
		uint32_t i;

		for (i = 0; i < e->n_packs; i++)
			kof_unmap_file(e->packs[i].map, e->packs[i].len);
		free(e->packs);
	}
	kof_unmap_anon(e->code, e->code_cap);
	free(e);
}
