/*
 * dbpackcheck.c - validating a pack: the hex program check and the whole-pack check, in the order dbcore.h specifies. Split from dbloader.c; the text is unchanged.
 */

#define _GNU_SOURCE

#include "dbloader_int.h"

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
int kof_db_pack_valid(const void *map, uint64_t len, const char *path)
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
		 * kof_db_load, which is the requirement that actually exists. */
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
	STRIDE(KOF_SEC_MUTATION_BLK, h->n_blk,   sizeof(struct kof_mutation_block));
	STRIDE(KOF_SEC_MUTATION_POOL, h->n_pool, 4);
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
			const struct kof_mutation_block *bk = (const void *)
				(base + h->sec[KOF_SEC_MUTATION_BLK].off);

			/* A block's hashes are read with no further checking on
			 * the scan path, so the slice is settled here. */
			if ((uint64_t)bk[k].first_hash + bk[k].n_hash > h->n_pool)
				REFUSE("block %u slices hashes that are not "
				       "there", k);
			if (bk[k].n_hash < KGENOME_MUTATION_MIN_HASH ||
			    bk[k].n_hash > KOF_MUTATION_MAX_HASH)
				REFUSE("block %u has %u hashes", k, bk[k].n_hash);
			if (bk[k].norm >= KGENOME_MUTATION_NORM_COUNT)
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
