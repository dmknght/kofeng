/*
 * sym_pool.h - the one writer of a KSYM block.
 *
 * INTERNAL. The layout and the readers are kofmod/kofsym.h, which is published to
 * modules; this is the half that makes a block, and it stays inside the engine.
 * Every producer of a block - the ELF and PE builders, the PE import merge and
 * the normalised view's copy - goes through it, because the block has two places
 * a symbol's attributes and name are written (the record and the pool entry, see
 * KOF_SYM_KEYLEN) and one function is how they cannot disagree.
 */

#ifndef KOF_SYM_POOL_H
#define KOF_SYM_POOL_H

#include <stdint.h>
#include <kofmod/kofsym.h>

/* One symbol, as a producer states it. `name` is `name_len` bytes, already
 * cleaned of whatever the producer does not want matched (control bytes). */
struct kof_symrec {
	uint8_t     type, bind, vis, flags;
	uint16_t    shndx;
	uint64_t    size, value;
	const char *name;
	uint32_t    name_len;
	uint8_t     cut;        /* the producer already cut the name */
};

struct kof_symw {
	uint8_t  *out;
	uint32_t  cap;          /* bytes the caller allows                       */
	uint32_t  rec_cap;      /* records the table reserves room for           */
	uint32_t  n;            /* records written                               */
	uint32_t  pool_n;       /* pool bytes written                            */
	uint32_t  pool_cap;     /* pool bytes the buffer holds after the table   */
	int       trunc;        /* something wanted did not fit                  */
};

/*
 * Start a block in `out` (`cap` >= KOF_SYM_HDRLEN bytes): the header is written,
 * with no `_start` and no origin - the caller sets those after kof_symw_end, they
 * are fixed header offsets.
 *
 * `want_recs` is how many records the caller expects to write (0 when it does not
 * know: the table then takes what the buffer holds and `trunc` is set only if a
 * symbol is refused), and `pool_room` how many pool bytes (0 when it does not
 * know: KOF_SYM_POOL_PER_REC a record is planned). The table is reserved for
 * min(want_recs, what the buffer holds), and when that is fewer than wanted the
 * block says it was cut (`trunc`).
 */
void kof_symw_begin(struct kof_symw *w, uint8_t *out, uint32_t cap,
		    uint32_t want_recs, uint32_t pool_room);

/* Append one symbol. 0 when it did not fit (the record table or the pool is
 * full), with `trunc` set - the symbol is not written and neither is any after
 * it that the caller then offers. A name past KOF_SYM_NAME_MAX is cut and says so. */
int kof_symw_put(struct kof_symw *w, const struct kof_symrec *r);

/* Append record `rec` of block `b` (n bytes) to `w`: the copy a rebuild makes. */
int kof_symw_put_from(struct kof_symw *w, const uint8_t *b, uint32_t n,
		      const uint8_t *rec);

/* Close the block: the pool moves up against the last record, the count and the
 * `truncated` byte are written. Returns the block's length in bytes. */
uint32_t kof_symw_end(struct kof_symw *w);

#endif /* KOF_SYM_POOL_H */
