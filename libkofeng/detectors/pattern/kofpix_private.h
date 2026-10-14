/*
 * kofpix_private.h - the layout of the pattern table's section: what the builder (kofpix_build.c)
 * writes and the reader (kofpix.c) reads. Private to detectors/pattern/. The reasons for the layout
 * are in kofpix.h.
 */
#ifndef KOFENG_KOFPIX_PRIVATE_H
#define KOFENG_KOFPIX_PRIVATE_H

#include "kofpix.h"


struct kofpix_regtab {
	uint32_t bit, fold, n_ent, dbits;
	uint32_t fb, n_lvl, n_keys, max_run;    /* max_run: the longest run of records sharing a hash */
	uint64_t dir_off, flt_off, rec_off, pad1;
	uint64_t kdir_off, klow_off;     /* the exact key set: see the sweep */
};

struct kofpix_hdr {
	uint32_t magic, version, n_reg, rec_size;
	uint64_t sec_len, pool_len;
	struct kofpix_regtab reg[KOFPIX_MAX_REG];
};

/* g is the hash of the key's four bytes (folded when the region folds): exact, since
 * the multiplier is odd. c is the four bytes after the key, nv of them valid. */
struct kofpix_rec {
	uint32_t g, c, uid, off;
	uint16_t len, klen, koff;
	uint8_t  flags;      /* the marker's own flags */
	uint8_t  nvh;        /* nv in the low three bits, 0x80 for a hex program */
};

_Static_assert(sizeof(struct kofpix_rec) == KOFPIX_REC_SIZE, "record size");
_Static_assert(sizeof(struct kofpix_regtab) == 80, "region table size");

#define KOFPIX_HEX 0x80u
#define KOFPIX_KEYS_SMALL 8192u     /* up to this many distinct keys the set is a sorted array of hashes */


#endif /* KOFENG_KOFPIX_PRIVATE_H */
