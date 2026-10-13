/*
 * sym_pool.c - the one writer of a KSYM block. See sym_pool.h and kofmod/kofsym.h.
 *
 * ORDER OF THE BLOCK while it is built: header, a table reserved for the records
 * the caller expects, then the pool. The records are not all known when the first
 * is written (a PE's are walked, not counted; an ELF's table may run out), so the
 * pool starts where the RESERVED table ends and kof_symw_end moves it down to where
 * the WRITTEN table ends. Pool offsets are from the start of the pool, so the move
 * changes nothing a record says.
 */

#include <string.h>

#include <kofcore.h>
#include "sym_pool.h"

void kof_symw_begin(struct kof_symw *w, uint8_t *out, uint32_t cap,
		    uint32_t want_recs, uint32_t pool_room)
{
	uint64_t room, rec_cap;

	memset(w, 0, sizeof *w);
	w->out = out;
	w->cap = cap;
	memset(out, 0, KOF_SYM_HDRLEN);
	out[KOF_SYM_H_MAGIC + 0] = KOF_SYM_MAGIC0;
	out[KOF_SYM_H_MAGIC + 1] = KOF_SYM_MAGIC1;
	out[KOF_SYM_H_MAGIC + 2] = KOF_SYM_MAGIC2;
	out[KOF_SYM_H_MAGIC + 3] = KOF_SYM_MAGIC3;
	kof_st_le16(out + KOF_SYM_H_VERSION, KOF_SYM_VERSION);
	kof_st_le16(out + KOF_SYM_H_RECLEN,  KOF_SYM_RECLEN);
	/* ABSENT until the caller says otherwise: zero is a valid index, and a
	 * reader would take it as "begin at record 1". See KOF_SYM_H_START. */
	kof_st_le16(out + KOF_SYM_H_START, KOF_SYM_NO_START);

	room = cap - KOF_SYM_HDRLEN;
	if (pool_room)
		rec_cap = room > pool_room ? (room - pool_room) / KOF_SYM_RECLEN : 0;
	else
		rec_cap = room / (KOF_SYM_RECLEN + KOF_SYM_POOL_PER_REC);
	if (rec_cap > KOF_SYM_ABS_MAX_RECS)
		rec_cap = KOF_SYM_ABS_MAX_RECS;
	if (want_recs && rec_cap > want_recs)
		rec_cap = want_recs;
	else if (want_recs && rec_cap < want_recs)
		w->trunc = 1;           /* the table was wanted larger than it can be */
	w->rec_cap = (uint32_t)rec_cap;
	w->pool_cap = (uint32_t)(room - rec_cap * KOF_SYM_RECLEN);
	if (w->pool_cap > KOF_SYM_ABS_MAX_POOL)
		w->pool_cap = KOF_SYM_ABS_MAX_POOL;
}

int kof_symw_put(struct kof_symw *w, const struct kof_symrec *r)
{
	uint32_t len = r->name_len, need;
	uint8_t cut = r->cut;
	uint8_t *rec, *pool, *e;

	if (len > KOF_SYM_NAME_MAX) {
		len = KOF_SYM_NAME_MAX;
		cut = 1;
	}
	need = KOF_SYM_KEYLEN + len + 1u;
	if (w->n >= w->rec_cap || need > w->pool_cap - w->pool_n) {
		w->trunc = 1;
		return 0;
	}
	pool = w->out + KOF_SYM_HDRLEN + (uint64_t)w->rec_cap * KOF_SYM_RECLEN;
	e = pool + w->pool_n;
	e[0] = r->type;
	e[1] = r->bind;
	e[2] = r->vis;
	e[3] = r->flags;
	memcpy(e + KOF_SYM_KEYLEN, r->name, len);
	e[KOF_SYM_KEYLEN + len] = 0;

	rec = w->out + KOF_SYM_HDRLEN + (uint64_t)w->n * KOF_SYM_RECLEN;
	memset(rec, 0, KOF_SYM_RECLEN);
	rec[KOF_SYM_R_TYPE]  = r->type;
	rec[KOF_SYM_R_BIND]  = r->bind;
	rec[KOF_SYM_R_VIS]   = r->vis;
	rec[KOF_SYM_R_FLAGS] = r->flags;
	kof_st_le32(rec + KOF_SYM_R_NAMEOFF, w->pool_n + KOF_SYM_KEYLEN);
	kof_st_le16(rec + KOF_SYM_R_NAMELEN, (uint16_t)len);
	kof_st_le16(rec + KOF_SYM_R_SHNDX, r->shndx);
	rec[KOF_SYM_R_NAMECUT] = cut;
	kof_st_le64(rec + KOF_SYM_R_SIZE, r->size);
	kof_st_le64(rec + KOF_SYM_R_VALUE, r->value);
	w->n++;
	w->pool_n += need;
	return 1;
}

int kof_symw_put_from(struct kof_symw *w, const uint8_t *b, uint32_t n,
		      const uint8_t *rec)
{
	struct kof_symrec r;

	r.type  = rec[KOF_SYM_R_TYPE];
	r.bind  = rec[KOF_SYM_R_BIND];
	r.vis   = rec[KOF_SYM_R_VIS];
	r.flags = rec[KOF_SYM_R_FLAGS];
	r.shndx = (uint16_t)kof_sym_u16(rec, KOF_SYM_R_SHNDX);
	r.size  = kof_sym_u64(rec, KOF_SYM_R_SIZE);
	r.value = kof_sym_u64(rec, KOF_SYM_R_VALUE);
	r.name  = kof_sym_name(b, n, rec, &r.name_len);
	r.cut   = rec[KOF_SYM_R_NAMECUT];
	return kof_symw_put(w, &r);
}

uint32_t kof_symw_end(struct kof_symw *w)
{
	uint64_t at = KOF_SYM_HDRLEN + (uint64_t)w->n * KOF_SYM_RECLEN;

	if (w->n < w->rec_cap)
		memmove(w->out + at,
			w->out + KOF_SYM_HDRLEN + (uint64_t)w->rec_cap * KOF_SYM_RECLEN,
			w->pool_n);
	kof_st_le32(w->out + KOF_SYM_H_COUNT, w->n);
	w->out[KOF_SYM_H_TRUNC] = (uint8_t)(w->trunc != 0);
	return (uint32_t)(at + w->pool_n);
}
