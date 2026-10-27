/*
 * infect_check.h - kgenome_infect_regions driven by the image adapters (elf_hdr.c, pe_parse.c): ranges drawn from the iteration's
 * rng, some inside the object and some hostile (a huge offset, a length that wraps), and the invariants of the answer.
 * Held: the status is in the enum; rows written <= cap and <= total; a row's file range lies inside the object; a flagged row
 * overlaps a range of the input (REPORTED rows included) and carries its kind; the same call twice gives one digest; and a cap of 0 or 1 never writes past it.
 */
#ifndef KOF_FUZZ_INFECT_CHECK_H
#define KOF_FUZZ_INFECT_CHECK_H

typedef enum kgenome_status (*infect_fn)(const struct kgenome_infect_req *, struct kgenome_infect_res *);

static void infect_check(struct fz_ctx *c, const struct kgenome_obj *obj, kof_buf f, infect_fn call)
{
	struct kgenome_infect_range in[6];
	struct kgenome_infect_row rows[KGENOME_INFECT_MAX + 1u];
	struct kgenome_infect_req rq;
	struct kgenome_infect_res rs, rs2;
	enum kgenome_status st;
	uint64_t seed = c->seed * 6364136223846793005ull + 1442695040888963407ull;   /* from the iteration's seed, so two calls agree */
	uint32_t i, nin;

	seed = seed * 6364136223846793005ull + 1442695040888963407ull;
	nin = 1u + (uint32_t)((seed >> 33) % 5u);
	for (i = 0; i < nin; i++) {
		uint64_t r, q;

		seed = seed * 6364136223846793005ull + 1442695040888963407ull;
		r = seed ^ (seed >> 29);
		seed = seed * 6364136223846793005ull + 1442695040888963407ull;
		q = seed >> 20;
		in[i].off = (r & 7u) == 0 ? (r >> 8) : q % (f.n + 1u);
		in[i].len = (r & 56u) == 0 ? ~0ull - (r >> 20) : (q >> 24) % 64u;
		in[i].kind = (uint32_t)(r >> 40) & 1u;
		in[i]._pad = 0;
	}
	memset(rows, 0x5a, sizeof rows);
	rq.obj = obj;
	rq.file = f;
	rq.inf = in;
	rq.n_inf = nin;
	rq.out = rows;
	rq.cap = KGENOME_INFECT_MAX;
	st = call(&rq, &rs);
	FZ_CHECK(c, (unsigned)st <= (unsigned)KGENOME_NOMEM, "kgenome_infect_regions: status outside the enum");
	FZ_CHECK(c, rs.n <= rs.total && rs.n <= rq.cap, "more rows written than the total or the room");
	FZ_CHECK(c, st == KGENOME_OK || st == KGENOME_BAD_INPUT || st == KGENOME_TRUNCATED, "an unexpected status");
	for (i = 0; i < rs.n; i++) {
		const struct kgenome_infect_row *r = &rows[i];
		fz_step(&c->steps, 1);
		FZ_CHECK(c, r->kind >= KGENOME_INFECT_ENTRY && r->kind <= KGENOME_INFECT_REPORTED, "a row of no kind");
		FZ_CHECK(c, memchr(r->name, 0, sizeof r->name) != NULL, "a row name without its terminator");
		if (r->kind != KGENOME_INFECT_REPORTED && r->off != KGENOME_NA)
			FZ_CHECK(c, r->off <= f.n && r->len <= f.n - r->off, "a region outside the object");
		if (r->flagged) {
			FZ_CHECK(c, r->inf_index < nin && r->inf_kind == in[r->inf_index].kind, "a flagged row without its range");
			if (r->len && in[r->inf_index].len && r->kind != KGENOME_INFECT_REPORTED)
				FZ_CHECK(c, r->off < in[r->inf_index].off + in[r->inf_index].len ||
					    in[r->inf_index].off + in[r->inf_index].len < in[r->inf_index].off,
					 "a flagged row that does not touch its range");
		}
		fz_digest(c, r->off ^ (r->len << 3) ^ ((uint64_t)r->kind << 56) ^ r->flagged);
	}
	rq.cap = 1;
	st = call(&rq, &rs2);
	FZ_CHECK(c, rs2.n <= 1u && rs2.total == rs.total, "a cap of one changed the total or overran");
	rq.cap = 0;
	rq.out = NULL;
	(void)call(&rq, &rs2);
	FZ_CHECK(c, rs2.n == 0 && rs2.total == rs.total, "a cap of zero wrote or changed the total");
	fz_digest(c, ((uint64_t)rs.total << 24) ^ rs.n_flagged ^ ((uint64_t)st << 60));
}

#endif /* KOF_FUZZ_INFECT_CHECK_H */
