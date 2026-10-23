/*
 * ksb_diag.c - --diagnose: one diagnose source in, one record out.
 */

#include "ksb.h"
#include <databases/diagsrc.h>


/* ---- diagnoses ------------------------------------------------------------
 *
 * A DIAGNOSE IS NOT A MODULE, so it does not go down the path above: there
 * is no code to compile, no blob to link and no vtable to call. It is a
 * tree of nucleo groups - see kofmod/kofdiagtree.h - and what the build does
 * with it is read the declarations and write the records out.
 *
 * SO IT IS NOT IN A .ksig PACK EITHER. The pack header carries a
 * FIXED-SIZE section table, so one more section is a format change that
 * every database in existence has to be rebuilt for. Diagnoses are a
 * different kind of content with no module, no pattern and no blob in
 * them, so they get a file of their own beside the packs and the loader
 * picks them up from the same directory.
 */

/* Written in front of the nodes. Little endian, like every other number
 * this program writes - see the note at the pack header. */
struct dhdr {
	uint16_t n_node;
	uint8_t  analysis;
	uint8_t  name_len;
};

/* How many signatures read the diagnose, and how many bytes of their names fit
 * in the record. Nothing unless this is a tree build that read every signature. */
static void diag_users(const struct ksb_ctx *ksb, const char *name,
		       unsigned *n_users, unsigned *users_len)
{
	unsigned q;

	*n_users = 0;
	*users_len = 0;
	if (ksb->diag.uses_known) {
		for (q = 0; q < ksb->diag.n_uses; q++)
			if (!strcmp(ksb->diag.uses[q].diag, name)) {
				(*n_users)++;
				if (*users_len + 1u +
				    strlen(ksb->diag.uses[q].user) < 250u)
					*users_len += 1u +
					    (unsigned)strlen(ksb->diag.uses[q].user);
			}
	}
}

/* The size of the record, byte for byte. Zero when a section would overflow. */
static int diag_size(const struct ksb_ctx *ksb, const struct kof_dsrc_view *vp,
		     unsigned users_len, size_t *need_out)
{
	struct kof_dsrc_view v = *vp;
	struct kof_dsrc_node *nd = v.nd;
	const char *name = v.name;
	char (*ref_tbl)[KOF_DIAG_NEED_LEN] = v.ref;
	int n_nd = v.n_nd, n_need = v.n_need, n_ref = v.n_ref;
	int n_when = v.n_when, has_seq = v.has_seq;
	const int has_dis = v.disease[0] != 0;
	size_t need;
	int i;

	need = sizeof(struct dhdr) + strlen(name) + (size_t)n_nd * 8u;
	for (i = 0; i < n_nd; i++) {
		if (nd[i].bits & KOF_DIAG_B_VAL)
			need += 2u + 8u;        /* kind, length, the value */
		if (nd[i].bits & KOF_DIAG_B_FIELD_OF)
			need += 2u + strlen(nd[i].sym);
	}
	/*
	 * AND THE SIGNS, AS A TRAILING SECTION. After the nodes so a reader
	 * built before they existed stops where it always stopped: the node
	 * loop ends on its own count and what follows is simply not read.
	 */
	/*
	 * The count byte is written whenever ANYTHING follows the nodes,
	 * because the tagged sections below sit after it and a reader that
	 * skipped it would take a tag for a count.
	 */
	/*
	 * THE USERS, if this is a tree build that read every signature. A
	 * stand-alone --diagnose cannot know, and writes nothing: absent means
	 * unknown, and unknown keeps running.
	 */
	if (n_need || n_when || n_ref || ksb->diag.uses_known || has_dis)
		need += 1u;                     /* the legacy name count: 0 */
	if (n_need)
		need += 2u + 2u * (size_t)n_need;   /* tag, length, caps */
	if (has_seq)
		need += 2u + 4u;                    /* tag, length, two caps */
	if (n_ref) {
		int k;

		size_t refbody = 1u;

		need += 2u + 1u;                /* tag, length, count */
		for (k = 0; k < n_ref; k++) {
			need += 1u + strlen(ref_tbl[k]);
			refbody += 1u + strlen(ref_tbl[k]);
		}
		/* The section's length is one byte: a longer body would be
		 * written truncated and read back as something else. */
		if (refbody > 255u) {
			fprintf(stderr, "FAIL: %s: the symbols this diagnose needs "
				"take %zu bytes, the section holds 255\n",
				name, refbody);
			return 0;
		}
	}
	if (ksb->diag.uses_known)
		need += 2u + 1u + users_len;
	/*
	 * TAGGED TRAILING SECTIONS, tag and length each one byte. The signs
	 * above are not tagged - they predate this - so anything added after
	 * them has to be skippable by a reader that does not know it, which
	 * a length is and a bare field is not.
	 */
	if (n_when)
		need += 2u + (size_t)n_when * 10u;
	if (has_dis)
		need += 2u + 5u;                        /* tag, length, id and type */
	*need_out = need;
	return 1;
}

/* The record itself, into a buffer diag_size sized. */
static void diag_fill(const struct ksb_ctx *ksb, const struct kof_dsrc_view *vp,
		      unsigned n_users, unsigned users_len, unsigned char *blob)
{
	struct kof_dsrc_view v = *vp;
	struct kof_dsrc_node *nd = v.nd;
	const char *name = v.name;
	uint16_t *need_tbl = v.need;
	char (*ref_tbl)[KOF_DIAG_NEED_LEN] = v.ref;
	struct kof_diag_when *when_tbl = v.when;
	int n_nd = v.n_nd, n_need = v.n_need, n_ref = v.n_ref;
	int n_when = v.n_when, has_seq = v.has_seq;
	uint16_t seq_first = v.seq_first, seq_then = v.seq_then;
	unsigned analysis = v.analysis;
	const int has_dis = v.disease[0] != 0;
	const uint32_t dis_id = has_dis ? kof_disease_id(v.disease) : 0u;
	const unsigned char dis_type = v.disease_type;
	size_t at;
	int i;

	blob[0] = (unsigned char)n_nd;
	blob[1] = (unsigned char)(n_nd >> 8);
	blob[2] = (unsigned char)analysis;
	blob[3] = (unsigned char)strlen(name);
	at = 4;
	memcpy(blob + at, name, strlen(name));
	at += strlen(name);
	for (i = 0; i < n_nd; i++) {
		/* a tail's parent is the head: the block is a star */
		unsigned par = i ? 0u : (unsigned)KOF_DIAG_NO_PARENT;

		blob[at + 0] = (unsigned char)nd[i].cap;
		blob[at + 1] = (unsigned char)(nd[i].cap >> 8);
		blob[at + 2] = (unsigned char)nd[i].flags;
		blob[at + 3] = (unsigned char)(nd[i].flags >> 8);
		blob[at + 4] = (unsigned char)par;
		blob[at + 5] = nd[i].role;
		blob[at + 6] = nd[i].bits;
		blob[at + 7] = (unsigned char)
			(((nd[i].bits & KOF_DIAG_B_VAL) ? 10u : 0u) +
			 ((nd[i].bits & KOF_DIAG_B_FIELD_OF)
			  ? 2u + strlen(nd[i].sym) : 0u));
		at += 8;
		if (nd[i].bits & KOF_DIAG_B_VAL) {
			unsigned q;

			blob[at++] = KDIG_ATTR_VALUE;
			blob[at++] = 8u;
			for (q = 0; q < 8u; q++)
				blob[at++] = (unsigned char)
					     (nd[i].val >> (q * 8u));
		}
		if (nd[i].bits & KOF_DIAG_B_FIELD_OF) {
			size_t L = strlen(nd[i].sym);

			blob[at++] = KDIG_ATTR_SYM;
			blob[at++] = (unsigned char)L;
			memcpy(blob + at, nd[i].sym, L);
			at += L;
		}
	}
	if (n_need || n_when || n_ref || ksb->diag.uses_known || has_dis)
		blob[at++] = 0;                 /* no names: see KDIG_SEC_NEEDS */
	if (n_need) {
		int k;

		blob[at++] = KDIG_SEC_NEEDS;
		blob[at++] = (unsigned char)(2 * n_need);
		for (k = 0; k < n_need; k++) {
			blob[at++] = (unsigned char)need_tbl[k];
			blob[at++] = (unsigned char)(need_tbl[k] >> 8);
		}
	}
	if (has_seq) {
		blob[at++] = KDIG_SEC_SEQUENCE;
		blob[at++] = 4;
		blob[at++] = (unsigned char)seq_first;
		blob[at++] = (unsigned char)(seq_first >> 8);
		blob[at++] = (unsigned char)seq_then;
		blob[at++] = (unsigned char)(seq_then >> 8);
	}
	if (n_when) {
		int k;

		blob[at++] = KDIG_SEC_WHEN;
		blob[at++] = (unsigned char)(n_when * 10);
		for (k = 0; k < n_when; k++) {
			unsigned q;

			blob[at++] = (unsigned char)when_tbl[k].fact;
			blob[at++] = (unsigned char)(when_tbl[k].fact >> 8);
			for (q = 0; q < 8u; q++)
				blob[at++] = (unsigned char)
					     (when_tbl[k].val >> (q * 8u));
		}
	}
	if (n_ref) {
		int k;
		size_t body = 1u;

		for (k = 0; k < n_ref; k++)
			body += 1u + strlen(ref_tbl[k]);
		blob[at++] = KDIG_SEC_REFS;
		blob[at++] = (unsigned char)body;
		blob[at++] = (unsigned char)n_ref;
		for (k = 0; k < n_ref; k++) {
			size_t L = strlen(ref_tbl[k]);

			blob[at++] = (unsigned char)L;
			memcpy(blob + at, ref_tbl[k], L);
			at += L;
		}
	}
	if (ksb->diag.uses_known) {
		unsigned q, left = users_len;

		blob[at++] = KDIG_SEC_USERS;
		blob[at++] = (unsigned char)(1u + users_len);
		blob[at++] = (unsigned char)(n_users > 255u ? 255u : n_users);
		for (q = 0; q < ksb->diag.n_uses; q++) {
			size_t L;

			if (strcmp(ksb->diag.uses[q].diag, name))
				continue;
			L = strlen(ksb->diag.uses[q].user);
			if (1u + L > left)
				continue;
			blob[at++] = (unsigned char)L;
			memcpy(blob + at, ksb->diag.uses[q].user, L);
			at += L;
			left -= 1u + (unsigned)L;
		}
	}
	if (has_dis) {
		blob[at++] = KDIG_SEC_DISEASE;
		blob[at++] = 5;
		blob[at++] = (unsigned char)dis_id;
		blob[at++] = (unsigned char)(dis_id >> 8);
		blob[at++] = (unsigned char)(dis_id >> 16);
		blob[at++] = (unsigned char)(dis_id >> 24);
		blob[at++] = dis_type;
	}
}

int ksb_diagnose_main(struct ksb_ctx *ksb, int argc, char **argv)
{
	const char *src = argc > 2 ? argv[2] : NULL;
	const char *out = argc > 3 ? argv[3] : NULL;
	static struct kof_dsrc d;
	struct kof_dsrc_view v;
	const struct kof_dsrc_report rep = { ksb_dsrc_error, ksb_dsrc_warn, ksb };
	char *text;
	size_t tn = 0;
	unsigned n_users = 0, users_len = 0;
	FILE *o;
	unsigned char *blob;
	size_t need;

	if (argc != 4 || !src || !out) {
		fprintf(stderr, "usage: %s --diagnose <src.c> <out.kdig>\n",
			argv[0]);
		return 2;
	}
	if (!kof_dsrc_cap_table_check())
		return 1;
	text = ksb_slurp(src, &tn);
	if (!text) {
		fprintf(stderr, "FAIL: cannot open %s\n", src);
		return 1;
	}
	ksb->src_name = src;
	/*
	 * READ AND CHECKED BY THE ONE READER the editor uses - see diagsrc.h. What
	 * is left here is the record: the view is serialised, not re-derived.
	 */
	kof_dsrc_parse(text, tn, &d, &rep);
	kof_dsrc_resolve(&d, &v, &rep);
	free(text);
	if (ksb->errors)
		return 1;
	if (v.disease[0] && !ksb_disease_note(ksb, v.disease, v.disease_type))
		return 1;
	diag_users(ksb, v.name, &n_users, &users_len);
	if (!diag_size(ksb, &v, users_len, &need))
		return 1;
	blob = calloc(1, need);
	if (!blob)
		return 1;
	diag_fill(ksb, &v, n_users, users_len, blob);
	/* Remembered so the tree build can check that every call names a
	 * diagnose that exists - see the end of ksb_tree_main. */
	if (ksb->diag.n_built < 64u) {
		ksb->diag.built_dis[ksb->diag.n_built] = (unsigned char)(v.disease[0] != 0);
		snprintf(ksb->diag.built[ksb->diag.n_built++], sizeof ksb->diag.built[0], "%s", v.name);
	}
	o = fopen(out, "wb");
	if (!o || fwrite(blob, 1, need, o) != need) {
		fprintf(stderr, "FAIL: cannot write %s\n", out);
		if (o) fclose(o);
		free(blob);
		return 1;
	}
	fclose(o);
	printf("== %s  %s  %d node, %d sign(s), %d ref(s), %d condition(s), %zu bytes\n",
	       src, v.name, v.n_nd, v.n_need, v.n_ref, v.n_when, need);
	free(blob);
	return 0;
}
