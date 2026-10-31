/*
 * ksb_diag.c - --diagnose: one diagnose source in, one record out.
 */

#include "ksb.h"
#include <kofdebug.h>
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
		     const struct ksb_meta *meta, unsigned users_len, size_t *need_out)
{
	struct kof_dsrc_view v = *vp;
	struct kof_dsrc_node *nd = v.nd;
	const char *name = v.name;
	char (*ref_tbl)[KOF_DIAG_NEED_LEN] = v.ref;
	int n_nd = v.n_nd, n_need = v.n_need, n_ref = v.n_ref;
	int n_when = v.n_when, has_seq = v.has_seq;
	const int has_dis = v.disease[0] != 0;
	const size_t wire_n = v.form ? kof_form_wire_size(v.form) : 0u;
	size_t need;
	int i;

	if (v.form && !wire_n) {
		fprintf(stderr, "FAIL: %s: the detection form does not make a record (kof_form_check)\n", name);
		return 0;
	}
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
	/* THE CATALOG SECTION IS ONE OF THE THINGS THAT FOLLOW: without it in this condition a
	 * record whose only extra is the section would have no count byte, and a reader built
	 * before the section existed would take its tag (9) for a count of nine names. */
	if (n_need || n_when || n_ref || ksb->diag.uses_known || has_dis || meta || wire_n)
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
	if (meta)
		need += 2u + KDIG_META_LEN;             /* tag, length, three ids and the type */
	/* THE DETECTION FORM: one stream cut into sections of at most 255 bytes (KDIG_SEC_FORM). */
	if (wire_n)
		need += kof_form_section_size(wire_n);
	*need_out = need;
	return 1;
}

/* The record itself, into a buffer diag_size sized. */
static void diag_fill(const struct ksb_ctx *ksb, const struct kof_dsrc_view *vp,
		      const struct ksb_meta *meta, unsigned n_users, unsigned users_len,
		      unsigned char *blob)
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
	if (n_need || n_when || n_ref || ksb->diag.uses_known || has_dis || meta || v.form)
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
	if (meta) {
		const uint64_t id[3] = { meta->family, meta->variant, meta->tag };
		unsigned z, q;

		blob[at++] = KDIG_SEC_META;
		blob[at++] = (unsigned char)KDIG_META_LEN;
		for (z = 0; z < 3u; z++)
			for (q = 0; q < 8u; q++)
				blob[at++] = (unsigned char)(id[z] >> (q * 8u));
		blob[at++] = meta->type;
	}
	if (v.form) {
		size_t wn = kof_form_wire_size(v.form);
		uint8_t *wire = malloc(wn);

		/* diag_size sized the record from this very stream; an allocation that fails here leaves the zeros the
		 * record was made with, which the loader refuses (a form that does not decode), never a half form. */
		if (wire) {
			(void)kof_form_wire_write(v.form, wire);
			at += kof_form_section_write(wire, wn, blob + at);
			free(wire);
		}
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
	struct ksb_meta meta_buf, *meta = NULL;

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
	if (ksb->errors) {
		kof_dsrc_view_free(&v);
		return 1;
	}
	/* THE CATALOG FACTS, NAMES TO IDS: the source carries names (a researcher reads it), the
	 * record carries ids. A name the catalogs do not have refuses the build with the line. */
	if (v.meta == KOF_DSRC_META_ALL) {
		if (!ksb_meta_check(ksb_catalog_get(ksb), &d, &v, &meta_buf, &rep)) {
			kof_dsrc_view_free(&v);
			return 1;
		}
		if (meta_buf.disabled) {
			/* Said by ksb_meta_check. Not written, so the pack and names.kdig hold nothing of it. */
			ksb->diag.n_disabled++;
			kof_dsrc_view_free(&v);
			return 0;
		}
		meta = &meta_buf;
		ksb_catalog_use(ksb_catalog_get(ksb), meta_buf.family, meta_buf.variant, meta_buf.tag);
	}
	if (v.disease[0] && !ksb_disease_note(ksb, v.disease, v.disease_type)) {
		kof_dsrc_view_free(&v);
		return 1;
	}
	diag_users(ksb, v.name, &n_users, &users_len);
	if (!diag_size(ksb, &v, meta, users_len, &need)) {
		kof_dsrc_view_free(&v);
		return 1;
	}
	blob = calloc(1, need);
	if (!blob) {
		kof_dsrc_view_free(&v);
		return 1;
	}
	diag_fill(ksb, &v, meta, n_users, users_len, blob);
	/* Remembered so the tree build can check that every call names a
	 * diagnose that exists - see the end of ksb_tree_main. */
	/* KNOWN DEFECT CAT1-1 (2026-10-31, R) [sev L]: built[] holds 64 names; a diagnose built after the 64th is not recorded here.
	 * Trigger: a tree of more than 64 diagnoses and a module whose kof_diag(NAME) names one of the later ones. Effect: tree_check_uses reports it as
	 * "which no source declares" (a dangling call) and the build stops; the list is also what the "read by no rule" warning walks.
	 * Reproducer: not run (read only; bases/ has 5 diagnoses today). Fix: size the list by the number of diagnose sources (a caller-grown array). */
	if (ksb->diag.n_built < 64u) {
		/* The catalog facts (family, variant, type, tag) ARE the declaration of what a match finds: the tag's activities and
		 * objects and the type make the verdict, so a diagnose that carries them is read by it (a disease of the old kind
		 * is the other way to say so). */
		ksb->diag.built_dis[ksb->diag.n_built] = (unsigned char)(v.disease[0] != 0 || meta != NULL);
		snprintf(ksb->diag.built[ksb->diag.n_built++], sizeof ksb->diag.built[0], "%s", v.name);
	}
	o = fopen(out, "wb");
	if (!o || fwrite(blob, 1, need, o) != need) {
		fprintf(stderr, "FAIL: cannot write %s\n", out);
		if (o) fclose(o);
		free(blob);
		kof_dsrc_view_free(&v);
		return 1;
	}
	fclose(o);
	if (v.form) {
		char ex[256];
		unsigned bq;

		for (bq = 0; bq < v.form->n_block; bq++)
			KOF_TRACE("[build] %s block %u: mask %x, side %u, %u hash(es) at %u\n", v.name, bq,
				  (unsigned)v.form->block[bq].mask, (unsigned)v.form->block[bq].side,
				  (unsigned)v.form->block[bq].n_hash, (unsigned)v.form->block[bq].first);
		KOF_TRACE("[build] %s: form record %zu byte(s), %u similarity matcher(s)\n", v.name, kof_form_wire_size(v.form),
			  (unsigned)v.form->n_sim);

		kof_form_expr_text(v.form, ex, sizeof ex);
		printf("== %s  %s  form: %u string(s), %u block(s), %u matcher(s), expression %s, %d condition(s), %zu bytes\n",
		       src, v.name, (unsigned)v.form->n_str, (unsigned)v.form->n_block, (unsigned)v.form->n_match, ex,
		       v.n_when, need);
	} else {
		printf("== %s  %s  %d node, %d sign(s), %d ref(s), %d condition(s), %zu bytes\n",
		       src, v.name, v.n_nd, v.n_need, v.n_ref, v.n_when, need);
	}
	kof_dsrc_view_free(&v);
	free(blob);
	return 0;
}
