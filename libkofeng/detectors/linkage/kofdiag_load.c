/*
 * kofdiag_load.c - one diagnose record, read: the nodes, the trailing sections, the detection form. Split from kofdiag.c
 * (the matcher) when the matcher grew the reached tier (2026-11-14); what loads a record and what matches one share no
 * static and no state, and kofdiag.h is the one header of both.
 */

#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "../../databases/pack/diagform.h"
#include "../../analyzers/parsers/kofformat.h"
#include <celllysis/nucleo.h>

int kof_diag_gate_valid(uint16_t fact, uint64_t val)
{
	if (fact == KOF_FACT_ANOMALY) {
		const struct kof_parser *p;
		const char *an;

		/* (format << 32) | bit and nothing else: bits 6..31 clear, the format one byte, one the parser table has, and the
		 * bit one its parser names. */
		if ((val & 0xffffffc0u) || (val >> 32) > 0xffu)
			return 0;
		p = kof_parser_of((uint8_t)(val >> 32));
		an = p && p->anomaly_name ? p->anomaly_name((unsigned)(val & 63u)) : NULL;
		return an && kof_parser_anomaly_bit(p, an) == (int)(val & 63u);
	}
	if (fact == KOF_FACT_NUCLEO) {
		const char *nm;

		if (!val || val > 0xffffu || !KGENOME_NUCLEO_VALID((uint16_t)val))
			return 0;
		nm = kgenome_nucleo_cap_name((uint16_t)val);
		return nm && strcmp(nm, "?") != 0;
	}
	return 1;
}

/* ---- loading -------------------------------------------------------------
 *
 * A RECORD IS ONE DIAGNOSE and nothing else - no module, no pattern, no blob.
 * The records of a database are carried in diag-<kind>.kdig packs (see
 * load_diagnoses in dbloader.c), which is a file beside the packs rather than a
 * section inside one: the pack header carries a fixed-size section table, so
 * one more section is a format change every database in existence has to be
 * rebuilt for, and none of what a pack exists to carry applies here.
 *
 * EVERYTHING IS BOUNDS CHECKED AGAINST THE RECORD'S OWN LENGTH, and a record
 * that does not add up is refused whole rather than loaded in part. A diagnose
 * half read is a diagnose that matches something its author did not write.
 */

/* The bodies of a record's KDIG_SEC_FORM sections, concatenated: one stream (see diagform.h). Heap, because a stream is
 * up to KOF_FORM_MAX_WIRE bytes and this runs once per record at load. */
struct formacc {
	uint8_t *p;
	size_t   n, cap;
};

static int formacc_add(struct formacc *fa, const uint8_t *b, size_t len)
{
	/* A section of no bytes adds none (and the first one has no buffer yet: memcpy(NULL, p, 0) is undefined). */
	if (!len)
		return 1;
	if (fa->n + len > KOF_FORM_MAX_WIRE)
		return 0;               /* refused whole, not cut: a stream cut in the middle is another form */
	if (fa->n + len > fa->cap) {
		size_t nc = fa->cap ? fa->cap : 1024u;
		uint8_t *g;

		while (nc < fa->n + len)
			nc *= 2u;
		g = realloc(fa->p, nc);
		if (!g)
			return 0;
		fa->p = g;
		fa->cap = nc;
	}
	memcpy(fa->p + fa->n, b, len);
	fa->n += len;
	return 1;
}

/*
 * ONE BLOCK OR TWO, AND EVERY NODE IN ONE OF THEM. The matcher descends from a root, so:
 *
 *   - every node's parents lead to a root. A parent cycle (1 -> 2 -> 1 beside a root 0) was accepted before
 *     2026-11-14: the matcher never reached those nodes, bound them to nothing and answered yes on the rest -
 *     a diagnose matching what its author did not write (DL-3). The builder never writes one; a damaged or
 *     crafted record does, and it is refused whole like every other record that does not add up.
 *   - one root, as always; or TWO, the second block of a KOF_DIAG_DECLARE_JOIN diagnose, and then at least one
 *     KOF_DIAG_B_JOIN node, every one of them in the second block (the second root in record order). A JOIN
 *     bit in a one-block record, two blocks with no join, or a third root refuses the record. A loader built
 *     before two blocks existed refuses every two-root record ("exactly one root"), so an engine that does not
 *     know the join never matches the diagnose without it.
 *   - a sequence makes THE head (seq_first/seq_then, node[0]), so it is refused in a record of two blocks.
 */
static int blocks_ok(const struct kof_diag_node *node, uint32_t n_node, const struct kof_diag *out)
{
	uint32_t i, roots = 0, joins = 0;
	uint32_t root2 = KOF_DIAG_NO_PARENT;

	for (i = 0; i < n_node; i++)
		if (node[i].parent == KOF_DIAG_NO_PARENT && ++roots == 2u)
			root2 = i;
	if (roots != 1u && roots != 2u)
		return 0;
	for (i = 0; i < n_node; i++) {
		uint32_t p = i, steps = 0;

		while (node[p].parent != KOF_DIAG_NO_PARENT) {
			if (++steps > n_node)
				return 0;               /* a parent cycle: no root at the end */
			p = node[p].parent;
		}
		if (node[i].bits & KOF_DIAG_B_JOIN) {
			if (p != root2)
				return 0;               /* a join in the first block, or in a one-block record */
			joins++;
		}
	}
	if (roots == 2u && (!joins || out->seq_first))
		return 0;
	return 1;
}

static int diag_load_(kof_buf rec, struct kof_diag *out, const struct kof_diag_store *st, struct formacc *fa)
{
	const uint8_t *b = rec.p;
	const uint64_t n = rec.n;
	struct kof_diag_node *node = st->node;
	char *name = st->name, *needs = st->needs;
	const uint32_t name_cap = st->name_cap, needs_cap = st->needs_cap;
	const uint8_t max_node = st->max_node;
	uint32_t n_node, nlen, i;
	/* How much of the string store a node attribute has taken - the
	 * signs below continue from here, because both are words this
	 * diagnose carries and one buffer is one thing to bound. */
	uint32_t nused = 0;
	uint64_t at;

	if (!b || !out || !node || !name || n < 4u)
		return 0;
	n_node = (uint32_t)b[0] | ((uint32_t)b[1] << 8);
	nlen   = b[3];
	/* NO NODE IS A FORM'S RECORD (KDIG_SEC_FORM); kof_diag_load below says whether it had one. */
	if (n_node > max_node || nlen + 1u > name_cap)
		return 0;
	at = 4u + nlen;
	if (n < at || (n - at) / 8u < n_node)
		return 0;

	memcpy(name, b + 4, nlen);
	name[nlen] = 0;
	memset(out, 0, sizeof *out);
	out->analysis = b[2];
	out->n_node = (uint8_t)n_node;
	out->name = name;
	out->node = node;

	for (i = 0; i < n_node; i++) {
		const uint8_t *r = b + at;
		uint32_t alen;

		if ((uint64_t)(r - b) + 8u > n)
			return 0;
		/* Every field, so a node array that held a value and a symbol before is clean after a record
		 * with neither (WP9-F13: val and sym were left, a pointer into a string store that may be gone). */
		memset(&node[i], 0, sizeof node[i]);
		node[i].cap    = (uint16_t)(r[0] | (r[1] << 8));
		node[i].flags  = (uint16_t)(r[2] | (r[3] << 8));
		node[i].parent = r[4];
		node[i].role   = r[5];
		node[i].bits   = r[6];
		node[i].attr_len = r[7];
		alen = r[7];
		at += 8u;
		if (at + alen > n)
			return 0;
		/*
		 * (kind, length, payload)*, and an unknown kind is skipped by
		 * its length rather than refused - that is what the length is
		 * for. A length that runs past the run refuses the record,
		 * like everything else here.
		 */
		{
			uint32_t k = 0;

			while (k + 2u <= alen) {
				uint32_t kind = b[at + k];
				uint32_t klen = b[at + k + 1u];

				k += 2u;
				if (k + klen > alen)
					return 0;
				/*
				 * THE NAME GOES IN THE DIAGNOSE'S OWN
				 * STRING STORE, beside the signs - it is the
				 * same kind of thing, a word this diagnose
				 * carries, and a second buffer would be a
				 * second thing to bound.
				 */
				if (kind == KDIG_ATTR_SYM && klen &&
				    needs && needs_cap) {
					if (nused + klen + 1u > needs_cap)
						return 0;
					memcpy(needs + nused, b + at + k, klen);
					needs[nused + klen] = 0;
					node[i].sym = needs + nused;
					nused += klen + 1u;
				}
				if (kind == KDIG_ATTR_VALUE && klen == 8u) {
					uint64_t v = 0;
					unsigned q;

					for (q = 0; q < 8u; q++)
						v |= (uint64_t)b[at + k + q]
						     << (q * 8u);
					node[i].val = v;
				}
				k += klen;
			}
		}
		at += alen;
		/*
		 * A PARENT THAT IS NOT A NODE HERE, or a node that is its own
		 * parent, is a file this build did not write. Refuse rather
		 * than clamp: a clamped index points at a real node, and the
		 * diagnose then quietly means something else.
		 */
		if (node[i].parent != KOF_DIAG_NO_PARENT &&
		    (node[i].parent >= n_node || node[i].parent == i))
			return 0;
		if (node[i].role >= KGENOME_DIAG_ROLE_COUNT)
			return 0;
	}
	/*
	 * ---- THE SIGNS, IF THE PACK CARRIES ANY -------------------------
	 *
	 * A trailing section, so a pack written before they existed simply
	 * ends after its nodes and answers none. Refused WHOLE on anything
	 * that does not add up, like the rest of the record: a diagnose with
	 * half its signs read would be filtered by a condition nobody wrote.
	 */
	if (needs && needs_cap && at < n) {
		uint32_t cnt = b[at++], k, used = nused;

		/*
		 * THE NAMES AN OLDER PACK WROTE HERE ARE SKIPPED, not read: the
		 * sign is now a capability (KDIG_SEC_NEEDS), and a diagnose
		 * built before that simply has no sign, which is the cheaper
		 * kind of wrong - it runs where it could have been spared.
		 */
		if (cnt > KOF_DIAG_MAX_NEED)
			return 0;
		for (k = 0; k < cnt; k++) {
			uint32_t L;

			if (at >= n)
				return 0;
			L = b[at++];
			if (!L || L >= KOF_DIAG_NEED_LEN || at + L > n)
				return 0;
			at += L;
		}
		/*
		 * ---- AND THE TAGGED SECTIONS AFTER THEM ----------------
		 *
		 * An unknown tag is SKIPPED and not refused: the length is
		 * there so a later build can add a section without every
		 * reader having to be taught it first. A length that runs
		 * past the end is a different matter and refuses the whole
		 * record, like everything else here.
		 */
		while (at + 2u <= n) {
			uint32_t tag = b[at], len = b[at + 1u];

			at += 2u;
			if (at + len > n)
				return 0;
			/*
			 * (fact u16, value u64) pairs - see KOF_DIAG_HAS_ATTRB.
			 * A FACT THIS BUILD DOES NOT KNOW REFUSES THE WHOLE
			 * RECORD: a condition silently dropped is a diagnose
			 * that runs on the files its author excluded, and it
			 * would do so quietly.
			 */
			/* The capabilities the object must import - u16 each. */
			if (tag == KDIG_SEC_NEEDS) {
				uint32_t q;

				if ((len & 1u) || len / 2u > KOF_DIAG_MAX_NEED)
					return 0;
				for (q = 0; q < len / 2u; q++)
					out->needcap[q] = (uint16_t)(b[at + 2u * q] |
							(b[at + 2u * q + 1u] << 8));
				out->n_needcap = (uint8_t)(len / 2u);
			}
			/* The two calls the head is built from - see
			 * KOF_DIAG_DECLARE_SEQUENCE. A length that is not two caps
			 * refuses the record: half a sequence would be a head built
			 * from something nobody wrote. */
			if (tag == KDIG_SEC_SEQUENCE) {
				if (len != 4u)
					return 0;
				out->seq_first = (uint16_t)(b[at] | (b[at + 1] << 8));
				out->seq_then  = (uint16_t)(b[at + 2] | (b[at + 3] << 8));
				if (!out->seq_first || !out->seq_then)
					return 0;
			}
			if (tag == KDIG_SEC_USERS && len >= 1u) {
				out->users_known = 1;
				out->n_users = b[at];
				out->users_off = (uint32_t)at;
				out->users_len = len;
			}
			/*
			 * THE SYMBOLS THE CODE MUST REFER INTO - see
			 * KOF_DIAG_DECLARE_SYMBOL. Same shape and the same string store as
			 * the signs, and refused whole on anything that does not
			 * add up, for the same reason: a diagnose with half its
			 * references read would be gated by a condition nobody
			 * wrote.
			 */
			if (tag == KDIG_SEC_REFS && len >= 1u && needs && needs_cap) {
				uint32_t cnt2 = b[at], z, p2 = (uint32_t)(at + 1u);

				if (cnt2 > KOF_DIAG_MAX_NEED)
					return 0;
				for (z = 0; z < cnt2; z++) {
					uint32_t L2;

					if (p2 >= at + len)
						return 0;
					L2 = b[p2++];
					if (!L2 || L2 >= KOF_DIAG_NEED_LEN ||
					    p2 + L2 > at + len ||
					    used + L2 + 1u > needs_cap)
						return 0;
					memcpy(needs + used, b + p2, L2);
					needs[used + L2] = 0;
					out->ref[z] = needs + used;
					used += L2 + 1u;
					p2 += L2;
				}
				out->n_ref = (uint8_t)cnt2;
			}
			/* The disease: an id and its type, nothing else. A length that is
			 * not five refuses the record like the rest - half an id is a
			 * different behaviour - and so does a type that is no maltype. */
			if (tag == KDIG_SEC_DISEASE) {
				if (len != 5u || b[at + 4u] >= KOF_MALTYPE_COUNT)
					return 0;
				out->disease = (uint32_t)b[at] | ((uint32_t)b[at + 1u] << 8) |
					       ((uint32_t)b[at + 2u] << 16) |
					       ((uint32_t)b[at + 3u] << 24);
				out->disease_type = b[at + 4u];
				if (!out->disease)
					return 0;
			}
			/* The catalog facts: three ids and the type, fixed layout (KDIG_SEC_META). A length
			 * that is not 25, an id of zero, a type that is no maltype or is Packer, or a second
			 * section refuses the record, like the disease: half an identity names another one. */
			if (tag == KDIG_SEC_META) {
				uint64_t id[3] = { 0, 0, 0 };
				unsigned q, z;

				if (len != KDIG_META_LEN || out->family_id ||
				    b[at + 24u] >= KOF_MALTYPE_COUNT ||
				    b[at + 24u] == KOF_MALTYPE_PACKER)
					return 0;
				for (z = 0; z < 3u; z++)
					for (q = 0; q < 8u; q++)
						id[z] |= (uint64_t)b[at + z * 8u + q] << (q * 8u);
				if (!id[0] || !id[1] || !id[2])
					return 0;
				out->family_id = id[0];
				out->variant_id = id[1];
				out->tag_id = id[2];
				out->type = b[at + 24u];
			}
			/* The detection form: a piece of one stream, put together after the loop. */
			if (tag == KDIG_SEC_FORM && !formacc_add(fa, b + at, len))
				return 0;
			if (tag == KDIG_SEC_WHEN) {
				uint32_t q;

				if (len % 10u)
					return 0;
				if (len / 10u > KOF_DIAG_MAX_WHEN)
					return 0;
				for (q = 0; q + 10u <= len; q += 10u) {
					const uint8_t *w = b + at + q;
					uint64_t v = 0;
					unsigned t;
					uint16_t fc = (uint16_t)(w[0] |
							 (w[1] << 8));

					if (!fc || fc >= KOF_FACT_COUNT)
						return 0;
					for (t = 0; t < 8u; t++)
						v |= (uint64_t)w[2 + t]
						     << (t * 8u);
					/* A gate condition names an anomaly or a capability the engine has, or the record goes. */
					if (!kof_diag_gate_valid(fc, v))
						return 0;
					/* The bound is on the RUNNING count: a record may carry several WHEN
					 * sections, and each is only checked against the array on its own. A
					 * record that does not fit is refused whole, not cut (rule 4). */
					if (out->n_when >= KOF_DIAG_MAX_WHEN)
						return 0;
					out->when[out->n_when].fact = fc;
					out->when[out->n_when].val = v;
					out->n_when++;
				}
			}
			at += len;
		}
	}

	return n_node ? blocks_ok(node, n_node, out) : 1;
}

/*
 * THE RECORD'S DETECTION FORM, if it has one. A diagnose is a graph or a form: a record with nodes and a form, with
 * neither, or whose form does not decode (a stream cut, an index outside its table, an expression that is not a tree, a
 * hex program that is not one) is refused whole, like every other section.
 */
int kof_diag_load(kof_buf rec, struct kof_diag *out, const struct kof_diag_store *st)
{
	struct formacc fa = { NULL, 0, 0 };
	int ok = diag_load_(rec, out, st, &fa);

	if (ok) {
		if (fa.n && out->n_node)
			ok = 0;
		else if (!fa.n && !out->n_node)
			ok = 0;
		else if (fa.n) {
			out->form = kof_form_decode(fa.p, fa.n, NULL);
			ok = out->form != NULL;
		} else {
			uint8_t k;

			/* A nucleo condition is asked after a form's expression: a graph carrying one is refused, as the reader refuses it. */
			for (k = 0; k < out->n_when; k++)
				if (out->when[k].fact == KOF_FACT_NUCLEO)
					ok = 0;
		}
	}
	free(fa.p);
	if (!ok && out)
		out->form = NULL;
	return ok;
}

void kof_diag_form_free(struct kof_diag *d)
{
	if (!d)
		return;
	kof_form_free((struct kof_form *)(uintptr_t)d->form);
	d->form = NULL;
}
