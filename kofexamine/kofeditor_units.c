#define _GNU_SOURCE

/*
 * kofeditor_units.c - the units a draft stands for (one per condition and one per block matcher): their count, order, names and file names.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"



/* One word of a file name: lower case, [a-z0-9_-] kept and the rest dropped. */
static size_t name_word(char *out, size_t cap, size_t n, const char *w)
{
	for (; *w && n + 1u < cap; w++) {
		unsigned char ch = (unsigned char)*w;

		if (isalnum(ch) || ch == '_' || ch == '-')
			out[n++] = (char)tolower(ch);
	}
	return n;
}

/* `<type>_<family>_<tag>` of one diagnose unit: what a running id is counted
 * within, and the one place the output's name is composed. The type is the
 * UNIT's own (struct cond.utype), the family the header's and the tag the
 * unit's. A type or tag not chosen yet is written `<type>` / `<tag>` so the gap
 * shows; no family is left out (a generic diagnose), so no underscore is
 * doubled. */
void kofeditor_tag_prefix(const struct kof_editor *e, uint8_t utype,
		       const char *tag, char *out, size_t cap)
{
	size_t n = 0;

	if (utype)
		n = name_word(out, cap, n, kof_maltype_name((uint32_t)utype - 1u));
	else
		n = (size_t)snprintf(out, cap, "<type>");
	if (e->dr.family[0]) {
		if (n && n + 1u < cap)
			out[n++] = '_';
		n = name_word(out, cap, n, e->dr.family);
	}
	if (n && n + 1u < cap)
		out[n++] = '_';
	if (tag[0])
		n = name_word(out, cap, n, tag);
	else
		n += (size_t)snprintf(out + n, n < cap ? cap - n : 0u, "<tag>");
	out[n < cap ? n : cap - 1u] = 0;
}

/*
 * THE DIAGNOSE UNITS, the one list, and the rule is two lines: a PATTERNS CONDITION is a unit, and a
 * BLOCKS MATCHER is a unit; nothing else is (a string matcher is part of the conditions that name it,
 * the Graphs tab writes nothing). The draw, the hit zones of the Type and Tag cells,
 * the file names, the preview and the writer all ask this list, so they cannot disagree about which
 * units exist. Order = the output's: the conditions first, then the block matchers.
 */
_Static_assert(DRAFT_UNIT_MAX == 2u * MAX_GROUP, "a draft holds MAX_GROUP conditions and MAX_GROUP matchers");

uint32_t draft_units(const struct kof_editor *e, struct draft_unit *out, uint32_t cap)
{
	uint32_t i, n = 0;

	for (i = 0; i < e->dr.n_cnd && n < cap; i++) {
		const struct cond *c = &e->dr.cnd[i];

		out[n].is_grp = 0;
		out[n].idx = i;
		out[n].utype = c->utype;
		out[n].tag = c->tag;
		n++;
	}
	for (i = 0; i < e->dr.n_grp && n < cap; i++) {
		const struct group *q = &e->dr.grp[i];

		if (q->kind != GRP_KIND_SIM)
			continue;
		out[n].is_grp = 1;
		out[n].idx = i;
		out[n].utype = q->utype;
		out[n].tag = q->tag;
		n++;
	}
	return n;
}

/* How many units the draft has: what Generate has to write. */
uint32_t draft_unit_count(const struct kof_editor *e)
{
	struct draft_unit u[DRAFT_UNIT_MAX];

	return draft_units(e, u, DRAFT_UNIT_MAX);
}

/* The units the open tab lists: Patterns its conditions, Blocks its matchers, Graphs none. */
uint32_t draft_units_on_tab(const struct kof_editor *e, uint8_t tab, struct draft_unit *out, uint32_t cap)
{
	struct draft_unit all[DRAFT_UNIT_MAX];
	uint32_t i, n = 0, m = draft_units(e, all, DRAFT_UNIT_MAX);

	if (tab != DT_PATTERNS && tab != DT_BLOCKS)
		return 0;
	for (i = 0; i < m && n < cap; i++)
		if (all[i].is_grp == (tab == DT_BLOCKS))
			out[n++] = all[i];
	return n;
}

/* Where unit (is_grp, idx) is in the output order, or -1 when it is no unit: its cells are not drawn and its name is empty. */
int draft_unit_find(const struct kof_editor *e, int is_grp, uint32_t idx)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	uint32_t i, n = draft_units(e, u, DRAFT_UNIT_MAX);

	for (i = 0; i < n; i++)
		if (!u[i].is_grp == !is_grp && u[i].idx == idx)
			return (int)i;
	return -1;
}

/* The first `<prefix>_NN.c` (NN 01 to 99) that is not a file of `dir` and not the name of a unit before `k` in `u`; 0 when none is free.
 * THE ONE PLACE A NEW NAME IS NUMBERED: the panel shows it and Save writes it, so they cannot differ. */
uint32_t kofeditor_unit_free_number(const char *dir, const char *prefix, const struct kofeditor_unit_out *u, uint32_t k)
{
	uint32_t nn, j;

	for (nn = 1; nn <= 99u; nn++) {
		char fn[200], path[4400];
		int taken = 0;

		snprintf(fn, sizeof fn, "%s_%02u.c", prefix, nn);
		snprintf(path, sizeof path, "%s/%s", dir, fn);
		for (j = 0; j < k; j++)
			taken |= !strcmp(u[j].fn, fn);
		if (!taken && access(path, F_OK) != 0)
			return nn;
	}
	return 0;
}

/* The name of unit k: the file of the diagnose it carries the id of, else the first free number (see kofeditor_unit_free_number). `u[0..k)` hold the
 * names of the units before it. A number is never derived from where the unit sits in the draft. */
void kofeditor_unit_name_in(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct kofeditor_unit_out *u)
{
	uint32_t lid = ul[k].is_grp ? e->dr.grp[ul[k].idx].link : e->dr.cnd[ul[k].idx].link;
	int li = kofeditor_loaded_find(e, lid);
	char prefix[160];
	uint32_t nn;

	if (li >= 0) {
		snprintf(u[k].fn, sizeof u[k].fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, e->dr.loaded[li].name);
		return;
	}
	kofeditor_tag_prefix(e, ul[k].utype, ul[k].tag, prefix, sizeof prefix);
	nn = kofeditor_unit_free_number(dir, prefix, u, k);
	if (nn)
		snprintf(u[k].fn, sizeof u[k].fn, "%s_%02u.c", prefix, nn);
	else
		snprintf(u[k].fn, sizeof u[k].fn, "%s_--.c", prefix);
}

/* The file name of unit `k` of the list, as Save will write it into the tree's diagnoses directory (kof_draft.tree_dir). */
static void unit_name(const struct kof_editor *e, const struct draft_unit *u, uint32_t k, char *out, size_t cap)
{
	struct kofeditor_unit_out tmp[DRAFT_UNIT_MAX];
	uint32_t j;

	memset(tmp, 0, sizeof tmp);
	for (j = 0; j <= k && j < DRAFT_UNIT_MAX; j++)
		kofeditor_unit_name_in(e, e->dr.tree_dir, u, j, tmp);
	snprintf(out, cap, "%s", tmp[k].fn);
}

void draft_set_tree_dir(struct kof_editor *e, const char *dir)
{
	snprintf(e->dr.tree_dir, sizeof e->dr.tree_dir, "%s", dir ? dir : "");
}

void draft_unit_name(const struct kof_editor *e, int is_grp, uint32_t idx, char *out, size_t cap)
{
	struct draft_unit u[DRAFT_UNIT_MAX];
	int k;

	if (!out || !cap)
		return;
	out[0] = 0;
	draft_units(e, u, DRAFT_UNIT_MAX);
	k = draft_unit_find(e, is_grp, idx);
	if (k >= 0)
		unit_name(e, u, (uint32_t)k, out, cap);
}

void cnd_file_name(const struct kof_editor *e, uint32_t ci, char *out, size_t cap)
{
	draft_unit_name(e, 0, ci, out, cap);
}

void grp_file_name(const struct kof_editor *e, uint32_t g, char *out, size_t cap)
{
	draft_unit_name(e, 1, g, out, cap);
}

/* ---- THE GENERATOR'S OUTPUT: one diagnose source per unit ---------------------- */

/* The variant's LETTERS out of the header's catalog name "<family>_<letters>" ("Mirai_A" -> "A"), or NULL
 * when the name does not start with the family: the source names the family once, so only letters follow. */
static const char *variant_letters(const struct kof_editor *e)
{
	size_t n = strlen(e->dr.family);

	if (!n || strncmp(e->dr.variant, e->dr.family, n) || e->dr.variant[n] != '_')
		return NULL;
	return e->dr.variant + n + 1u;
}

/*
 * THE DECLARATIONS OF ONE UNIT, as diagsrc items: its name (the file's stem), the header's format
 * and subtype options (the declarations the panel has always had that a diagnose source can say),
 * and the four catalog lines - family and variant from the header, type and tag from the unit.
 * ONE function builds the list, for the file that is written and for the preview that lists it, and
 * the text of every line is the shared printer's (kof_dsrc_print): this file has no string code of
 * its own for a declaration.
 *
 * A gap (no family, no variant, no type, no tag) is simply not in the list; the caller that writes
 * refuses before it gets here (kofeditor_draft_unit_gap), the preview shows what is missing.
 */
void draft_unit_items(const struct kof_editor *e, const char *stem, uint8_t utype,
		      const char *tag, struct kof_dsrc *d)
{
	struct kof_dsrc_item *it;
	uint32_t f;

	memset(d, 0, sizeof *d);
	it = &d->item[d->n++];
	it->kind = KDS_NAME;
	snprintf(it->s1, sizeof it->s1, "%s", stem);
	if (e->dr.fmt_mask) {
		char words[KOF_DSRC_WORDS_LEN] = "";
		size_t at = 0;
		uint64_t val = 0;

		for (f = 0; f < KOF_FMT_COUNT; f++) {
			const char *id = kof_format_ident((uint8_t)f);

			if (!(e->dr.fmt_mask & (1u << f)) || !id)
				continue;
			if (at + strlen(id) + 4u >= sizeof words)
				break;
			at += (size_t)snprintf(words + at, sizeof words - at, "%s%s", at ? " | " : "", id);
			val |= (uint64_t)f;
		}
		it = &d->item[d->n++];
		it->kind = KDS_FORMAT;
		it->v = val;
		snprintf(it->s1, sizeof it->s1, "%s", words);
	}
	if (e->dr.opt_on[OPT_SUBTYPE]) {
		it = &d->item[d->n++];
		it->kind = KDS_SUBTYPE;
		it->v = e->dr.opt_val[OPT_SUBTYPE];
	}
	/* The two options a signature declared as targets (KOF_TARGET_SIZE_MIN, KOF_TARGET_ARCH) are conditions of the diagnose: the
	 * engine's facts for them (KOF_FACT_SIZE_MIN, KOF_FACT_ARCH_SET), written as KOF_DIAG_HAS_ATTRB lines. */
	if (e->dr.opt_on[OPT_SIZE_MIN]) {
		it = &d->item[d->n++];
		it->kind = KDS_ATTRB;
		it->a = (uint16_t)KOF_FACT_SIZE_MIN;
		it->v = e->dr.opt_val[OPT_SIZE_MIN];
	}
	if (e->dr.opt_on[OPT_ARCH] && e->dr.opt_val[OPT_ARCH] < 64u) {
		it = &d->item[d->n++];
		it->kind = KDS_ATTRB;
		it->a = (uint16_t)KOF_FACT_ARCH_SET;
		it->v = (uint64_t)1 << e->dr.opt_val[OPT_ARCH];
	}
	if (e->dr.family[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_FAMILY;
		snprintf(it->s1, sizeof it->s1, "%s", e->dr.family);
	}
	if (e->dr.variant[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_VARIANT;
		snprintf(it->s1, sizeof it->s1, "%s", variant_letters(e) ? variant_letters(e) : e->dr.variant);
	}
	if (utype) {
		it = &d->item[d->n++];
		it->kind = KDS_TYPE;
		it->a = (uint16_t)(utype - 1u);
	}
	if (tag[0]) {
		it = &d->item[d->n++];
		it->kind = KDS_TAG;
		snprintf(it->s1, sizeof it->s1, "%s", tag);
	}
}

/* Why a unit cannot be written, or NULL: the header and the unit must both say what the file is about. */
const char *kofeditor_draft_unit_gap(const struct kof_editor *e, uint8_t utype, const char *tag)
{
	/* What a diagnose has no condition for is refused, not dropped: the file would say less than the panel does. */
	if (e->dr.opt_on[OPT_SIZE_MAX])
		return "the header sets a maximum size, which a diagnose has no condition for (the engine has none by design)";
	if (e->dr.opt_on[OPT_ARCH] && e->dr.opt_val[OPT_ARCH] >= 64u)
		return "the header names an architecture past the 64 a set of them holds";
	if (!e->dr.family[0])
		return "the header has no family";
	if (!e->dr.variant[0])
		return "the header has no variant";
	if (!utype)
		return "it has no type";
	if (!tag[0])
		return "it has no tag";
	if (!variant_letters(e) || !kof_dsrc_variant_word_ok(variant_letters(e)))
		return "the variant's name is not \"<family>_<letters>\"";
	if (!kof_dsrc_catalog_word_ok(e->dr.family) || !kof_dsrc_catalog_word_ok(tag))
		return "a name has a character a diagnose source cannot hold";
	return NULL;
}
