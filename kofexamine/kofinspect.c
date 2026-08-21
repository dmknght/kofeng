/*
 * kofinspect.c - see kofinspect.h.
 *
 * WHY THIS RUNS THE MATCHER RATHER THAN READING A SCAN RESULT
 *
 * A scan is lazy on purpose: a module asks for a marker and the host answers,
 * memoised, so the only markers ever searched for are the ones some module's
 * logic reached. That is the right economics for scanning and the wrong shape
 * for this - the markers of a module whose first condition failed were never
 * looked for at all, and those are exactly the ones being asked about here.
 *
 * So this drives the matcher directly, over every marker the database declares.
 * It is affordable for the same reason the scan path is: the presence set answers
 * most markers with one hash of four bytes and never touches the object.
 *
 * kof_match_where rather than kof_match_lookup, and not for the offset alone.
 * lookup is memoised by (pattern, region) slot and returns "absent" outright when
 * no memo is attached - correct for the scan path that always attaches one, and a
 * silent wrong answer here. The ad-hoc entry points have no such dependency.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "kofinspect.h"
#include "../libkofeng/kofmatchers/kofmatch.h"
#include "../libkofeng/kofscanners/scan.h"

/*
 * The parsers, by their internal headers.
 *
 * Same reach kofexamine's own comment defends and for the same reason: there is
 * no public "parse this and hand me the view" surface, because no host has ever
 * wanted one. What changed is that there are now two consumers of it in this
 * tree rather than one, so the reach lives here once instead of in each.
 */
#include "../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../libkofeng/kofparsers/containers/docole_parse.h"
#include "../libkofeng/kofparsers/containers/zip_parse.h"
#include "../libkofeng/kofparsers/containers/tar_parse.h"
#include "../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../libkofeng/kofparsers/containers/rar_parse.h"
#include "../libkofeng/kofparsers/containers/xz_parse.h"
#include "../libkofeng/kofparsers/containers/rtf_parse.h"
#include "../libkofeng/kofparsers/containers/pdf_parse.h"

/* ---- the formats, and how to get a view of one ---------------------------- */

static int elf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_elf_parse(b, (struct kof_elf_info *)v, c);
}

static int gzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_gzip_parse(b, (struct kof_gzip_info *)v, c);
}

static int docole_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_docole_parse(b, (struct kof_docole_info *)v, c);
}

static int zip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_zip_parse(b, (struct kof_zip_info *)v, c);
}

static int tar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_tar_parse(b, (struct kof_tar_info *)v, c);
}

static int rtf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rtf_parse(b, (struct kof_rtf_info *)v, c);
}

static int xz_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_xz_parse(b, (struct kof_xz_info *)v, c);
}

static int rar_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_rar_parse(b, (struct kof_rar_info *)v, c);
}

static int sevenzip_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_7z_parse(b, (struct kof_7z_info *)v, c);
}

static int pe_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pe_parse(b, (struct kof_pe_info *)v, c);
}

static int pdf_parse_thunk(kof_buf b, void *v, struct kof_obj_ctx *c)
{
	return kof_pdf_parse(b, (struct kof_pdf_info *)v, c);
}

static uint64_t anom_elf(const void *v)
{
	return ((const struct kof_elf_info *)v)->anomalies;
}

static uint64_t anom_pe(const void *v)
{
	return ((const struct kof_pe_info *)v)->anomalies;
}

static uint64_t anom_gzip(const void *v)
{
	return ((const struct kof_gzip_info *)v)->anomalies;
}

static uint64_t anom_docole(const void *v)
{
	return ((const struct kof_docole_info *)v)->anomalies;
}

static uint64_t anom_zip(const void *v)
{
	return ((const struct kof_zip_info *)v)->anomalies;
}

static uint64_t anom_tar(const void *v)
{
	return ((const struct kof_tar_info *)v)->anomalies;
}

static uint64_t anom_7z(const void *v)
{
	return ((const struct kof_7z_info *)v)->anomalies;
}

static uint64_t anom_rar(const void *v)
{
	return ((const struct kof_rar_info *)v)->anomalies;
}

static uint64_t anom_xz(const void *v)
{
	return ((const struct kof_xz_info *)v)->anomalies;
}

static uint64_t anom_pdf(const void *v)
{
	return ((const struct kof_pdf_info *)v)->anomalies;
}

static uint64_t anom_rtf(const void *v)
{
	return ((const struct kof_rtf_info *)v)->anomalies;
}

const char *kof_inspect_subtype_name(uint8_t fmt, uint8_t sub)
{
	if (fmt == KOF_FMT_ELF)
		switch (sub) {
		case KOF_ELF_NONE: return "ET_NONE";
		case KOF_ELF_REL:  return "ET_REL";
		case KOF_ELF_EXEC: return "ET_EXEC";
		case KOF_ELF_DYN:  return "ET_DYN";
		case KOF_ELF_CORE: return "ET_CORE";
		default:           return "ET_?";
		}
	if (fmt == KOF_FMT_PE)
		switch (sub) {
		case KOF_PE_EXE: return "EXE";
		case KOF_PE_DLL: return "DLL";
		case KOF_PE_SYS: return "SYS";
		default:         return "?";
		}
	return 0;
}

static const struct kof_inspect_fmt formats[] = {
	{ (uint32_t)sizeof(struct kof_elf_info), kof_elf_sniff, elf_parse_thunk,
	  kof_elf_region_bits, KOF_ELF_REGION_COUNT,
	  kof_elf_region_name, kof_elf_anomaly_name, anom_elf },
	{ (uint32_t)sizeof(struct kof_pe_info), kof_pe_sniff, pe_parse_thunk,
	  kof_pe_region_bits, KOF_PE_REGION_COUNT,
	  kof_pe_region_name, kof_pe_anomaly_name, anom_pe },
	{ (uint32_t)sizeof(struct kof_gzip_info), kof_gzip_sniff, gzip_parse_thunk,
	  kof_gzip_region_bits, KOF_GZIP_REGION_COUNT,
	  kof_gzip_region_name, kof_gzip_anomaly_name, anom_gzip },
	{ (uint32_t)sizeof(struct kof_docole_info), kof_docole_sniff,
	  docole_parse_thunk, kof_docole_region_bits, KOF_DOCOLE_REGION_COUNT,
	  kof_docole_region_name, kof_docole_anomaly_name, anom_docole },
	{ (uint32_t)sizeof(struct kof_zip_info), kof_zip_sniff, zip_parse_thunk,
	  kof_zip_region_bits, KOF_ZIP_REGION_COUNT,
	  kof_zip_region_name, kof_zip_anomaly_name, anom_zip },
	{ (uint32_t)sizeof(struct kof_tar_info), kof_tar_sniff, tar_parse_thunk,
	  kof_tar_region_bits, KOF_TAR_REGION_COUNT,
	  kof_tar_region_name, kof_tar_anomaly_name, anom_tar },
	{ (uint32_t)sizeof(struct kof_7z_info), kof_7z_sniff, sevenzip_parse_thunk,
	  kof_7z_region_bits, KOF_7Z_REGION_COUNT,
	  kof_7z_region_name, kof_7z_anomaly_name, anom_7z },
	{ (uint32_t)sizeof(struct kof_rar_info), kof_rar_sniff, rar_parse_thunk,
	  kof_rar_region_bits, KOF_RAR_REGION_COUNT,
	  kof_rar_region_name, kof_rar_anomaly_name, anom_rar },
	{ (uint32_t)sizeof(struct kof_xz_info), kof_xz_sniff, xz_parse_thunk,
	  kof_xz_region_bits, KOF_XZ_REGION_COUNT,
	  kof_xz_region_name, kof_xz_anomaly_name, anom_xz },
	{ (uint32_t)sizeof(struct kof_rtf_info), kof_rtf_sniff, rtf_parse_thunk,
	  kof_rtf_region_bits, KOF_RTF_REGION_COUNT,
	  kof_rtf_region_name, kof_rtf_anomaly_name, anom_rtf },
	{ (uint32_t)sizeof(struct kof_pdf_info), kof_pdf_sniff, pdf_parse_thunk,
	  kof_pdf_region_bits, KOF_PDF_REGION_COUNT,
	  kof_pdf_region_name, kof_pdf_anomaly_name, anom_pdf }
};


/*
 * Identify the object and parse it.
 *
 * The first format whose sniff claims the bytes wins and no other is tried: a
 * sniff that claims something is a claim, and asking a second parser what it
 * thinks of an object the first recognised is how a tool ends up with two
 * answers and a rule for picking between them.
 *
 * The view is the caller's to free. It is a plain malloc of the format's own
 * info struct - there is nothing to tear down - so free() is the whole of the
 * release and no kof_inspect_release exists to wrap it.
 */
const struct kof_inspect_fmt *kof_inspect_identify(kof_buf buf,
						   struct kof_obj_ctx *ctx,
						   void **view_out)
{
	uint32_t i;

	*view_out = NULL;
	memset(ctx, 0, sizeof *ctx);

	for (i = 0; i < sizeof formats / sizeof formats[0]; i++) {
		void *view;

		if (!formats[i].sniff(buf))
			continue;
		view = malloc(formats[i].view_size);
		if (view && formats[i].parse(buf, view, ctx)) {
			*view_out = view;
			return &formats[i];
		}
		free(view);
		return NULL;
	}
	return NULL;
}



const char *kof_touch_kind_name(enum kof_touch_kind k)
{
	switch (k) {
	/* Not "every marker": the count beside it already says how many of how
	 * many, so the word would be the same fact twice and the two would have
	 * to agree. The kinds only have to name what a count cannot. */
	case KOF_TOUCH_COMPLETE:   return "markers";
	case KOF_TOUCH_PARTIAL:    return "some markers";
	case KOF_TOUCH_ELSEWHERE:  return "wrong region";
	case KOF_TOUCH_INELIGIBLE: return "did not run";
	}
	return "?";
}

/*
 * The preconditions, in the order the scan path applies them.
 *
 * Mirrored from kof_scan rather than reasoned out again: a module is ruled out
 * here exactly when it would have been ruled out there, or the "did not run"
 * answer is a guess about the engine rather than a report of it.
 */
static const char *ruled_out_by(const struct kof_module *m,
				const struct kof_obj_ctx *ctx, uint64_t size)
{
	if (!(m->target_mask & (1u << ctx->format)))
		return "targets another format";
	if (size < m->size_min)
		return "object is below its minimum size";
	if (m->arch_mask &&
	    (ctx->arch >= 32 || !(m->arch_mask & (1u << ctx->arch))))
		return "targets another architecture";
	if (m->subtype_mask &&
	    (ctx->subtype >= 32 || !(m->subtype_mask & (1u << ctx->subtype))))
		return "targets another kind of this format";
	return NULL;
}

/*
 * Where is this marker, searching the extents given?
 *
 * The first hit and not all of them: a viewer scrolls to one place, and a marker
 * that occurs forty times is not forty findings. KOF_BROKEN when it is in none of
 * them, which is the value the rest of this engine uses for "applies, but not
 * determined" and reads correctly as absent here.
 */
static uint64_t where_in(struct kof_match_ctx *m, const struct kof_range *ext,
			 uint32_t n_ext, const struct kof_touch_str *s)
{
	uint32_t i;

	for (i = 0; i < n_ext; i++) {
		uint64_t at = kof_match_where(m, ext[i].off, ext[i].len,
					      s->bytes, s->len, s->kind,
					      s->flags);
		if (at != KOF_BROKEN)
			return at;
	}
	return KOF_BROKEN;
}

/* Most interesting first; within a kind, the one with more markers present. */
static int cmp_touch(const void *a, const void *b)
{
	const struct kof_touch *x = a, *y = b;

	if (x->kind != y->kind)
		return (int)x->kind - (int)y->kind;
	if (x->n_in_rgn != y->n_in_rgn)
		return x->n_in_rgn < y->n_in_rgn ? 1 : -1;
	if (x->n_present != y->n_present)
		return x->n_present < y->n_present ? 1 : -1;
	return 0;
}

int kof_touch_object(struct kof_engine *eng, kof_buf buf,
		     const struct kof_obj_ctx *ctx,
		     struct kof_touch **out, uint32_t *n_out)
{
	struct kof_match_ctx m;
	struct kof_range *whole = NULL, *named = NULL;
	struct kof_touch *v = NULL;
	uint32_t n = 0, i, j, n_whole = 0;
	int ok = 0;

	*out = NULL;
	*n_out = 0;
	if (!eng || !eng->n_mods)
		return 1;

	/*
	 * A memo is deliberately not attached - see the note at the top - but the
	 * presence set is, because it is what makes asking about every marker in the
	 * database affordable rather than merely possible.
	 */
	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, eng->n_str, 0))
		return 0;
	kof_match_begin(&m, buf);

	whole = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *whole);
	named = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *named);
	v     = calloc(eng->n_mods, sizeof *v);
	if (!whole || !named || !v)
		goto out;

	/* The object entire, which is what "is this marker here at all" means. One
	 * extent in practice; resolved rather than assumed because KOF_SCAN_ALL is
	 * the host's answer and this should not have a second one. */
	n_whole = kof_scan_resolve_range(ctx, KOF_SCAN_ALL, whole);
	if (n_whole == 0 && buf.n) {
		/*
		 * Nothing identified the object, so the parse never set obj_size
		 * and the host's answer for KOF_SCAN_ALL is empty. The buffer is
		 * still the object, and an unrecognised blob full of a family's
		 * markers is one of the few things worth being told about - a
		 * memory dump, a carved payload, a stub nothing parses yet.
		 */
		whole[0].off = 0;
		whole[0].len = buf.n;
		n_whole = 1;
	}

	for (i = 0; i < eng->n_mods; i++) {
		const struct kof_module *mod = &eng->mods[i];
		struct kof_touch *t = &v[n];
		uint32_t n_named = 0;
		const char *why;

		memset(t, 0, sizeof *t);
		t->mod     = mod;
		t->maltype = mod->maltype;
		t->family  = kof_db_family(eng, mod);
		if (!t->family)
			t->family = "";
		t->n_str   = mod->n_str;

		if (mod->n_names) {
			t->name = calloc(mod->n_names, sizeof *t->name);
			t->name_id = calloc(mod->n_names, sizeof *t->name_id);
			if (!t->name || !t->name_id)
				goto out;
			for (j = 0; j < mod->n_names; j++)
				t->name[j] = kof_db_name_at(eng, mod, j,
							    &t->name_id[j]);
			t->n_names = mod->n_names;
		}

		why = ruled_out_by(mod, ctx, buf.n);

		/*
		 * A module ruled out still gets its markers looked for, because
		 * "all five of its markers are here and it targets the wrong
		 * format" is a real thing to see - a family ported, or a sample
		 * mis-identified. What it does not get is a region resolve: its
		 * regions belong to a format this object is not.
		 */
		if (!why)
			n_named = kof_scan_resolve_range(ctx, mod->scan_mask,
							 named);

		if (mod->n_str) {
			t->str = calloc(mod->n_str, sizeof *t->str);
			if (!t->str)
				goto out;
		}

		for (j = 0; j < mod->n_str; j++) {
			const struct kof_str_ent *e;
			struct kof_touch_str *s = &t->str[j];
			const uint8_t *bytes = NULL;

			e = kof_db_str(eng, mod, j, &bytes);
			if (!e || !bytes) {
				s->at = KOF_BROKEN;
				continue;
			}
			s->bytes = bytes;
			s->len   = e->len;
			s->kind  = e->kind;
			s->flags = e->flags;
			s->uid   = eng->packs[mod->pack_id].uid_base + e->uid;

			s->at = where_in(&m, whole, n_whole, s);
			if (s->at != KOF_BROKEN)
				t->n_present++;

			if (n_named && where_in(&m, named, n_named, s) !=
					KOF_BROKEN) {
				s->in_rgn = 1;
				t->n_in_rgn++;
			}
		}

		/* Not evidence, and at database scale it would be the whole list. */
		if (t->n_present == 0) {
			free(t->str);
			free((void *)t->name);
			free(t->name_id);
			t->str = NULL;
			t->name = NULL;
			t->name_id = NULL;
			continue;
		}

		if (why) {
			t->kind = KOF_TOUCH_INELIGIBLE;
			t->ruled_out = why;
		} else if (t->n_in_rgn == 0) {
			t->kind = KOF_TOUCH_ELSEWHERE;
		} else if (t->n_in_rgn == t->n_str) {
			t->kind = KOF_TOUCH_COMPLETE;
		} else {
			t->kind = KOF_TOUCH_PARTIAL;
		}
		n++;
	}

	if (n > 1)
		qsort(v, n, sizeof *v, cmp_touch);
	*out = v;
	*n_out = n;
	v = NULL;
	ok = 1;

out:
	if (v)
		kof_touch_free(v, eng->n_mods);
	free(whole);
	free(named);
	kof_match_state_free(&m);
	return ok;
}

void kof_touch_free(struct kof_touch *v, uint32_t n)
{
	uint32_t i;

	if (!v)
		return;
	for (i = 0; i < n; i++) {
		free(v[i].str);
		free((void *)v[i].name);
		free(v[i].name_id);
	}
	free(v);
}
