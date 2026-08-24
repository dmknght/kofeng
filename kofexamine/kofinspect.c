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

#include <stdio.h>
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

/*
 * The names of an ELF's program and section header types.
 *
 * Here rather than in a front end because both front ends need them and neither
 * owns them: they are the file format's vocabulary, the same way the subtype
 * names below are. NULL for a value with no name, so the caller can print the
 * number instead and say something true rather than nothing.
 */
const char *kof_inspect_ptype_name(uint32_t t)
{
	switch (t) {
	case 0:          return "PT_NULL";
	case 1:          return "PT_LOAD";
	case 2:          return "PT_DYNAMIC";
	case 3:          return "PT_INTERP";
	case 4:          return "PT_NOTE";
	case 5:          return "PT_SHLIB";
	case 6:          return "PT_PHDR";
	case 7:          return "PT_TLS";
	case 0x6474e550: return "PT_GNU_EH_FRAME";
	case 0x6474e551: return "PT_GNU_STACK";
	case 0x6474e552: return "PT_GNU_RELRO";
	case 0x6474e553: return "PT_GNU_PROPERTY";
	case 0x65a3dbe6: return "PT_OPENBSD_RANDOMIZE";
	default:         return NULL;
	}
}

const char *kof_inspect_shtype_name(uint32_t t)
{
	switch (t) {
	case 0:          return "SHT_NULL";
	case 1:          return "SHT_PROGBITS";
	case 2:          return "SHT_SYMTAB";
	case 3:          return "SHT_STRTAB";
	case 4:          return "SHT_RELA";
	case 5:          return "SHT_HASH";
	case 6:          return "SHT_DYNAMIC";
	case 7:          return "SHT_NOTE";
	case 8:          return "SHT_NOBITS";
	case 9:          return "SHT_REL";
	case 10:         return "SHT_SHLIB";
	case 11:         return "SHT_DYNSYM";
	case 14:         return "SHT_INIT_ARRAY";
	case 15:         return "SHT_FINI_ARRAY";
	case 16:         return "SHT_PREINIT_ARRAY";
	case 17:         return "SHT_GROUP";
	case 18:         return "SHT_SYMTAB_SHNDX";
	case 0x6ffffff6: return "SHT_GNU_HASH";
	case 0x6ffffffd: return "SHT_GNU_VERDEF";
	case 0x6ffffffe: return "SHT_GNU_VERNEED";
	case 0x6fffffff: return "SHT_GNU_VERSYM";
	default:         return NULL;
	}
}

/* ---- reading a compiled hex pattern back ---------------------------------- */

/* Little endian by hand: the program is written that way whatever the host is,
 * which is the point of a pack being portable. */
static uint32_t hx_u32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t hx_u16(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

/* Every offset in a program is from its own start, and every one of them came
 * out of a file, so each is checked against the length the caller vouches for
 * rather than against the program's own claim about itself. */
static int hx_ok(uint32_t n, uint32_t off, uint32_t need)
{
	return off <= n && need <= n - off;
}

/* Does any gap in this program run without an upper bound. */
static int hx_open(const uint8_t *prog, uint32_t n)
{
	uint32_t n_steps = hx_u16(prog + 0);
	uint32_t steps_off = hx_u32(prog + 32), s;

	if (!hx_ok(n, steps_off, n_steps * 8u))
		return 0;
	for (s = 0; s < n_steps; s++)
		if (hx_u16(prog + steps_off + s * 8u + 2) >= KOF_HEX_GAP_OPEN)
			return 1;
	return 0;
}

void kof_inspect_hex_span(const uint8_t *prog, uint32_t n, char *out,
			  uint32_t cap)
{
	uint32_t lo, hi;

	if (!out || cap == 0)
		return;
	out[0] = 0;
	if (!prog || n < 48u)
		return;
	lo = hx_u32(prog + 4);
	hi = hx_u32(prog + 8);
	/*
	 * An open gap makes max_span a sum that includes a sentinel, so the
	 * only true thing left to say is the floor.
	 */
	if (hx_open(prog, n))
		snprintf(out, cap, "%u+", lo);
	else if (lo != hi)
		snprintf(out, cap, "%u-%u", lo, hi);
	else
		snprintf(out, cap, "%u", lo);
}

static void hx_put(char *out, uint32_t cap, uint32_t *at, const char *s)
{
	while (*s && *at + 1u < cap)
		out[(*at)++] = *s++;
	out[*at] = 0;
}

uint32_t kof_inspect_hex_text(const uint8_t *prog, uint32_t n,
			      char *out, uint32_t cap)
{
	static const char dig[] = "0123456789ABCDEF";
	uint32_t n_steps, steps_off, at = 0, s;

	if (!out || cap == 0)
		return 0;
	out[0] = 0;
	if (!prog || n < 48u)
		return 0;
	n_steps   = hx_u16(prog + 0);
	steps_off = hx_u32(prog + 32);
	if (!hx_ok(n, steps_off, n_steps * 8u))
		return 0;

	for (s = 0; s < n_steps && at + 1u < cap; s++) {
		const uint8_t *st = prog + steps_off + s * 8u;
		uint32_t gap_min = hx_u16(st + 0), gap_max = hx_u16(st + 2);
		uint32_t alt_first = hx_u16(st + 4), n_alts = hx_u16(st + 6);
		uint32_t alts_off = hx_u32(prog + 36);
		uint32_t a;

		/*
		 * The gap before this step, in the same brackets the pattern
		 * was written with - and the same ones kofexamine already
		 * prints, so one pattern reads the same in both tools.
		 *
		 * The open forms matter most: gap_max carries KOF_HEX_GAP_OPEN
		 * as a sentinel for "no limit", and printing it as a number
		 * says 256 where the pattern says "however far it takes".
		 */
		if (gap_max) {
			char t[32];

			if (!gap_min && gap_max >= KOF_HEX_GAP_OPEN)
				snprintf(t, sizeof t, "[-]");
			else if (gap_max >= KOF_HEX_GAP_OPEN)
				snprintf(t, sizeof t, "[%u-]", gap_min);
			else if (gap_min == gap_max)
				snprintf(t, sizeof t, "[%u]", gap_min);
			else
				snprintf(t, sizeof t, "[%u-%u]", gap_min,
					 gap_max);
			hx_put(out, cap, &at, t);
		}
		if (!hx_ok(n, alts_off, (alt_first + n_alts) * 8u))
			return at;
		if (n_alts > 1u)
			hx_put(out, cap, &at, "(");
		for (a = 0; a < n_alts && at + 1u < cap; a++) {
			const uint8_t *al = prog + alts_off + (alt_first + a) * 8u;
			uint32_t len = hx_u16(al + 0), flags = hx_u16(al + 2);
			uint32_t doff = hx_u32(al + 4), b;
			int masked = (flags & 1u) != 0;

			if (a)
				hx_put(out, cap, &at, "|");
			if (!hx_ok(n, doff, masked ? len * 2u : len))
				return at;
			for (b = 0; b < len && at + 2u < cap; b++) {
				uint8_t byte = prog[doff + b];
				uint8_t mask = masked ? prog[doff + len + b]
						      : 0xffu;
				char t[3];

				/* A nibble the mask does not cover is a
				 * wildcard, and saying so per nibble is the
				 * only faithful rendering of a half masked
				 * byte. */
				t[0] = (mask & 0xf0u) ? dig[(byte >> 4) & 15]
						      : '?';
				t[1] = (mask & 0x0fu) ? dig[byte & 15] : '?';
				t[2] = 0;
				hx_put(out, cap, &at, t);
			}
		}
		if (n_alts > 1u)
			hx_put(out, cap, &at, ")");
	}
	return at;
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
	/* One word for both, because the count beside it already says how many
	 * of how many. "some markers (3/10)" spends a word saying what "(3/10)"
	 * has just said, and the two would then have to agree. The kinds only
	 * have to name what a count cannot. */
	case KOF_TOUCH_COMPLETE:
	case KOF_TOUCH_PARTIAL:    return "markers";
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

	if (x->fired != y->fired)
		return y->fired - x->fired;
	if (x->kind != y->kind)
		return (int)x->kind - (int)y->kind;
	if (x->n_in_rgn != y->n_in_rgn)
		return x->n_in_rgn < y->n_in_rgn ? 1 : -1;
	if (x->n_present != y->n_present)
		return x->n_present < y->n_present ? 1 : -1;
	return 0;
}

/*
 * Did a scan report this module, and under which of its names.
 *
 * Matched on the composed name because struct kof_finding carries a name and no
 * module id. The target prefix is the engine's and not the module's to claim,
 * so the comparison starts after it.
 */
static const char *fired_as(const struct kof_touch *t,
			    const char *const *finding, uint32_t n_finding)
{
	uint32_t j, k;

	for (j = 0; j < t->n_names; j++) {
		char want[224];

		if (!t->name[j])
			continue;
		snprintf(want, sizeof want, "%s:%s-%s",
			 kof_maltype_name(t->maltype), t->family, t->name[j]);
		for (k = 0; k < n_finding; k++) {
			const char *p = strchr(finding[k], '/');

			if (strcmp(p ? p + 1 : finding[k], want) == 0)
				return t->name[j];
		}
	}
	return NULL;
}

int kof_touch_object(struct kof_engine *eng, kof_buf buf,
		     const struct kof_obj_ctx *ctx,
		     const char *const *finding, uint32_t n_finding,
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

		t->fired_name = fired_as(t, finding, n_finding);
		t->fired = t->fired_name != NULL;

		/*
		 * Nothing present and nothing reported is not evidence, and at
		 * database scale it would be the whole list - most of a database
		 * is modules that have no business with any given object.
		 *
		 * A module that FIRED stays whatever its markers did. A
		 * structural detection declares none at all, and leaving it out
		 * would put a finding on the scanner's output that this pane
		 * silently disagreed with.
		 */
		if (t->n_present == 0 && !t->fired) {
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
		} else if (t->n_str == 0) {
			/* Declares no markers at all - a structural detection,
			 * reading scalars rather than searching. Every one of
			 * its none are in the right place, vacuously; calling
			 * that "wrong region" would be answering a question it
			 * never asked. */
			t->kind = KOF_TOUCH_COMPLETE;
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
