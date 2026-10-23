/*
 * ksb_resolve.c - The one-per-module declarations (format, arch, subtype,
 *    size, step) and what they resolve to.
 */

#include "ksb.h"

#include <ctype.h>
#include <kofmod/elf.h>      /* the ELF region names a range may be built from */
#include <analyzers/parsers/scripts/script_parse.h>
#include <kofmod/pe.h>       /* and the PE ones */
#include <kofmod/amsi.h>   /* an event's two regions */

/*
 * Handle one source line: a macro is found within the line, but its arguments are
 * read from the full buffer, because an invocation may wrap onto the next line.
 * nth_arg treats a newline like any other space, so it spans lines by itself.
 */
/*
 * ---------------------------------------------------------------------------
 * THE DECLARATIONS THE BUILD READS OUT OF A SOURCE.
 *
 * These were read by the shell, with grep and sed, against C source. That was
 * wrong in a way this file is already equipped to avoid: the scan below runs on
 * a buffer kof_dsrc_blank_comments has been over, so a macro NAMED IN A COMMENT is not a
 * declaration. The shell had no such notion and counted it - a signature whose
 * header block explained that it "used to be KOF_TARGET_FORMAT(KOF_FMT_PE)" was
 * refused with "2 KOF_TARGET_FORMAT declarations", which names nothing a reader
 * can act on.
 *
 * It was also learning enum values by matching this project's own headers with
 * a regex. Those values are constants to a C program, and the engine publishes
 * the identifier-to-value direction for every one of them - kof_format_from_name
 * and its siblings - so the vocabulary is inherited rather than re-derived.
 * ---------------------------------------------------------------------------
 */

/*
 * The text between the parentheses, with whitespace squeezed out - except inside
 * a string literal, which is a word the author wrote and "Generic emulation" is
 * two.
 *
 * Nesting is counted rather than stopping at the first ')', so an argument that
 * is itself a call - KOF_TARGET_SIZE_MIN(sizeof(x)) - is read whole instead of
 * being cut in half. The shell's sed pattern stopped at [^)]* and could not.
 */
static int decl_arg(const char *at, char *out, size_t cap)
{
	int depth = 0, in_str = 0;
	size_t n = 0;

	while (*at && *at != '(')
		at++;
	if (!*at)
		return 0;
	for (; *at; at++) {
		/* A parenthesis inside a literal is text, not nesting. */
		if (!in_str) {
			if (*at == '(') {
				depth++;
				if (depth == 1)
					continue;
			} else if (*at == ')') {
				depth--;
				if (!depth)
					break;
			}
		}
		if (depth >= 1 && *at == '"' && at[-1] != '\\')
			in_str = !in_str;
		if (depth >= 1 && (in_str || !isspace((unsigned char)*at))) {
			if (n + 1u >= cap)
				return 0;
			out[n++] = *at;
		}
	}
	out[n] = 0;
	return depth == 0 && n > 0;
}

/* Whether `hay` names `needle` as a whole identifier, so KOF_FMT_ZIP does not
 * answer for a source that said KOF_FMT_DOCZIP. The shell matched substrings
 * and got away with it only because no two names in the enum happen to overlap;
 * the next one added could. */
static int names_ident(const char *hay, const char *needle)
{
	size_t nl = strlen(needle);
	const char *p = hay;

	while ((p = strstr(p, needle)) != NULL) {
		char before = (p == hay) ? 0 : p[-1];
		char after = p[nl];

		if (!isalnum((unsigned char)before) && before != '_' &&
		    !isalnum((unsigned char)after) && after != '_')
			return 1;
		p += nl;
	}
	return 0;
}

void ksb_decl_collect(struct ksb_ctx *ksb, const char *at, int lineno)
{
	int i;

	for (i = 0; i < SD_COUNT * 2; i++) {
		struct simple_decl *d = &ksb->decl.simple[i % SD_COUNT];
		const char *want = (i < SD_COUNT) ? d->name : d->alias;
		const char *p = at;
		size_t nl;

		if (!want)
			continue;
		nl = strlen(want);

		while ((p = strstr(p, want)) != NULL) {
			/* A longer identifier that merely contains this one is
			 * not this declaration. */
			if (p[nl] != '(' ||
			    (p != at && (isalnum((unsigned char)p[-1]) ||
					 p[-1] == '_'))) {
				p += nl;
				continue;
			}
			if (d->count == 0) {
				d->line = lineno;
				if (!decl_arg(p, d->arg, sizeof d->arg))
					d->arg[0] = 0;
			}
			d->count++;
			p += nl;
		}
	}
}

/* Does the resolved list name this target. An empty list that came from
 * KOF_FMT_ANY names everything; an empty list that came from nowhere names
 * nothing, and is refused before this is ever asked. */
int ksb_target_named(struct ksb_ctx *ksb, uint8_t id)
{
	int i;

	if (ksb->decl.any_target)
		return 1;
	for (i = 0; i < ksb->decl.n_targets; i++)
		if (ksb->decl.target[i] == id)
			return 1;
	return 0;
}

/*
 * The resolved target list as text, for the intermediate file: "4,8,9", or
 * empty for a module that named everything.
 *
 * Ids and not a mask, because that is what the list IS now - and a number per
 * target is also what lets .pre stay readable when the axis passes 32, which
 * is the whole point of the change. See n_target in dbloader.h.
 */
void ksb_target_text(struct ksb_ctx *ksb, char *out, size_t cap)
{
	size_t n = 0;
	int i;

	out[0] = 0;
	for (i = 0; i < ksb->decl.n_targets && n + 8u < cap; i++)
		n += (size_t)snprintf(out + n, cap - n, i ? ",%u" : "%u",
				      (unsigned)ksb->decl.target[i]);
}

/* One name at a time out of "A|B|C", which is the only shape these arguments
 * take: the declarations are masks and the language for combining them is '|'. */
static const char *decl_next(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == '|')
		p++;
	if (!*p)
		return NULL;
	while (*p && *p != '|') {
		if (n + 1u < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return p;
}

static void resolve_format(struct ksb_ctx *ksb)
{
	const struct simple_decl *d = &ksb->decl.simple[SD_FORMAT];
	char one[128];
	const char *p = d->arg;

	if (d->count > 1) {
		ksb_err(ksb, d->line, "more than one KOF_TARGET_FORMAT; use one "
				      "declaration with '|'");
		return;
	}
	if (!d->count || !d->arg[0]) {
		ksb_err(ksb, 1, "no KOF_TARGET_FORMAT(...) declaration; a module must "
				"say what it applies to");
		return;
	}
	/*
	 * ANY is every format at once, and the mask is derived from the enum
	 * rather than written down. It was once the literal 127, which stopped
	 * meaning "every format" the moment one was added - and a module that
	 * silently no longer covers a format is a detection that does not
	 * happen, which no test notices.
	 */
	if (names_ident(d->arg, "KOF_FMT_ANY")) {
		/* An EMPTY LIST, which is how the engine spells "any" - so
		 * this no longer has to be derived from the enum at all, and
		 * cannot fall behind it. */
		ksb->decl.n_targets = 0;
		ksb->decl.any_target = 1;
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint8_t fmt;

		if (!kof_format_from_name(one, &fmt)) {
			char msg[192];

			snprintf(msg, sizeof msg,
				 "KOF_TARGET_FORMAT names no known format: %s",
				 one);
			ksb_err(ksb, d->line, msg);
			return;
		}
		if (ksb->decl.n_targets >= (int)KOF_TARGET_LIST_MAX) {
			char msg[192];

			/* Refused rather than truncated: a list cut short is a
			 * rule narrower than its source with nothing printed -
			 * the failure KOF_TARGET_LIST_MAX's note describes. */
			snprintf(msg, sizeof msg,
				 "KOF_TARGET_FORMAT names more than %u formats "
				 "- use KOF_FMT_ANY", (unsigned)KOF_TARGET_LIST_MAX);
			ksb_err(ksb, d->line, msg);
			return;
		}
		ksb->decl.target[ksb->decl.n_targets++] = fmt;
	}
}

static void resolve_arch(struct ksb_ctx *ksb)
{
	const struct simple_decl *d = &ksb->decl.simple[SD_ARCH];
	char one[128];
	const char *p = d->arg;

	if (!d->count)
		return;
	if (d->count > 1) {
		ksb_err(ksb, d->line, "more than one KOF_TARGET_ARCH; use one "
				      "declaration with '|'");
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint8_t a;

		if (!kof_arch_from_name(one, &a)) {
			char msg[192];

			snprintf(msg, sizeof msg,
				 "KOF_TARGET_ARCH names no known architecture: "
				 "%s", one);
			ksb_err(ksb, d->line, msg);
			return;
		}
		ksb->decl.arch_mask |= 1u << a;
	}
}

/*
 * Subtypes are the format's own vocabulary, so which header answers depends on
 * what the module targets - and naming one format's subtypes while targeting
 * another is refused here rather than left to collide at scan time. The values
 * deliberately overlap between formats; see the note on ctx->subtype.
 */
static void resolve_subtype(struct ksb_ctx *ksb)
{
	const struct simple_decl *d = &ksb->decl.simple[SD_SUBTYPE];
	char one[128];
	const char *p = d->arg;
	int want_elf = ksb_target_named(ksb, KOF_FMT_ELF);
	int want_pe = ksb_target_named(ksb, KOF_FMT_PE);
	int want_amsi = ksb_target_named(ksb, KOF_EVT_AMSI);
	int want_proc = ksb_target_named(ksb, KOF_EVT_PROC);
	int want_script = ksb_target_named(ksb, KOF_FMT_SCRIPT);

	if (!d->count)
		return;
	if (d->count > 1) {
		ksb_err(ksb, d->line, "more than one KOF_TARGET_SUBTYPE; use one "
				      "declaration with '|'");
		return;
	}
	while ((p = decl_next(p, one, sizeof one)) != NULL) {
		uint32_t v;
		char msg[192];

		if (kof_elf_type_from_name(one, &v)) {
			if (!want_elf) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target ELF", one);
				ksb_err(ksb, d->line, msg);
				return;
			}
		} else if (kof_pe_image_from_name(one, &v)) {
			if (!want_pe) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target PE", one);
				ksb_err(ksb, d->line, msg);
				return;
			}
		} else if (kof_script_type_from_name(one, &v)) {
			if (!want_script) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target SCRIPT", one);
				ksb_err(ksb, d->line, msg);
				return;
			}
		} else if (kof_amsi_kind_from_name(one, &v)) {
			if (!want_amsi) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %s but the "
					 "module does not target AMSI", one);
				ksb_err(ksb, d->line, msg);
				return;
			}
		} else if (kof_proc_os_from_name(one, &v)) {
			if (!want_proc) {
				snprintf(msg, sizeof msg,
					 "KOF_TARGET_SUBTYPE names %.40s but "
					 "the module does not target a "
					 "process", one);
				ksb_err(ksb, d->line, msg);
				return;
			}
		} else {
			snprintf(msg, sizeof msg,
				 "KOF_TARGET_SUBTYPE names no known subtype: "
				 "%s", one);
			ksb_err(ksb, d->line, msg);
			return;
		}
		if (v >= 32u) {
			ksb_err(ksb, d->line, "subtype value is outside the mask");
			return;
		}
		ksb->decl.subtype_mask |= 1u << v;
	}
}

/*
 * A plain arithmetic expression, evaluated only far enough to be a number.
 *
 * The shell required "a plain arithmetic expression" and then handed it to $((
 * )), which is a full expression evaluator with variable expansion in it. This
 * accepts a decimal or hex literal with the shifts and multiplications a size
 * is actually written with, and refuses anything else - which is the rule the
 * error message always claimed.
 */
static int decl_uint(const char *p, uint64_t *out)
{
	uint64_t acc = 0;
	int any = 0;

	while (*p) {
		uint64_t v;
		char *end;

		if (*p == '+') { p++; continue; }
		v = strtoull(p, &end, 0);
		if (end == p)
			return 0;
		p = end;
		while (*p == '<' && p[1] == '<') {
			uint64_t sh = strtoull(p + 2, &end, 0);

			if (end == p + 2 || sh > 63u)
				return 0;
			v <<= sh;
			p = end;
		}
		while (*p == '*') {
			uint64_t m = strtoull(p + 1, &end, 0);

			if (end == p + 1)
				return 0;
			v *= m;
			p = end;
		}
		acc += v;
		any = 1;
	}
	*out = acc;
	return any;
}

static void resolve_size_min(struct ksb_ctx *ksb)
{
	const struct simple_decl *d = &ksb->decl.simple[SD_SIZE_MIN];

	if (!d->count)
		return;
	if (d->count > 1) {
		ksb_err(ksb, d->line, "more than one KOF_TARGET_SIZE_MIN; a module has "
				      "one minimum");
		return;
	}
	if (!decl_uint(d->arg, &ksb->decl.size_min)) {
		ksb_err(ksb, d->line, "KOF_TARGET_SIZE_MIN is not a plain arithmetic "
				      "expression");
		return;
	}
	/* Zero is what a module with no declaration already has, so declaring
	 * it says nothing and reads as though it did. */
	if (!ksb->decl.size_min)
		ksb_err(ksb, d->line, "KOF_TARGET_SIZE_MIN(0) constrains nothing; omit it");
}

static void resolve_analyze_step(struct ksb_ctx *ksb)
{
	const struct simple_decl *d = &ksb->decl.simple[SD_ANALYZE_STEP];

	if (!d->count)
		return;
	if (d->count > 1) {
		ksb_err(ksb, d->line, "more than one KOF_ANALYZE_STEP; a module is one step");
		return;
	}
	if (names_ident(d->arg, "KOF_ANALYZE_UNWRAP"))
		ksb->decl.step = KOF_ANALYZE_UNWRAP;
	else if (names_ident(d->arg, "KOF_ANALYZE_UNPACK"))
		ksb->decl.step = KOF_ANALYZE_UNPACK;
	else if (names_ident(d->arg, "KOF_ANALYZE_DECRYPT"))
		ksb->decl.step = KOF_ANALYZE_DECRYPT;
	else if (names_ident(d->arg, "KOF_ANALYZE_CARVE"))
		ksb->decl.step = KOF_ANALYZE_CARVE;
	else if (names_ident(d->arg, "KOF_ANALYZE_RECOVER"))
		ksb->decl.step = KOF_ANALYZE_RECOVER;
	else
		ksb_err(ksb, d->line, "KOF_ANALYZE_STEP names no step a module may declare; "
				      "use KOF_ANALYZE_UNWRAP, _UNPACK, _DECRYPT, _CARVE or "
				      "_RECOVER (NORMZ is the host's own)");
}

/* The quoted text of a string declaration, without its quotes. Empty when the
 * declaration is absent, which is what an optional one looks like. */
static void decl_text(const struct simple_decl *d, char *out, size_t cap)
{
	const char *a = d->arg;
	size_t n = 0;

	out[0] = 0;
	if (!d->count || a[0] != '"')
		return;
	a++;
	while (*a && *a != '"' && n + 1u < cap)
		out[n++] = *a++;
	out[n] = 0;
}

void ksb_resolve_decls(struct ksb_ctx *ksb)
{
	decl_text(&ksb->decl.simple[SD_CONTENT], ksb->decl.content, sizeof ksb->decl.content);
	resolve_format(ksb);
	resolve_arch(ksb);
	resolve_subtype(ksb);
	resolve_size_min(ksb);
	resolve_analyze_step(ksb);
}

/*
 * A run starts with the declarations it looks for named, in the order of the
 * SD_* enum, and with no file-name type.
 */
void ksb_decl_init(struct ksb_ctx *ksb)
{
	static const struct simple_decl init[SD_COUNT] = {
		{ "KOF_TARGET_FORMAT",  "KOF_TARGET_EVENT", 0, 0, { 0 } },
		{ "KOF_TARGET_ARCH",    NULL, 0, 0, { 0 } },
		{ "KOF_TARGET_SUBTYPE", NULL, 0, 0, { 0 } },
		{ "KOF_TARGET_SIZE_MIN",NULL, 0, 0, { 0 } },
		{ "KOF_ANALYZE_STEP",    NULL, 0, 0, { 0 } },
		{ "KOF_TARGET_CONTENT", NULL, 0, 0, { 0 } }
	};

	memcpy(ksb->decl.simple, init, sizeof init);
	ksb->decl.name_type = -1;
}
