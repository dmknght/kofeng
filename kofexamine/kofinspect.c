#define _GNU_SOURCE

/*
 * kofinspect.c - see kofinspect.h. The format names, declaring and identifying a
 * format, a PDF text string, hex respacing, the symbol block's names and the
 * mutation view. Writing out is kofinspect_dump.c, where a marker is
 * kofinspect_locate.c, describing is kofinspect_describe.c.
 */

#include "kofinspect_private.h"

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
/* ---- the formats, and how to get a view of one ---------------------------- */

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

/* The program is little endian whatever the host is, which is the point of a
 * pack being portable: read with kof_ld_le16/32 (kofcore.h). */





const char *kof_inspect_subtype_name(uint8_t fmt, uint8_t sub)
{
	if (fmt == KOF_FMT_ELF)
		switch (sub) {
		case KGENOME_ELF_NONE: return "ET_NONE";
		case KGENOME_ELF_REL:  return "ET_REL";
		case KGENOME_ELF_EXEC: return "ET_EXEC";
		case KGENOME_ELF_DYN:  return "ET_DYN";
		case KGENOME_ELF_CORE: return "ET_CORE";
		default:           return "ET_?";
		}
	if (fmt == KOF_FMT_PE)
		switch (sub) {
		case KGENOME_PE_EXE: return "EXE";
		case KGENOME_PE_DLL: return "DLL";
		case KGENOME_PE_SYS: return "SYS";
		default:         return "?";
		}
	if (fmt == KOF_EVT_AMSI)
		switch (sub) {
		case KOF_AMSI_IMAGE:   return "image";
		case KOF_AMSI_COMMAND: return "command";
		default:               return 0;
		}
	if (fmt == KOF_EVT_PROC)
		switch (sub) {
		case KOF_PROC_OS_WINDOWS: return "windows";
		case KOF_PROC_OS_LINUX:   return "linux";
		case KOF_PROC_OS_MACOS:   return "macos";
		default:                  return 0;
		}
	/* Nothing for KOF_SCRIPT_ANY: "Script Script" says less than "Script",
	 * and the kind is only worth a word when a word was found. */
	if (fmt == KOF_FMT_SCRIPT)
		return sub == KOF_SCRIPT_ANY ? 0 : kof_script_type_name(sub);
	return 0;
}

/*
 * A VIEW MAY OWN TABLES (zip, pdf: struct kof_view_ops), so a tool that parses one has two
 * duties the scanner does for itself: tell the parse how much it may hold - the engine's own
 * cap, since a tool has no ledger of a tree - and give the tables back with the view.
 * kof_inspect_free is that second duty; `fmt` is what identify or declare answered, NULL
 * for a view that was never parsed.
 */
static void inspect_arm(const struct kof_parser *p, void *view)
{
	const struct kof_view_ops *o = kof_view_ops_of(p->format);

	if (o)
		o->mem(view)->room = KOF_ENGINE_MEM_CAP;
}

void kof_inspect_free(const struct kof_parser *fmt, void *view)
{
	const struct kof_view_ops *o = fmt && view ? kof_view_ops_of(fmt->format) : NULL;

	if (o)
		o->release(view);
	free(view);
}

/*
 * Identify the object and parse it.
 *
 * The first format whose sniff claims the bytes wins and no other is tried: a
 * sniff that claims something is a claim, and asking a second parser what it
 * thinks of an object the first recognised is how a tool ends up with two
 * answers and a rule for picking between them.
 *
 * The view is the caller's to free, with kof_inspect_free: a plain malloc of the
 * format's own info struct, except that zip and pdf views own tables the parse
 * allocated, which that call gives back before the free.
 */
/*
 * THE SAME THING FOR AN OBJECT THAT CANNOT BE SNIFFED.
 *
 * A process record and an AMSI submission carry no magic anybody could sniff -
 * they are reached by a caller that already KNOWS what it is holding, which is
 * why kofformat.c gives them rows whose sniff never accepts. identify() walks
 * the sniffs, so it answers "Raw" for both, and a viewer then shows a process
 * as unidentified bytes with no panel of its own.
 *
 * Declared rather than guessed, and only by a caller that built the bytes.
 */
const struct kof_parser *kof_inspect_declare(kof_buf buf, uint8_t format,
					     struct kof_obj_ctx *ctx,
					     void **view_out)
{
	const struct kof_parser *p = kof_parser_of(format);
	void *view;

	*view_out = NULL;
	memset(ctx, 0, sizeof *ctx);
	if (!p)
		return NULL;
	view = malloc(p->view_size);
	if (!view)
		return NULL;
	/*
	 * ZEROED BEFORE THE PARSE, AND IT WAS NOT.
	 *
	 * Most fields of a view are the parser's own answers and it does not
	 * matter what they held first. Some are INPUTS the caller fills -
	 * kgenome_pe_info.layout and kof_amsi_view.obj_off are the two today - and
	 * a parser reads those rather than writing them. pe_parse deliberately
	 * carries `layout` across its own memset, so whatever was in this
	 * allocation IS the answer.
	 *
	 * Straight out of malloc that answer is uninitialised heap. If it
	 * happened to equal KGENOME_PE_LAYOUT_MAPPED, a file read off a disk was
	 * parsed as though its sections sat at their virtual addresses, and
	 * every region resolved to the wrong bytes - nondeterministically,
	 * which is worse than consistently wrong because it cannot be
	 * reproduced.
	 *
	 * THIS IS THE SAME BUG THE SCANNER HAD at its sniff path, found first
	 * and fixed there. Both entry points are now the same rule: a parse
	 * that was given no input must not find one.
	 */
	memset(view, 0, p->view_size);
	inspect_arm(p, view);
	if (!p->parse(buf, view, ctx)) {
		kof_inspect_free(p, view);
		return NULL;
	}
	*view_out = view;
	return p;
}

const struct kof_parser *kof_inspect_identify(kof_buf buf,
						   struct kof_obj_ctx *ctx,
						   void **view_out)
{
	const struct kof_parser *parsers;
	uint32_t i, n;

	*view_out = NULL;
	memset(ctx, 0, sizeof *ctx);

	parsers = kof_parser_list(&n);
	for (i = 0; i < n; i++) {
		void *view;

		if (!parsers[i].sniff(buf))
			continue;
		view = malloc(parsers[i].view_size);
		/* Zeroed for the reason kof_inspect_declare's is - a sniffed
		 * object supplied no inputs, so the parse must not find any. */
		if (view) {
			memset(view, 0, parsers[i].view_size);
			inspect_arm(&parsers[i], view);
		}
		if (view && parsers[i].parse(buf, view, ctx)) {
			*view_out = view;
			return &parsers[i];
		}
		/* KNOWN DEFECT EX-1 (2026-10-24, R) [sev M]: kof_inspect_identify returns NULL when a sniff accepted and the
		 * parse then refused, where the engine's identify() tries the next parser, so a file the scanner names shows as Raw here.
		 * Trigger: a valid magic over a damaged or foreign body. Effect: the examiner disagrees with the scanner on the format.
		 * Reproducer: none yet. Fix: reset ctx per candidate and free the view when the next parser succeeds (lifetime question:
		 * ctx is memset once, above, not per attempt). */
		kof_inspect_free(&parsers[i], view);
		return NULL;
	}
	return NULL;
}



/* See kofinspect.h for why this is shared rather than one copy per tool. */
const char *kof_region_label(const char *enum_name)
{
	const char *p = enum_name;
	int have = 0, want, seen = 0;

	if (!enum_name)
		return "?";
	/*
	 * KOF_SCAN_<FMT>_NAME is three underscores in, and that is most of
	 * them. But a SHARED region has no format part - KOF_SCAN_ALL,
	 * KOF_SCAN_EMBEDDED - and demanding a third underscore returned those
	 * in full, so a row read "KOF_SCAN_EMBEDDED" where every neighbour read
	 * one word.
	 *
	 * So: skip three when there are three, two when that is all there is.
	 * KOF_SCAN_ALL -> ALL, KOF_SCAN_SYM_IMP -> IMP,
	 * KOF_SCAN_PDF_CONTENT_METADATA -> CONTENT_METADATA, KOF_SCAN_EMBEDDED ->
	 * EMBEDDED.
	 */
	for (p = enum_name; *p; p++)
		if (*p == '_')
			have++;
	want = have >= 3 ? 3 : 2;
	if (have < 2)
		return enum_name;
	for (p = enum_name; *p && seen < want; p++)
		if (*p == '_')
			seen++;
	return p;
}

/* ---- a PDF text string on one line - see kofinspect.h ---------------------- */

uint32_t kof_pdf_text(const uint8_t *p, uint64_t n, int hex,
		      char *out, uint32_t cap)
{
	uint8_t buf[512];
	uint64_t i;
	uint32_t w = 0, have = 0;
	int wide = 0;

	if (!out || !cap)
		return 0;
	out[0] = 0;
	if (!p || !n)
		return 0;

	/*
	 * Into a small buffer first, because the three transformations compose:
	 * a hex string may decode INTO UTF-16, and a literal string's escapes
	 * have to be gone before the pairs can be counted. Bounded rather than
	 * allocated - this is one line of a screen, and a title longer than the
	 * buffer is cut rather than grown into.
	 */
	if (hex) {
		int hi = -1;

		for (i = 0; i < n && have < sizeof buf; i++) {
			int v = kof_hex_val(p[i]);

			if (v < 0)
				continue;              /* whitespace, mostly */
			if (hi < 0) {
				hi = v;
				continue;
			}
			buf[have++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
		/* A trailing lone digit pairs with zero, which is what the
		 * format says about hex strings generally. */
		if (hi >= 0 && have < sizeof buf)
			buf[have++] = (uint8_t)(hi << 4);
	} else {
		for (i = 0; i < n && have < sizeof buf; i++) {
			if (p[i] == '\\' && i + 1u < n) {
				uint8_t e = p[++i];

				switch (e) {
				case 'n': buf[have++] = '\n'; break;
				case 'r': buf[have++] = '\r'; break;
				case 't': buf[have++] = '\t'; break;
				case 'b': buf[have++] = '\b'; break;
				case 'f': buf[have++] = '\f'; break;
				/* A digit begins an octal escape, which is a
				 * byte this does not need to name: the bytes
				 * that matter to a reader are the printable
				 * ones, and an octal escape of one is rare
				 * enough that rendering the digits is a
				 * smaller wrong than a parser for them. */
				default:  buf[have++] = e; break;
				}
				continue;
			}
			buf[have++] = p[i];
		}
	}

	/* UTF-16BE, and only on the byte order mark: a document that writes
	 * plain bytes must not have every other one dropped because its title
	 * happens to be even in length. */
	if (have >= 2u && buf[0] == 0xfeu && buf[1] == 0xffu)
		wide = 1;

	for (i = wide ? 3u : 0u; i < have && w + 1u < cap; i += wide ? 2u : 1u) {
		uint8_t ch = buf[i];

		out[w++] = (ch >= 0x20u && ch < 0x7fu) ? (char)ch : '.';
	}
	out[w] = 0;
	return w;
}

void kof_hex_respace(const char *in, char *out, size_t cap)
{
	size_t n = 0;
	uint32_t half = 0;
	const char *p;

	for (p = in; *p; p++)
		if (kof_hex_val((uint8_t)*p) < 0 && *p != ' ' && *p != '\t') {
			snprintf(out, cap, "%s", in);
			return;
		}
	/*
	 * Respacing GROWS the text by half, and a spelling that would not fit
	 * after that is left exactly as it was. Spacing is a courtesy; losing
	 * the tail of a pattern to it is not a trade worth making.
	 */
	for (p = in, n = 0; *p; p++)
		if (*p != ' ' && *p != '\t')
			n++;
	/* n/2 + 2 is what the escaping adds; checked against the room left
	 * rather than added to n first. */
	if (n > cap || n / 2u + 2u > cap - n) {
		snprintf(out, cap, "%s", in);
		return;
	}
	n = 0;
	for (p = in; *p && n + 4u < cap; p++) {
		if (*p == ' ' || *p == '\t')
			continue;
		if (half == 2u) {
			out[n++] = ' ';
			half = 0;
		}
		out[n++] = *p;
		half++;
	}
	out[n] = 0;
}

/* ---- the symbol block - see kofinspect.h ---------------------------------- */

/* ELF's own names for ELF's own numbering, spelled by the constants kofsym.h
 * declares rather than by the numbers - the two tools had one list each and
 * only one of them was written from the header. */
const char *kof_sym_type_name(uint8_t type)
{
	switch (type) {
	case KOF_STT_NOTYPE:     return "NOTYPE";
	case KOF_STT_OBJECT:     return "OBJECT";
	case KOF_STT_FUNC:       return "FUNC";
	case KOF_STT_SECTION:    return "SECTION";
	case KOF_STT_FILE:       return "FILE";
	case KOF_STT_COMMON:     return "COMMON";
	case KOF_STT_TLS:        return "TLS";
	case KOF_STT_GNU_IFUNC:  return "GNU_IFUNC";
	default:                 return "?";
	}
}

const char *kof_sym_bind_name(uint8_t bind)
{
	switch (bind) {
	case KOF_STB_LOCAL:      return "LOCAL";
	case KOF_STB_GLOBAL:     return "GLOBAL";
	case KOF_STB_WEAK:       return "WEAK";
	case KOF_STB_GNU_UNIQUE: return "GNU_UNIQ";
	default:                 return "?";
	}
}

const char *kof_sym_vis_name(uint8_t vis)
{
	switch (vis) {
	case KOF_STV_DEFAULT:   return "DEFAULT";
	case KOF_STV_INTERNAL:  return "INTERNAL";
	case KOF_STV_HIDDEN:    return "HIDDEN";
	case KOF_STV_PROTECTED: return "PROTECTED";
	default:                return "?";
	}
}

const char *kof_sym_origin_name(const uint8_t *blk, uint32_t n)
{
	if (!blk || n < KOF_SYM_HDRLEN)
		return "none";
	switch (blk[KOF_SYM_H_ORIGIN]) {
	case KOF_SYM_ORIGIN_SYMTAB: return ".symtab";
	case KOF_SYM_ORIGIN_DYNSYM: return ".dynsym";
	case KOF_SYM_ORIGIN_PE_DIR: return "imports+exports";
	case KOF_SYM_ORIGIN_PE_RESOLVED: return "imports+exports+resolved";
	default:                    return "none";
	}
}


/*
 * The chain page stood here - ~780 lines that drew one WALK as indented
 * pseudo code. It goes with the chain matcher: a walk is the wrong unit
 * to draw, because a producer with several consumers is a tree and a step
 * joined by control has no row in a sequence. What replaces it draws a
 * store of nodes and typed edges.
 */


uint32_t kof_inspect_mutation(const struct kof_scanner *sc,
			    struct kof_mutation_view *out, uint32_t max_out)
{
	const struct kof_engine *e;
	uint32_t b, n = 0;

	if (!sc || !out || !max_out)
		return 0;
	e = sc->eng;
	if (!e || !e->n_blk || !sc->mutation.set)
		return 0;

	for (b = 0; b < e->n_blk && n < max_out; b++) {
		const struct kof_mutation_block *blk = &e->blk_tab[b];
		uint32_t i;

		out[n].block     = b;
		out[n].scan_mask = blk->scan_mask;
		out[n].norm      = blk->norm;
		out[n].n_hash    = blk->n_hash;
		out[n].score     = (uint8_t)kof_mutation_pct(&sc->mutation, b);
		out[n].matched   = kof_mutation_matched(&sc->mutation, b);
		out[n].rule      = "";
		/*
		 * Which module declared it. A linear walk because the tables
		 * are tens to hundreds of rules and this runs once per object a
		 * PERSON asked about, not per object scanned.
		 */
		for (i = 0; i < e->n_mods; i++) {
			const struct kof_module *m = &e->mods[i];
			const char *fam;

			if (!m->n_block || b < m->block_base ||
			    b >= m->block_base + m->n_block)
				continue;
			fam = kof_db_family(e, m);
			out[n].rule = fam ? fam : "";
			break;
		}
		n++;
	}
	return n;
}

