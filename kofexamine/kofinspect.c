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

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * kof_memmem calls memmem() from an inline function whether or not anything
 * here does. _POSIX_C_SOURCE alone hides it and the inline stops compiling -
 * the same reason kofexamine.c and kofviewer.c both say _GNU_SOURCE. */
#define _GNU_SOURCE

#include <kofmod/kofsym.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "kofinspect.h"
#include "../libkofeng/kofcore/kofplatform.h"
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/scanners/scan.h"
#include <kofmod/script.h>
/* KOF_PROC_OS_LIST: the platform a process record is from, which is its
 * subtype - see the note on that list. */
#include <kofmod/proc.h>
#include "../libkofeng/analyzers/parsers/kofformat.h"

/*
 * The parsers, by their internal headers.
 *
 * Same reach kofexamine's own comment defends and for the same reason: there is
 * no public "parse this and hand me the view" surface, because no host has ever
 * wanted one. What changed is that there are now two consumers of it in this
 * tree rather than one, so the reach lives here once instead of in each.
 */
#include "../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../libkofeng/analyzers/parsers/events/amsi_parse.h"

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
		/*
		 * KNOWN DEFECT: THIS GIVES UP WHERE THE SCANNER CARRIES ON.
		 *
		 * A sniff accepted and the parse then refused, and this returns
		 * "nothing identified it" rather than trying the next parser.
		 * The engine's own identify() continues down the table, so the
		 * two disagree: a file the scanner names is shown as Raw here.
		 *
		 * Reachable: a sniff is a few magic bytes and a parse reads the
		 * whole structure, so anything that opens with a valid magic and
		 * is damaged after it takes this path - and so does a file that
		 * deliberately carries one format's magic and another's body.
		 *
		 * Not fixed here because the fix is a loop change with a
		 * lifetime question in it - which view is freed when the second
		 * parser succeeds after the first has already written into ctx -
		 * and ctx is memset once, above, rather than per attempt. The
		 * honest version resets ctx per candidate.
		 */
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

/* ---- writing an object out ------------------------------------------------ */

#define DUMP_NAME_MAX  255            /* what a filesystem component usually holds */
#define DUMP_KEEP_MAX  48             /* readable prefix retained when shortening */

/* Bytes a dump name may carry as they are: anything else is replaced, so a name
 * out of a file cannot become a separator or a parent reference. */
static int name_char_ok(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

static const char *base_of(const char *path)
{
	return kof_path_base(path);
}

static void dump_dir_name(const char *base, char *out, size_t cap)
{
	size_t n = strlen(base), i, keep = 0;
	int clean = 1;

	for (i = 0; i < n; i++)
		if (!name_char_ok((unsigned char)base[i])) {
			clean = 0;
			break;
		}

	if (clean && n + sizeof "__dump" - 1 <= DUMP_NAME_MAX &&
	    n + sizeof "__dump" < cap) {
		snprintf(out, cap, "_%s_dump", base);
		return;
	}

	/* Dropping to a bare checksum would be simpler and would make every
	 * result unrecognisable. */
	while (keep < n && keep < DUMP_KEEP_MAX &&
	       name_char_ok((unsigned char)base[keep]))
		keep++;
	snprintf(out, cap, "_%.*s%s%08x_dump", (int)keep, base, keep ? "-" : "",
		 kof_crc32(base, n));
}

int kof_dump_dir_for(const char *path, char *out, uint32_t cap)
{
	const char *base = base_of(path);
	size_t lead = (size_t)(base - path);
	char name[DUMP_NAME_MAX + 1];

	dump_dir_name(base, name, sizeof name);
	if (lead + strlen(name) + 1 > cap)
		return 0;
	memcpy(out, path, lead);
	memcpy(out + lead, name, strlen(name) + 1);
	return 1;
}

/* One sentence for the caller to show, and 0, in one statement at every site
 * that has something to say. */
static int dump_fail(char *err, uint32_t cap, const char *what, const char *at)
{
	if (err && cap)
		snprintf(err, cap, "%s %.200s", what, at);
	return 0;
}

/*
 * EVERY FILE A DUMP WRITES IS OPENED THROUGH kof_fopen_trunc, AND NOT fopen.
 *
 * The dump directory's name is derived from the sample's own - see
 * kof_dump_dir_for - so every path under it is predictable by whoever put the
 * sample there, and a sample is routinely examined where it was found: an
 * extracted archive, a shared drop directory, somebody else's tree. fopen(,"wb")
 * follows a symlink and takes its mode from the umask, so a planted
 * "_sample_dump/01.KGENOME_SCAN_ELF_CODE" pointing elsewhere makes the dumper write
 * the sample's bytes through it.
 *
 * kof_fopen_trunc is O_CREAT|O_TRUNC|O_NOFOLLOW at 0600 - the same create-or-
 * truncate this had, refusing the link, and not readable by the rest of the
 * machine. It is what kofevt_log_create already uses, for a file that is also
 * rewritten on purpose; kof_fopen_new is the wrong one here, because re-dumping
 * a sample must overwrite the last dump rather than fail.
 *
 * On Windows the LAYOUT file below loses its CRLF translation with the mode
 * change, which is the whole cost: it is written LF-only, like every other text
 * this toolset emits.
 */
static int dump_write(const char *path, const void *bytes, uint64_t len,
		      char *err, uint32_t err_cap)
{
	FILE *f = kof_fopen_trunc(path);

	if (!f)
		return dump_fail(err, err_cap, "cannot write", path);
	if (len && fwrite(bytes, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		return dump_fail(err, err_cap, "short write to", path);
	}
	if (fclose(f) != 0)
		return dump_fail(err, err_cap, "cannot write", path);
	return 1;
}

/*
 * Every extent of every region, in file order.
 *
 * The numbered files say where each region begins; this says where each run of
 * each region is, which is the layout itself. It is also where the partition
 * claim becomes checkable line by line: consecutive rows are adjacent, the first
 * starts at zero and the last ends at the object size, or one of those is not
 * true and the row it breaks on says which region got it wrong.
 */
struct layout_row {
	uint64_t    off, len;
	const char *name;
};

uint32_t kof_declared_regions(const struct kof_scan_region *rgn, uint32_t n_rgn,
			      uint32_t scan_mask, struct kof_range *out,
			      uint32_t max_out)
{
	uint32_t i, n = 0;

	if (!rgn || !out || !max_out)
		return 0;
	for (i = 0; i < n_rgn && n < max_out; i++) {
		/* A row of no length says the region is not in this object,
		 * which is the same answer as no row at all - see
		 * declared_resolve_scan in the engine, which drops them too. */
		if (!(rgn[i].mask & scan_mask) || !rgn[i].len)
			continue;
		out[n].off = rgn[i].off;
		out[n].len = rgn[i].len;
		n++;
	}
	return n;
}

static int dump_layout(const char *dir, const struct kof_parser *f,
		       const struct kof_obj_ctx *ctx, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	static struct layout_row row[KOF_SCAN_MAX_EXTENTS * 8];
	char path[KOF_DUMP_PATH_ROOM];
	uint32_t nrow = 0, i, k, j;
	FILE *out;

	for (i = 0; i < f->n_regions; i++) {
		const char *rn = f->region_name(f->regions[i]);
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, f->regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS) : 0;
		for (k = 0; k < n && nrow < sizeof row / sizeof row[0]; k++) {
			row[nrow].off = ext[k].off;
			row[nrow].len = ext[k].len;
			row[nrow].name = rn ? rn : "?";
			nrow++;
		}
	}
	for (i = 1; i < nrow; i++) {
		struct layout_row t = row[i];
		for (j = i; j > 0 && row[j - 1].off > t.off; j--)
			row[j] = row[j - 1];
		row[j] = t;
	}

	if ((size_t)snprintf(path, sizeof path, "%s/LAYOUT", dir) >= sizeof path)
		return dump_fail(err, err_cap, "path too long under", dir);
	out = kof_fopen_trunc(path);   /* see dump_write */
	if (!out)
		return dump_fail(err, err_cap, "cannot write", path);
	fprintf(out, "%-12s %-12s %s\n", "offset", "length", "region");
	for (i = 0; i < nrow; i++)
		fprintf(out, "%-12llu %-12llu %s\n",
			(unsigned long long)row[i].off,
			(unsigned long long)row[i].len, row[i].name);
	if (fclose(out) != 0)
		return dump_fail(err, err_cap, "cannot write", path);
	return 1;
}

static int dump_region(const char *dir, uint32_t rank, const char *region,
		       const struct kof_obj_ctx *ctx, kof_buf buf, uint32_t bit,
		       uint64_t *out_len, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	char name[KOF_DUMP_PATH_ROOM];
	uint32_t n, i;
	FILE *f;

	*out_len = 0;
	n = ctx->resolve_scan ? ctx->resolve_scan(ctx, bit, ext,
						  KOF_SCAN_MAX_EXTENTS) : 0;
	if (n == 0)
		return 1;                /* an empty region is not a failure */

	/* The directory already names the object, and the region's enum identifier
	 * already names the format, so the file is just the region. */
	if ((size_t)snprintf(name, sizeof name, "%s/%02u.%s", dir, rank, region)
	    >= sizeof name)
		return dump_fail(err, err_cap, "path too long under", dir);
	f = kof_fopen_trunc(name);     /* see dump_write */
	if (!f)
		return dump_fail(err, err_cap, "cannot write", name);
	for (i = 0; i < n; i++) {
		/*
		 * CLIPPED TO THE OBJECT, because an extent is not a promise.
		 *
		 * resolve_scan is a FUNCTION POINTER, and the thing behind it
		 * is not always a format parser that bounded its own answer.
		 * kof_declared_regions is one of the producers - it copies the
		 * off/len an unpacked child DECLARED, and it is handed no
		 * object size to check them against - so an extent arriving
		 * here can run past the bytes it claims to describe.
		 *
		 * Unclipped, this fwrite reads whatever follows the object in
		 * memory and writes it into a file on disk: a crash on the good
		 * day, and somebody else's heap in the dump on the bad one.
		 *
		 * This is the engine's own rule and not a new one. match_ranges
		 * clips every extent before searching it and says why: "an
		 * extent is produced by a format collector and describes the
		 * object it was parsed from, so it should already fit - but the
		 * two ad-hoc entry points do not trust that either."
		 * kof_inspect_region_entropy, in this file, clips for the same
		 * reason. This was the one reader that took the length on
		 * trust.
		 */
		uint64_t len = kof_clip_len(buf.n, ext[i].off, ext[i].len);

		if (!len)
			continue;
		if (fwrite(buf.p + ext[i].off, 1, (size_t)len, f)
		    != (size_t)len) {
			fclose(f);
			return dump_fail(err, err_cap, "short write to", name);
		}
		*out_len += len;
	}
	if (fclose(f) != 0)
		return dump_fail(err, err_cap, "cannot write", name);
	return 1;
}

int kof_dump_object(const char *dir, kof_buf buf,
		    const struct kof_parser *f,
		    const struct kof_obj_ctx *ctx,
		    struct kof_dump_stat *st, char *err, uint32_t err_cap)
{
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	char path[KOF_DUMP_PATH_ROOM];
	uint64_t first[16];
	uint32_t order[16], nord = 0, i, k;

	if (st)
		memset(st, 0, sizeof *st);
	if (err && err_cap)
		err[0] = 0;
	if (kof_mkdir(dir, 0777) != 0 && errno != EEXIST)
		return dump_fail(err, err_cap, "cannot create", dir);

	/*
	 * The whole object, numbered 00 so it sorts before the regions and reads
	 * as what it is: the thing the others are parts of. Named KOF_SCAN_ALL
	 * rather than "full" or the object's own filename because that is what
	 * the engine calls the whole of an object - one vocabulary in the
	 * directory rather than two.
	 *
	 * Worth having even though the caller usually has the file, because a
	 * dump is often taken of something that never was a file: for a
	 * recovered child this is the only copy outside the scan.
	 */
	if (buf.n) {
		if ((size_t)snprintf(path, sizeof path, "%s/00.KOF_SCAN_ALL", dir)
		    >= sizeof path)
			return dump_fail(err, err_cap, "path too long under", dir);
		if (!dump_write(path, buf.p, buf.n, err, err_cap))
			return 0;
		if (st)
			st->whole_bytes = buf.n;
	}

	if (!f || !ctx)
		return 1;

	/* Ordered by where each one begins. A region with no extents is not
	 * written and does not take a number, so the numbers are contiguous over
	 * what is actually there. */
	for (i = 0; i < f->n_regions && nord < 16; i++) {
		uint32_t n = ctx->resolve_scan
			   ? ctx->resolve_scan(ctx, f->regions[i], ext,
					       KOF_SCAN_MAX_EXTENTS) : 0;
		if (n == 0)
			continue;
		first[nord] = ext[0].off;
		order[nord] = i;
		nord++;
	}
	for (i = 1; i < nord; i++) {
		uint64_t fo = first[i];
		uint32_t oi = order[i];

		for (k = i; k > 0 && first[k - 1] > fo; k--) {
			first[k] = first[k - 1];
			order[k] = order[k - 1];
		}
		first[k] = fo;
		order[k] = oi;
	}

	for (i = 0; i < nord; i++) {
		uint64_t len;

		if (!dump_region(dir, i + 1,
				 f->region_name(f->regions[order[i]]),
				 ctx, buf, f->regions[order[i]], &len,
				 err, err_cap))
			return 0;
		if (len && st) {
			st->regions++;
			st->region_bytes += len;
		}
	}

	return dump_layout(dir, f, ctx, err, err_cap);
}


/*
 * WHERE AN OBJECT'S DUMP BELONGS, as a path under the dump root.
 *
 * HERE AND NOT IN THE ENGINE, although it reads the engine's names. A dump
 * directory is a thing a TOOL makes on a disk, and the engine has no business
 * with it - the same line kofscanner's own usage draws when it says what to
 * keep is policy. What the engine publishes is the VOCABULARY - KOF_OBJ_SEP,
 * kobj_toplevel_len, KOF_OBJ_LABEL_NORM - and this spells a path out of it.
 *
 * THE ENGINE ALREADY KNOWS THE TREE AND THE TOOLS WERE THROWING IT AWAY. An
 * object's name carries its whole descent - "f//0//1:norm" is the normalised
 * view of the second child of the first child - and both front ends dumped
 * with a FLAT counter instead, so every object in a file landed in one
 * directory as siblings. Measured on 111.exe, which is VMProtect under MPRESS:
 * four objects three levels deep came out as `unpacked.1`, `unpacked.2`,
 * `unpacked.3` and `unpacked.4.norm` beside one another, and the last is a
 * rendering OF the third. A reader cannot tell what came out of what, which is
 * the one thing the tree was for.
 *
 * So the placement is computed here, from the engine's own name, and both
 * tools ask rather than each inventing a scheme. "f//0//1:norm" gives
 * "0/1.norm"; the file itself gives "", which is the dump root.
 *
 * A VIEW IS NOT A CHILD AND IS NOT GIVEN A LEVEL OF ITS OWN. `norm` is the
 * same bytes seen another way - see KOF_OBJ_LABEL_NORM - so it hangs off its
 * object's own name rather than becoming a directory beneath it. A label that
 * is not a view names the child and does the same, because a label is a word
 * about the child rather than a step down.
 *
 * Returns the length written, or 0 when it would not fit.
 */
static uint32_t dump_rel_dir(const char *name, char *out, uint32_t cap)
{
	const char *p = name;
	uint32_t n = 0;

	if (!out || !cap)
		return 0;
	out[0] = 0;
	if (!name)
		return 0;
	/* Past the file's own name: everything before the first separator is
	 * the root and is the caller's to place. */
	p = name + kobj_toplevel_len(name);
	while (p[0] == KOF_OBJ_SEP[0] && p[1] == KOF_OBJ_SEP[1]) {
		const char *seg = p + KOF_OBJ_SEP_LEN;
		const char *e = seg;

		while (*e && !(e[0] == KOF_OBJ_SEP[0] &&
			       e[1] == KOF_OBJ_SEP[1]))
			e++;
		if (n && n + 1u < cap)
			out[n++] = '/';
		while (seg < e) {
			char c = *seg++;

			/*
			 * The ':' between an index and its label becomes a
			 * '.', and anything a path should not carry becomes
			 * '_'. A label is the engine's word and is not a file
			 * name - "3:bin/x86" holds a separator of its own, and
			 * left alone it would make a directory nobody asked
			 * for.
			 */
			if (c == ':')
				c = '.';
			else if (c == '/' || c == '\\' || c < 0x20 ||
				 (unsigned char)c > 0x7e)
				c = '_';
			if (n + 1u < cap)
				out[n++] = c;
		}
		p = e;
	}
	out[n] = 0;
	return n;
}

/*
 * ---- ONE OBJECT OF A SCAN, WRITTEN WHERE THE TREE SAYS ---------------------
 *
 * THE ONE PLACE A DUMP TREE IS LAID OUT, and there used to be two. kofexaminer
 * wrote from inside the engine's per-object callback; kofviewer kept its own
 * array of objects and looped over that afterwards. Two walks, two naming
 * schemes - `unpacked.N` against `N.label` - over one tree, and neither
 * carried the DEPTH: every object of a file landed in the dump root as
 * siblings. Measured on 111.exe, which is VMProtect under MPRESS: four objects
 * three levels apart came out as `unpacked.1` through `unpacked.4.norm`, and
 * the last is a rendering OF the third.
 *
 * The engine already knows the shape - it names an object by its whole descent
 * - so the placement is asked of it, with dump_rel_dir, and this is the only
 * caller either tool needs.
 *
 * WHAT THE ENGINE DOES AND WHAT THIS DOES. The engine answers WHERE; this
 * creates the directories and writes the bytes. That split is not tidiness: a
 * scanner that writes files is a scanner deciding what to keep, and
 * kofscanner's own usage text says that is policy and the wrong place for it.
 *
 * `root` is the dump directory for the FILE - kof_dump_dir_for's answer.
 * `name` is the engine's name for this object. The object's own bytes are
 * written as `object` at every level below the top, because at the top they
 * are already `00.KOF_SCAN_ALL`.
 */
static int dump_mkpath(const char *path, char *err, uint32_t err_cap)
{
	char tmp[KOF_DUMP_PATH_ROOM];
	size_t n = strlen(path), i;

	if (n + 1u > sizeof tmp)
		return dump_fail(err, err_cap, "path too long", path);
	memcpy(tmp, path, n + 1u);
	/* Each component in turn, so a tree three deep does not need the
	 * caller to have made the levels above it. */
	for (i = 1; i < n; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = 0;
		if (kof_mkdir(tmp, 0777) != 0 && errno != EEXIST)
			return dump_fail(err, err_cap, "cannot create", tmp);
		tmp[i] = '/';
	}
	if (kof_mkdir(tmp, 0777) != 0 && errno != EEXIST)
		return dump_fail(err, err_cap, "cannot create", tmp);
	return 1;
}

int kof_dump_walk(const char *root, const char *name, kof_buf buf,
		  const struct kof_parser *f,
		  const struct kof_obj_ctx *ctx,
		  struct kof_dump_stat *st,
		  char *dir_out, uint32_t dir_cap,
		  char *err, uint32_t err_cap)
{
	char rel[KOF_DUMP_PATH_ROOM], dir[KOF_DUMP_PATH_ROOM];

	if (err && err_cap)
		err[0] = 0;
	if (!root || !name)
		return dump_fail(err, err_cap, "no dump root for", name ? name : "?");

	dump_rel_dir(name, rel, sizeof rel);
	if (rel[0]) {
		char path[KOF_DUMP_PATH_ROOM];

		if ((size_t)snprintf(dir, sizeof dir, "%s/%s", root, rel) >=
		    sizeof dir)
			return dump_fail(err, err_cap, "path too long under",
					 root);
		if (!dump_mkpath(dir, err, err_cap))
			return 0;
		/*
		 * The bytes themselves, beside the regions rather than in
		 * them: a reader wants the recovered file whole, and a region
		 * is a view of it.
		 */
		if ((size_t)snprintf(path, sizeof path, "%s/object", dir) >=
		    sizeof path)
			return dump_fail(err, err_cap, "path too long under",
					 dir);
		if (!dump_write(path, buf.p, buf.n, err, err_cap))
			return 0;
	} else {
		if ((size_t)snprintf(dir, sizeof dir, "%s", root) >= sizeof dir)
			return dump_fail(err, err_cap, "path too long", root);
		if (!dump_mkpath(dir, err, err_cap))
			return 0;
	}
	if (dir_out && dir_cap &&
	    (size_t)snprintf(dir_out, dir_cap, "%s", dir) >= dir_cap)
		return dump_fail(err, err_cap, "path too long", dir);
	/*
	 * AND THE REGIONS, WHEN THE CALLER HAS THE PARSE IN HAND.
	 *
	 * A caller with `ctx` is one the engine has just handed an object to,
	 * and its regions are on that. A caller without it - kofexaminer, which
	 * re-identifies the bytes so it can DESCRIBE them - takes the directory
	 * back and dumps the regions from its own parse. Both write the same
	 * files in the same place; only who parsed differs.
	 */
	if (!ctx)
		return 1;
	return kof_dump_object(dir, buf, f, ctx, st, err, err_cap);
}

/* ---- where a marker is, and in which region ------------------------------ */

int kof_region_map_build(struct kof_region_map *map,
			 const struct kof_obj_ctx *ctx,
			 const struct kof_parser *fmt)
{
	uint32_t k;

	memset(map, 0, sizeof *map);
	if (!ctx || !fmt)
		return 0;
	for (k = 0; k < fmt->n_regions && map->n_reg < 32u; k++) {
		struct kof_range *e = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *e);
		uint32_t n;

		if (!e)
			return 0;
		{
			struct kof_ext_buf eb = kof_ext_fixed(e, KOF_SCAN_MAX_EXTENTS);

			n = kof_scan_resolve_range(ctx, fmt->regions[k], &eb);
		}
		if (!n) {
			free(e);
			continue;
		}
		map->mask[map->n_reg] = fmt->regions[k];
		map->ext[map->n_reg]  = e;
		map->n[map->n_reg]    = n;
		map->n_reg++;
	}
	return 1;
}

void kof_region_map_free(struct kof_region_map *map)
{
	uint32_t k;

	for (k = 0; k < map->n_reg; k++)
		free(map->ext[k]);
	memset(map, 0, sizeof *map);
}

uint32_t kof_region_map_at(const struct kof_region_map *map, uint64_t off)
{
	uint32_t k, j;

	if (!map)
		return 0;
	for (k = 0; k < map->n_reg; k++)
		for (j = 0; j < map->n[k]; j++)
			if (off >= map->ext[k][j].off &&
			    off < map->ext[k][j].off + map->ext[k][j].len)
				return map->mask[k];
	return 0;
}

/*
 * How long the match at each hit actually is.
 *
 * kof_match_where says where a match starts and not where it ends, and the
 * engine keeps that to itself. Truncating the buffer is how to ask: a match
 * needs its whole length to be there, so the shortest cut it still matches
 * under IS its length. Monotonic, so it is a bisection. Skipped entirely for a
 * pattern of fixed length, which is nearly all of them.
 */
static void locate_lens(struct kof_locate *o, struct kof_match_ctx *m,
			kof_buf buf, const uint8_t *pat, uint16_t plen,
			uint8_t kind, uint8_t flags, uint32_t span_min,
			uint32_t span_max)
{
	uint32_t h;

	for (h = 0; h < o->n_hits; h++) {
		uint32_t lo = span_min, hi = span_max;

		if (span_max <= span_min) {
			o->hit_len[h] = span_min;
			continue;
		}
		if (o->hits[h] + hi > buf.n)
			hi = (uint32_t)(buf.n - o->hits[h]);
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			kof_match_begin(m, kof_buf_make(buf.p,
							o->hits[h] + mid));
			if (kof_match_at(m, o->hits[h], pat, plen, kind, flags))
				hi = mid;
			else
				lo = mid + 1u;
		}
		o->hit_len[h] = lo;
	}
	kof_match_begin(m, buf);        /* put the context back */
}

/*
 * Walk one window, recording every occurrence.
 *
 * `region` is asked for each hit so the caller can prefer one the mask names.
 * The word-boundary test is re-asked at the hit rather than trusted from the
 * windowed search: a range search treats the START of its range as a word
 * boundary, which is right when the range is a region a module named and wrong
 * when it is only "past the last hit".
 */
static void locate_walk(struct kof_locate *o, struct kof_match_ctx *m,
			uint64_t from, uint64_t end, const uint8_t *pat,
			uint16_t plen, uint8_t kind, uint8_t flags,
			uint32_t mask, const struct kof_region_map *map,
			uint32_t fixed_region, uint64_t *first,
			uint32_t *first_mask)
{
	while (from < end) {
		uint64_t at = kof_match_where(m, from, end - from, pat, plen,
					      kind, flags);
		uint32_t rm;

		if (at == KGENOME_BROKEN)
			return;
		if ((flags & KOF_STR_FULLWORD) &&
		    !kof_match_at(m, at, pat, plen, kind, flags)) {
			from = at + 1u;
			continue;
		}
		if (o->n_hits < KOF_LOCATE_HITS)
			o->hits[o->n_hits++] = at;
		else
			o->clipped = 1;
		rm = fixed_region ? fixed_region : kof_region_map_at(map, at);
		if (*first == KGENOME_BROKEN) {
			*first = at;
			*first_mask = rm;
		}
		o->seen_mask |= rm;
		if (o->at == KGENOME_BROKEN &&
		    (!mask || (mask & KOF_SCAN_ALL) || (rm & mask))) {
			o->at = at;
			o->at_mask = rm;
			o->in_rgn = 1;
			o->cur_hit = o->n_hits ? o->n_hits - 1u : 0u;
		}
		from = at + 1u;
		if (o->clipped && o->at != KGENOME_BROKEN)
			return;         /* the list is full and we have an answer */
	}
}

int kof_locate_str(struct kof_match_ctx *m, struct kof_match_ctx *msym,
		   const struct kof_region_map *map, kof_buf obj,
		   const uint8_t *sym, uint32_t sym_n, uint32_t mask,
		   const uint8_t *pat, uint16_t plen, uint8_t kind,
		   uint8_t flags, uint32_t span_min, uint32_t span_max,
		   struct kof_range *scratch, uint32_t cap,
		   struct kof_locate *out)
{
	uint64_t first = KGENOME_BROKEN;
	uint32_t first_mask = 0, h;

	memset(out, 0, sizeof *out);
	out->at = KGENOME_BROKEN;
	if (!pat || !plen)
		return 0;

	/*
	 * 1. THE SYMBOL HALVES, imports before exports.
	 *
	 * This order is kof_find_str's, so the occurrence reported is the one
	 * that decided the detection rather than a different one that happens
	 * to come first in the file.
	 */
	for (h = 0; h < 2u && sym && sym_n; h++) {
		uint32_t bit = h ? KOF_SCAN_SYM_EXP : KOF_SCAN_SYM_IMP;
		uint32_t n, e;

		if (!(mask & bit))
			continue;
		n = kof_sym_extents(sym, sym_n, bit, scratch, cap);
		if (!n)
			continue;
		kof_match_begin(msym, kof_buf_make(sym, sym_n));
		for (e = 0; e < n; e++)
			locate_walk(out, msym, scratch[e].off,
				    scratch[e].off + scratch[e].len, pat, plen,
				    kind, flags, mask, NULL, bit, &first,
				    &first_mask);
		if (out->n_hits) {
			out->sym = bit;
			locate_lens(out, msym, kof_buf_make(sym, sym_n), pat,
				    plen, kind, flags, span_min, span_max);
			return 1;
		}
	}

	/* 2. The file, preferring an occurrence the mask names. */
	if (!obj.p || plen > obj.n)
		return 0;
	kof_match_begin(m, obj);
	locate_walk(out, m, 0, obj.n, pat, plen, kind, flags, mask, map, 0,
		    &first, &first_mask);
	/*
	 * 3. Present, and nowhere the mask names. That is the finding, so the
	 * row still points at an occurrence and says the rule cannot fire on
	 * it - the union is what a widened range would have to cover.
	 */
	if (out->at == KGENOME_BROKEN && first != KGENOME_BROKEN) {
		out->at = first;
		out->at_mask = out->seen_mask ? out->seen_mask : first_mask;
		out->cur_hit = 0;
		out->off_rgn = 1;
	}
	if (out->n_hits)
		locate_lens(out, m, obj, pat, plen, kind, flags, span_min,
			    span_max);
	return out->at != KGENOME_BROKEN;
}

/* ---- describing one collected event ------------------------------------- */

/* The attribute, or nothing. One helper so every use below reads the same and
 * a NULL style cannot be forgotten at one of them. */
static const char *sty(const char *a) { return a ? a : ""; }

void kof_inspect_event_log(const struct kofevt_log_hdr *h,
			   uint64_t events, uint64_t records,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user)
{
	char line[256];

	if (!h || !out)
		return;
	snprintf(line, sizeof line, "  %s%-11s%s%s/%s",
		 sty(st ? st->id : NULL), "collected", sty(st ? st->off : NULL),
		 kof_evt_platform_name((uint8_t)h->platform),
		 kof_evt_arch_name((uint8_t)h->arch));
	out(user, line);

	/*
	 * NAMED FOR THE COMPONENT, NOT THE LIBRARY.
	 *
	 * "Windows watcher" is what collected this; libkoforbit/grille is the library
	 * it happens to be built from, and a reader of a log has no reason to
	 * know that name. The two are separable on purpose - the collector
	 * ships and versions on its own - so the log says which collector, and
	 * its version says which contract its records follow.
	 *
	 * A version of zero is a log written before collectors carried one. It
	 * is left off rather than shown as "0.0", which would read as a real
	 * answer.
	 */
	if (h->src_major || h->src_minor)
		snprintf(line, sizeof line, "  %s%-11s%s%s %u.%u  build %lu",
			 sty(st ? st->id : NULL), "collector",
			 sty(st ? st->off : NULL),
			 h->platform == KOF_PLAT_WINDOWS ? "Windows watcher"
			 : h->platform == KOF_PLAT_LINUX ? "Linux watcher"
							 : "watcher",
			 (unsigned)h->src_major, (unsigned)h->src_minor,
			 (unsigned long)h->build);
	else
		snprintf(line, sizeof line, "  %s%-11s%s%s  build %lu",
			 sty(st ? st->id : NULL), "collector",
			 sty(st ? st->off : NULL),
			 h->platform == KOF_PLAT_WINDOWS ? "Windows watcher"
			 : h->platform == KOF_PLAT_LINUX ? "Linux watcher"
							 : "watcher",
			 (unsigned long)h->build);
	out(user, line);

	/*
	 * BOTH NUMBERS, because they are different questions and the gap
	 * between them is a fact. A submission split over nine continuations
	 * is ten records and one event; a reader given only one of those two
	 * cannot tell a busy log from a chatty one.
	 */
	snprintf(line, sizeof line, "  %s%-11s%s%llu",
		 sty(st ? st->id : NULL), "events", sty(st ? st->off : NULL),
		 (unsigned long long)events);
	out(user, line);
	snprintf(line, sizeof line, "  %s%-11s%s%llu",
		 sty(st ? st->id : NULL), "records", sty(st ? st->off : NULL),
		 (unsigned long long)records);
	out(user, line);

	if (h->root_pid) {
		snprintf(line, sizeof line, "  %s%-11s%s%lu",
			 sty(st ? st->id : NULL), "traced pid",
			 sty(st ? st->off : NULL),
			 (unsigned long)h->root_pid);
		out(user, line);
	}
}

void kof_inspect_event(const struct kof_evt *e,
		       const struct kof_inspect_style *st,
		       kof_inspect_line out, void *user)
{
	char pend[256], line[512];
	unsigned k;
	int have_pend = 0;

	if (!e || !out)
		return;
	pend[0] = '\0';

	for (k = 0; ; k++) {
		char nm[32], vl[256], one[256];
		uint16_t fo = 0, fl = 0;

		if (!kof_evt_field(e, k, nm, sizeof nm, vl, sizeof vl))
			break;
		(void)kof_evt_field_extent(e, k, &fo, &fl);

		if (!fl) {
			/* A flag row, alone on its line - see the header. */
			if (have_pend) {
				out(user, pend);
				have_pend = 0;
			}
			snprintf(line, sizeof line, "       %s%-11s%.100s%s",
				 sty(st ? st->warn : NULL), nm, vl,
				 sty(st ? st->off : NULL));
			out(user, line);
			continue;
		}
		snprintf(one, sizeof one, "  %s%04X%s %s%-10s%s%-24.24s",
			 sty(st ? st->loc : NULL), (unsigned)fo,
			 sty(st ? st->off : NULL),
			 sty(st ? st->id : NULL), nm,
			 sty(st ? st->off : NULL), vl);
		if (!have_pend) {
			snprintf(pend, sizeof pend, "%s", one);
			have_pend = 1;
		} else {
			snprintf(line, sizeof line, "%s   %s", pend, one);
			out(user, line);
			have_pend = 0;
		}
	}
	if (have_pend)
		out(user, pend);
}

/* ---- what built an object ------------------------------------------------ */

uint32_t kof_inspect_region_entropy(const struct kof_obj_ctx *ctx,
				    kof_buf bytes, uint32_t mask)
{
	/*
	 * Static, and the reason is the size: KOF_SCAN_MAX_EXTENTS ranges is
	 * 64KB, which is more than an interactive tool should put on the stack
	 * and more than is worth allocating per row. kofexamine's own region
	 * loop already keeps one of these for the same reason.
	 *
	 * It is safe here because the callers are the two tools, both of which
	 * draw on one thread. A library that grew a threaded caller would have
	 * to take the buffer from it instead.
	 */
	static struct kof_range ext[KOF_SCAN_MAX_EXTENTS];
	static uint32_t hist[256];
	uint64_t total = 0;
	uint32_t n, i;

	if (!ctx || !ctx->resolve_scan || !bytes.p || !bytes.n)
		return 0;
	n = ctx->resolve_scan(ctx, mask, ext, KOF_SCAN_MAX_EXTENTS);
	if (!n)
		return 0;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < n; i++) {
		uint64_t off = ext[i].off, len = ext[i].len, k;

		if (off >= bytes.n)
			continue;
		if (len > bytes.n - off)
			len = bytes.n - off;
		for (k = 0; k < len; k++)
			hist[bytes.p[off + k]]++;
		total += len;
	}
	return kentropy_hist(hist, total);
}

/* One heap row, or nothing when the heap is absent. */
static void clr_row(const struct kof_inspect_style *st, kof_inspect_line out,
		    void *user, const char *name,
		    const struct kgenome_clr_stream *s)
{
	char line[256];

	if (!s->len)
		return;
	snprintf(line, sizeof line, "  %s%-11s %s0x%llx  %llu byte(s)",
		 sty(st ? st->id : NULL), name, sty(st ? st->off : NULL),
		 (unsigned long long)s->off, (unsigned long long)s->len);
	out(user, line);
}

void kof_inspect_dotnet(const struct kof_obj_ctx *ctx, const void *info,
			const struct kof_inspect_style *st,
			kof_inspect_line out, void *user)
{
	const struct kgenome_pe_info *p;
	const struct kgenome_clr_meta *m;
	char line[256];
	unsigned i;

	if (!ctx || !info || !out || ctx->format != KOF_FMT_PE)
		return;
	p = info;
	m = &p->clr;
	if (!kgenome_clr_present(m))
		return;

	snprintf(line, sizeof line,
		 "  %s%-11s %s0x%llx  %u stream(s)%s",
		 sty(st ? st->id : NULL), "metadata", sty(st ? st->off : NULL),
		 (unsigned long long)m->root_off, (unsigned)m->streams_read,
		 m->streams_read < m->streams ? "  (fewer than declared)" : "");
	out(user, line);

	clr_row(st, out, user, "#~", &m->tables);
	clr_row(st, out, user, "#Strings", &m->strings);
	clr_row(st, out, user, "#US", &m->us);
	clr_row(st, out, user, "#Blob", &m->blob);
	clr_row(st, out, user, "#GUID", &m->guid);

	if (m->res_len) {
		snprintf(line, sizeof line,
			 "  %s%-11s %s0x%llx  %llu byte(s)",
			 sty(st ? st->id : NULL), "resources",
			 sty(st ? st->off : NULL),
			 (unsigned long long)m->res_off,
			 (unsigned long long)m->res_len);
		out(user, line);
	}

	/*
	 * The anomalies, spelled out rather than as a hex word. They are the
	 * difference between "this heap is empty" and "this heap is somewhere
	 * this object does not reach", and a reader cannot tell those apart
	 * from the rows above.
	 */
	for (i = 0; i < KGENOME_CLR_ANOM_COUNT; i++) {
		if (!(m->anomalies & (1u << i)))
			continue;
		snprintf(line, sizeof line, "  %s%-11s %s%s",
			 sty(st ? st->warn : NULL), "", sty(st ? st->warn : NULL),
			 kgenome_clr_anomaly_name(i));
		out(user, line);
	}
}

void kof_inspect_toolchain(const struct kof_obj_ctx *ctx, const void *info,
			   kof_buf bytes,
			   const struct kof_inspect_style *st,
			   kof_inspect_line out, void *user)
{
	char line[256];

	if (!ctx || !info || !out)
		return;

	if (ctx->format == KOF_FMT_PE) {
		const struct kgenome_pe_info *p = info;

		/*
		 * NOT A CLAIM: the runtime needs the CLI header to load the
		 * image at all, so an image carrying one IS managed whatever
		 * else it says. It also changes what every other row means -
		 * the entry point is a token rather than code, and the text
		 * section holds IL - which is worth knowing before reaching
		 * for a disassembler.
		 */
		if (p->clr_len) {
			snprintf(line, sizeof line,
				 "  %s%-11s %s.NET  runtime %u.%u  metadata %s%s",
				 sty(st ? st->id : NULL), "compiler",
				 sty(st ? st->off : NULL),
				 (unsigned)p->clr_major, (unsigned)p->clr_minor,
				 p->clr_version[0] ? p->clr_version : "?",
				 (p->clr_flags & 1u) ? "  IL only" : "");
			out(user, line);
		}
		/*
		 * The linker's own two bytes. 14.x is a modern MSVC, 6.x an old
		 * one, 2.x the GNU linker, and .NET assemblies conventionally
		 * write 8.0 or 48.0.
		 *
		 * NOTHING VERIFIES THEM and a packer may write anything there -
		 * which is said here, in the code, and not on the row: a caveat
		 * printed beside every value is one nobody reads twice.
		 */
		if (p->linker_major || p->linker_minor) {
			snprintf(line, sizeof line, "  %s%-11s %s%u.%u",
				 sty(st ? st->id : NULL), "linker",
				 sty(st ? st->off : NULL),
				 (unsigned)p->linker_major,
				 (unsigned)p->linker_minor);
			out(user, line);
		}
		return;
	}

	if (ctx->format == KOF_FMT_ELF) {
		const struct kgenome_elf_info *e = info;
		uint32_t i;
		int interp = 0;

		/*
		 * STATIC OR DYNAMIC, from the one structure that decides it: a
		 * PT_INTERP segment names the loader an image needs, and an
		 * image with no interpreter is one nothing has to load for it.
		 */
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (e->seg[i].type == 3u) {   /* PT_INTERP */
				interp = 1;
				break;
			}
		snprintf(line, sizeof line, "  %s%-11s %s%s",
			 sty(st ? st->id : NULL), "linking",
			 sty(st ? st->off : NULL),
			 interp ? "dynamic" : "static");
		out(user, line);

		/*
		 * The compiler's own stamp, which GCC and clang both write into
		 * .comment and neither is obliged to. Absent is common and says
		 * nothing - a stripped binary has none - so the row is left off
		 * rather than reported as unknown.
		 */
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			char txt[80];
			uint64_t off, len, k, w = 0;

			if (strcmp(e->sec[i].name, ".comment"))
				continue;
			off = e->sec[i].file_off;
			len = e->sec[i].file_size;
			if (!bytes.p || !len || off >= bytes.n)
				break;
			if (len > bytes.n - off)
				len = bytes.n - off;
			if (len > sizeof txt - 1u)
				len = sizeof txt - 1u;
			/* NUL separated; the first entry is what built the
			 * object, the rest are the linker's and its inputs'. */
			for (k = 0; k < len; k++) {
				char c = (char)bytes.p[off + k];

				if (!c)
					break;
				if (c >= 0x20 && c < 0x7f)
					txt[w++] = c;
			}
			txt[w] = '\0';
			if (w) {
				snprintf(line, sizeof line, "  %s%-11s %s%s",
					 sty(st ? st->id : NULL), "compiler",
					 sty(st ? st->off : NULL), txt);
				out(user, line);
			}
			break;
		}
	}
}

void kof_inspect_event_verbs(const uint64_t *count, uint32_t keep,
			     const struct kof_inspect_style *st,
			     kof_inspect_line out, void *user)
{
	char pend[160], line[320];
	int vb, have_pend = 0;

	if (!count || !out)
		return;
	pend[0] = '\0';
	for (vb = 1; vb < 32; vb++) {
		char one[160];

		if (!count[vb])
			continue;
		snprintf(one, sizeof one, "  %s%-11s %s%-10llu%s",
			 sty(st ? st->id : NULL),
			 kof_evt_verb_name((uint16_t)vb),
			 sty(st ? st->off : NULL),
			 (unsigned long long)count[vb],
			 (keep & (1u << (unsigned)vb)) ? "" : "hidden");
		if (!have_pend) {
			snprintf(pend, sizeof pend, "%s", one);
			have_pend = 1;
		} else {
			snprintf(line, sizeof line, "%s   %s", pend, one);
			out(user, line);
			have_pend = 0;
		}
	}
	if (have_pend)
		out(user, pend);
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

