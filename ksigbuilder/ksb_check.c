/*
 * ksb_check.c - --module, the refusals: what each kind of module may not be,
 *    checked in the source.
 */

#include "ksb.h"

/*
 * ---------------------------------------------------------------------------
 * ONE MODULE, END TO END: the whole of what ksigbuilder --module did.
 *
 * The script is gone. What it was - argument handling, artefact naming, a set
 * of greps over the source, the compiler and linker invocations, the refusals,
 * and the .meta record - is here, in the language the rest of this toolchain is
 * already written in.
 *
 * The reason is not tidiness. A shell script needs a shell, and the platform
 * this engine now builds for does not have one: every recipe that ran grep, sed
 * and awk was a reason a Windows host had to install a POSIX toolchain before
 * it could build a single signature. The last two programs, the compiler and
 * the linker, cannot be removed and are not - they are spawned from here.
 *
 * The greps are the other half of the reason. Reading C source for declarations
 * with a regex cannot tell a declaration from the same words inside a comment,
 * and this file has had a comment stripper since long before it had this mode.
 * ---------------------------------------------------------------------------
 */

/* `#include <kofmod/NAME.h>`, allowing the spaces the preprocessor allows. */
static int src_includes(struct ksb_ctx *ksb, const char *name)
{
	char pat[64];
	const char *p = ksb->decl.src_text;

	if (!p)
		return 0;
	snprintf(pat, sizeof pat, "kofmod/%s.h>", name);
	while ((p = strstr(p, pat)) != NULL) {
		const char *q = p;

		/* Walk back over "<", spaces and "include" to a '#'. */
		while (q > ksb->decl.src_text && q[-1] != '\n' && q[-1] != '#')
			q--;
		if (q > ksb->decl.src_text && q[-1] == '#')
			return 1;
		p += strlen(pat);
	}
	return 0;
}

struct fmt_hdr { const char *hdr; uint8_t fmt; };

static const struct fmt_hdr fmt_headers[] = {
	{ "elf",      KOF_FMT_ELF    },
	{ "pe",       KOF_FMT_PE     },
	{ "macho",    KOF_FMT_MACHO  },
	{ "gzip",     KOF_FMT_GZIP   },
	{ "docole",   KOF_FMT_DOCOLE },
	{ "tar",      KOF_FMT_TAR    },
	{ "sevenzip", KOF_FMT_7Z     },
	{ "bz2",      KOF_FMT_BZIP2  },
	{ "chm",      KOF_FMT_CHM    },
	{ "cab",      KOF_FMT_CAB    },
	{ "lha",      KOF_FMT_LHA    },
	{ "arj",      KOF_FMT_ARJ    },
	/*
	 * zip.h is deliberately absent, and so are the headers of the other
	 * formats whose modules target exactly one anyway.
	 *
	 * zip.h is the one header two formats share, because a zip and a zip
	 * that is a document differ in what is INSIDE them and not in how they
	 * are read. The one-header-one-format rule below would refuse a module
	 * that targets both, which is the ordinary case for an archive module.
	 */
	{ NULL, 0 }
};
/*
 * A module may include exactly one format header, and only for a format it
 * targets.
 *
 * kof_elf() and its siblings cast ctx->file_header, and that cast is sound only
 * because the module cannot run against anything else. Two headers, or a header
 * for a format the module does not declare, and the cast is a promise nothing
 * keeps.
 */
int ksb_check_format_headers(struct ksb_ctx *ksb)
{
	int i, n = 0;
	const char *seen = NULL;

	for (i = 0; fmt_headers[i].hdr; i++) {
		if (!src_includes(ksb, fmt_headers[i].hdr))
			continue;
		n++;
		seen = fmt_headers[i].hdr;
		if (!ksb_target_named(ksb, fmt_headers[i].fmt)) {
			fprintf(stderr, "FAIL: includes kofmod/%s.h but does "
					"not target that format\n",
				fmt_headers[i].hdr);
			return 0;
		}
	}
	if (n > 1) {
		fprintf(stderr, "FAIL: module includes %d format headers; "
				"exactly one is allowed\n"
				"      split it into one module per format\n", n);
		return 0;
	}
	if (n == 1 && (ksb->decl.n_targets > 1 || ksb->decl.any_target)) {
		fprintf(stderr, "FAIL: kofmod/%s.h with %d targets is unsound\n"
				"      kof_<fmt>() casts ctx->file_header; with "
				"more than one target\n"
				"      there is no single view it can return\n",
			seen, ksb->decl.any_target ? (int)KOF_FMT_COUNT : ksb->decl.n_targets);
		return 0;
	}
	return 1;
}

/*
 * WHAT EACH KIND MAY NOT BE, checked in the source rather than hoped for.
 *
 * A detector is not an unpacker and does not describe one; an unpacker has to say
 * which step of opening an object it is.
 */
int ksb_kind_checks(struct ksb_ctx *ksb, int kind)
{
	int n_kind = ksb->decl.simple[SD_ANALYZE_STEP].count;

	if (kind == 0) {                        /* detector */
		if (n_kind) {
			fprintf(stderr, "FAIL: KOF_ANALYZE_STEP on a detector; "
					"it describes an unpacker\n");
			return 0;
		}
		return 1;
	}

	/* unpacker */
	if (!n_kind) {
		fprintf(stderr, "FAIL: an unpack module must declare "
			"KOF_ANALYZE_STEP\n"
			"      KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK)  - it "
			"hid a program\n"
			"      KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP)   - it "
			"carried files\n");
		return 0;
	}
	return 1;
}

/*
 * The lower-bound test must not be written twice.
 *
 * The declaration is what the host trusts and filters on; a copy in the body is
 * a second statement of the same rule, and the one the host cannot see is the
 * one that wins silently.
 */
int ksb_check_size_body(struct ksb_ctx *ksb)
{
	if (ksb->decl.size_min && strstr(ksb->decl.src_text, "ctx->obj_size <")) {
		fprintf(stderr, "FAIL: obj_size has a lower-bound test in the "
				"body and also a KOF_TARGET_SIZE_MIN "
				"declaration;\n      the declaration is "
				"authoritative, so remove the check from "
				"kof_scan\n");
		return 0;
	}
	return 1;
}
