/*
 * script.h - which interpreter a script is written for.
 *
 * A KIND, NOT A FORMAT, and the distinction is the whole design.
 *
 * The format axis says how bytes are LAID OUT: where the header is, which
 * regions exist, which parser can read it. By that test php, python, perl and
 * the rest are one format - they have no header, no regions, and no parser can
 * do anything with them that it cannot do with any other text. ctx->subtype is
 * the axis for "read identically, different kind", and it already carries
 * exactly this distinction for ELF (a .so and an executable) and for PE.
 *
 * It is also the only axis with room. KOF_FMT_COUNT is 18 and
 * KOF_TARGET_FIRST_EVENT is 18, so the format space is full to the byte: one
 * more format and the static assert in kofsig.h fires, and raising the ceiling
 * moves every target value already compiled into every database.
 *
 *
 * WHAT IT IS FOR, in one sentence: nobody runs a PHP signature against a Python
 * file. A kind is a PRECONDITION - the host compares it without calling the
 * module - so a rule that declares one is not offered the objects it could only
 * ever answer no about.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_SCRIPT);
 *     KOF_TARGET_SUBTYPE(KOF_SCRIPT_PHP);
 *
 *
 * COVERAGE IS DELIBERATELY PARTIAL, and A WRONG KIND IS WORSE THAN NONE.
 *
 * Anything not named outright stays KOF_SCRIPT_ANY, which is a real answer: a
 * script whose language is not written down is still a script, and the host
 * never filters on kind 0 - see kof_module_precond - so an unrecognised one is
 * offered to every rule. A kind that is merely PROBABLE would do the opposite:
 * it would make every rule for the real language decline the object, silently.
 *
 * Measured, and it is why the "<%" family needs a second marker: "<%@" opens an
 * ASP.NET page and a JSP page and appears in classic ASP, so on its own it
 * named all three ASP.NET - cmdjsp.jsp and cmdasp.asp both came out wrong.
 *
 * NODEJS IS NOT ITS OWN KIND. It is JavaScript with a different set of globals,
 * and a rule about "eval(" or about a wallet-stealing snippet is about the
 * language. KOF_SCRIPT_JS covers both, and a rule that really needs the runtime
 * says so with a marker rather than with a target.
 *
 * The numbers are VALUES, not bits: the host tests 1u << ctx->subtype against
 * the module's mask, so they have to stay below 32. They collide with other
 * formats' subtype values on purpose - KOF_ELF_REL is also 1 - and that is safe
 * because the format is tested first; see the note on ctx->subtype in kofsig.h.
 */

#ifndef KOFENG_SCRIPT_H
#define KOFENG_SCRIPT_H

#include "kofsig.h"

/*
 * X(NAME, value). One list: the enum below, the words ksigbuilder accepts in
 * KOF_TARGET_SUBTYPE, and the set the editor offers all come from it - the same
 * arrangement elf.h uses, and for the same reason. A second copy of this list
 * somewhere else is a copy that falls behind without anything saying so.
 */
#define KOF_SCRIPT_TYPE_LIST(X)                                              \
	X(KOF_SCRIPT_ANY,    0)                                              \
	X(KOF_SCRIPT_SHELL,  1)                                              \
	X(KOF_SCRIPT_PHP,    2)                                              \
	X(KOF_SCRIPT_PYTHON, 3)                                              \
	X(KOF_SCRIPT_PERL,   4)                                              \
	X(KOF_SCRIPT_RUBY,   5)                                              \
	X(KOF_SCRIPT_JS,     6)                                              \
	X(KOF_SCRIPT_PSH,    7)                                              \
	X(KOF_SCRIPT_LUA,    8)                                              \
	X(KOF_SCRIPT_TCL,    9)                                              \
	X(KOF_SCRIPT_ASP,   10)                                              \
	X(KOF_SCRIPT_ASPX,  11)                                              \
	X(KOF_SCRIPT_JSP,   12)                                              \
	X(KOF_SCRIPT_BAT,   13)                                              \
	X(KOF_SCRIPT_VBS,   14)                                              \
	X(KOF_SCRIPT_CFM,   15)

enum kof_script_type {
#define KOF_SCRIPT_TYPE_X(name, val) name = val,
	KOF_SCRIPT_TYPE_LIST(KOF_SCRIPT_TYPE_X)
#undef KOF_SCRIPT_TYPE_X
	KOF_SCRIPT_TYPE_COUNT = 16
};

/* The identifier a signature source writes, to its value - the direction
 * ksigbuilder needs, so it asks this header instead of keeping a copy. */
static inline int kof_script_type_from_name(const char *s, uint32_t *out)
{
#define KOF_SCRIPT_X_FROM(name, val)                                         \
	if (kof_streq_(s, #name)) { *out = (uint32_t)(val); return 1; }
	KOF_SCRIPT_TYPE_LIST(KOF_SCRIPT_X_FROM)
#undef KOF_SCRIPT_X_FROM
	(void)s; (void)out;
	return 0;
}

/* And back, for anything that shows a kind to a person. */
static inline const char *kof_script_type_name(uint8_t v)
{
	switch (v) {
	case KOF_SCRIPT_SHELL:  return "Shell";
	case KOF_SCRIPT_PHP:    return "PHP";
	case KOF_SCRIPT_PYTHON: return "Python";
	case KOF_SCRIPT_PERL:   return "Perl";
	case KOF_SCRIPT_RUBY:   return "Ruby";
	case KOF_SCRIPT_JS:     return "JavaScript";
	case KOF_SCRIPT_PSH:    return "PowerShell";
	case KOF_SCRIPT_LUA:    return "Lua";
	case KOF_SCRIPT_TCL:    return "Tcl";
	case KOF_SCRIPT_ASP:    return "ASP";
	case KOF_SCRIPT_ASPX:   return "ASP.NET";
	case KOF_SCRIPT_JSP:    return "JSP";
	case KOF_SCRIPT_BAT:    return "Batch";
	case KOF_SCRIPT_VBS:    return "VBScript";
	case KOF_SCRIPT_CFM:    return "ColdFusion";
	default:                return "Script";
	}
}

/*
 * THE TWO REGIONS, and there have to be two because every byte of an object
 * belongs to exactly one - the engine's fuzz corpus checks that partition on
 * every parse, and a format that claimed none failed it on the first shebang
 * script it met.
 *
 * The bits are 1 and 2 because the region axis is ONE space shared by every
 * format: bit 1 is HEADERS everywhere and bit 2 is the executable content -
 * CODE in an ELF and in a PE. A rule written over ELF and SCRIPT together can
 * therefore name one range and have it mean the right thing in both, which is
 * the whole reason the numbering corresponds.
 *
 * HEADER is the line that named the interpreter - and ONLY where that line is a
 * thing apart from the program:
 *
 *   a "#!" line            names an interpreter and is not a statement.
 *   a "<%@ ... %>" run     declares the page; the server does not run it as
 *                          code, and its directives are worth naming alone.
 *
 * PHP HAS NO HEADER, and calling its first tag one was wrong about what the
 * file is. "<?php" OPENS A BLOCK OF CODE - it is the first byte of a body, the
 * same as every other "<?php" further down - so a file with several blocks had
 * one of them arbitrarily cut in half and the first piece named something else.
 * The tag belongs to the block it opens, and "?>" to the block it closes.
 *
 * There is no FOOTER for the same reason: "?>" is the end of a body, not a
 * region of its own.
 */
#define KOF_SCAN_SCRIPT_HEADER (1u << 1)
#define KOF_SCAN_SCRIPT_BODY   (1u << 2)

/*
 * AND THE THIRD, WHICH ONLY A SERVER PAGE HAS.
 *
 * A .jsp or .asp is not a program with some text in it, it is TEXT WITH CODE
 * ISLANDS: markup, and inside it runs of "<% ... %>" that the server executes.
 * The two are different languages in one file, and treating the whole of it as
 * the program is wrong in both directions - normalising markup by Java's rules
 * turns "http://x" in an href into a comment, and a marker meant for the
 * program is offered every byte of the page.
 *
 * So BODY keeps its meaning - THE PROGRAM - and becomes several extents, one
 * per island; the markup between them is this. A file with no islands (a shell
 * script, a .php that is all code) has an empty MARKUP and one BODY, which is
 * exactly what it had before this bit existed.
 *
 * Bit 3, which is DATA in the shared region axis - see the note above. Inert
 * content that the thing is about but does not execute is what DATA means in
 * an ELF too, so a rule written over both reads the same way.
 */
#define KOF_SCAN_SCRIPT_MARKUP (1u << 3)


/*
 * The view a module reached for KOF_FMT_SCRIPT gets.
 *
 * Small on purpose: there is no structure here to describe. `kind` is the same
 * value as ctx->subtype and is repeated because a module reads the view for
 * everything else and should not have to know which of the two facts lives
 * where. `tag_len` is how many bytes the thing that named the interpreter took -
 * the shebang line, or "<?php" - so a rule can skip it.
 */
/*
 * HOW MANY CODE ISLANDS ARE KEPT SEPARATELY.
 *
 * MEASURED, because the first number was guessed and a real shell walked
 * straight past it. Over 100 webshells that carry closing tags the island
 * count is 3 at the median, 19 at the ninetieth centile and 122 at the
 * maximum - Ani-Shell.php, which is an ordinary 87 KB php shell and not an
 * outlier in any other respect. Four of the hundred need more than 32.
 *
 * 256 is twice the largest thing measured. The cost is 8 bytes an island in a
 * view the host allocates once per format, so 2 KB - which buys the whole
 * measured population with room over it.
 *
 * WHAT HAPPENS PAST IT CHANGED TOO, and that was the damage. The overflow used
 * to EXTEND THE LAST ISLAND TO THE END OF THE OBJECT, on the argument that
 * markup scanned as code costs a few false candidates while code scanned as
 * markup is code no rule sees. That argument assumed the cap was rarely
 * reached. At 32 it was reached by a real shell and the last island swallowed
 * 67697 of 87075 bytes - 78% of the file, nearly all of it html, declared to
 * be code.
 *
 * And it is no longer only about candidates. The form pass runs the LANGUAGE's
 * rules over whatever BODY names, so markup called code is markup rewritten by
 * php's rules: "//" in an unquoted href read as a comment, the spaces in a
 * sentence closed up. A tail left as MARKUP is still searched by every rule
 * with a whole-object range, which is most of them.
 *
 * So the tail past the cap is markup, and KOF_SCRIPT_ANOM_ISLANDS_FULL says
 * so - a silent cliff is what made the first one survive this long.
 */
#define KOF_SCRIPT_MAX_ISLAND 256u

/*
 * The parse had more code islands than it can describe one at a time.
 *
 * Everything past the cap is reported as markup - see the note above - so a
 * rule targeting BODY does not see it. The bit exists so that is a thing the
 * examiner prints rather than a thing a reader has to deduce from a region
 * that looks short.
 */
#define KOF_SCRIPT_ANOM_ISLANDS_FULL (1u << 0)

struct kof_script_info {
	uint8_t  kind;          /* enum kof_script_type */
	uint8_t  from_shebang;  /* 1 when a "#!" line named it */
	uint16_t n_island;      /* 0 for anything that is not a server page */
	/*
	 * WHERE THE HEADER STARTS, which is not always zero.
	 *
	 * A page opens with html and reaches its "<?php" wherever it reaches
	 * it. The header was [0, tag_len) - everything up TO and including the
	 * tag - so all of that leading markup was declared to be the header.
	 * Measured: 20 of 103 files in the corpus, up to 4072 bytes of html in
	 * one. A header is the thing that NAMED the language, not whatever
	 * happened to come before it, and the bytes before it are markup like
	 * any other markup.
	 */
	uint32_t tag_off;
	/*
	 * HOW LONG THE TAG ITSELF IS - 5 for "<?php", 2 for "<%", the whole
	 * line for a "#!".
	 *
	 * This used to hold where the header ENDED, counted from zero, which is
	 * a different number and disagreed with the name of the field for every
	 * file whose tag is not at offset zero. Two facts now sit in two fields.
	 */
	uint32_t tag_len;
	/*
	 * And how long the HEADER REGION is, from tag_off.
	 *
	 * Separate because they differ: a "<%@" page's header is the whole run
	 * of directives and its tag is three bytes, and php's header is nothing
	 * at all while its tag is five. Zero means the format has no header -
	 * see the note on KOF_SCAN_SCRIPT_HEADER.
	 */
	uint32_t head_len;
	uint64_t anomalies;     /* none defined yet; kept so the row has one */
	/*
	 * The islands, in file order and never merged. Two runs of code with
	 * markup between them are two things a rule may want to talk about
	 * separately - a marker that happens to span the gap would be matching
	 * across text the server never executes together.
	 */
	struct {
		uint32_t off, len;
	} island[KOF_SCRIPT_MAX_ISLAND];
};

/*
 * The parse's answer for this object, the way every other format's header hands
 * one over - so nothing outside the parser casts ctx->file_header by hand.
 *
 * NULL is possible here and is not for most formats: a script is identified by
 * a tag or a shebang and nothing else, so an object can be KOF_FMT_SCRIPT with
 * a parse that refused. Callers check.
 */
static inline const struct kof_script_info *kof_script(
					const struct kof_obj_ctx *ctx)
{
	return (const struct kof_script_info *)ctx->file_header;
}

/* How many code islands the parse found, and 0 for a program - which is the
 * question "is this a page" asked of the object rather than of its bytes. */
static inline uint32_t kof_script_islands_of(const struct kof_obj_ctx *ctx)
{
	const struct kof_script_info *s = kof_script(ctx);

	return s ? s->n_island : 0u;
}

#endif /* KOFENG_SCRIPT_H */
