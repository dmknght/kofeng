/*
 * clr.h - the regions of a .NET assembly, named ONCE for every format that can
 * host one.
 *
 * CLR AND NOT CLI, THOUGH THE SPEC SAYS CLI.
 *
 * ECMA-335 calls the runtime the Common Language Infrastructure and names the
 * 72-byte structure at the COM descriptor directory the "CLI header". Those
 * three letters mean something else in this product: an AMSI submission is very
 * often a COMMAND LINE, deobfuscating one is a job this tree will grow, and a
 * file called cli_parse.c would be read as that by everyone who met it before
 * they met the spec. CLR is what pe.h already spells - clr_off, clr_version -
 * so it is also the name the tree was going to use anyway. The spec's own term
 * is kept in prose wherever it names an actual structure.
 *
 * WHY THESE BITS ARE SHARED AND EVERY OTHER FORMAT'S ARE NOT.
 *
 * Every other region set in this directory belongs to one format: bit 2 is
 * KOF_SCAN_PE_CODE in a PE and KOF_SCAN_ELF_CODE in an ELF, and nothing is
 * confused by that because resolve_scan is the format's own - the bit is
 * interpreted by whoever owns the object. KOF_SCAN_ALL is the one exception,
 * and it is an exception because "everything" means the same thing everywhere.
 *
 * A .NET assembly is the second thing that means the same everywhere, for a
 * reason that is about the format rather than about convenience: the assembly
 * is not the container. ECMA-335 puts the metadata inside a PE, and that PE can
 * itself be carried - by an ELF single-file bundle, by a Mono mkbundle image, by
 * an AMSI submission, by a byte array in somebody's heap. The metadata is
 * identical in all of them. A rule about a type name is a rule about the
 * assembly, and having to write it once per host would be writing the same rule
 * about the same bytes because they arrived by different roads.
 *
 * So: these bits mean the same thing in every format that resolves them, and
 * nothing. A format that cannot host an assembly resolves them to no extents,
 * which is what every format already does for a region it has nothing in.
 *
 *
 * BITS 8 AND UP, WHICH IS WHERE THE SHARED SPACE IS.
 *
 * The highest bit any format uses for itself is 7 - PE's RESOURCE, DOCOLE's
 * UNCLAIMED - so 8 through 31 are free in all of them at once. A shared region
 * has to be free EVERYWHERE, not just where it is first used, which is the
 * whole reason they are allocated from the top of the word rather than from
 * wherever the host happened to stop.
 *
 *
 * WHAT THIS COSTS THE HOST'S OWN REGIONS, said because it is a real change.
 *
 * The metadata sits INSIDE a section - .text, always, in every assembly a
 * compiler emits. So a host resolving these must hand those bytes to the CLR
 * regions and not to its own CODE, or the same offset is in two regions and the
 * partition is gone. PE already does exactly this for its resource directory,
 * which sits inside .rsrc: settle_claims ranks the more specific claimant above
 * the section, and the section keeps what is left.
 *
 * The consequence is that KOF_SCAN_PE_CODE on a managed assembly stops
 * returning the metadata. That is the point rather than a side effect - a rule
 * that says "native code" was never meant to be searching a string heap - but a
 * rule written before this that leaned on CODE covering everything will see
 * less.
 */

#ifndef KOFMOD_CLR_H
#define KOFMOD_CLR_H

#include <stdint.h>

/*
 * The six parts of an assembly worth naming separately, and the separation is
 * the point: a name in #Strings and a literal in #US are two different claims
 * about a sample, and a rule that could not tell them apart would be making the
 * weaker one while sounding like the stronger.
 */
enum kof_scan_cli {
	/*
	 * The runtime header (ECMA-335 calls it the CLI header), the metadata
	 * root header, and the stream headers.
	 *
	 * Structure, not content: the runtime version, the entry point token,
	 * where each heap is. A rule keyed here is making a claim about how the
	 * assembly was BUILT - "v2.0.50727" is a .NET 2.0 toolchain, a stream
	 * named "#-" instead of "#~" means the tables are uncompressed, which
	 * is what an obfuscator leaves behind.
	 */
	KOF_SCAN_CLR_HEADER   = 1u << 8,

	/*
	 * The table heap: "#~", or "#-" when the tables are uncompressed.
	 *
	 * Every declaration in the assembly - types, methods, fields, the
	 * imports it P/Invokes - as rows of indices. Reachable as bytes today;
	 * walking the rows needs the heap-size flags and per-table row counts,
	 * and is what a later pass over method bodies will need.
	 */
	KOF_SCAN_CLR_TABLES   = 1u << 9,

	/*
	 * "#Strings": every NAME in the assembly, as UTF-8 - namespaces, type
	 * names, method names, the DLLs it P/Invokes.
	 *
	 * The strongest place in an assembly to key a rule. A name here was
	 * chosen by whoever wrote the code and is what the runtime resolves
	 * against, so it cannot be renamed without the assembly changing
	 * meaning - unlike a literal, which can be encoded, split or built at
	 * run time.
	 */
	KOF_SCAN_CLR_STRINGS  = 1u << 10,

	/*
	 * "#US": the user string heap - every string LITERAL the code loads,
	 * stored as UTF-16LE with a length prefix.
	 *
	 * UTF-16 IS WHY THIS IS ITS OWN REGION rather than part of the blob
	 * heap. A literal here is written 4D 00 5A 00, so an ASCII pattern
	 * never matches it and a byte-level scan for a base64 run sees runs of
	 * length one. A rule for this region wants KOF_DEFINE_STR_WIDE, and
	 * anything that wants to DECODE what is here has to collapse the
	 * encoding first - which is only knowable by knowing you are in #US.
	 */
	KOF_SCAN_CLR_US       = 1u << 11,

	/*
	 * "#Blob" and "#GUID": signatures, constant values, custom attribute
	 * arguments, and the module version id.
	 *
	 * One region for two heaps because both are opaque length-prefixed
	 * bytes with no text in them, and splitting them would be two names for
	 * the same kind of claim. An embedded payload stored as a constant
	 * lands here.
	 */
	KOF_SCAN_CLR_BLOB     = 1u << 12,

	/*
	 * Manifest resources: whole files the assembly carries.
	 *
	 * Named by the runtime header's Resources directory, each one length
	 * prefixed. This is where a loader keeps its second stage, and the
	 * right end state for it is a container module emitting each resource
	 * as a CHILD object - the region exists so that a rule can reach the
	 * area before that module does, and so the bytes are not silently part
	 * of CODE in the meantime.
	 */
	KOF_SCAN_CLR_RESOURCE = 1u << 13
};

/*
 * Every CLR bit, for a host building its own region list. A host that can carry
 * an assembly appends this to its own X-list; nothing else changes.
 */
#define CLR_REGIONS(X)          \
	X(KOF_SCAN_CLR_HEADER)  \
	X(KOF_SCAN_CLR_TABLES)  \
	X(KOF_SCAN_CLR_STRINGS) \
	X(KOF_SCAN_CLR_US)      \
	X(KOF_SCAN_CLR_BLOB)    \
	X(KOF_SCAN_CLR_RESOURCE)

#define KOF_SCAN_CLR_CLAIMED (KOF_SCAN_CLR_HEADER | KOF_SCAN_CLR_TABLES |     \
			      KOF_SCAN_CLR_STRINGS | KOF_SCAN_CLR_US |        \
			      KOF_SCAN_CLR_BLOB | KOF_SCAN_CLR_RESOURCE)

/* "CLR_HDR", "#~", "#Strings", "#US", "#Blob", "CLR_RES", or NULL when the
 * bit is not one of these - so a host can chain this before its own namer. */
const char *kof_clr_region_name(uint32_t bit);

/* One extent in the object, already clipped to it. Zero length means the heap
 * was absent, or was declared outside the bytes that are present - which is
 * ordinary for a submission that was cut short, and is why every consumer reads
 * the length rather than assuming the heap is there. */
struct kof_clr_stream {
	uint64_t off, len;
};

enum {
	/* The metadata root did not start with BSJB. */
	KOF_CLR_ANOM_NO_BSJB      = 1u << 0,
	/* A stream header named a range that is not inside the object. Clipped
	 * rather than dropped, and said. */
	KOF_CLR_ANOM_STREAM_CUT   = 1u << 1,
	/* Two streams claim overlapping bytes - which no compiler emits and
	 * which breaks the partition if honoured, so the later one is dropped. */
	KOF_CLR_ANOM_STREAM_OVER  = 1u << 2,
	/* The tables heap is "#-": uncompressed, physically the same tables
	 * written the long way. Every obfuscator that rewrites metadata leaves
	 * this; almost no compiler does. */
	KOF_CLR_ANOM_TABLES_RAW   = 1u << 3,
	/* More stream headers declared than were readable. */
	KOF_CLR_ANOM_STREAM_SHORT = 1u << 4
};

#define KOF_CLR_ANOM_COUNT 5

/*
 * WHAT A HOST FOUND, all offsets relative to the OBJECT rather than to the
 * metadata root.
 *
 * Object-relative because that is what a region resolver hands back and what a
 * finding's offset means. The root-relative numbers the format actually stores
 * are an implementation detail of reading it, and every consumer that saw them
 * would have to add the same base.
 */
struct kof_clr_meta {
	uint64_t root_off;     /* the metadata root; 0 when there is none */
	uint64_t root_len;     /* its header, version string and stream table */

	struct kof_clr_stream tables, strings, us, blob, guid;
	uint64_t res_off, res_len;   /* the manifest resource area */

	uint16_t streams;      /* as the header declared */
	uint16_t streams_read; /* how many were readable and in range */
	uint32_t anomalies;    /* KOF_CLR_ANOM_* */

	/* The metadata version string, as written - "v2.0.50727", "v4.0.30319".
	 * The closest thing a managed image has to a compiler stamp. */
	char version[32];
};

/* Non-zero when this object carries .NET metadata. */
static inline int kof_clr_present(const struct kof_clr_meta *m)
{
	return m && m->root_off != 0;
}

const char *kof_clr_anomaly_name(unsigned index);

#endif /* KOFMOD_CLR_H */
