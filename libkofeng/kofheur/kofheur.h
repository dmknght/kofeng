/*
 * kofheur.h - scoring an object by the suspicious traces it carries.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS NOT
 *
 * A signature says "these bytes are that family". This says something weaker and
 * differently useful: "this object carries traces that clean software does not".
 * It never names a family and never reports INFECT, because the evidence it works
 * from cannot establish identity - only that something is worth a look.
 *
 * WHY A SCORE RATHER THAN A RULE
 *
 * The traces are individually weak and individually forgeable, and no one of them
 * decides anything. Measured over 6523 malware and 13638 clean ELF objects - the
 * clean set deliberately including 1482 legitimately packed binaries from six
 * different packers - not one trace separated cleanly on its own. What did
 * separate was their sum, and the sum needed the values to be MEASURED rather
 * than assigned: the same anomaly is worth 2.75 nats in a file and 5.71 nats in
 * the image recovered from inside a packer, and nobody guesses a ratio like that.
 *
 * THE THREE PARTS
 *
 *   1. facts   - what the parse and the unpackers already worked out, normalised
 *                into fixed-width fields with no strings to re-parse.
 *   2. values  - one number per fact, a log likelihood ratio measured on a
 *                corpus. Data, not code: a table the model owns, so a later
 *                build can ship a better table without touching this file.
 *   3. score   - the sum, raised by how deep inside a packer the object sits.
 *
 * COST WHEN IT IS OFF
 *
 * Nothing. The collector is not entered, no facts are gathered, and the scan path
 * runs exactly as it did before - see kof_scan_option.heur_level. That is the
 * point of keeping collection inside this module rather than in the parser: an
 * engine built for scanning should not pay for a feature nobody asked for.
 */

#ifndef KOFENG_KOFHEUR_H
#define KOFENG_KOFHEUR_H

#include <stdint.h>
#include "../core/kofcore.h"

struct kof_obj_ctx;

/*
 * WHICH TRACE, AS A NUMBER.
 *
 * An anomaly is (format, bit) because the same bit means different things in
 * different formats - bit 3 is one thing in an ELF and another in a PE - and a
 * table keyed by the pair is the only one that stays right when a parser adds a
 * flag. Everything that is not an anomaly gets an id above the anomaly space.
 */
/*
 * A TRACE IS EITHER AN ANOMALY OR A FACT ABOUT HOW THE OBJECT WAS REACHED.
 *
 * Anomalies are named by their format AND their mask, never by a bit index. The
 * masks are the parser's own constants, so a term reads KOF_ELF_ANOM_SECTAB_MISSING
 * and cannot drift when a parser inserts a flag. Writing indices by hand was tried
 * and six of seven were wrong.
 */
struct kof_heur_anom_term {
	uint8_t  format;         /* enum kof_format */
	uint64_t mask;           /* KOF_<FMT>_ANOM_* */
	int32_t  centinats;
	/*
	 * One word for what this trace suggests, and it lives in the TABLE.
	 *
	 * The report needs to say more than a number, and the only thing entitled
	 * to name what a trace means is whoever measured it. Putting the word in
	 * the model rather than in a switch is what lets a heuristic authored in
	 * bases/ bring its own vocabulary without the engine learning it.
	 */
	const char *guess;
};

enum kof_heur_fact {
	/* The object came out of something that packs executables. Weak on its
	 * own - legitimate software is packed too, measured at 2.9% of a clean
	 * corpus - and it is here because it CONDITIONS everything else. */
	KOF_HEUR_F_PACKED = 0,
	/* An unpacker recognised its own format and could not finish. Legitimate
	 * packing unpacks cleanly; measured 0 of 13638 clean objects. */
	KOF_HEUR_F_UNPACK_PARTIAL,
	/* A database marker is present but outside every region its module
	 * searches - the marker is there and the rule could never have fired. */
	KOF_HEUR_F_MARKER_OUTSIDE,
	/* Two or more markers of one family, where that family did not fire. */
	KOF_HEUR_F_FAMILY_PARTIAL,
	KOF_HEUR_F_COUNT
};

struct kof_heur_flag_term {
	uint32_t fact;           /* enum kof_heur_fact */
	int32_t  centinats;
	const char *guess;
};

/*
 * The model: values, which formats they were measured on, a bar, and how much
 * deeper evidence is worth.
 *
 * All of it is data. A heuristic authored in bases/ would supply this struct and
 * nothing else would change - which is why the scorer takes it as an argument
 * rather than reading a global.
 */
struct kof_heur_model {
	const struct kof_heur_anom_term *anom;
	uint32_t n_anom;
	const struct kof_heur_flag_term *flag;
	uint32_t n_flag;

	/*
	 * WHICH FORMATS THIS MODEL HAS ANYTHING TO SAY ABOUT.
	 *
	 * A format outside this mask is NOT SCORED, which is a different answer
	 * from scoring zero. Zero would read as "measured, and it looks clean";
	 * not scored says the honest thing, that nobody has measured this
	 * population and a number here would be borrowed from another one.
	 *
	 * The values this build ships were measured on ELF and nothing else. A
	 * PE, and a doczip in particular, has a different anomaly vocabulary and
	 * a different clean population - the traces that separate an ELF may
	 * hardly exist there. Adding a format means measuring it, not widening
	 * this mask.
	 */
	uint32_t formats;        /* 1u << enum kof_format */

	/* The score at or above which the object is reported. Set from the
	 * highest score any clean object reached, plus a margin. */
	int32_t  bar_centinats;
	/*
	 * How much one packer layer multiplies the evidence found inside it,
	 * in percent. 100 leaves it unchanged.
	 *
	 * Measured and NOT yet used: the corpus held six objects two layers deep,
	 * three malicious and three clean, so there is no basis for a number
	 * above 100. It is here because the shape is right and the data is what
	 * is missing - and a later corpus can set it without a code change.
	 */
	/*
	 * WHAT ONE PACKER LAYER IS WORTH ON ITS OWN.
	 *
	 * Added per layer, and the reason it has to be ADDED rather than
	 * multiplied is the whole of why depth did not work before.
	 *
	 * depth_gain_pct multiplies the evidence found INSIDE an object, and the
	 * object that matters after a good unpack has none: a packer that did
	 * its job hands back a clean, well formed program. Measured on
	 * 1f85b0c47432... - Ezuri wrapping UPX wrapping TeamTNT - the middle
	 * layer scores 386 and the payload, which is the malware, scores 0.
	 * Multiplying zero by any gain leaves zero, so the deepest object, the
	 * one every layer was put there to hide, could never be reached at all.
	 *
	 * So the layering is evidence in its own right. Nothing legitimate is
	 * wrapped twice: a packer exists to stop a file being read, and doing it
	 * again says the first was not considered enough.
	 */
	int32_t  depth_centinats;

	uint32_t depth_gain_pct;
};

/*
 * What one object carries, gathered once.
 *
 * Fixed width, no pointers into anything that can move, no strings. It is built
 * for being scored, not for being printed.
 */
struct kof_heur_facts {
	uint8_t  format;
	uint8_t  packer_depth;   /* packer layers between this object and the file */
	uint64_t anomalies;
	uint32_t flags;          /* 1u << enum kof_heur_fact */
};

#define KOF_HEUR_FL(f) (1u << (uint32_t)(f))

/* The parse's anomaly word for whatever this object turned out to be, or 0.
 * One place that knows the eleven view layouts, so nothing else has to. */
uint64_t kof_heur_anomalies(const struct kof_obj_ctx *ctx);

/*
 * Score, in centinats, and whether there was a model to score with.
 *
 * Returns 0 and leaves *out untouched when this model covers no such format -
 * the caller then knows to say nothing rather than to say "clean". A trace with
 * no term is worth nothing, which is how a table drops one that measured as
 * noise without needing to be edited around it.
 */
int      kof_heur_score(const struct kof_heur_model *m,
			const struct kof_heur_facts *f, int32_t *out,
			const char **guess);

/* The model this build ships. NULL when it holds no terms. */
const struct kof_heur_model *kof_heur_default(void);

#endif /* KOFENG_KOFHEUR_H */
