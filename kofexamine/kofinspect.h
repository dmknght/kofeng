/*
 * kofinspect.h - what the database already knows about one object.
 *
 * A scan answers one question: did any module decide something. This answers the
 * question underneath it - which of the database's markers are in this object at
 * all, whose they are, and for each module that did not fire, WHY it did not.
 *
 * The distinction is the whole point. "Three of Mirai's five markers are here"
 * and "Mirai's markers are all here but Mirai targets ELF and this is a PE" and
 * "the markers are here but not in the region Mirai looks in" are three different
 * findings that a scan collapses into the same silence. The first is a variant to
 * write, the second is nothing, and the third is a build or packing difference -
 * and telling them apart by hand is hours of work that the engine already has the
 * facts for.
 *
 * Nothing here is a verdict and nothing here should be read as one. A module's
 * logic is compiled code in the pack; the most this can say is which of the
 * strings it declared are present. Whether that would have satisfied its
 * conditions is a question only the module can answer, and the answer is the scan.
 */

#ifndef KOFENG_KOFINSPECT_H
#define KOFENG_KOFINSPECT_H

#include <stdint.h>
#include "../libkofeng/core/kofcore.h"
#include "../libkofeng/kofdb/kofdb.h"

/* ---- what a format is ------------------------------------------------------
 *
 * Everything a consumer needs in order to see an object the way the engine does,
 * and nothing about how to show it. Rendering is left out on purpose: the two
 * front ends in this tree render nothing alike - one prints lines, one paints
 * panes - and a print callback here would be the printer's shape imposed on
 * both.
 */
struct kof_inspect_fmt {
	uint32_t    view_size;
	int       (*sniff)(kof_buf);
	int       (*parse)(kof_buf, void *, struct kof_obj_ctx *);
	const uint32_t *regions;
	uint32_t    n_regions;
	const char *(*region_name)(uint32_t);
	const char *(*anomaly_name)(unsigned);
	uint64_t  (*anomalies)(const void *);
};

/*
 * Identify and parse. Returns the format, fills `ctx`, and hands back a view the
 * caller frees with free(). NULL when nothing claimed the bytes, in which case
 * `ctx` is zeroed and `*view_out` is NULL - and that is a real answer rather
 * than a failure: an object nothing parses still has bytes and still has markers
 * in it.
 *
 * There is no "sniffed but refused" answer to be had here, and that is a
 * property of the parsers rather than an omission: every sniff already
 * establishes what its parse re-checks before giving up. Measured over 2500
 * corpus files and 1080 crafted near-format ones - not one reached a parse that
 * then failed. A parser loosened later would change that, and this is the place
 * the answer would have to come back through.
 */
const struct kof_inspect_fmt *kof_inspect_identify(kof_buf, struct kof_obj_ctx *,
						   void **view_out);

/* The subtype in the format's own vocabulary - ET_EXEC, DLL - or NULL. A number
 * would be no use: the same value means REL for an ELF and DLL for a PE. */
const char *kof_inspect_subtype_name(uint8_t fmt, uint8_t sub);

/* An ELF program or section header type, by its name - NULL when it has none. */
const char *kof_inspect_ptype_name(uint32_t t);
const char *kof_inspect_shtype_name(uint32_t t);

/*
 * Why a module is on the list.
 *
 * Ordered by how much attention it deserves, so sorting by this value is sorting
 * by interest. COMPLETE first because every marker being present is the strongest
 * thing this can observe; INELIGIBLE last because it means the module never ran
 * and its markers being present says nothing about it.
 */
enum kof_touch_kind {
	KOF_TOUCH_COMPLETE = 0,  /* every marker it declares, in the regions it names */
	KOF_TOUCH_PARTIAL,       /* some of them, in the regions it names */
	KOF_TOUCH_ELSEWHERE,     /* present in the object, none in those regions */
	KOF_TOUCH_INELIGIBLE     /* a precondition ruled it out; it never ran */
};

/* One declared marker, and where it turned out to be. */
struct kof_touch_str {
	const uint8_t *bytes;    /* into the pack's string pool, not owned */
	uint16_t       len;
	uint8_t        kind;     /* enum kof_pack_str_kind */
	uint8_t        flags;    /* KOF_STR_ICASE | KOF_STR_FULLWORD */
	/*
	 * The pattern's identity across the WHOLE database, not within its pack -
	 * pack-local ids plus the pack's base, the same number the engine's memo
	 * is keyed by. Two rows carrying one uid are two modules that picked the
	 * same bytes, which is worth being able to see.
	 */
	uint32_t       uid;

	/*
	 * Two answers, not one, and they are the reason this file exists.
	 *
	 * `at` is where the marker is in the object, searched over everything, so a
	 * viewer can highlight it whether or not it counts for this module. `in_rgn`
	 * is whether it is inside the regions this module actually names, which is
	 * the only one that would have counted. A marker with `at` set and `in_rgn`
	 * clear is the interesting case: present, and in the wrong place.
	 */
	uint64_t       at;       /* KOF_BROKEN when absent from the object */
	int            in_rgn;
};

/* One module, and how close this object came to it. */
struct kof_touch {
	const struct kof_module *mod;
	const char             *family;     /* "" when the module declared none */
	uint32_t                maltype;
	enum kof_touch_kind     kind;

	/*
	 * Did this module actually report something on this object.
	 *
	 * A separate fact from every other one here, and the only one that is a
	 * verdict. Every marker being present is not it: a module's conditions
	 * are compiled code, and "all five markers are here" says nothing about
	 * whether the module asked for all five, asked for two of them, or asked
	 * for something else entirely alongside. Only a scan knows, so it is
	 * the caller's scan result that fills this, handed to kof_touch_object.
	 */
	int                     fired;
	const char             *fired_name;  /* the variant it reported, if any */

	/* Set only for KOF_TOUCH_INELIGIBLE: the precondition that ruled it out,
	 * as the word a reader needs rather than as a mask to decode. */
	const char             *ruled_out;

	/*
	 * The variants this module can report, in declaration order.
	 *
	 * Listed rather than resolved, because which one a module WOULD report is
	 * a property of its logic and its logic is compiled code. What can be said
	 * is which names it holds, and that is worth saying: it is the string a
	 * scanner would print, so a row here can be matched against a verdict by
	 * eye instead of by guessing which family the family name belongs to.
	 */
	uint32_t                n_names;
	const char            **name;       /* n_names of them, owned; entries are not */
	uint32_t               *name_id;    /* the source line each was written on */

	uint32_t                n_str;      /* markers the module declares */
	uint32_t                n_present;  /* found anywhere in the object */
	uint32_t                n_in_rgn;   /* found where the module looks */
	struct kof_touch_str   *str;        /* n_str of them, owned */
};

/*
 * Every module the object touches at all, most interesting first.
 *
 * A module none of whose markers are present and which reported nothing is not
 * on the list: it is not evidence, and at database scale it would be the whole
 * list - most of a database has no business with any given object.
 *
 * `ctx` must be the parsed context for `buf` - the regions come from the parse,
 * so a module's declared range cannot be resolved without it. An object nothing
 * identified still works: no format means no region resolves, every marker is
 * ELSEWHERE, and that is the truthful answer rather than an empty one.
 *
 * Returns 0 on allocation failure, in which case nothing is written.
 */
/*
 * `finding` are the names a scan reported for THIS object, as the engine
 * composes them - "ELF-a32/Botnet:Mirai-0i0bq". Passed in rather than applied
 * afterwards because they change which modules belong on the list at all: a
 * module that fired has to be there whether or not it declares a marker, and a
 * structural detection declares none.
 */
int  kof_touch_object(struct kof_engine *eng, kof_buf buf,
		      const struct kof_obj_ctx *ctx,
		      const char *const *finding, uint32_t n_finding,
		      struct kof_touch **out, uint32_t *n_out);

void kof_touch_free(struct kof_touch *v, uint32_t n);


/* The word for a kind, for a caller that prints one. */
const char *kof_touch_kind_name(enum kof_touch_kind);

#endif /* KOFENG_KOFINSPECT_H */
