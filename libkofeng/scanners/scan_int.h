/*
 * scan_int.h - what the units of the scanner share with each other, and with
 * nothing else.
 *
 * scan.c used to be one file of six thousand lines, and "this stage owns this
 * state" had stopped being checkable: walking a tree, opening an object,
 * normalising it, matching it and naming the verdict sat in one translation
 * unit, every part with a `static` helper the others reached for. The units
 * are split by WHICH STAGE of the pipeline they are, and each says in its first
 * lines what that is. A helper two units need is declared HERE with the `sx_`
 * prefix that marks it as internal to this family. Nothing outside scanners/
 * includes this header.
 */

#ifndef KOF_SCAN_INT_H
#define KOF_SCAN_INT_H

#include "scan.h"

#include <pthread.h>

/*
 * Iterative, with its own stack of pending directories.
 *
 * Not recursive, and no depth ceiling: a filesystem may legally be deeper than any
 * number picked here, and putting the limit on the C stack makes the failure mode a
 * stack overflow - a crash, in a library, out of a directory tree. On the heap, running
 * out is reported instead. max_depth is policy for callers who want it, not a safety
 * net.
 *
 * Paths grow rather than living in a fixed buffer, so an over-long one fails visibly
 * instead of being skipped without a word.
 */
struct pending {
	char    *path;
	uint32_t depth;
};

/*
 * The work queue of a parallel walk: paths in, one worker each takes one out.
 *
 * BOUNDED, and that is the only interesting decision in it. An unbounded queue
 * would let the producer run the whole directory tree ahead of the workers and
 * hold every path in the tree at once - 14 000 strings here, and no bound at all
 * on a larger one. A bound makes the producer wait when the workers are behind,
 * which is exactly when it should.
 *
 * A ring of pointers rather than a list: the paths are strdup'd by the producer
 * and freed by whoever takes them, so ownership moves with the pointer and there
 * is nothing to walk on shutdown but the slots still holding one.
 */
struct mtq {
	pthread_mutex_t lock;
	pthread_cond_t  can_put, can_take;
	char          **slot;
	size_t          cap, head, tail, n;
	int             closed;      /* the producer has finished enumerating */
	int             aborted;     /* a callback asked to stop */
};

struct walk {
	struct kof_scanner *sc;
	const struct kof_scan_option *opt;
	kof_on_object cb;
	void *user;

	struct pending *stack;
	size_t          n, cap;

	char   *path_buf;     /* reusable, holds the entry currently being examined */
	size_t  path_cap;

	int      aborted;
	int      out_of_memory;
	uint64_t objects;
	/* Objects that reported something, or that the scan could not finish.
	 * Read across one file by scan_file - see the note there on why a file
	 * with either is never remembered. */
	uint64_t found;

	/* Set only on the producer of a parallel walk: where a regular file goes
	 * instead of being scanned here. NULL in every single threaded walk, and
	 * the one branch that tests it is the whole difference between them. */
	struct mtq *q;
};

/* ---- the walk (scan_walk.c, for now scan.c) ------------------------------- */
int  sx_push_dir(struct walk *w, const char *path, size_t len, uint32_t depth);
void sx_read_dir(struct walk *w, const char *dir, uint32_t depth);
void sx_scan_file(struct walk *w, const char *path);

/* A module's report, taken: finding, verdict slot, repair, infected spans. */
struct kof_finding *sx_mod_report(struct kof_scanner *sc,
				  const struct kof_obj_ctx *ctx,
				  const struct kof_scan_option *opt,
				  struct kof_result *res,
				  const struct kof_module *m, uint32_t level);

/* ---- one object (scan.c) --------------------------------------------------- */
void sx_scan_object(struct kof_scanner *sc, kof_buf buf,
		    const struct kof_scan_option *opt, struct kof_result *out,
		    uint32_t pdepth, int from_packer,
		    const char *inherit_predict, uint8_t as_fmt);

/* ---- the parallel walk (scan_mt.c) ---------------------------------------- */
void sx_mtq_put(struct walk *w, const char *path, size_t len);

/* ---- the verdict (scan_verdict.c) ---- */
int sx_verdict_take(struct kof_scanner *sc, const struct kof_finding *f, 	int all_matches);
void sx_finding_str(const struct kof_scanner *sc, 	const struct kof_obj_ctx *ctx, 	const struct kof_module *m, struct kof_finding *f);

/* ---- the verdict (scan_verdict.c) ---- */
void sx_verdict_vals(struct kof_finding *f, const struct kof_obj_ctx *ctx, 	 const struct kof_module *m, uint32_t engine);

/* ---- the normalised view (scan_norm*.c) ------------------------------------ */
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


/*
 * THE SAME EXECUTABLE, SAID PLAINLY, AS ONE CHILD.
 *
 * A UTF-16 marker is the same letters with a zero between each one, so an
 * ASCII pattern does not match it; a long run of padding is bytes every rule
 * is swept across for nothing. executables.h turns both into a shorter view
 * that says the same thing, and this is where that view becomes an object.
 *
 * A CHILD, NEVER A REWRITE. The parent keeps every byte and every offset it
 * had: cure_patch writes the file at an offset, kof_find_str_where hands a
 * module an offset to read a layout from, and a module author has no way to
 * know which view an offset came from. So the view gets its own object with
 * its own offset space and its own name, which is what the scan tree is for.
 *
 * ONE CHILD AND NOT ONE PER REGION. The presence table is 32MB built per
 * object, so N children cost N builds; one child costs one. The view is the
 * whole object normalised rather than a bag of pieces, so the ranges inside it
 * still mean what they meant.
 *
 * WHAT IT IS WORTH, measured before it was written: 2.6% of bytes on 293 ELF64
 * from /usr/bin and 1.1% on 1129 PE. That is not the reason it is here - the
 * reason is the wide marker and, later, the decoded payload - and the floor
 * below exists so the 97% of objects with nothing to gain do not pay for a
 * copy to find that out.
 */
#define NORM_MIN_OBJ   (4u << 10)   /* below this there is nothing to save */

/*
 * The executable region, in the one bit ELF and PE agree on: KOF_SCAN_ELF_CODE
 * and KOF_SCAN_PE_CODE are both 1u << 2. Written as the bit rather than as
 * either name because norm_emit serves both formats and naming one of them
 * would read as though the other were an oversight.
 */
#define NORM_CODE_MASK     (1u << 2)

/* 7.5 bits per byte, which is DENSE_EIGHTHS in emu_unpack.c and is measured
 * there. Not shared through a header: the two are the same number for the same
 * reason rather than one derived from the other, and a later measurement may
 * move one without moving the other. */
#define NORM_DENSE_EIGHTHS 60u

#define NORM_MIN_SAVE  16u          /* per cent, or it is not worth an object */

/*
 * THE PARENT'S REGIONS, GATHERED SO THE VIEW CAN CARRY THEM.
 *
 * One entry per extent rather than per region, because a region is a list: an
 * ELF with three executable segments has three CODE extents and a view that
 * named one of them would hide the other two.
 *
 * Bits 1 to 7, which covers both vocabularies - an ELF names five kinds and a
 * PE seven, and both number from 1. Bit 0 is KOF_SCAN_ALL, which is the whole
 * object and needs no carrying; the symbol bits are 30 and 31 and are extents
 * over the canonical RECORDS, not over the file, so no byte of this buffer is
 * ever theirs.
 */
#define NORM_RGN_BITS 7u

/*
 * WHICH OF THEM MUST NOT MOVE, AS A BIT PER BYTE.
 *
 * HEADERS and CODE, and the two share their bit numbers across the formats -
 * KOF_SCAN_ELF_HEADERS and KOF_SCAN_PE_HEADERS are both 1u << 1, CODE both
 * 1u << 2 - so one test serves an ELF and a PE without asking which this is.
 * That is a coincidence of two independent choices and not a rule, so it is
 * checked here rather than relied on silently.
 */
#define NORM_KEEP_MASK ((1u << 1) | (1u << 2))

/* ---- the normalised view (scan_norm*.c) ---- */
void sx_norm_emit(struct kof_scanner *sc, struct kof_obj_ctx *ctx,       kof_buf buf);
uint32_t sx_norm_gather(struct kof_obj_ctx *ctx, struct kof_src_region *r, 	    uint32_t cap);
void sx_bits_set(uint8_t *b, uint64_t from, uint64_t to);
void sx_bits_clr(uint8_t *b, uint64_t from, uint64_t to);
void sx_norm_keep_bits(uint8_t *keep, uint64_t n, 	   const struct kof_src_region *r, uint32_t nr, 	   uint32_t keep_mask);
void sx_norm_keep_exec(uint8_t *keep, uint64_t n, 	   const struct kof_elf_info *e, 	   const struct kof_src_region *r, uint32_t nr);
void sx_norm_keep_exec_pe(uint8_t *keep, uint64_t n, 	      const struct kof_pe_info *e, 	      const struct kof_src_region *r, uint32_t nr);
uint32_t sx_norm_syms(struct kof_scanner *sc, struct kof_obj_ctx *ctx, 	  uint8_t *out, uint32_t cap);

/* ---- stages of one object (scan.c and the stage units) ---- */
int sx_prefilter(const struct kof_module *m, const struct kof_obj_ctx *ctx,      uint32_t present, struct kof_stats *st,      struct kof_result *out);
void sx_need_multi(struct kof_scanner *sc, struct kof_obj_ctx *ctx);
void sx_need_plague(struct kof_scanner *sc, struct kof_obj_ctx *ctx);
uint32_t sx_heur_run(struct kof_scanner *sc, struct kof_obj_ctx *ctx, 	 const struct kof_scan_option *opt, 	 struct kof_result *out, uint32_t phase, 	 uint32_t present, const char **predict);
int sx_script_forms(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, 	const struct kof_scan_option *opt, uint32_t pdepth);
void sx_heur_object(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, 	const struct kof_scan_option *opt, uint32_t pdepth, 	uint32_t partial, struct kof_result *out);
/*
 * WHERE THE OPEN STAGE IS FOR ONE OBJECT. One value, not a flag per question:
 * FRESH until the first step asks, then REFUSED (the gate said no), ACTIVE
 * (modules are being asked), FAMILY (the predicted family opened it, so the
 * general steps are skipped) or DONE (sx_open_end has run).
 */
enum kof_open_state {
	KOF_OPEN_FRESH = 0,
	KOF_OPEN_REFUSED,
	KOF_OPEN_ACTIVE,
	KOF_OPEN_FAMILY,
	KOF_OPEN_DONE
};

struct kof_open {
	enum kof_open_state state;
	int                 applies;    /* something wanted to open this object */
};

void sx_open_step(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		  const struct kof_scan_option *opt, struct kof_result *res,
		  uint32_t pdepth, uint32_t want, const char *predict,
		  enum kof_analyze step, struct kof_open *o);
uint32_t sx_open_end(struct kof_scanner *sc, struct kof_obj_ctx *ctx,
		     const struct kof_scan_option *opt, struct kof_open *o);
void sx_identify(struct kof_scanner *sc, kof_buf buf, struct kof_obj_ctx *ctx,      uint8_t as_format, const void *as_view, uint32_t as_view_len);
void sx_lib_facts(struct kof_scanner *sc, struct kof_obj_ctx *ctx,       kof_buf buf);
uint32_t sx_declared_resolve_scan(const struct kof_obj_ctx *ctx, 		      uint32_t scan_mask, struct kof_range *out, 		      uint32_t max_out);
uint32_t sx_regions_present(const struct kof_obj_ctx *ctx, uint32_t wanted);
uint32_t sx_sym_halves_present(const struct kof_obj_ctx *ctx, 		   uint32_t wanted);
void sx_dense_code_unread(struct kof_scanner *sc, 	      const struct kof_obj_ctx *ctx);
void sx_plague_feed(struct kof_scanner *sc, struct kof_obj_ctx *ctx, 	   uint32_t present, int from_packer);
void sx_multi_prepass(struct kof_scanner *sc, struct kof_obj_ctx *ctx, 	  uint32_t present);
void sx_mod_begin(struct kof_scanner *sc, const struct kof_module *m);
void sx_take_repair(struct kof_scanner *sc, struct kof_result *res);
void sx_take_infected(struct kof_scanner *sc, struct kof_result *res);
const struct kof_module *sx_kof_scan_derived_by(const struct kof_scanner *sc);
int sx_unp_eligible(const struct kof_scanner *sc, 	const struct kof_module *m, 	const struct kof_obj_ctx *ctx, 	const struct kof_scan_option *opt, 	uint32_t want);
int sx_unp_is_family(const struct kof_scanner *sc, 	 const struct kof_module *m, const char *predict);

/* ---- ceilings the unpack stage and scan.c share --------------------------- */
#include "objtree.h"
#include "../detectors/overlord/matchers/kofmultimatch.h"
#include "../detectors/heur/kofheur.h"
#include "../kofcore/kofmod/heur.h"
#include "../kofcore/kofdebug.h"
#include "../detectors/pathogen/kofdiag.h"
#include "../analyzers/parsers/binaries/pe/pe_sym.h"
#include "../kofcore/kofmod/kofsym.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/parsers/binaries/disasm/xref.h"
#include "../analyzers/trueline/trueline.h"
#include "../kofcore/kofmod/elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"
#include "../analyzers/normalize/executables.h"
#include "scan_int.h"


/*
 * HOW MANY LAYERS OF PACKING THE INTERPRETER WILL GO THROUGH.
 *
 * Counted in PACKER layers, not tree depth - a tar inside a tar is not two
 * layers of packing, and pdepth already makes that distinction for the
 * heuristic. Emulator output is marked as a packer's, so it adds a layer like
 * any other unpacked payload.
 *
 * Two, because a packer wrapped in another packer is a real thing and a third
 * layer has not been seen: no object in the malware corpus reaches even the
 * second by this route. The reason for a ceiling at all is cost - each layer is
 * its own budget, up to 256 million instructions, so an object crafted to nest
 * could otherwise spend minutes of a scan on itself.
 */
#define EMU_MAX_PACKER_DEPTH 1u

/*
 * How many times one scan will honour a rule's ask for the emulator.
 *
 * A number and not a fraction of the tree, because the thing being bounded is
 * wall time on a tree of any size. 512 is what the measured population supports
 * with room to spare: the rule that asks today fires on 18 of 4398 malware
 * objects and on none of 5252 clean ones, so a scan that reaches this ceiling
 * is looking at something no measured corpus resembles - and the honest thing
 * then is to stop interpreting, not to keep going.
 */
#define HEUR_EMU_MAX KOF_SCAN_EMU_MAX

/* ---- the pipeline (scan_pipeline.c) ------------------------------------------- */
/*
 * THE STAGES OF ONE OBJECT, in the order they run. Each is a row of the pipeline
 * table in scan_pipeline.c with a function that takes the object's kof_pipeline.
 *
 * The opening steps are the module ABI's own (enum kof_analyze) and keep its
 * order; what is new is that the rest of the object's life has names too, so a
 * module can say WHERE it runs instead of the engine deciding by which loop
 * happened to call it. Detectors are not all at the end: a detector that is
 * about what an unpacker produced runs between steps, and the table is what lets
 * that be a declaration and not another loop.
 */
enum kof_stage {
	KOF_STAGE_FACTS = 0,    /* identify, regions, library facts - the host    */
	KOF_STAGE_DETECT,       /* detectors on the object as it arrived          */
	KOF_STAGE_EXAMINE,      /* rules about what it IS, before it is opened    */
	KOF_STAGE_UNWRAP,       /* the opening steps, in enum kof_analyze order   */
	KOF_STAGE_UNPACK,
	KOF_STAGE_DECRYPT,
	KOF_STAGE_CARVE,
	KOF_STAGE_NORMZ,        /* the object said plainly - the host's own      */
	KOF_STAGE_SCRIPT,       /* the second form of a script                    */
	KOF_STAGE_SERVE,        /* what the engine completed, declared            */
	KOF_STAGE_VERDICT,      /* rules about what the stages above produced     */
	KOF_STAGE_RECONCILE,    /* a parent's guesses against its children        */
	KOF_STAGE_MODEL,        /* the scored model                               */
	KOF_STAGE_COUNT
};

/*
 * EVERYTHING ONE OBJECT'S STAGES HAND EACH OTHER, in one record that lives for
 * the object and no longer. It replaces the locals of what was one function of
 * five hundred lines and the loose scanner fields that carried the same facts
 * between the parts of it: a stage reads what it needs from here and writes what
 * the next one needs here, and the table in scan_pipeline.c is the only thing that
 * says which stage follows which.
 */
struct kof_pipeline {
	/* inputs, fixed for the object */
	struct kof_scanner              *sc;
	const struct kof_scan_option    *opt;
	struct kof_result               *out;
	kof_buf                          buf;
	uint32_t                         pdepth;
	int                              from_packer;
	const char                      *inherit_predict;
	uint8_t                          as_fmt;
	/* the object's context, built by FACTS */
	struct kof_obj_ctx               ctx;
	uint32_t                         present;   /* regions and symbol halves that exist */
	/* what EXAMINE collected */
	uint32_t                         want;
	const char                      *predict;
	/*
	 * HOW MANY OF out->v A DETECTOR PUT THERE, counted before the
	 * heuristics ran.
	 *
	 * Not out->n, and the difference is the whole reason this field exists.
	 * By the time this struct is filled the rule heuristics have appended
	 * their own findings, and a rule heuristic is not a verdict that the
	 * object has been identified - it is usually the opposite, "I could not
	 * sx_identify this", which is exactly the object whose remaining steps
	 * matter most. Stopping on one measured six samples where the parent
	 * said Heur:Truncated and the payload one layer down said Botnet:Mirai:
	 * the chain would have ended on the weaker of the two statements and
	 * deleted the stronger.
	 *
	 * Whether a heuristic MAY stop the chain is a question for the rule
	 * that wrote it rather than for the engine - see enum kof_eng_want,
	 * which has no word for it yet. Until it does, only a detector counts.
	 */
	uint32_t                         det_n;
	/* A rule said its finding is a conclusion - see KOF_ENG_CONCLUDE.
	 * Kept apart from det_n because the two are different claims and the
	 * note on det_n is a measurement about detectors only. */
	int                              concluded;
	/* where the pipeline is, and where the OPEN stage is for this object */
	enum kof_stage                   stage;
	enum kof_analyze                 step;
	struct kof_open                  open;
};

/* One object through every stage. */
void sx_pipeline_run(struct kof_pipeline *p);
void sx_obj_begin(struct kof_scanner *sc);

#endif /* KOF_SCAN_INT_H */
