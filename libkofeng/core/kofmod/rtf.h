/*
 * rtf.h - the RTF view of an object.
 *
 * The first format here that is SYNTAX rather than structure. Every other parser in
 * this engine finds things by arithmetic - a header field says where the next thing
 * is - and RTF has none of that: it is a stream of braces, control words and text,
 * and where anything sits is decided by reading forward from the start.
 *
 *
 * WHY IT IS WORTH PARSING AT ALL
 *
 * Because of what an RTF can carry rather than what it is. An embedded object is
 * written as \objdata followed by the object HEX ENCODED, and that object is
 * routinely a compound file - which this engine already reads, macros and all. So
 * the whole of the work here is finding the hex and turning it back into bytes; the
 * moment that is done the existing DOCOLE path takes over.
 *
 * That is also the vector: the equation editor exploits of 2017 arrive exactly this
 * way, as an \objdata blob whose class is Equation.3.
 *
 * Measured honestly: of 273 RTF files on this machine only 3 carry \objdata, 26
 * carry \bin and 18 carry \pict. So this corpus does not demonstrate the value -
 * it demonstrates the shape. The format is implemented because it is a real vector
 * that was missing, not because these 273 files argued for it.
 *
 *
 * WHY THE REGIONS ARE SO FEW
 *
 * A control word per region would be the obvious split and it does not survive
 * contact with the format: an ordinary 38KB document holds thousands of them, and
 * a run each would exhaust any extent budget on the first file. So the DATA is
 * carved out - the hex blobs and the raw \bin runs, which is where the bulk and the
 * payload both are - and everything else is one region.
 *
 * That leaves BODY holding control words and text together. It is not a loss: the
 * things worth searching for there are control words like \objupdate, and BODY is
 * small precisely because the blobs were taken out of it.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move or
 * change meaning.
 */

#ifndef KOFENG_RTF_H
#define KOFENG_RTF_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_RTF_INFO_VERSION 1

enum kof_scan_rtf {
	KOF_RTF_BODY_BIT      = 1u << 1,  /* control words and text */
	KOF_SCAN_RTF_OBJDATA  = 1u << 2,  /* hex encoded embedded objects */
	KOF_SCAN_RTF_BINARY   = 1u << 3,  /* \bin runs and \pict data */
	KOF_SCAN_RTF_UNCLAIMED = 1u << 4
};

/* Spelled the long way round so a module reads it as a region and not as a bit. */
#define KOF_SCAN_RTF_BODY KOF_RTF_BODY_BIT

#define KOF_SCAN_RTF_CLAIMED                                                 \
	(KOF_SCAN_RTF_BODY | KOF_SCAN_RTF_OBJDATA | KOF_SCAN_RTF_BINARY)

enum kof_rtf_class {
	KOF_RTF_CLS_BODY = 0,
	KOF_RTF_CLS_OBJDATA,
	KOF_RTF_CLS_BINARY,
	KOF_RTF_CLS_COUNT
};

/*
 * Bounds.
 *
 * Documents on this machine run to 5.7MB and hold at most a handful of embedded
 * objects, so the object cap is far above anything ordinary. The nesting bound is
 * the one that does work: RTF groups nest, a reader has to track depth, and a file
 * of nothing but open braces is two bytes per level.
 */
#define KOF_RTF_MAX_OBJECTS  256u
#define KOF_RTF_MAX_EXTENTS 1024u
#define KOF_RTF_MAX_DEPTH    256u

/* A control word is at most 32 letters by the specification. Anything longer is
 * not a control word, and writing one is a way of hiding a real one behind it. */
#define KOF_RTF_CTRL_MAX 32u

enum {
	KOF_RTF_ANOM_BAD_HEADER   = 1ull << 0,
	KOF_RTF_ANOM_UNBALANCED   = 1ull << 1,  /* braces do not close */
	KOF_RTF_ANOM_DEPTH        = 1ull << 2,  /* nesting past the bound */
	KOF_RTF_ANOM_OBJECTS_FULL = 1ull << 3,
	KOF_RTF_ANOM_EXTENTS_FULL = 1ull << 4,
	KOF_RTF_ANOM_TRUNCATED    = 1ull << 5,  /* a \bin runs past the end */
	KOF_RTF_ANOM_BAD_HEX      = 1ull << 6,  /* an objdata blob is not hex */
	KOF_RTF_ANOM_LONG_CTRL    = 1ull << 7,  /* a control word past 32 letters */
	KOF_RTF_ANOM_OBJUPDATE    = 1ull << 8,  /* the object updates itself on open */
	KOF_RTF_ANOM_OVERLAP      = 1ull << 9
};

struct kof_rtf_object {
	uint64_t data_off;      /* first hex digit of \objdata */
	uint64_t data_len;      /* bytes of hex, whitespace included */
	uint64_t hex_bytes;     /* what it decodes to */
	uint64_t class_off;     /* \objclass name, 0 if absent */
	uint32_t class_len;
	uint32_t suspicious;    /* KOF_RTF_OBJ_* */
};

enum {
	KOF_RTF_OBJ_UPDATE  = 1u << 0,  /* \objupdate: opens without being clicked */
	KOF_RTF_OBJ_OLE     = 1u << 1,  /* decodes to a compound file */
	KOF_RTF_OBJ_OLE1    = 1u << 2,  /* decodes to an OLE1 packaged object */
	KOF_RTF_OBJ_BAD_HEX = 1u << 3
};

struct kof_rtf_info {
	uint32_t version;         /* KOF_RTF_INFO_VERSION */
	uint32_t valid;
	uint64_t anomalies;

	uint32_t n_objects;
	uint32_t max_depth;       /* deepest group nesting reached */
	uint32_t n_controls;      /* control words seen */
	uint32_t n_bin;           /* \bin runs */

	uint64_t region_bytes[KOF_RTF_CLS_COUNT];

	uint32_t n_runs;
	uint32_t reserved0;
	struct {
		uint64_t off, len;
		uint32_t cls;         /* enum kof_rtf_class */
		uint32_t reserved;
	} run[KOF_RTF_MAX_EXTENTS];

	struct kof_rtf_object obj[KOF_RTF_MAX_OBJECTS];
};

static inline const struct kof_rtf_info *kof_rtf(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_rtf_info *)ctx->file_header;
}

#endif /* KOFENG_RTF_H */
