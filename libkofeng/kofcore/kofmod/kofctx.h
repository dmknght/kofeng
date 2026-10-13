/*
 * kofctx.h - struct kof_obj_ctx: everything a module knows about the object it
 * was asked about.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFCTX_H
#define KOFENG_KOFCTX_H

#include <stdint.h>
#include <range.h>   /* struct kof_range - core */
#include "kofcontent.h"

struct kof_obj_ctx {
	uint8_t  format;      /* enum kof_format */
	uint8_t  arch;        /* enum kof_arch */

	/*
	 * What KIND of thing this format holds, in the format's own vocabulary.
	 *
	 * A third prefilter axis beside format and architecture, and the reason it is
	 * an axis rather than more format values is the test that separated DOCOLE
	 * from DOCZIP: those are different formats because a document's parts live in
	 * different PLACES in each, so a module written for one cannot run against the
	 * other. A shared library and an executable are read identically - same
	 * parser, same view, same regions - so they are one format and two kinds.
	 *
	 * Deliberately NOT normalised across formats, unlike arch. The value is
	 * whatever the format's own header field says: for ELF it is e_type verbatim,
	 * for PE it is composed from the DLL characteristic and the subsystem, and
	 * those two are no more comparable than EM_AARCH64 is to
	 * IMAGE_FILE_MACHINE_ARM64. So the values are declared in elf.h and pe.h and
	 * the numbers COLLIDE between formats - KOF_ELF_REL and KOF_PE_DLL are both 1.
	 *
	 * That is safe rather than sloppy, because the target is tested first: the
	 * subtype test is only ever reached for an object of a format the module
	 * already declared. The build refuses a module that names one format's
	 * subtypes while targeting another, so the collision cannot be reached by
	 * accident.
	 *
	 * Zero for a format with no such notion, which is every container.
	 */
	uint8_t  subtype;
	/*
	 * WHICH FAMILY OF THAT FORMAT, when the subtype itself is not known.
	 *
	 * KOF_SUBFAM_NONE for every format that has no such notion, which is
	 * all of them but KOF_FMT_SCRIPT. It exists because a script can be
	 * recognised down to a family and no further: "<% ... %>" is asp, aspx
	 * or jsp and a page carrying no directive does not say which, so the
	 * subtype is 0 and the family is not. See kof_module_precond, which
	 * declines a module whose declared subtypes all sit in some OTHER
	 * family - the one thing the family is certain about.
	 *
	 * This was the `reserved` byte, so the layout is unchanged.
	 */
	uint8_t  subfamily;

	uint64_t obj_size;
	uint64_t entry_off;   /* KOF_NA if not applicable, KOF_BROKEN if unresolved */

	/*
	 * Turn a region mask into the ranges it names: sorted by offset, touching or
	 * overlapping ranges coalesced, clipped to the object. Returns how many were
	 * written, 0 if the mask names nothing present.
	 *
	 * Set by whichever parser identified the object, and reached through this
	 * pointer so the host never dispatches on format. NULL when nothing
	 * identified the object; only KOF_SCAN_ALL is answerable then, and the host
	 * answers that itself. Unrecognised bits are ignored, not refused.
	 */
	uint32_t (*resolve_scan)(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				 struct kof_range *out, uint32_t max_out);

	/*
	 * Where the bytes of ONE entry are, for a format that has entries.
	 *
	 * The same shape as resolve_scan and answering the other question. A region
	 * is what a byte IS; an entry is what a byte BELONGS TO, and the two are not
	 * interchangeable: a compound file's macro region is every VBA stream at
	 * once, while decompressing is a thing done to one stream. Joining the region
	 * gives a concatenation with no boundaries in it, which is why this exists.
	 *
	 * The ranges are in object coordinates and are NOT settled: a stream is a
	 * chain and its sectors arrive in the order the chain gives, which is the
	 * order its bytes go back together in. Sorting them would corrupt the stream.
	 *
	 * NULL for a format whose entries have no bytes of their own, and for every
	 * format that has no entries.
	 */
	uint32_t (*resolve_entry)(const struct kof_obj_ctx *ctx, uint32_t index,
				  struct kof_range *out, uint32_t max_out);

	/*
	 * The parsed structure for format, or NULL if the format has none.
	 * A void pointer so that adding a format neither widens this struct nor
	 * puts a pointer in front of every module that will never use it.
	 * Modules do not name it: they call the accessor their format header
	 * provides, so its type and layout stay internal.
	 */
	const void *file_header;

	/* Byte level access to the object. */
	const struct kof_content *content;



	/*
	 * Attach a finding: a level, and an index into the name table the build
	 * emitted beside the blob.
	 *
	 * The name string never enters the blob. A family gets renamed on
	 * reclassification far more often than its logic changes, and resolving
	 * through a table fails visibly - a stale table yields "unknown" rather than
	 * some other family's name. The authored name is only the family part; the
	 * host prefixes the format and architecture it already established.
	 *
	 * Called through KOF_SCAN_MATCH, so reporting and returning cannot come apart.
	 */
	void (*report)(const struct kof_obj_ctx *ctx, uint32_t level,
		       uint32_t name_id);

	/*
	 * The same thing said without deciding anything: what the module worked
	 * out, for whoever is watching.
	 *
	 * A finding changes a verdict and ends the module. A note changes nothing
	 * and the module carries on - "this is UPX 1.3 with NRV2E", "the block
	 * chain stopped after four of them" - which is the difference between an
	 * answer and the reasoning behind it. Nothing in a normal scan looks at
	 * these; a host that wants them says so, and a host that does not pays one
	 * NULL test per note.
	 *
	 * Named through the same table a finding uses, so note text never enters
	 * the blob either, and a note carries one number because the interesting
	 * ones are nearly always "which version" or "how many".
	 *
	 * Called through kof_debug, which does not return - and is spelled in lower
	 * case for that reason. The upper case macros in this header are the ones
	 * that change control flow; KOF_SCAN_MATCH reports AND returns, and a reader
	 * should be able to tell the two apart without looking either of them up.
	 */
	void (*debug)(const struct kof_obj_ctx *ctx, uint32_t name_id,
		      uint64_t value);

	/* Host state the accessors need. Opaque, and no module has any reason to
	 * touch it; it is here so the accessors can take the context rather than
	 * reach for a global, which keeps them usable from more than one thread. */
	const void *priv;

	/*
	 * WHAT THIS OBJECT CONTAINS, as the parse found it. See struct kof_entry.
	 *
	 * Sets *out to a table the PARSE owns - it lives in the view, so it is
	 * valid as long as the view is - and returns how many entries are in it.
	 * NULL for a format with no entries, which is most of them, and returning
	 * zero is the same answer as not having the pointer.
	 *
	 * Read by the host to decide what to open, and by a tool to show what is
	 * inside without opening anything. Those were two separate walks before,
	 * and the viewer's own was built by scraping the scan's callback - which
	 * is how one missing initialiser deleted the root object from its tree and
	 * took every region row with it.
	 */
	uint32_t (*entries)(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out);

	/*
	 * HOW THIS OBJECT'S CARRIED FILES ARE FOUND. See enum kof_embed_search.
	 *
	 * The other half of carried files, and it is a SEPARATE FIELD from the
	 * mask below because it has three answers and a mask has only two.
	 *
	 * A PE or an ELF can hold a file that was read in at compile time -
	 * //go:embed, an #included blob, a resource the linker placed in
	 * .rodata - and NOTHING in the structure says so: the section table
	 * says ".rodata, 2MB, read-only data", not that some range of it is a
	 * ZIP. A parser cannot declare that without guessing, and guessing is
	 * the one thing it must not do. So the engine searches for magic and
	 * validates a header, which is format independent and belongs in one
	 * place.
	 *
	 * What is NOT format independent is where looking is worthwhile, and
	 * that is all these two fields say.
	 *
	 * WHY NOT A MASK ALONE, which is how this was first written: the
	 * comment then claimed zero meant BOTH "the whole object" and "the
	 * opt-out", which cannot both be true. An object with NO PARSE AT ALL
	 * carries a zeroed context - a raw buffer, an AMSI bytecode block,
	 * anything the sniff chain declined - and that object is the single
	 * most important one to search, since a raw dropper's payload is found
	 * no other way. A PDF is the opposite: /EF already said where every
	 * attachment is, and searching anyway is what made one document produce
	 * the same attachment twice. Spelling both as zero makes one of them
	 * wrong whichever way the default goes.
	 */
	uint8_t  embed_search;   /* enum kof_embed_search */
	uint8_t  embed_pad[3];

	/*
	 * The regions to search, read ONLY when embed_search is
	 * KOF_EMBED_SCOPED. Meaningless otherwise, and the engine does not look
	 * at it - so a parser that sets a mask and forgets the policy gets
	 * today's behaviour rather than a silent narrowing.
	 */
	uint32_t embed_scope;
};

#endif /* KOFENG_KOFCTX_H */
