/*
 * kofcontent.h - struct kof_content: the vtable of services the host gives a
 * module, reached as ctx->content.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFCONTENT_H
#define KOFENG_KOFCONTENT_H

#include <stdint.h>
#include "cell.h"
#include "kofdecode.h"
#include "kofregion.h"
#include "kofentry.h"

/*
 * Bounded reads over the object under scan, addressed by offset from its start.
 *
 * Deliberately not a pointer to the bytes:
 *
 *   - a module cannot read out of bounds through a call that checks, so the
 *     untrusted surface collapses to these few functions
 *   - the addressing model survives a change of source: when input arrives as a
 *     stream the host implements these differently and no module changes
 *   - hot loops stay on the host side, optimised once
 *
 * An out of range read yields zero rather than faulting. A module that needs to tell
 * "zero byte" from "past the end" compares against obj_size first.
 */
struct kof_obj_ctx;

struct kof_content {
	uint8_t  (*rd8) (const struct kof_obj_ctx *, uint64_t off);
	uint16_t (*rd16)(const struct kof_obj_ctx *, uint64_t off);
	uint32_t (*rd32)(const struct kof_obj_ctx *, uint64_t off);
	uint64_t (*rd64)(const struct kof_obj_ctx *, uint64_t off);

	int      (*memeq)(const struct kof_obj_ctx *, uint64_t off,
			  const void *pat, uint32_t len);

	/*
	 * Look for a declared string in a declared range. Non-zero if present.
	 *
	 * Both arguments are indices the build assigned to KOF_DEFINE_STR and
	 * KOF_TARGET_RANGE, so the pattern bytes are neither here nor in the blob:
	 * the host holds them in the record beside it. Reached through kof_find_str.
	 *
	 * A call rather than a precomputed bit, so the host is free to answer from a
	 * table it filled in one batched pass or to search on the spot and remember.
	 * The module cannot tell, so batching stays a host side decision.
	 */
	int (*find_str)(const struct kof_obj_ctx *, uint32_t str_id,
			uint32_t range_id);

	/*
	 * The same declared string, at an offset the module worked out.
	 *
	 * A different operation from find_str and priced differently: find_str_at
	 * is one comparison the length of the pattern, find_str_in searches an
	 * ad-hoc window. Neither resolves a region and neither is memoised, because
	 * the offset is a runtime value and there is nothing constant to key on.
	 *
	 * Both bounds check against the object. A module may hand over any offset -
	 * one read out of the file, one computed from it - and a comparison that
	 * walks off the mapping is the failure this layer exists to prevent.
	 */
	int (*find_str_at)(const struct kof_obj_ctx *, uint32_t str_id,
			   uint64_t off);
	int (*find_str_in)(const struct kof_obj_ctx *, uint32_t str_id,
			   uint64_t off, uint64_t len);

	uint32_t (*csum)(const struct kof_obj_ctx *, uint64_t off, uint32_t len);

	/*
	 * PRODUCING CHILD OBJECTS - unpack modules only.
	 *
	 * Both are NULL for a detector, the same way resolve_scan is NULL when
	 * nothing identified the object. A detect module that calls one gets
	 * nothing rather than a special case somewhere in the host, and the rule
	 * that only an unpacker produces is a property of the pointers rather than
	 * a check that could be forgotten.
	 *
	 * window() is the cheap one: a child that is already a contiguous range of
	 * this object - an overlay, a stored archive entry - costs no copy and no
	 * memory, because it is the parent's mapping seen through a different
	 * offset. It spends no byte budget, since nothing was produced; depth and
	 * the child count are what bound it.
	 *
	 * emit() is for bytes that did not exist before: decompressed output.
	 * It returns zero once the budget is gone, and a module must stop when it
	 * does. The budget is the host's and is checked here, at the write, rather
	 * than after a buffer has already been filled - by then the memory has been
	 * spent, which is the whole failure being prevented. Whether the output
	 * ends up in memory or in an unnamed temporary file is decided here too,
	 * and a module cannot tell.
	 *
	 * child() closes the object being emitted and starts the next.
	 *
	 * inflate() is emit() with a decoder in front of it: the module names a
	 * DEFLATE stream inside this object and the host decodes it straight into
	 * the sink. Output never crosses back into the module, so a bomb is refused
	 * by the same code that refuses an ordinary emit and the decoder stops the
	 * moment it is. Returns bytes produced.
	 *
	 * A host service for the reason find_str is one: the module supplies the
	 * decision - THIS range, THIS format - and the host does the work over the
	 * bytes. A decoder inside a module would pull its input one byte at a time
	 * through rd8, an indirect call per byte of a compressed stream, and every
	 * module that met a DEFLATE stream would carry its own copy of the decoder.
	 *
	 * Standard and shared belongs here; a transform peculiar to one family - an
	 * XOR key, a bespoke run encoding, a packer's own scheme - is the module's
	 * own business and is written with emit. That is why both exist.
	 */
	int (*window)(const struct kof_obj_ctx *, uint64_t off, uint64_t len);
	int (*emit)(const struct kof_obj_ctx *, const void *bytes, uint32_t n);
	int (*child)(const struct kof_obj_ctx *);

	/*
	 * `out_hint` is what the container SAYS the output will be, and it is a
	 * hint in the strict sense: it sizes a buffer and bounds nothing. The
	 * bounds are the host's budgets, which never read it.
	 *
	 * It exists because not every decoder can stream. DEFLATE bounds a back
	 * reference at 32KB, so inflate runs in fixed memory and ignores this.
	 * NRV2 bounds it at nothing - a match may reach any byte already produced
	 * - so its output has to be addressable in full while it decodes, and
	 * something has to decide how large that is before the first byte. A
	 * container that states the size is the only party that knows; a container
	 * that lies gets a buffer of the size it asked for, clamped to what the
	 * ceiling allows, and a decode that stops when it fills.
	 */
	uint64_t (*unpack)(const struct kof_obj_ctx *, uint32_t method,
			   uint64_t off, uint64_t len, uint64_t out_hint);

	/*
	 * Decode the front of a stream into the module's own buffer.
	 *
	 * The same decoders as `unpack`, writing where the caller can read
	 * instead of into the object being produced. It exists for the case
	 * where a container's layout is described by a header the container
	 * itself compressed: UPX writes a chain of blocks whose first one is
	 * the original ELF header and its program headers, and where the later
	 * blocks belong is written there and nowhere else. Without this a
	 * module can produce those bytes but never read them, so it can only
	 * lay the blocks end to end - which is wrong for every ELF whose
	 * segments are not adjacent.
	 *
	 * Bounded by `cap`, which is the caller's own buffer: nothing is
	 * allocated, so a length out of the object cannot size anything here.
	 * A back reference reaches only bytes already produced, so the first
	 * `cap` bytes decode the same whether or not the rest ever does.
	 *
	 * Returns bytes written - less than `cap` when the stream ends first,
	 * zero when nothing could be decoded.
	 */
	uint32_t (*unpack_peek)(const struct kof_obj_ctx *, uint32_t method,
				uint64_t off, uint64_t len,
				void *out, uint32_t cap);

	/* Where a declared string is, rather than whether. KOF_BROKEN if absent. */
	/*
	 * WHAT THE NEXT CHILD IS, when the producer knows.
	 *
	 * The companion of name_next and it works the same way: declared just
	 * before the child is made, consumed by the making, cleared whatever
	 * happens - so a claim can never be worn by the child after.
	 *
	 * A CLAIM AND NOT A GUESS. A container declares what its own structure
	 * told it: a PDF knows a stream is page content because /Contents said
	 * so. It must NOT declare what it would have to guess - the contents of
	 * an attachment are the sniff chain's business, and a wrong declaration
	 * runs the wrong parse and hides what the sniff would have found.
	 *
	 * KOF_FMT_UNKNOWN is a legitimate thing to declare and means exactly
	 * that: I will not say. It is also what happens if this is never
	 * called.
	 */
	void (*child_format)(const struct kof_obj_ctx *, uint8_t fmt);

	/*
	 * WHAT THE NEXT CHILD IS FOR - enum kof_entry_kind.
	 *
	 * Beside child_format and NOT the same thing. A format GATES: it decides
	 * which modules are offered the object, so naming one too precisely
	 * takes the object away from rules that would have seen it. A kind gates
	 * nothing. It says what the thing is for, which is what a policy reads
	 * and what a reader needs - and it is safe to state even when a format
	 * would not be.
	 *
	 * IT IS ALSO THE CHILD'S NAME WHEN NOTHING NAMED IT. name_next takes a
	 * range in the object, because a name is text the file already contains
	 * and a module has nowhere to build one - but most things a container
	 * carries have no name in them at all. A PDF page stream is not called
	 * anything; neither is a font program. Measured on one document, 12 of
	 * 14 recovered objects arrived anonymous, and a reader saw a column of
	 * identical rows. The kind is the honest name for those: not what it is
	 * called, but what it is.
	 */
	void (*child_kind)(const struct kof_obj_ctx *, uint32_t kind);

	/*
	 * WHAT THE NEXT CHILD WILL NEED DONE TO IT, said by the module that is
	 * about to make it.
	 *
	 * An unpacker knows something about its output that no later look at
	 * the bytes recovers. MPRESS decompresses an image whose code is
	 * ordinary and whose payload the PROGRAM decrypts at run time: the
	 * executable section averages 4.6 bits per byte, so the emulator's
	 * entropy gate correctly says "not packed" and wrongly concludes
	 * "nothing to run". The module knew better before it produced a byte.
	 *
	 * SAID RATHER THAN INFERRED, and the difference is the point. Every
	 * inference tried here was weak - "a PE importing fewer than four
	 * functions" needed a threshold nobody had measured, and giving the
	 * child a header at all destroyed the stronger evidence, which was
	 * that it had none. A declaration is a fact about how the object came
	 * to exist, and it cannot be erased by what is done to the object
	 * afterwards.
	 *
	 * `want` is a KOF_ENG_* mask (enum kof_eng_want). `level` is the lowest
	 * --heur the ask is honoured at, so a module can say "this is worth the emulator, but only for a caller
	 * who asked for that much work" - the engine compares it and drops the
	 * ask rather than the module testing a level it cannot see.
	 *
	 * The engine still bounds what it grants: the packer depth ceiling and
	 * the whole-scan emulation ceiling apply to it, so a directory of crafted
	 * files cannot spend a scan.
	 */
	void (*child_want)(const struct kof_obj_ctx *, uint32_t want,
			   uint32_t level);

	/*
	 * WHERE THE ORIGINAL PROGRAM WILL BE ONCE THIS OBJECT'S LOADER HAS RUN.
	 *
	 * A RANGE HERE IS A FETCH, NOT A HOP, and that decides which packers
	 * can use this at all. The run ends the moment an instruction is
	 * fetched from one of these addresses, so a range only means "handover"
	 * when the loader NEVER executes inside it. That holds for MPRESS and
	 * for Oreans' protectors, where the program sits in sections the stub
	 * only ever writes to. It does not hold for PECompact, which
	 * decompresses into the section its own entry point is in: naming that
	 * section ends the run at instruction 0, and naming the others ends it
	 * six instructions later at the stub's first jump - both measured on
	 * 007 Spy.exe. That family has no range to name, and declaring nothing
	 * is the correct answer for it.
	 *
	 * About the CHILD this module is about to produce, and carried with it:
	 * it is what the interpreter needs before it starts on that child, so
	 * that a fetch from one of these ranges ends the run as a handover
	 * instead of running on into the program itself. The module that
	 * unpacked the loader is the only thing that knows, and it knows before
	 * the child exists.
	 *
	 * The engine cannot work this out. For one packer the program is in the
	 * sections that have no file bytes; for another - Oreans' - those are
	 * the LOADER and the program is in the sections that do, encrypted. The
	 * two are mirror images and nothing structural tells them apart, so the
	 * module that recognised the container is the only thing that knows.
	 *
	 * `rva` is an address in the object's own image, not a file offset.
	 * Declaring nothing is normal and means "stop the run the usual ways".
	 */
	void (*emu_watch)(const struct kof_obj_ctx *, uint64_t rva,
			  uint64_t len);

	/*
	 * WHICH ENTRY THE NEXT CHILD IS THE CONTENT OF.
	 *
	 * The third of the three declarations a producer makes before handing a
	 * child over, and the one that ties it back to what the parse said. A
	 * host can then show ONE row for a stream rather than two - the coded
	 * extent and the decoded content are one thing in two states, and
	 * without this nothing could tell that.
	 *
	 * The entry's OWN index, which is kof_entry.index - the format's number
	 * for it, not a position in the table. Producers that are not opening a
	 * declared entry - an emulator writing a payload, a packer peeling a
	 * stub - simply do not call this, and the child reports
	 * KOF_ENTRY_NONE.
	 */
	void (*child_entry)(const struct kof_obj_ctx *, uint32_t index);

	/*
	 * RUN AN ENTRY'S WHOLE CODING CHAIN AND HAND BACK THE CHILD.
	 *
	 * The host side of kof_entry.coding, and the reason that field is an
	 * array. A module cannot do this itself: a chain needs a buffer between
	 * its steps, and a module has no writable memory by design.
	 *
	 * `index` is the entry's OWN index - kof_entry.index, the format's
	 * number for it - not a position in the table.
	 *
	 * It refuses rather than half-decodes. An entry flagged
	 * KOF_ENT_F_CODED_UNKNOWN has a step this build cannot express, and
	 * running the steps it CAN express would produce bytes that are neither
	 * the coded form nor the original - so it reports UNSUPPORTED and makes
	 * nothing. Returns the bytes produced, zero when it produced none.
	 */
	uint64_t (*unpack_chain)(const struct kof_obj_ctx *, uint32_t index);

	uint64_t (*find_str_where)(const struct kof_obj_ctx *, uint32_t str_id,
				   uint64_t off, uint64_t len);

	/*
	 * Copy a named region into the object being produced, joined up.
	 *
	 * For the formats that scatter one logical thing across the file. A CFB
	 * stream is a chain of sectors in whatever order the allocator left them, so
	 * the region that names it is a list of extents rather than a range - and a
	 * pattern lying across the join between two of them is in neither extent. The
	 * only way to find it is to have the bytes contiguous, and the only way to
	 * have them contiguous is to copy.
	 *
	 * The module supplies the decision - THIS region - and the host does the work,
	 * for the same reason unpack() is shaped that way. Every byte goes through
	 * emit(), so the copy is charged to the same budget and stopped by the same
	 * ceiling as a decompression; there is no second pool and no way for a module
	 * to gather more than the host allows.
	 *
	 * `cap` is the module's own limit, applied on top of the host's and never
	 * above it: a format knows what an honest instance of it costs, and 4MB of
	 * macros is already far past anything a document has a reason to hold. Zero
	 * means the host's ceiling alone.
	 *
	 * Returns bytes emitted, which is short of the region when a cap bound. The
	 * module closes it with kunp_rcstruct_done() - gathering does not, because a module may
	 * want more than one region in one child.
	 */
	uint64_t (*gather)(const struct kof_obj_ctx *, uint32_t region_mask,
			   uint64_t cap);

	/*
	 * Name the NEXT child this module produces.
	 *
	 * Given as a range in THIS object, never as a string: the name is already in
	 * the file - an archive entry name, a stored filename - so a module says
	 * where it is and the host reads it, which is the same idiom unpack() and
	 * find_str_where() use. A module has no writable data to build a string in
	 * anyway.
	 *
	 * One call rather than a named variant of each producer, because there are
	 * two ways to make a child - a window and an emit - and a format that stores
	 * some entries and compresses others uses both for entries that are named the
	 * same way. Stamping the next child covers both and covers whatever producer
	 * is added later.
	 *
	 * The host SANITISES what it reads, and that is not decoration. The name was
	 * written by whoever built the file and it ends up in a report, a log, maybe
	 * a web page: a terminal escape inside it can forge an entire output line,
	 * and a newline splits one record into two. A scanner that prints archive
	 * names verbatim is a scanner whose report is written by the thing it is
	 * scanning.
	 *
	 * Cleared once used, and cleared when the module returns - a name set for a
	 * child that was never produced does not drift onto the next one.
	 */
	void (*name_next)(const struct kof_obj_ctx *, uint64_t off, uint64_t len);
	/*
	 * AND A NAME THE MODULE KNOWS RATHER THAN READS.
	 *
	 * name_next takes the child's name from bytes already in the object,
	 * which is right for a container: the entry name is in the archive. A
	 * packer has no such bytes. What it has is what it worked OUT - which
	 * build of the packer wrote this file - and that is worth carrying on
	 * the child, because the child is the thing that build produced and a
	 * reader looking at it in kofviewer has no other way to know.
	 *
	 * The string is copied; it may be a literal. It is spent by the next
	 * child like every other pending claim.
	 */
	void (*note_next)(const struct kof_obj_ctx *, const char *text);

	/*
	 * READ BACK, AND PATCH, WHAT THIS MODULE HAS ALREADY PRODUCED.
	 *
	 * unpack_peek decodes the FRONT of a stream into a caller's buffer,
	 * which answers "the layout is in the first block". It does not answer
	 * the other shape: a container whose header depends on something buried
	 * in the content. MPRESS is that shape - the original entry point and
	 * the import table are written in a fix-up stub that the packer
	 * compressed along with the program, and measured over six files that
	 * stub sits between 1.8 KB and 2.0 MB into the decompressed content.
	 * Peeking cannot reach it and a module may not keep a buffer that size.
	 *
	 * So: produce the content, read the stub back out of what was produced,
	 * and patch the header that was emitted before any of it was known.
	 * Offsets are from the start of the child, whether it is still in
	 * memory or has spilled to a file.
	 *
	 * produced_read returns the byte count, which is short at the end of
	 * what exists. produced_poke writes over bytes ALREADY EMITTED and
	 * refuses anything past them: it is for correcting a field, never for
	 * appending, and emit remains the only way to make the child longer.
	 */
	uint32_t (*produced_read)(const struct kof_obj_ctx *, uint64_t off,
				  void *out, uint32_t cap);
	int (*produced_poke)(const struct kof_obj_ctx *, uint64_t off,
			     const void *bytes, uint32_t n);

	/*
	 * THE PARENT AGAIN, AS THE START OF THIS CHILD - see DESIGN-object-
	 * pipeline.md section 5.
	 *
	 * For a module that CHANGES an object rather than building a new one.
	 * `strxor_tab_00.c` alters 7799 bytes of a 5353472 byte object; written
	 * as an emit it has to re-emit all of it in file order, which means
	 * sorting its own edit list and resolving its own overlaps - and both
	 * were got wrong, once dropping 114353 bytes and once letting a record
	 * swallow its neighbour.
	 *
	 * With this it declares the derivation, then uses produced_poke to
	 * change the ranges it knows about, in any order. The engine holds the
	 * bytes; the module holds only what it found.
	 *
	 * AND IT IS WHAT STOPS A MODULE MEETING ITS OWN OUTPUT. A derived
	 * object is never offered back to the module that derived it, which
	 * replaces three hand-written recursion guards - two of which were
	 * wrong when they were written. A NEW object is still offered to
	 * everyone, so a zip inside a zip, or MPRESS under MPRESS, is unchanged.
	 *
	 * Charged like any other production: the child is as big as the parent
	 * and the budgets see that.
	 *
	 * Returns 0 if the sink is not empty, if a budget refused it, or if the
	 * host does not carry it.
	 */
	int (*derive)(const struct kof_obj_ctx *);

	/*
	 * The child is an IMAGE the engine lays out from the sections just
	 * declared: zero filled to their span, written at addresses with
	 * produced_poke, and given its header by the engine when it closes.
	 * See `section` below.
	 */
	int (*image)(const struct kof_obj_ctx *);

	/*
	 * WHERE THE NEXT WRITE LANDS, in a child made by `derive` or `image`.
	 *
	 * Everything that produces bytes - emit, and every decompressor behind
	 * unpack_form - goes to the same place, so this is the whole of
	 * "decompress that stream into this section". Set it, decode, and the
	 * output is where it belongs; nothing has to be staged in a buffer a
	 * module cannot afford.
	 */
	int (*at)(const struct kof_obj_ctx *, uint64_t off);

	/*
	 * A SECTION OF THE CHILD, SAID RATHER THAN ENCODED INTO A HEADER.
	 *
	 * See DESIGN-object-pipeline.md. A module that rebuilds an image knows
	 * its layout exactly and has, until now, had one way to pass it on:
	 * synthesise a PE header and let the engine parse it back. That round
	 * trip loses whatever the header has no field for, and three of those
	 * losses are measured:
	 *
	 *   - HOLLOW. SizeOfRawData must be the span for the file to be
	 *     readable, so a section that had no bytes in the original stops
	 *     looking like one. VMProtect's destinations are recognised by
	 *     exactly that, so one layer in they became invisible and the
	 *     module had to anchor on a coincidence in the data instead.
	 *   - PAD. The zero fill between VirtualSize and the page boundary is
	 *     inside the section, so the partition hands it to DATA:
	 *     update_v103.exe's child had a DATA region of 3972 bytes, every
	 *     one of them NULL.
	 *   - ORIGIN. MPRESS stands up an import directory that was not in the
	 *     file. Nothing records that it was invented, so a reader cannot
	 *     tell it from one that was read.
	 *
	 * Declared sections are in address order or they are refused: the
	 * engine lays the child out from them and a layout it cannot order is
	 * a layout it cannot write.
	 *
	 * Late is normal. A module may declare a section before its content
	 * exists and correct it afterwards with section_set - which is what
	 * mpress_pe.c's thirteen kunp_rcstruct_poke calls are doing by hand today.
	 */
	int (*section)(const struct kof_obj_ctx *, const char *name,
		       uint64_t rva, uint64_t vsize, uint32_t perm,
		       uint32_t flags);
	/*
	 * FORGET THE LAYOUT AND SAY IT AGAIN.
	 *
	 * For a module whose final shape is not the one it had to declare in
	 * order to get an image at all. mpress_pe.c is that shape: it lays the
	 * child out from the parent's sections, decompresses, and only then can
	 * mp_split find the landmarks that say where the real boundaries are -
	 * a dozen pieces that do not line up with what was declared. Correcting
	 * them one at a time cannot express it, because the new pieces sit
	 * between the old ones.
	 *
	 * The image keeps its size and its content; only the description is
	 * cleared. The table that replaces it still has to cover the same
	 * extent, and the engine says so at the close rather than trusting it.
	 */
	int (*sections_reset)(const struct kof_obj_ctx *);
	/* The entry point of the child, which is often knowable only after its
	 * content exists. */
	int (*child_entry_rva)(const struct kof_obj_ctx *, uint64_t rva);

	/*
	 * A DATA DIRECTORY OF THE CHILD, for the one a module REBUILT.
	 *
	 * The engine carries over the directories the parent declared that
	 * still point at something. This is the other case: an import table
	 * MPRESS never had - it keeps a hint list - and that this module stood
	 * up at an address of its own choosing. Saying it here is what replaces
	 * poking the address and the size into a header by hand.
	 */
	int (*child_dir)(const struct kof_obj_ctx *, uint32_t idx,
			 uint64_t rva, uint64_t size);

	/*
	 * READ THE LAYOUT OUT OF WHAT HAS JUST BEEN PRODUCED.
	 *
	 * For a packer that hands back an IMAGE and not a file - UPX does. The
	 * original header is somewhere inside the decompressed bytes and the
	 * section table in it IS the layout, but the module does not know where
	 * until it has decompressed, and parsing a PE header is not a thing
	 * every module should carry its own copy of.
	 *
	 * So: declare a span, take an image, decompress into it, and then ask.
	 * The sections, the entry point and the image base are declared from
	 * what was found, replacing whatever was declared to get the room.
	 *
	 * This replaces KOF_FORM_PE_IMAGE, which did the same search inside the
	 * decoder and then allocated a SECOND buffer and copied every section
	 * into it so that the engine could parse the result back. The bytes
	 * were already where they belonged; only the statement was missing.
	 */
	/*
	 * Answers WHERE THE IMAGE ENDS - the address just past its last
	 * section, which is also the length the child has just been cut back
	 * to - or 0 when no layout could be read.
	 *
	 * The end is the answer and not a side effect. A module that folds
	 * something ELSE in behind the image - pages a run wrote outside it -
	 * has to know where behind is, and it cannot work that out: the span
	 * it declared to get the image was a guess about size, and the header
	 * found inside says something else. Returning a flag instead cost the
	 * surplus: emu_harvest.h wrote its extra pages at the span's end,
	 * this call then cut the child back to the image, and five declared
	 * sections came out with SizeOfRawData 0 and SEC_PAST_EOF - measured
	 * on 007 Spy.exe.
	 */
	uint64_t (*layout_of_produced)(const struct kof_obj_ctx *);

	/*
	 * ---- DRIVING THE INTERPRETER FROM A MODULE -------------------------
	 *
	 * An unpack module is the abstraction over HOW a family comes apart -
	 * statically, by running it, or by alternating. So the run is asked for
	 * here and its result is read here, and the interpreter creates
	 * nothing: it gathers, and this module decides what any of it is.
	 *
	 * That is a hardening as much as a tidy: the component that executes
	 * hostile bytes has no path to making objects, declaring regions or
	 * naming anything. It reports.
	 *
	 * emu_run answers how many regions the run left, or 0 - which is also
	 * what the host answers when it refuses, because a budget is the
	 * host's and never the module's.
	 *
	 * `vouched` is a module saying it RECOGNISED this family and that a run
	 * is worth its cost. Without it the host asks its own question first -
	 * is this object dense, unloadable, a loader, carrying an appendix -
	 * which is the only thing that can be asked about a file nobody
	 * recognised. Either way the ceilings are the host's.
	 *
	 * A region is valid until this module returns; kunp_emu_take copies
	 * one into the child being built, at the current cursor.
	 */
	uint32_t (*emu_run)(const struct kof_obj_ctx *, uint32_t vouch_level);
	int (*emu_region)(const struct kof_obj_ctx *, uint32_t i, uint64_t *va,
			  uint64_t *len, uint32_t *kind);
	int (*emu_take)(const struct kof_obj_ctx *, uint32_t i);
	/* Whether anything has already opened this object - what a last-resort
	 * module asks before it spends a run on something already in hand. */
	int (*opened_already)(const struct kof_obj_ctx *);

	/*
	 * "I stopped before I was finished."
	 *
	 * Every other way an object becomes incomplete is something the host can
	 * see: a budget spent, a ceiling reached, a decoder reporting a corrupt
	 * stream. This is the one it cannot - a module that met a compression
	 * method it does not implement, or a structure it stopped trusting, and
	 * returned early. Without it that object is reported CLEAN, which is the
	 * one verdict it must never get: the container was opened, part of it was
	 * read, and the rest was never looked at.
	 *
	 * It is deliberately not an error and does not stop anything. A module says
	 * what it managed and what it did not, and the host decides what that means
	 * for the object.
	 *
	 * The reason is the module's to give because the module is the only thing
	 * that knows it: the host can see a budget run out, and it cannot see that
	 * a packer used a compression method this build has never heard of.
	 */
	void (*incomplete)(const struct kof_obj_ctx *, uint32_t reason);

	/*
	 * Decode one entry of this object into the object being produced.
	 *
	 * Gather and decompress in one call, and the two are together because
	 * neither half is usable alone: `unpack` reads a CONTIGUOUS range of the
	 * object, and an entry's bytes are a chain - measured over 1322 streams in
	 * real documents, 23.6% are not consecutive. Joining first and decoding
	 * after would need somewhere to put the joined bytes, and the only place a
	 * module has is the child it is building, which is the output.
	 *
	 * `index` is into the format's own entry table, so what it means is the
	 * format's business; the host asks resolve_entry above and never reads a
	 * view itself.
	 *
	 * Returns bytes produced, and does not close the child - a module joining
	 * two entries into one object is a legitimate thing to want.
	 */
	uint64_t (*unpack_entry)(const struct kof_obj_ctx *, uint32_t method,
				 uint32_t index, uint64_t out_hint);

	/*
	 * The object's symbol records, in the KSYM layout kofmod/kofsym.h fixes,
	 * or NULL when it has none.
	 *
	 * A POINTER, not a reader like rd8 above, and the difference is
	 * deliberate. rd8 exists because the object's bytes may be mapped,
	 * spilled or windowed and a module must not hold a pointer into them.
	 * This block is neither: it is built on demand into storage the scanner
	 * owns for the length of the object, so handing it over directly costs
	 * nothing and lets a rule walk records with plain array indexing -
	 * which is the whole point of a fixed record length.
	 *
	 * Built at most once per object, and only if something asks.
	 */
	const uint8_t *(*syms)(const struct kof_obj_ctx *, uint32_t *nbytes);

	/*
	 * WHAT THE CODE DOES WITH A DATA ADDRESS.
	 *
	 * Built at most once per object, and only if something asks - one
	 * linear sweep of the executable sections, no more.
	 */
	uint32_t (*data_xref)(const struct kof_obj_ctx *, uint64_t va,
			      uint64_t size);

	/*
	 * WOULD ANYTHING LOOK INSIDE A CHILD OF THIS FORMAT.
	 *
	 * Asked by a producer BEFORE it spends the work, and it is the whole of
	 * smart deep scan on the engine's side.
	 *
	 * IT IS NOT A POLICY, IT IS THE GATE ASKED EARLY. A module is offered
	 * an object only when its target list names the object's format, so a
	 * child of a format no loaded rule targets is a child that will be
	 * produced and handed to nobody. The engine already knew that before
	 * the inflate started; this is how a producer can know it too. There is
	 * no list of kinds to open anywhere in the engine, and nothing to edit
	 * when a format is added - the answer comes from the DATABASE, so
	 * writing the rule is what turns the work back on.
	 *
	 * KOF_FMT_UNKNOWN IS ALWAYS WANTED, and that is the case that matters
	 * most rather than an exception to be tidied away. A carried file's
	 * contents are not known until it is opened, so refusing to open it
	 * because nothing targets "unknown" would be refusing to look at
	 * exactly the thing a container is used to hide.
	 *
	 * ADVICE AND NOT A GATE: nothing refuses a child whose format this
	 * answered no for. A producer that asks saves its own work; one that
	 * does not spends it. Enforcing it at the push would be the bug this
	 * engine already had once - decompress everything, then drop the
	 * results on the floor - which is what --heur 0 used to do.
	 *
	 * Answers 1 when there is no answer to give (no database loaded), so a
	 * tool with no rules at all still opens what it finds.
	 */
	int (*fmt_wanted)(const struct kof_obj_ctx *, uint8_t fmt);

	/*
	 * THE SHAPE OF A REGION, WITHOUT ITS BYTES.
	 *
	 * Every other way a module reaches a region hands it the CONTENT - a
	 * string search through it, a gather of it into a child. This hands it
	 * the GEOMETRY, and the two answer different questions: "is this marker
	 * in the data section" against "how much of this file is data at all,
	 * and is it in one piece".
	 *
	 * The second question is one a module could not ask before, and
	 * re-deriving it is not a fair alternative: the ranges come out of the
	 * parser's tables through the settle and complement machinery in
	 * rangelist.h, and a module computing its own complement would be a
	 * second implementation of the partition - which would be wrong on
	 * exactly the hostile files that make the answer interesting.
	 *
	 * WHAT IT IS FOR, measured. The largest single unclaimed run in 4526
	 * clean ELF objects is 4095 bytes, which is what alignment padding can
	 * be and no more; in 3775 malware objects, 723 have one larger than a
	 * page. A run that big is a file somebody appended, and `widest_off` is
	 * where it starts - so nothing has to be searched for.
	 *
	 * Returns 0 and leaves *out zeroed when the object has no regions -
	 * an unidentified object, or a mask naming nothing present.
	 */
	int (*region_shape)(const struct kof_obj_ctx *, uint32_t region_mask,
			    struct kof_region_shape *out);

	/*
	 * HOW RANDOM A REGION'S BYTES ARE, in eighths of a bit - 0 to 64.
	 *
	 * Beside region_shape and for the same reason: a rule could ask what a
	 * region CONTAINS and how big it is, and could not ask what KIND of
	 * bytes they are. That is the cheapest fact there is about a region and
	 * the one most heuristics reach for second - padding sits near 0, text
	 * and tables between 1 and 4, code near 6, and compressed or encrypted
	 * data above 7.5.
	 *
	 * A rule could not compute it either. The bytes of a region are
	 * scattered, the accessors hand them over one at a time, and a module
	 * has no writable data to keep a histogram in - so the answer had to
	 * come from the host or not at all.
	 *
	 * OVER THE WHOLE REGION, every range of it, because that is what the
	 * mask names. A caller that wants one run measures it with the offset
	 * and length region_shape returned.
	 *
	 * Zero for an empty region, which reads as "nothing to measure" rather
	 * than as "uniform".
	 */
	uint32_t (*region_entropy)(const struct kof_obj_ctx *,
				   uint32_t region_mask);

	/*
	 * THE SAME, OVER ONE EXTENT THE CALLER NAMES.
	 *
	 * The general form, and region_entropy is the convenience: a region is
	 * scattered and its entropy is that of all its ranges together, which
	 * is the right answer to "what kind of bytes is this region" and the
	 * WRONG answer to "what kind of bytes are in that one run".
	 *
	 * Measured, and this is why both exist: the unclaimed region of one
	 * carrier sample is three runs - 3576 bytes of zero padding, one byte,
	 * and a 31968-byte ELF. Over the region it reads 4.5 bits; over the
	 * run that matters it reads 4.5 and over another sample's 6.0, while
	 * the padding dilutes a third down to 4.1. A gate written on the region
	 * measures the padding as much as the payload.
	 *
	 * Clipped to the object, so an extent that runs past the end measures
	 * what is there. Zero for an empty or out-of-range extent.
	 */
	uint32_t (*entropy_at)(const struct kof_obj_ctx *, uint64_t off,
			       uint64_t len);

	/*
	 * HOW MUCH OF A DECLARED BLOCK IS IN THIS OBJECT, nought to a hundred.
	 *
	 * The argument is an index the build assigned to KOF_MUTATION_BLOCK, the
	 * same way find_str's are assigned to KOF_DEFINE_STR - so the hashes are
	 * neither here nor in the blob, and the host answers from one pass it
	 * made over the regions any loaded block asked for.
	 *
	 * A PERCENTAGE AND NOT A VERDICT. What the number means is the rule's to
	 * decide, in the rule, beside everything else it decides - see
	 * kofmod/kofmutation.h for why the thresholds are not in the matcher.
	 *
	 * Zero for a block nothing could be fed for, which is the same answer as
	 * "none of it was there". A rule cannot tell those apart and must not
	 * try: a region that was never resolved and a region with nothing in it
	 * are one fact about this object.
	 */
	uint32_t (*mutation_score)(const struct kof_obj_ctx *, uint32_t block_id);

	
	/*
	 * THREE SLOTS NOBODY IMPLEMENTS, kept so that no entry after them moves (the
	 * vtable's order is the module ABI). Each is NULL by design; a module that
	 * reads one reads NULL.
	 */
	void *reserved_0;
	void *reserved_1;
	void *reserved_2;

	/*
	 * SEVEN SLOTS NOBODY IMPLEMENTS - they carried the repair of an object and
	 * the address arithmetic it was made from - kept so that no entry after them
	 * moves. NULL by design, like the three above.
	 */
	void *reserved_3;
	void *reserved_4;
	void *reserved_5;
	void *reserved_6;
	void *reserved_7;
	void *reserved_8;
	void *reserved_9;

	/*
	 * THE NEXT CHILD REPLACES THIS OBJECT - it is not a thing this object
	 * CONTAINS, it is what this object WAS.
	 *
	 * For a wrapper that is nothing but a wrapper. msfvenom applies its XOR
	 * encoder as many times as asked, and each layer is a forty-six byte
	 * stub in front of the next layer's ciphertext; a module cannot call
	 * another, so it peels one layer and hands the rest over as a child,
	 * which comes back round and peels the next. Three layers, three
	 * objects - and two of them are a decryptor and bytes nobody can read.
	 * Measured on samples/msfvenom-encr/rc4_1: three objects reported,
	 * 230, 180 and 250 bytes, and only the last is a program.
	 *
	 * So the module says it: what I just produced is me, one layer in. The
	 * object is still SCANNED - every rule still runs on it, and a stub
	 * that is itself a detection is still detected - it is not REPORTED as
	 * a thing recovered, because it is not a separate thing.
	 *
	 * NEVER THE FILE ON DISK. A top-level object is what the caller handed
	 * over and is reported whatever any module says about it; the engine
	 * refuses this there rather than trusting every module to check.
	 *
	 * Said before the child is closed, like every other pending
	 * declaration, and it applies to the object declaring it rather than
	 * to the child - which is why it is not spelled as a property of the
	 * child.
	 */
	void (*supersede)(const struct kof_obj_ctx *);

	/*
	 * WHAT KIND OF FILE THE DECLARED IMAGE IS TO BE WRITTEN AS.
	 *
	 * A declared image gets its header from the engine - see `section`. For
	 * a packer that unpacks a PE the answer needs no asking: the child is
	 * the parent's own image and the parent's header is the template. For a
	 * DECODER it does. What comes out of an msfvenom stub is shellcode, and
	 * shellcode is not a file of any format at all; which file it should
	 * become is a fact about the payload, not about the bytes - a payload
	 * peeled out of an ELF is Linux shellcode and belongs in an ELF, one
	 * peeled out of a PE is Windows shellcode and belongs in a PE - and
	 * after the first layer the parent is FORMATLESS, so the engine has
	 * nothing left to copy.
	 *
	 * So the module says it. `fmt` is a KOF_FMT_*, `arch` a KOF_ARCH_*, and
	 * `base` where the image is to be loaded; `entry` is declared
	 * separately, relative to `base`, like every other address.
	 *
	 * This replaces three decoders assembling a fifty-two byte ELF header
	 * by hand out of a shared file. That is exactly the round trip the
	 * declaration mechanism exists to end, and it had the failure mode that
	 * argument predicts: the header was written with kunp_rcstruct_write as
	 * ordinary content, so nothing in the engine knew it WAS a header, and
	 * the child's first fifty-two bytes were a region like any other.
	 *
	 * Declaring nothing keeps the old answer - the parent's format and the
	 * parent's header as the template.
	 */
	void (*as_format)(const struct kof_obj_ctx *, uint8_t fmt, uint8_t arch,
			  uint64_t base);

	/*
	 * WHICH BUILD OF THE PACKER THIS OBJECT IS - said once, before the
	 * unpacking, because the unpacking depends on it.
	 *
	 * A module that recognises a family usually has to work out WHICH
	 * version of it before it can read anything: MPRESS writes no version
	 * in the file, and its seven known builds put the packed section's
	 * address, the fix stub's address and the coding at different offsets
	 * from the entry point. A module reading those without settling the
	 * build first is reading whatever happens to be there.
	 *
	 * So the string comes out of the module's OWN table - the one it
	 * already needs in order to unpack at all - and this hands it to the
	 * engine, which puts it on the object as kof_result.packer_build. It is
	 * copied on the way in; a module holds no state and the pointer is only
	 * good for the call.
	 *
	 * Free form, and deliberately: "MPRESS 2.12-2.19 LZMAT" is what the
	 * evidence supports and a range is an honest answer where several
	 * builds share a layout.
	 */
	void (*packer_build)(const struct kof_obj_ctx *, const char *build);

	/*
	 * ---- READING THE MACHINE THE RUN LEFT ------------------------------
	 *
	 * A run stops somewhere, and where it stopped is usually only half the
	 * answer. The other half is in the registers and in guest memory: the
	 * address a RET was about to return to, the buffer a stub had just
	 * finished writing, the pointer a decryptor kept its table behind.
	 *
	 * TinyAntivirus's Sality cure is the case that makes this concrete -
	 * see THIRD-PARTY.md. It hooks every instruction, waits for a one-byte
	 * 0xC3, reads [ESP] to find where the virus body is, verifies a
	 * signature there, and then reads the ORIGINAL entry point and the
	 * original bytes of the host out of a table the virus keeps inside
	 * itself. Every step after the stop is a read of a register or of guest
	 * memory, and a module here could do none of them: kof_emu_get_reg and
	 * kof_emu_read exist, and nothing carried them across the ABI.
	 *
	 * VALID ONLY WHILE THE MACHINE IS. Same lifetime as a region handed
	 * back by emu_region: from the emu_run that produced it until this
	 * module returns. The engine frees the machine then - see
	 * kof_scanner.emu.live.
	 *
	 * `gpr` is the index the interpreter numbers registers by, which is the
	 * x86 encoding order: 0 ax, 1 cx, 2 dx, 3 bx, 4 sp, 5 bp, 6 si, 7 di,
	 * 8-15 r8-r15. Named that way rather than by a fresh enum because it is
	 * the numbering the instruction stream itself uses.
	 */
	uint64_t (*emu_reg)(const struct kof_obj_ctx *, uint32_t gpr);
	uint32_t (*emu_read)(const struct kof_obj_ctx *, uint64_t va,
			     uint8_t *out, uint32_t n);

	/*
	 * ---- WHAT THE CHILD IMPORTS, SAID RATHER THAN ENCODED --------------
	 *
	 * THE LAST ROUND TRIP, and the one the rest of this mechanism was built
	 * to end. A packer that rebuilds imports KNOWS them: MPRESS keeps a
	 * hint list - per library a delta to its IAT slot, its name, then its
	 * functions by name or by ordinal - and a module reading it has every
	 * fact a symbol needs. It then had nowhere to put them, so it built an
	 * IMAGE_IMPORT_DESCRIPTOR array, a lookup table and a string pool by
	 * hand, wrote them into a section it invented, pointed a data directory
	 * at them, and the engine PARSED THEM BACK to recover what the module
	 * had known all along. A hundred and fifty lines of PE structure
	 * encoding inside an unpack module, which is the thing the object
	 * pipeline forbids.
	 *
	 * So the module says it and the engine writes it, exactly as it already
	 * does for sections and for the header.
	 *
	 * import() declares ONE binding: the library, the function, the ordinal
	 * when it was imported by number instead of by name, and the address of
	 * the thunk the loader writes into. `fn` is ignored when `ordinal` is
	 * non-zero and vice versa - a PE import is one or the other and never
	 * both - and a module that has neither has not got an import.
	 *
	 * A DESCRIPTOR PER RUN OF ONE LIBRARY, not per distinct name. Calls are
	 * grouped in the order they arrive, so a new descriptor begins wherever
	 * the library differs from the call before it. That is what the source
	 * tables look like - a hint list is grouped by library and so is an
	 * import directory - and it means a module that walks its container in
	 * order gets the natural table without sorting anything. A library that
	 * genuinely appears twice gets two descriptors, which is legal and is
	 * what the container said.
	 *
	 * import_bytes() answers how much room the declared imports need, so
	 * that a module can reserve it in the layout IT owns. The module must
	 * ask: only it knows where a free address is, and the engine must not
	 * invent one - putting a table somewhere the module did not plan for is
	 * how a section ends up overlapping.
	 *
	 * import_at() says where to write it. The engine writes the table, the
	 * lookup entries and the names there, FILLS EACH DECLARED THUNK with
	 * its lookup entry - the value a thunk holds before binding, which is
	 * what a loader and this engine's own IAT filler expect - and points
	 * the import directory at it. All of that happens when the child
	 * closes, beside the header, and for the same reason: a declaration may
	 * be corrected until then.
	 *
	 * Returns 0 on refusal - the table is full, the pool is full, or the
	 * arguments do not describe an import - so a module stops rather than
	 * producing a child whose directory is missing entries.
	 */
	/*
	 * ---- PAUSING A RUN ON WHAT IS ABOUT TO EXECUTE --------------------
	 *
	 * emu_watch names an ADDRESS, and for three families here that is the
	 * wrong question: PECompact and Petite finish in bytes that never run
	 * at the address they occupy in the file, and Sality's whole first
	 * stage is polymorphic - the only fixed thing about it is that it ends
	 * in a one-byte `C3`.
	 *
	 * So a module names BYTES instead. The run stops when the instruction
	 * ABOUT TO EXECUTE begins with them - before it executes, so a `ret`
	 * still has its target on the stack - and that stop is a PAUSE: the
	 * machine is intact, emu_reg and emu_read answer about that moment, and
	 * emu_resume carries on from it.
	 *
	 * `len` is the whole instruction's length, or 0 for "do not care". It
	 * is what tells `C3` from `C2 imm16` and from something longer that
	 * merely starts with the same byte.
	 *
	 * emu_resume returns what emu_run returns: the number of regions when
	 * the run has finished for good, and 0 when it has paused again. A
	 * module that resumes without bound would spend a whole budget one
	 * pause at a time, so it counts its own resumes - the host bounds the
	 * instructions, not the pauses.
	 *
	 * This is TinyAntivirus's Sality detector expressed without a hook:
	 * it hooks every instruction, waits for a one-byte C3, reads [ESP] and
	 * checks what is there. A hook would put module code inside the loop
	 * that executes hostile bytes; a pause keeps the module the caller.
	 * See THIRD-PARTY.md.
	 */
	void (*emu_watch_insn)(const struct kof_obj_ctx *, const uint8_t *bytes,
			       uint32_t n, uint32_t len);
	uint32_t (*emu_resume)(const struct kof_obj_ctx *);

	int (*import)(const struct kof_obj_ctx *, const char *dll,
		      const char *fn, uint32_t ordinal, uint64_t iat_rva);
	uint64_t (*import_bytes)(const struct kof_obj_ctx *);
	int (*import_at)(const struct kof_obj_ctx *, uint64_t rva);

	/*
	 * ---- READING CODE WITHOUT RUNNING IT -------------------------------
	 *
	 * See kofmod/cell.h, which holds the vocabulary and the argument for
	 * why a module needs this at all. In short: a byte signature over a
	 * polymorphic decryptor names one GENERATION of it, so a rule has to
	 * be written against what the instructions MEAN - and until now a
	 * module could not decode one.
	 *
	 * dis_seek starts a walk at an offset. `keep` carries the register
	 * constant map across the move, which is what following a branch
	 * inside one walk needs; 0 starts the map empty.
	 *
	 * dis_next decodes at the cursor, advances it, and updates the map.
	 * Answers 0 at the end of the object or on bytes that do not decode.
	 *
	 * dis_reg answers a register's constant, or 0 for "not knowable
	 * here" - which is a real answer and not an error. cursor.c says what
	 * the map follows and what it deliberately does not.
	 */
	/*
	 * STOP HERE, AND TAKE WHAT THE RUN HAS ALREADY LEFT.
	 *
	 * A paused run - see emu_watch_insn - used to have two ends: resume
	 * until it finishes, or abandon the machine with everything it
	 * decrypted still inside it. Neither is what a module wants once it
	 * has what it came for.
	 *
	 * MEASURED, and it is not a small cost. The Sality module recognises
	 * its family at the FIRST pause, a few thousand instructions in, and
	 * then disarmed the watch and resumed - which ran to the 268,435,456
	 * instruction ceiling and took forty seconds on one file. Everything
	 * after the pause was spent proving nothing.
	 *
	 * So this ends the run where it stands and gathers the regions
	 * exactly as a finished run does, answering the same count. It is the
	 * module's half of "emulate what is necessary": the interpreter
	 * cannot know when enough has been decrypted, and the module that
	 * recognised the family can.
	 */
	/*
	 * RUN IN SLICES, so the module can look between them.
	 *
	 * Set before emu_run, and honoured by emu_run and emu_resume alike:
	 * each of them comes back after at most this many instructions with
	 * the machine ALIVE and paused, exactly as an instruction watch does.
	 * Zero, the default, means run to the host's ceiling.
	 *
	 * This is what periodic scanning is built on - decrypt a little, look,
	 * decide. The alternative is waiting for the decryptor to finish, and
	 * measured on Sality that is 186 million instructions for data that is
	 * in memory after about twenty million.
	 */
	void (*emu_slice)(const struct kof_obj_ctx *, uint64_t insn);

	uint32_t (*emu_stop)(const struct kof_obj_ctx *);

	int (*dis_seek)(const struct kof_obj_ctx *, uint64_t off, int keep);
	int (*dis_next)(const struct kof_obj_ctx *, struct cell_insn *out);
	int (*dis_reg)(const struct kof_obj_ctx *, uint8_t r, uint64_t *out);

	/*
	 * ---- LOOKING AT A REGION A RUN LEFT ---------------------------------
	 *
	 * A REGION IS A SNAPSHOT AND emu_read IS THE LIVE MACHINE. While a run
	 * is paused a module reads the machine; once it has ENDED there is no
	 * machine, and what survives is what was gathered.
	 *
	 * WHY BOTH ARE NEEDED, measured. Three of the four Sality samples pause
	 * mid-decryption, get looked at, and are recognised out of live memory.
	 * The fourth never does: its decryptor faults at seven million
	 * instructions and the run ends - and the body IS in the region that
	 * run left, at offset 0x14b. Without this the module has the answer in
	 * its hand and no way to read it.
	 *
	 * A module may already COPY these bytes into a child, so being allowed
	 * to LOOK at them is not a new power.
	 *
	 * Returns how many bytes were copied: 0 for a region that does not
	 * exist, and short at the region's end.
	 */
	uint32_t (*emu_region_read)(const struct kof_obj_ctx *, uint32_t i,
				    uint64_t off, uint8_t *out, uint32_t n);

	/*
	 * ---- SAYING WHERE THE INFECTION IS ---------------------------------
	 *
	 * See `struct kof_infected` in kofeng.h. A module that has located
	 * damage says where, and this is how that location leaves the module
	 * instead of being thrown away with it.
	 *
	 * Bounds-checked against the object, like every other range a module
	 * hands over, and silently ignored once the cap is reached.
	 */
	void (*infected)(const struct kof_obj_ctx *, uint64_t off, uint64_t len,
			 uint32_t kind);

	/*
	 * ---- CHANGING A PAUSED MACHINE ------------------------------------
	 *
	 * A watch used to be able to LOOK and nothing else - emu_reg and
	 * emu_read answer about the moment the run stopped, and then the only
	 * choices were to resume or to give up. That is half of what stopping
	 * on an instruction is for.
	 *
	 * The other half is INTERVENING, and it is why fault handlers exist in
	 * the published designs: a handler examines the machine, decides the
	 * guest is about to do something the interpreter cannot follow, and
	 * corrects it - it moves the instruction pointer past a construct, it
	 * substitutes the value a missing library would have returned, it puts
	 * back something the guest wrecked on purpose. Without a way to write,
	 * every one of those is a run that simply ends.
	 *
	 * ONLY WHILE PAUSED. A machine that is running belongs to the
	 * interpreter and one that has been handed over no longer exists; both
	 * refuse.
	 *
	 * THE MODULE OWNS WHAT IT BREAKS. None of this is checked for sense -
	 * an instruction pointer set into the middle of an instruction is a
	 * legal thing to ask for and a rule may have a reason. What IS checked
	 * is that the memory exists, because a write to a page the guest does
	 * not have is a write that would go nowhere quietly.
	 */
	void (*emu_set_reg)(const struct kof_obj_ctx *, uint32_t gpr,
			    uint64_t value);
	void (*emu_set_ip)(const struct kof_obj_ctx *, uint64_t va);
	uint32_t (*emu_write)(const struct kof_obj_ctx *, uint64_t va,
			      const uint8_t *bytes, uint32_t n);

	/*
	 * ---- THE OBJECT'S PROFILE, ASKED ONE FACT AT A TIME ---------------
	 *
	 * The measure that stood in the row above asked "how near is this
	 * object to that reference", which needs a reference - a sequence
	 * somebody took off a sample they already had. That was the only
	 * question the behaviour vocabulary could be asked, and it is not the
	 * question that measured well.
	 *
	 * Measured over 3655 malware and 1225 clean objects, what separated
	 * them was not nearness to a sample but the PRESENCE of single facts
	 * and of single links between them:
	 *
	 *     alloc-exec with W+X          31.2% of malware, 0 of clean
	 *     socket opened as a datagram  33.0%             0
	 *     a write fed by a write       12.8%             0
	 *     a spawn fed by a spawn       35.9%             0
	 *
	 * None of those is expressible as "resembles this reference", and all
	 * of them are one comparison. So they get their own two calls.
	 *
	 * AT THE END OF THE TABLE, so every entry before them keeps its offset
	 * and a module built against an older header is unaffected.
	 */
	/*
	 * DOES THIS OBJECT ASK FOR THIS CAPABILITY, with at least these flags.
	 *
	 * `flags` of zero means "with any flags, or none" - it is a REQUIREMENT
	 * and not a pattern, so a node carrying more than was asked for still
	 * answers yes. The flags a rule may ask for are the ones a stored step
	 * keeps: see the KOF_FLOWF_* bits.
	 */
	/*
	 * DOES THIS OBJECT CARRY DIAGNOSE `id`.
	 *
	 * A diagnose is a shape the code has - a region allocated writable
	 * and executable, filled, and jumped into - and it carries NO
	 * verdict of its own. This is how a rule reads one: the engine has
	 * already decided, per object, which of them are there, and a
	 * signature asks for the answer the way it asks whether an object
	 * came out of a packer. See kofmod/kofdiagtree.h for what a diagnose
	 * is, and bases/diagnoses/ for the ones that exist.
	 *
	 * THE SLOT WAS pth_has, which asked a question about a sequence of
	 * capabilities with distances between them. The question is close
	 * enough that reusing the slot is honest; what it could not hold is
	 * written up under "THE BEHAVIOUR MACROS ARE GONE".
	 *
	 * ZERO IS "NOT FOUND", never "not there". A packed object has no
	 * code to read until it is unpacked, and an architecture the value
	 * model does not have answers zero for everything. A rule needing
	 * certainty of absence cannot have it here.
	 */
	int (*diag)(const struct kof_obj_ctx *, uint16_t id);
	/*
	 * DID AN ARGUMENT OF `dst` COME FROM WHAT `src` RETURNED.
	 *
	 * The link, which is what makes a set of capabilities a shape: "opened
	 * a socket" and "read from the socket it opened" are different claims
	 * and only the second one is about this program's structure.
	 *
	 * ZERO IS "NO LINK WAS SEEN", never "there is none" - the sweep loses
	 * a pointer spilled to the stack, and on a PE that is nearly all of
	 * them. A rule that needs certainty of absence cannot have it here.
	 */
	/* was pth_feeds - same. */
	void *pth_feeds_unused;

	/*
	 * THE DIAGNOSE GRAPH, AS RECORDS - see kofmod/kofdiagtree.h.
	 *
	 * APPENDED, like every slot added since this vtable shipped, so that
	 * nothing above it moves and a module built against an older header
	 * cannot reach it and cannot call the wrong one.
	 *
	 * Built at most once per object from the analysis that already ran,
	 * and NULL with zero bytes when none did - which is the normal answer
	 * for an object no rule asked about.
	 */
	const uint8_t *(*graph)(const struct kof_obj_ctx *, uint32_t *nbytes);

	/* Do two diagnoses meet at a node of this capability - see
	 * kof_diag_share. Appended, like every slot added since this vtable
	 * shipped. */
	int (*diag_share)(const struct kof_obj_ctx *, uint16_t cap,
			  uint16_t a, uint16_t b);

	/*
	 * Did this diagnose match AND does it carry this name - see
	 * kof_diag_str_any and kof_diag_str_all. Appended, like
	 * every slot added since this vtable shipped.
	 */
	int (*diag_str)(const struct kof_obj_ctx *, uint16_t diag,
			     const char *name);

	/*
	 * ---- TELLING THE MACHINE, BEFORE IT STARTS -----------------------
	 *
	 * Two facts a packer module knows and the interpreter cannot: what one
	 * of its anti-emulation tests must be answered, and which bytes of the
	 * image must not be run as written. Declared like emu_watch_insn - once,
	 * before kunp_emu_run, and gone when the module returns - so neither is a
	 * case in the interpreter and neither costs anything for a file no module
	 * claimed.
	 *
	 * emu_api_returns  make the Windows API `name` return `ret`. The call is
	 *                  still logged as that call and the guest still pops its
	 *                  own arguments; only the VALUE is replaced. Answers 0
	 *                  when the declaration was not kept: a full table, or a
	 *                  name of 48 characters or more. A name this environment
	 *                  has no handler for is not an error here and does nothing
	 *                  later - the null-call policy already answers it.
	 *
	 * emu_patch        replace `n` bytes (1..16) wherever `find` occurs inside
	 *                  a section of the PE, in the copy that is mapped. The
	 *                  file, and the bytes the guest reads back as itself, are
	 *                  not touched. The dump of a run carries the patched
	 *                  bytes, so patch a stub, not the program. Answers 0 when
	 *                  the table is full or `n` is out of range.
	 *
	 * PE only today: an ELF run ignores both. AT THE END OF THE TABLE, so a
	 * module built against an older header is unaffected.
	 */
	uint32_t (*emu_api_returns)(const struct kof_obj_ctx *, const char *name,
				    uint64_t ret);
	uint32_t (*emu_patch)(const struct kof_obj_ctx *, const uint8_t *find,
			      const uint8_t *rep, uint32_t n);
	/*
	 * api_resolved   the i-th API the program finds for itself, read out of
	 *                the loader data instead of its import table: the engine
	 *                runs the program's own resolver against the modelled
	 *                loader and keeps the names it arrives at. Copies the
	 *                DLL and the function name into the caller's buffers and
	 *                answers 1; 0 when there is no i-th, so a loop on it ends.
	 *                One entry per distinct API however many places call it.
	 *                A program that does not read the loader data answers 0
	 *                at once - it costs a decode and nothing else.
	 * sym_import     report one import of THIS object that its tables do not
	 *                list, so that everything which reads the object's
	 *                symbols - a rule on imports, a similarity, the result a
	 *                tool shows - sees the program as it would if the author
	 *                had used the import table. PE only. A name reported is
	 *                kept once. Answers 1 when it was taken.
	 *
	 * AT THE END OF THE TABLE, so a module built against an older header is
	 * unaffected. Together they are how a decrypt step reports symbols: the
	 * same kind of work as recovering a string the program hides, with the
	 * result going to the object's description.
	 */
	uint32_t (*api_resolved)(const struct kof_obj_ctx *, uint32_t i,
				 char *dll, uint32_t dll_cap,
				 char *fn, uint32_t fn_cap);
	uint32_t (*sym_import)(const struct kof_obj_ctx *, const char *dll,
			       const char *fn);
	/*
	 * decrypt        run the cipher a descriptor names over a range of THIS object
	 *                and produce the result, as repeated kunp_rcstruct_write calls
	 *                would. Returns the bytes produced - zero when the descriptor
	 *                is not a cipher or the host refused (budget).
	 * decrypt_peek   the same into the caller's own buffer, producing nothing: for
	 *                a module that has to read the front of the plaintext before it
	 *                can say what the object is, or how long it is - the additive
	 *                cipher's length is only known by running it.
	 *
	 * AT THE END OF THE TABLE, so a module built against an older header is
	 * unaffected. See kofmod/kofdecode.h for what a descriptor is and why the
	 * loop is the host's.
	 */
	uint64_t (*decrypt)(const struct kof_obj_ctx *, const struct kof_capsid *,
			    uint64_t off, uint64_t len);
	uint32_t (*decrypt_peek)(const struct kof_obj_ctx *,
				 const struct kof_capsid *, uint64_t off,
				 uint64_t len, void *out, uint32_t cap);
	/*
	 * capsid_apply   run a cipher over bytes the MODULE holds - not the object.
	 *                Pure arithmetic with no scanner state, so a detector may ask
	 *                too. What it is for: a module testing a candidate key needs
	 *                the first bytes of its keystream, and calling decrypt_peek
	 *                for every position of an object would key the cipher that
	 *                many times; one call over a few zero bytes yields the
	 *                keystream, once.
	 */
	uint32_t (*capsid_apply)(const struct kof_capsid *, const void *in,
				 uint32_t n, void *out, uint32_t cap);
	/*
	 * diag32, diag_share32, diag_str32   the three diagnose questions with the
	 * diagnose named by its FULL 32-bit id (kof_diag_id32_) instead of the 16-bit
	 * fold the slots above take. The fold lets two names share an id - with 256
	 * diagnoses the chance that some pair does is about 40% - and the loader had to
	 * refuse the second one; the full hash makes that a one-in-a-million event at
	 * the sizes a database reaches (and still refused, never silently answered for
	 * the wrong diagnose). The kof_diag, kof_diag_share and kof_diag_str_* macros
	 * ask these; the 16-bit slots stay where they are for a module built before.
	 *
	 * AT THE END OF THE TABLE, so a module built against an older header is
	 * unaffected.
	 */
	int (*diag32)(const struct kof_obj_ctx *, uint32_t id);
	int (*diag_share32)(const struct kof_obj_ctx *, uint16_t cap,
			    uint32_t a, uint32_t b);
	int (*diag_str32)(const struct kof_obj_ctx *, uint32_t diag,
			  const char *name);
	/*
	 * view_next   the next row of the table of this object's parsed view, by a
	 *             cursor the CALLER owns: row *cursor, then *cursor is advanced; NULL
	 *             at the end, or for a format whose view has no walkable table.
	 *             The row is the format's own (struct kof_zip_entry for ZIP and DOCZIP,
	 *             struct kof_pdf_object for PDF) and is read through kof_zip_next /
	 *             kof_pdf_next, never by hand.
	 *
	 *             Why a call and not an array in the view: the tables are as long as the
	 *             archive (they were fixed arrays of 4096), so a module has no array to
	 *             index and no count that is a limit; and because the call goes through
	 *             the host the host KNOWS a module read the table - a module that never
	 *             does while the archive has rows is one built for the layout before
	 *             this slot, which would open nothing and say nothing, and the engine
	 *             reports that object instead (struct kof_view_mem.walked).
	 *
	 * AT THE END OF THE TABLE, so a module built against an older header is
	 * unaffected; a module built against this one needs a host that has the slot,
	 * which is what KOFSIG_ABI_VERSION is for.
	 */
	const void *(*view_next)(const struct kof_obj_ctx *, uint32_t *cursor);
};

#endif /* KOFENG_KOFCONTENT_H */
