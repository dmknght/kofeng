/*
 * kofentry.h - what the host and a module say about the entries of a
 * container: decoder ids, entry kinds, struct kof_entry.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFENTRY_H
#define KOFENG_KOFENTRY_H

#include <stdint.h>

/*
 * Which decoder kof_unpack_at should run.
 *
 * Named here rather than taken from each format's own numbering because the
 * service is one call: a module that has read UPX's method byte maps it to one of
 * these, and a module reading some other container's maps to the same set. The
 * host does not learn a container's numbering, and a new container does not need a
 * new entry point.
 *
 * NRV2 carries its bit width in the id because the width is part of the coding
 * rather than a variant of it - see kuncoat_nrv2_bits for what that cost to learn.
 */
/*
 * What the unpacked bytes are, so the host knows whether to reassemble them.
 *
 * RAW is the ordinary answer and means the output is already a file - a gzip
 * member, a UPX packed ELF, anything the packer restores whole.
 *
 * THERE WAS A SECOND FORM HERE AND IT IS GONE.
 *
 * KOF_FORM_PE_IMAGE meant "what I just decompressed is a mapped image, put a
 * file back together out of it", and the engine answered it by hunting for a PE
 * header inside the output, allocating a SECOND buffer the size of the whole
 * image, and copying every section into it so the result could be parsed back -
 * two copies of an image to recover a layout the bytes already carried.
 *
 * A module says it where it can see it happening now: declare a span, take an
 * image, decompress into it, then kunp_rcstruct_layout_of_image, which reads
 * that header and DECLARES the sections. One buffer, and the module decides
 * when. See upx_pe.c and `layout_of_produced`.
 *
 * With one form left there is nothing to choose, so the argument went with it.
 */

enum kof_unp_method {
	/*
	 * NO CODING AT ALL - the bytes are already what they are.
	 *
	 * Zero has always meant this where a chain is stored (see
	 * kof_entry.coding, "all zero means STORED"), and naming it makes the
	 * one case that needs saying expressible: an entry that is stored and
	 * SCATTERED. A stored entry in one range is a window and costs nothing;
	 * a stored entry in several is a JOIN, which is a copy and a budget,
	 * and kunp_static_entry is where that belongs.
	 *
	 * A cabinet is why. Its uncompressed folders are cut into blocks with
	 * an eight byte header between them, so a stored file larger than a
	 * block is several ranges - and every stored file over 32KB is.
	 */
	KOF_UNP_STORED = 0,
	KOF_UNP_DEFLATE = 1,   /* RFC 1951; streams, needs no size hint */

	/*
	 * MS-OVBA 2.4.1, the coding an Office document holds its macros in.
	 *
	 * Streams like DEFLATE and needs no size hint, for a reason worth stating:
	 * a back reference is measured from the start of the current 4096 byte
	 * chunk and cannot reach past it, so the window is fixed however long the
	 * stream runs.
	 */
	KOF_UNP_OVBA = 2,

	/*
	 * LZMA2: LZMA cut into chunks that say what to carry over.
	 *
	 * No parameters in the id, unlike KOF_UNP_LZMA: an LZMA2 stream carries its
	 * own properties and may change them part way through, so there is nothing
	 * for a caller to pass. It is what 7-Zip writes its content with - measured
	 * over 369 archives, every folder that could be located uses it and none use
	 * plain LZMA.
	 */
	KOF_UNP_LZMA2 = 3,

	/*
	 * Hex text back into bytes, which is how RTF carries an embedded object.
	 *
	 * Not compression and named as a coding anyway, because it sits in exactly
	 * the same place: a module points at a range and gets an object out. The
	 * decoder skips whitespace, which is not politeness - splitting the hex
	 * with spaces is how a blob is kept from matching a fixed prefix.
	 */
	KOF_UNP_HEXTEXT = 4,

	/*
	 * LZMA2 with the x86 branch transform undone afterwards.
	 *
	 * One method rather than a second argument, on the same reasoning that put
	 * LZMA's properties in its id: a filter is meaningless for eight of nine
	 * codings, and an argument that is ignored almost everywhere is worse than
	 * an id that says what it is. Measured over the 7z archives here, 77 folders
	 * need it and 334 do not.
	 */
	KOF_UNP_LZMA2_BCJ_X86 = 5,

	/*
	 * RAR 2.9/3.x, the LZ half.
	 *
	 * RAR picks between LZ and PPMd per block and says which in the first bit of
	 * each block header. Measured over 13971 compressed entries here, 92.6% of
	 * blocks are LZ; a PPM block is refused rather than guessed at, and the
	 * caller is told which happened.
	 */
	KOF_UNP_RAR3 = 6,

	/*
	 * 7z's four stream x86 filter, driven by entry index rather than by a range.
	 *
	 * BCJ2 does not read one run of bytes: it merges a main stream, a stream of
	 * call targets, a stream of jump targets and a range coder that says which
	 * candidate opcodes were converted. Which packed stream is which comes from
	 * the folder's bind pairs, so only the host can resolve it - see
	 * kunp_static_entry.
	 */
	KOF_UNP_BCJ2 = 7,

	/*
	 * RAR 5, which shares a name with RAR3 and no code.
	 *
	 * A separate id and not a parameter of the RAR3 one: the two formats agree
	 * on nothing below the signature - different block framing, different table
	 * encoding, different slot arithmetic, different filters - so the host picks
	 * a decoder here rather than branching inside one.
	 */
	KOF_UNP_RAR5 = 8,
	/*
	 * RFC 1950 - the same DEFLATE data behind two bytes of framing.
	 *
	 * Its own method rather than two lines in every caller, because zlib
	 * framing is not peculiar to any one format: a PDF's /FlateDecode uses
	 * it, and so does anything else that reached for the obvious library.
	 * The rule kofsig.h states for the whole unpack surface applies to it -
	 * standard and shared belongs in the host - and the first module to meet
	 * it had open-coded the header check, which is one copy away from every
	 * later one getting it subtly different.
	 *
	 * The framing is CHECKED, not assumed: a stream that does not carry a
	 * valid zlib header is decoded as raw DEFLATE from its first byte, which
	 * is what a producer that emitted RFC 1951 under a zlib name meant. So a
	 * caller that is unsure which it has can name this one and be right
	 * either way.
	 */
	KOF_UNP_ZLIB = 9,

	/*
	 * ASCII85 back into bytes: five printable characters carry four.
	 *
	 * Not compression, and named as a coding for the reason HEXTEXT is - it
	 * sits in exactly the same place, a range in, an object out. PDF writes
	 * it IN FRONT OF a Flate to make a stream survive a text-only channel,
	 * so its whole importance is that it appears in a CHAIN: a decoder
	 * handed the Flate half alone inflates ASCII85 text and fails, which is
	 * how a clean document came to be reported as one the engine could not
	 * finish.
	 *
	 * Output is at most four fifths of input, which is what makes it usable
	 * as an INTERMEDIATE step - see the chain runner. A step whose output
	 * cannot be bounded from its input has nowhere to be put.
	 */
	KOF_UNP_ASCII85 = 10,

	/*
	 * The other two transport codings, and see libuncoat/decoders/textcode.h for
	 * why the three belong together.
	 *
	 * ASCIIHEX is bounded by its input like ASCII85, so it can be a middle
	 * step of a chain. RUNLENGTH expands up to 128x and cannot be sized
	 * from its input, so it can only be a last step - the host reports a
	 * chain that asks for more rather than guessing a buffer.
	 *
	 * Both are rare, and that is a reason to have them rather than not:
	 * reaching for an old or unusual coding is how a file gets past a
	 * parser that only implemented the common one.
	 */
	KOF_UNP_ASCIIHEX = 11,
	KOF_UNP_RUNLENGTH = 12,

	/*
	 * LZW as PDF and TIFF write it - most-significant-bit first, which is
	 * NOT the GIF variant. See libuncoat/decompressors/lzw.h.
	 *
	 * Worth having because it was superseded: a filter nobody expects is a
	 * filter a parser was never taught, and that is a cheap way to put
	 * ordinary content past one.
	 *
	 * Output is unbounded, so it streams and can only be the LAST step of a
	 * chain - like DEFLATE and for the same reason.
	 */
	KOF_UNP_LZW = 13,

	/*
	 * bzip2, whole streams of it - see libuncoat/decompressors/bunzip.h.
	 *
	 * A .bz2 file, a zip entry stored with method 12, and the compressed
	 * half of a .tar.bz2 are all this one coding, and none of them could be
	 * looked inside before it existed.
	 *
	 * THE RANGE IS THE WHOLE STREAM, "BZh" AND ALL - unlike DEFLATE, where
	 * a caller passes the coded bytes and keeps the wrapper to itself.
	 * bzip2 has no separable wrapper: the level digit in those four bytes
	 * states the block size, which the decoder needs before it can read
	 * anything, and everything after them is a bit stream that is not byte
	 * aligned. A zip entry stored with method 12 holds a complete stream for
	 * the same reason, so both callers pass the same thing.
	 *
	 * Output is unbounded, so it streams and can only be the LAST step of a
	 * chain - like DEFLATE and LZW, and for the same reason: an
	 * intermediate has to be sized from its input and a block sorted coding
	 * cannot be.
	 */
	KOF_UNP_BZIP2 = 14,

	/*
	 * MSZIP, WHICH IS NOT ONE CODING BUT A SEQUENCE OF THEM.
	 *
	 * A cabinet's MSZIP folder is one deflate stream PER BLOCK, each behind
	 * the two bytes "CK", and every block after the first may reference up
	 * to 32KB of the previous block's output. So it is decoded through
	 * kunp_static_entry rather than kof_unpack_at: what it needs is the list
	 * of blocks, which resolve_entry answers, and a decoder that can be
	 * seeded, which kuncoat_inflate_seeded is.
	 *
	 * `out_hint` CARRIES TWO NUMBERS for this method: the file's offset
	 * inside the folder's decoded stream in the high 32 bits, its length in
	 * the low 32. A CFFILE has both, a range can hold neither, and putting
	 * them in the entry would be one format's meaning inside the host's
	 * structure.
	 */
	KOF_UNP_MSZIP = 15,

	/*
	 * LZX, AND THE WINDOW IS IN THE ID.
	 *
	 * The coding behind a help file's pages and most of a modern cabinet's
	 * content. Its window is not in the stream - a cabinet states it in the
	 * folder's compression type, a help file in its ControlData - so a
	 * decoder handed only the bytes cannot run, and the id carries it the
	 * way KOF_UNP_LZMA carries its three parameters.
	 *
	 * Use KOF_UNP_LZX(bits) or KOF_UNP_LZX_RESET(bits) to build one, with
	 * bits from 15 to 21.
	 *
	 * `out_hint` carries where to start and how much to take: the offset
	 * INSIDE the decoded stream in the high 32 bits, the length in the low
	 * 32. A stream can only be entered at a restart point, so a file part
	 * way in is reached by decoding from that point and dropping what comes
	 * before - which is the caller's arithmetic, not the decoder's.
	 *
	 * TWO IDS, BECAUSE THE PIECES MEAN TWO DIFFERENT THINGS. An entry
	 * coded with LZX is scattered either way, and what resolve_entry hands
	 * back is read differently:
	 *
	 *   KOF_UNP_LZX       - the pieces are ONE stream, cut up by something
	 *                       that is not the coding. A cabinet folder is
	 *                       this: the stream runs from the folder's first
	 *                       block to its last and the block headers sit in
	 *                       the middle of it, so the pieces are joined and
	 *                       decoded once.
	 *   KOF_UNP_LZX_RESET - each piece is a stream OF ITS OWN, because the
	 *                       container restarts the coding at intervals and
	 *                       says where. A help file is this - see chm.h -
	 *                       and the pieces are decoded one after another
	 *                       with the decoder starting again at each.
	 *
	 * Running a reset container's pieces together decodes the first and
	 * produces refuse from the second, and joining them would do the same;
	 * the two cannot share an id and be told apart by the host.
	 *
	 * ABOVE THE LZMA RANGE, and that is not spare room being used up. LZMA
	 * carries three parameters in its id and runs from 64 to 288, so a base
	 * of 128 - which is what this was - made KOF_UNP_LZX(15) and an LZMA
	 * stream with a particular lc/lp/pb THE SAME NUMBER. Nothing caught it
	 * because no parser fills an LZMA chain yet; kof_unp_method_name
	 * already answered "lzma" for every LZX id.
	 */
	KOF_UNP_LZX_BASE = 320,
	KOF_UNP_LZX_RESET_BASE = 352,

	KOF_UNP_NRV2B_8 = 16, KOF_UNP_NRV2B_16, KOF_UNP_NRV2B_32,
	KOF_UNP_NRV2D_8,      KOF_UNP_NRV2D_16, KOF_UNP_NRV2D_32,
	KOF_UNP_NRV2E_8,      KOF_UNP_NRV2E_16, KOF_UNP_NRV2E_32,

	/*
	 * LZSS WITH BLOCK HUFFMAN - LHA's and ARJ's coding, which is ONE
	 * coding under four sets of constants. See lzhuf.h.
	 *
	 * Four ids and not one with a parameter, because a container names the
	 * variant and does not name a dictionary size: an archive says "-lh5-"
	 * or "method 1", and a module that had to turn that into a width would
	 * be keeping the table this enum already is.
	 *
	 * ARJ's methods 1, 2 and 3 are one id: the number says how hard the
	 * compressor looked, not what a decoder must do. Its method 4 is a
	 * different coding and has none here.
	 *
	 * THE DECODER NEEDS THE OUTPUT LENGTH, unlike every other entry here.
	 * The stream has no end marker at all - it stops when the declared
	 * original size has been produced - so out_hint is not a hint for
	 * these and a caller that does not know it cannot decode at all.
	 */
	KOF_UNP_LZHUF_ARJ = 25,   /* ARJ -m1, -m2, -m3 */
	KOF_UNP_LZHUF_LH5 = 26,   /* LHA -lh5-: 8KB dictionary */
	KOF_UNP_LZHUF_LH6 = 27,   /* LHA -lh6-: 32KB */
	KOF_UNP_LZHUF_LH7 = 28,   /* LHA -lh7-: 64KB */

	/*
	 * aPLib, which is how a Themida protected PE carries its loader.
	 *
	 * No parameters, unlike LZMA: the coding has none. The stream states
	 * neither its compressed nor its uncompressed length, so a caller
	 * bounds it with out_cap and checks what came out against whatever its
	 * container declared - see bases/unp/themida_pe.c, where the container
	 * is a section's VirtualSize.
	 */
	KOF_UNP_APLIB = 29,

	/*
	 * LZMAT, WHICH IS WHAT MPRESS USED BEFORE IT MOVED TO LZMA.
	 *
	 * A byte oriented LZ77 with a nibble stream running through it. No
	 * parameters - the coding has none - and no declared lengths, so a
	 * caller bounds it with out_cap and checks the result against whatever
	 * its container said. Measured, two of the seven MPRESS files here are
	 * this coding and nothing else in the engine reads it.
	 *
	 * The two that follow are the same stream with MPRESS's call target
	 * conversion undone afterwards, for the same reason the LZMA pair
	 * below carries it: the transform rewrites addresses relative to a
	 * position in the OUTPUT, so it runs once the output is whole, and
	 * the width decides which opcodes were converted.
	 */
	KOF_UNP_LZMAT = 30,
	KOF_UNP_LZMAT_MPRESS32 = 31,
	KOF_UNP_LZMAT_MPRESS64 = 32,

	/*
	 * ASPACK 2.X's OWN CODING - a Huffman coded LZ77, see aspack.h.
	 *
	 * No parameters, and that is measured rather than assumed: the two
	 * tables that steer it are carried in the stub and are the same bytes
	 * in every build this engine recognises. The module checks the stub's
	 * copies before it asks for a decode, so a build that differs is
	 * reported as unsupported instead of decoded into something plausible.
	 *
	 * The stream states no length; the block table in the stub does, and
	 * out_hint is that length and a hard bound.
	 *
	 * KOF_UNP_ASPACK_E8E9 is the same coding with ASPack's call/jmp filter
	 * undone afterwards, which only the FIRST block of an image carries.
	 * The filter's marker byte differs per file and rides in the id, the
	 * way KOF_UNP_LZMA carries lc/lp/pb and for the same reason - a
	 * parameter meaningless for every other coding is worse than an id
	 * that says what it is. 256 ids, built with KOF_UNP_ASPACK_MARK.
	 *
	 * Placed above KOF_UNP_LZMA_MPRESS64's 640..864 rather than in the gap
	 * below it, for the reason KOF_UNP_LZX_RESET_BASE's note gives: an id
	 * range that overlaps another is a bug nothing catches until two
	 * codings answer to one number.
	 */
	KOF_UNP_ASPACK = 33,

	/*
	 * LZMA carries three parameters, so the id carries them.
	 *
	 * lc, lp and pb decide the shape of the probability model and there is no
	 * default that works - a stream decoded with the wrong three produces
	 * plausible bytes that are not the file. They ride in the method id rather
	 * than in a fourth argument because every other coding needs no parameters
	 * and a parameter that is meaningless for eight of nine methods is worse
	 * than an id that says what it is.
	 *
	 * Use KOF_UNP_LZMA_PROPS to build one. The packing is the specification's
	 * own: lc + 9*lp + 45*pb, which fits 0..224 above the base.
	 */
	KOF_UNP_LZMA = 64,

	/*
	 * LZMA WITH MPRESS'S CALL TARGET CONVERSION UNDONE AFTERWARDS.
	 *
	 * The same arrangement KOF_UNP_LZMA2_BCJ_X86 uses and for the same
	 * reason: the transform rewrites addresses that are relative to a
	 * position in the OUTPUT, so it can only run once the whole output is
	 * in hand, and the host is what has it. A module names the coding and
	 * the filter together because they are not separable - a caller that
	 * could ask for one without the other would be able to ask for the
	 * wrong pair.
	 *
	 * TWO BASES, NOT ONE WITH A FLAG, BECAUSE THE FILTERS DIFFER. MPRESS's
	 * 32 bit stub converts only E8 and E9; its 64 bit stub also converts
	 * FF15/FF17 and 8D05, which are rip-relative and do not exist on i386.
	 * Undoing the wide rule on a 32 bit image rewrites four bytes after
	 * every 0x8D that the packer left alone, so the pair is chosen by the
	 * image's width and the id has to carry it.
	 *
	 * Each base carries lc + 9*lp + 45*pb above it, exactly as
	 * KOF_UNP_LZMA does - so each occupies 224, and 384..608 and 640..864
	 * are what they take. Above KOF_UNP_LZX_RESET_BASE's 32 for the reason
	 * the note there gives: an id range that overlaps another is a bug
	 * nothing catches until two codings answer to one number.
	 */
	KOF_UNP_LZMA_MPRESS32 = 384,
	KOF_UNP_LZMA_MPRESS64 = 640,

	/* See KOF_UNP_ASPACK. 896..1151, one id per marker byte. */
	KOF_UNP_ASPACK_E8E9 = 896
};

/* ASPack's call/jmp coding with `mark` as the filter's marker byte. */
#define KOF_UNP_ASPACK_MARK(mark)                                           \
	((uint32_t)KOF_UNP_ASPACK_E8E9 + ((uint32_t)(mark) & 0xffu))

/*
 * Build one. `bits` is the image's width, 32 or 64, and nothing else is
 * defined - the host refuses an id it cannot place, which is what a wrong
 * width would produce.
 */
#define KOF_UNP_LZMA_MPRESS_PROPS(lc, lp, pb, bits)                         \
	((uint32_t)((bits) == 64u ? KOF_UNP_LZMA_MPRESS64                   \
				  : KOF_UNP_LZMA_MPRESS32) +                \
	 (uint32_t)(lc) + 9u * (uint32_t)(lp) + 45u * (uint32_t)(pb))

#define KOF_UNP_LZMA_PROPS(lc, lp, pb)                                      \
	((uint32_t)KOF_UNP_LZMA + (uint32_t)(lc) + 9u * (uint32_t)(lp) +    \
	 45u * (uint32_t)(pb))

/* The LZX window, in the id - see KOF_UNP_LZX_BASE. `bits` is 15 to 21. */
#define KOF_UNP_LZX(bits)  ((uint32_t)KOF_UNP_LZX_BASE + (uint32_t)(bits))
#define KOF_UNP_LZX_RESET(bits) \
	((uint32_t)KOF_UNP_LZX_RESET_BASE + (uint32_t)(bits))

/* Either shape, which is what a host asks when it only wants to know that the
 * coding is LZX - a name, a listing, a bound on the window. */
#define KOF_UNP_IS_LZX(m)                                                   \
	(((m) > (uint32_t)KOF_UNP_LZX_BASE &&                               \
	  (m) <= (uint32_t)KOF_UNP_LZX_BASE + 21u) ||                       \
	 ((m) > (uint32_t)KOF_UNP_LZX_RESET_BASE &&                         \
	  (m) <= (uint32_t)KOF_UNP_LZX_RESET_BASE + 21u))

/*
 * WHERE IT IS WORTH LOOKING FOR A FILE NOBODY DECLARED.
 *
 * Set by a parser on its context; read by the engine when it descends. Three
 * answers, and the third is not the same as "no answer" - which is the whole
 * reason this is an enumeration rather than a mask with zero meaning something.
 */
enum kof_embed_search {
	/*
	 * Nothing declared a scope, so search the whole object.
	 *
	 * The value zero deliberately, so an object with no parse at all gets
	 * the full search by simply saying nothing. That is today's behaviour
	 * and it is the correct behaviour for those objects: a raw buffer or a
	 * bytecode block has no structure to consult and no region to narrow
	 * to, and a whole PE inside one is exactly what a search is for.
	 */
	KOF_EMBED_ANYWHERE = 0,

	/*
	 * The structure names its carried files, so do not search at all.
	 *
	 * For a format whose entry table IS the answer: PDF /EF, a zip central
	 * directory, a CFB directory, a MIME part list. Searching such an
	 * object cannot find anything the parser did not already declare, and
	 * measurably does find the same bytes a second time - one attachment,
	 * two children, and the second one scanned again for nothing.
	 */
	KOF_EMBED_DECLARED = 1,

	/*
	 * Search, but only inside the regions named in ctx->embed_scope.
	 *
	 * For a format that CANNOT declare its carried files but does know
	 * where one could be. An ELF's embedded blob is in its data, never in
	 * .text; a PE's is in its overlay or its resources. Narrowing is not
	 * only cheaper - a magic-shaped run of bytes inside executable code is
	 * a false child, and not looking there is how it stops being one.
	 *
	 * It gives up the rare file hidden somewhere unexpected. That is the
	 * trade, stated rather than hidden.
	 */
	KOF_EMBED_SCOPED = 2
};

/*
 * Everything a module knows about the object it was asked about.
 *
 * The common tier holds only what means the same thing for every kind of
 * object. entry_off qualifies: it is an offset into the object for anything
 * executable and KOF_NA for anything that is not. e_type does not, because
 * ET_DYN is an ELF concept, so it lives in the ELF view.
 *
 */
/*
 * WHAT A CONTAINER SAYS IS INSIDE IT, AND WHO ACTS ON THAT.
 *
 * A region says which bytes are what KIND. This says which bytes are a THING -
 * a file, a script, a picture - and the difference is the whole of why both
 * exist.
 *
 * WHY A REGION IS NOT ENOUGH, measured rather than argued. A PDF carrying 25
 * images has them in one IMAGE region of 1.3MB, and every question about one
 * image is unanswerable there: which of the 25 matched, where that one starts,
 * whether a PE was appended to the end of one of them. Worse, the region is a
 * UNION - kof_rl_normalise merges ranges that touch - so two files laid end to
 * end become one range and a pattern can match across the seam between them,
 * which is a finding about neither file. A region is the right answer for the
 * parts of ONE thing: a PE's code across several sections is code, and a
 * pattern spanning two of them is a real pattern. It is the wrong answer for a
 * SET of independent things.
 *
 * WHY THE PARSER DECLARES AND DOES NOT ACT. A parser knows where an entry is,
 * what it is, and how it is coded; it has no business deciding whether opening
 * it is worth the budget, and it cannot know - that depends on which rules are
 * loaded, which is the host's knowledge and changes per scan. So the parser
 * fills this in and the host decides. Before this, that decision lived in the
 * unpacker MODULES, which are compiled blobs shipped in a database: skipping
 * images meant editing a blob and rebuilding it, and the policy was per format
 * rather than per engine.
 *
 * WHY THE HOST AND NOT THE MODULE PRODUCES THE CHILD. A module can emit bytes,
 * and that is all it can say about them - so every child arrived untyped and
 * was then guessed at by the sniff chain. Measured on one document: 32 children
 * were produced, 1386 rule evaluations were considered against them, and NONE
 * ran, because an unidentified child is a child no rule targets. Declaring the
 * format here is what makes the work worth doing.
 *
 * Layout rule: append only, like every other structure in this header.
 */

/*
 * What an entry IS, in terms every container shares.
 *
 * Deliberately not a format: a picture is a picture whether it arrives as JPEG
 * in a PDF or as PNG in a zip, and a host deciding whether to spend a
 * decompression on it is asking the same question either way. `format` below is
 * the separate, stronger claim a parser may or may not be able to make.
 */
enum kof_entry_kind {
	KOF_ENT_UNKNOWN = 0,
	KOF_ENT_CONTENT,      /* the container's own presentation data */
	KOF_ENT_SCRIPT,       /* code meant to run when the file is opened */
	KOF_ENT_METADATA,     /* what the file says about itself */
	KOF_ENT_IMAGE,        /* pixels */
	KOF_ENT_FONT,         /* a program for a rasteriser */
	KOF_ENT_EMBEDDED,     /* a file the container carries AS a file */
	KOF_ENT_STRUCTURE,    /* the container's own index or graph, coded */
	/*
	 * THE SAME PROGRAM, WRITTEN ONE WAY. Not a thing the container carried
	 * but a form of the object itself - reindented, uncommented, or with
	 * the literals it joins at run time already joined.
	 *
	 * It is a kind rather than a flag because the pass that makes these has
	 * to recognise its own output: normalising a normalised form yields the
	 * same bytes, and folding one yields what folding its parent already
	 * did, so without a mark every script would be walked twice for a child
	 * that already exists.
	 */
	KOF_ENT_NORMALIZED,
	KOF_ENT_KIND_COUNT
};

/*
 * What an entry IS, as a word.
 *
 * Beside the enum it names, and it exists for the reason kof_format_name does:
 * every host that shows an entry needs this, and the alternative is each one
 * carrying its own table - which is how kofexaminer and kofviewer came to
 * disagree about region labels.
 *
 * SHORT WORDS, because they go in a column beside a length. And UPPER CASE, so
 * a kind cannot be mistaken for a NAME read out of the file, which sits in the
 * same cell and is whatever somebody wrote there.
 *
 * The default is "?" and not "UNKNOWN": UNKNOWN is a real kind - the parser
 * found a thing and declines to say what it is - while a value outside the
 * enumeration is this build not recognising it, which is a fault and not a
 * fact. Spelling them the same would hide the second behind the first.
 */
/*
 * What a coding IS, as a word.
 *
 * Here for the reason kof_entry_kind_name is here: a host that shows an entry
 * has to show its chain, and the alternative is each host inventing a
 * shorthand. One did - the viewer printed a bare "z" for "there is a coding"
 * - and a single letter with no legend anywhere is not a label, it is a thing
 * the reader has to come and ask about.
 *
 * The LZMA ids carry their parameters, so they are a range rather than a
 * value and are named by the range. The NRV2 variants differ only in bit
 * width, which is not worth a column, so they are named by family.
 */
static inline const char *kof_unp_method_name(uint32_t m)
{
	if (KOF_UNP_IS_LZX(m))
		return "lzx";
	if (m >= KOF_UNP_LZMA && m <= KOF_UNP_LZMA + 224u)
		return "lzma";
	if ((m >= KOF_UNP_LZMA_MPRESS32 && m <= KOF_UNP_LZMA_MPRESS32 + 224u) ||
	    (m >= KOF_UNP_LZMA_MPRESS64 && m <= KOF_UNP_LZMA_MPRESS64 + 224u))
		return "lzma+mpress";
	if (m >= KOF_UNP_ASPACK_E8E9 && m <= KOF_UNP_ASPACK_E8E9 + 0xffu)
		return "aspack+e8e9";
	if (m >= KOF_UNP_NRV2B_8 && m <= KOF_UNP_NRV2B_32)
		return "nrv2b";
	if (m >= KOF_UNP_NRV2D_8 && m <= KOF_UNP_NRV2D_32)
		return "nrv2d";
	if (m >= KOF_UNP_NRV2E_8 && m <= KOF_UNP_NRV2E_32)
		return "nrv2e";
	switch (m) {
	case 0:                     return "";        /* nothing to undo */
	case KOF_UNP_DEFLATE:       return "deflate";
	case KOF_UNP_ZLIB:          return "zlib";
	case KOF_UNP_ASCII85:       return "ascii85";
	case KOF_UNP_ASCIIHEX:      return "asciihex";
	case KOF_UNP_RUNLENGTH:     return "runlength";
	case KOF_UNP_LZW:           return "lzw";
	case KOF_UNP_OVBA:          return "ovba";
	case KOF_UNP_LZMA2:         return "lzma2";
	case KOF_UNP_LZMA2_BCJ_X86: return "lzma2+bcj";
	case KOF_UNP_HEXTEXT:       return "hex";
	case KOF_UNP_RAR3:          return "rar3";
	case KOF_UNP_RAR5:          return "rar5";
	case KOF_UNP_BCJ2:          return "bcj2";
	case KOF_UNP_APLIB:         return "aplib";
	case KOF_UNP_ASPACK:        return "aspack";
	case KOF_UNP_LZMAT:         return "lzmat";
	case KOF_UNP_LZMAT_MPRESS32:
	case KOF_UNP_LZMAT_MPRESS64: return "lzmat+cto";
	case KOF_UNP_LZHUF_ARJ:     return "arj";
	case KOF_UNP_LZHUF_LH5:     return "lh5";
	case KOF_UNP_LZHUF_LH6:     return "lh6";
	case KOF_UNP_LZHUF_LH7:     return "lh7";
	default:                    return "?";
	}
}

static inline const char *kof_entry_kind_name(uint32_t kind)
{
	switch (kind) {
	case KOF_ENT_UNKNOWN:   return "UNKNOWN";
	case KOF_ENT_CONTENT:   return "CONTENT";
	case KOF_ENT_SCRIPT:    return "SCRIPT";
	case KOF_ENT_METADATA:  return "METADATA";
	case KOF_ENT_IMAGE:     return "IMAGE";
	case KOF_ENT_FONT:      return "FONT";
	case KOF_ENT_EMBEDDED:  return "EMBEDDED";
	case KOF_ENT_STRUCTURE: return "STRUCTURE";
	case KOF_ENT_NORMALIZED: return "NORMALIZED";
	default:                return "?";
	}
}
/*
 * The bytes are not one range: ask resolve_entry with this entry's `index`.
 *
 * A FLAG AND NOT A ZERO LENGTH, which is how this was first written. An
 * in-band sentinel is the shape hostile input abuses - a declared length of
 * zero then means two different things and the reader has to guess which. A
 * compound file stream is a chain rather than a range, and over 1322 streams
 * in real documents 23.6% are not consecutive, so this is the ordinary case
 * for a whole format and not an edge.
 */
#define KOF_ENT_F_SCATTERED  (1u << 0)

/*
 * THE CODING CHAIN IS INCOMPLETE: something the container declared is not in
 * `coding`, so running `coding` does NOT arrive at the original bytes.
 *
 * Two shapes of the same thing, and the flag covers both. The chain can be
 * EMPTY because the first coding was inexpressible - and an empty chain
 * otherwise means stored, which is the opposite of the truth. Or it can be
 * PARTIAL: every method in it is real and there was one more step the parser
 * could not name, so running it produces bytes that are neither the coded
 * form nor the original.
 *
 * enum kof_unp_method has no value for "a coding that exists and which I
 * cannot perform", and it should not have one: every value in it names a
 * decoder that is present. So the absence has to be said some other way, and
 * without a way to say it the absence is indistinguishable from stored.
 *
 * That is not a cosmetic difference. /Filter [/ASCII85Decode /FlateDecode]
 * reduces to no expressible chain, an empty chain reads as stored, and the
 * host would then window raw ASCII85 AS THOUGH IT WERE THE ORIGINAL BYTES -
 * a rule written against the decoded content matches nothing, and one written
 * against a fixed prefix matches the wrong thing. Reporting the range as
 * present-but-unopenable is the difference between a known gap and a silent
 * wrong answer.
 *
 * Set by the parser when it read the container's declared coding and could
 * not express all of it. THE HOST MUST CHECK IT BEFORE IT CHECKS `coding`,
 * because a partial chain looks perfectly runnable, and report
 * KOF_UNP_UNSUPPORTED - the honest answer: a coding this build lacks is a gap
 * a later build closes, and it is not the same thing as damage.
 */
#define KOF_ENT_F_CODED_UNKNOWN  (1u << 1)

struct kof_entry {
	/*
	 * Where the bytes are, when they are one range. Meaningless when
	 * KOF_ENT_F_SCATTERED is set, and the host must not read it then.
	 */
	uint64_t off, len;

	/* The name, as a range in THIS object and never as a string, for the
	 * reason name_next gives: the name is already in the file, and a parser
	 * has nowhere to build one. Zero length when nothing named it. */
	uint64_t name_off, name_len;

	/* What the decoded bytes should come to, when the container declares it.
	 * Zero when it does not. A hint and never a bound - the host's ceiling
	 * is what bounds, and this must never be an allocation size. */
	uint64_t out_hint;

	/*
	 * THE FORMAT'S OWN INDEX FOR THIS ENTRY, which is not its position in
	 * this array.
	 *
	 * resolve_entry takes the format's index, and a parser may build this
	 * table as a PROJECTION of something else - PDF does, from its object
	 * table, where only the rows that carry a stream become entries. So the
	 * two numbers differ, and assuming they are the same reads the wrong
	 * entry's ranges. That is a correctness bug and not a tidiness point.
	 */
	uint32_t index;

	uint32_t kind;        /* enum kof_entry_kind */
	uint32_t flags;       /* KOF_ENT_F_* */

	/*
	 * HOW TO GET BACK TO THE ORIGINAL BYTES, IN ORDER.
	 *
	 * A CHAIN and not one method, because containers have chains: PDF
	 * writes /Filter [/ASCII85Decode /FlateDecode] and the two are applied
	 * in that order. Held as a single value, a parser had to name one of
	 * them and the order was lost - PDF stored a BITMASK, said so in its
	 * own header, and the decompressor then guessed. Measured: on 1 of 3
	 * real documents that guess fails twice, reaches
	 * kunp_rcstruct_broken(KOF_UNP_UNSUPPORTED), and a clean file is reported as
	 * one the engine could not finish.
	 *
	 * Applied [0] first. A zero terminates - and a FULL array has no
	 * terminator, so a host reads at most four whatever it finds in [3].
	 *
	 * Four, because no real chain is longer and a bound is what stops a
	 * hostile one multiplying. A chain that needed a fifth is reported
	 * through KOF_ENT_F_CODED_UNKNOWN and not quietly cut to four, which
	 * is what happened while the bound sat in the loop condition instead.
	 *
	 * All zero means STORED - the bytes are already what they are - but
	 * ONLY when KOF_ENT_F_CODED_UNKNOWN is clear. Set, it means the
	 * container declared a coding that this build cannot express, and the
	 * bytes must not be handed on as if they were the original.
	 *
	 * The host stops at the first method it does not know and reports
	 * KOF_UNP_UNSUPPORTED, which is the honest answer: a coding this build
	 * lacks is a gap a later build closes. It must never carry on with the
	 * rest of the chain, since every step after a missed one decodes
	 * refuse.
	 */
	/*
	 * uint16_t AND NOT uint8_t, which is what this was.
	 *
	 * A method id does not fit in a byte. KOF_UNP_LZMA is 64 and CARRIES
	 * ITS PARAMETERS IN THE ID - lc + 9*lp + 45*pb, 0..224 above the base -
	 * so the ids run to 288, and KOF_UNP_LZMA_PROPS builds one as a
	 * uint32_t for that reason. Stored in a byte, LZMA(8,4,4) truncates to
	 * 32, which is not an invalid value that something would catch: it is
	 * KOF_UNP_NRV2E_32, a real decoder, and the entry would then name a
	 * coding the container never declared. Exactly the class of silent
	 * wrong answer KOF_ENT_F_CODED_UNKNOWN exists to prevent, arriving
	 * through the width of the field instead.
	 *
	 * No parser fills an LZMA chain yet - PDF has no LZMA - so this is
	 * fixed while it costs four bytes and nothing else. A 7z or xz entry
	 * table is where it would have been found the hard way.
	 */
	uint16_t coding[4];   /* enum kof_unp_method each, [0] applied first */

	/*
	 * The format the parser is WILLING TO DECLARE about the decoded bytes,
	 * or KOF_FMT_UNKNOWN when it will not.
	 *
	 * A claim and not a guess. A PDF knows a content stream is a content
	 * stream because /Contents said so, and it does NOT know what is inside
	 * an /EmbeddedFile - so it declares the first and leaves the second to
	 * the sniff chain, which is what the sniff chain is for. Declaring
	 * wrongly is worse than declaring nothing: the parse named by it runs
	 * instead of the one the bytes deserve.
	 */
	uint8_t  format;
	uint8_t  reserved[3];  /* to 64 bytes; the assert below is the check */
};

/*
 * 64 bytes, and it is not tidiness: a format's view holds an ARRAY of these -
 * PDF's is 1024 long - so padding is multiplied by the entry count and paid on
 * every parse. Widening coding from 8 to 16 bits fitted in the space the
 * reserved bytes already held; the next field that does not will show up here
 * rather than as 8KB more view per document.
 */
_Static_assert(sizeof(struct kof_entry) == 64, "entry record grew padding");

#endif /* KOFENG_KOFENTRY_H */
