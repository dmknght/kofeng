/*
 * kofdefine.h - the entry points of a module (kof_scan, kof_unpack, kof_cure),
 * the macros that define them, and the analysis step a module declares.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFDEFINE_H
#define KOFENG_KOFDEFINE_H

#include <stdint.h>
#include "kofctx.h"

/*
 * Entry point. Defined by the module, called by the loader - through
 * KOF_DEFINE_SCAN below, which is what puts `ctx` in scope for the macros.
 *
 * Returns nothing. A module's output is what it reports, so there is no verdict
 * to return, and a module with nothing to say simply ends - which is why no
 * trailing "return clean" has to be written. Bailing out early is a bare return.
 *
 * The linker script places this first, so its offset inside the blob is zero and
 * the loader needs no symbol table at runtime. Other module roles will follow the
 * same pattern with their own header and their own entry: kof_unpack() from
 * kofunp.h, kof_cure() from kofcure.h.
 */
void kof_scan(const struct kof_obj_ctx *ctx);

/*
 * The other entry point: yield the objects inside this one.
 *
 * A module exports exactly one of kof_scan and kof_unpack, and which one it is
 * decides the kind of the pack it is built into - the build derives that from the
 * exported symbol rather than from a declaration, because a declaration can
 * disagree with the code and an exported symbol cannot.
 *
 * The two are dispatched from different points and never see each other's records:
 * detectors run while an object is being scanned, unpackers afterwards, once the
 * engine has a verdict on the container itself. That ordering is what lets an
 * archive already identified as an exploit be left unopened.
 */
void kof_unpack(const struct kof_obj_ctx *ctx);

/*
 * SEARCHING FOR DECLARED STRINGS
 *
 *     if (kof_find_str(loaded, busybox)) ...
 *     if (kof_find_str_all(code, prologue, marker)) ...
 *     if (kof_find_str_any(data, irc_who, irc_pong, irc_nick)) ...
 *     if (kof_find_str_multi(data, m1, m2, m3, m4) >= 2) ...
 *
 * Range first, then the strings, because the range is the one thing every form
 * shares and the strings are the part that varies in number. The other order
 * cannot express the variadic forms at all: a trailing range after a list of
 * strings is not something a macro can pick out.
 *
 * Every name resolves through an identifier the build defines from the
 * KOF_DEFINE_STR and KOF_TARGET_RANGE declarations in this source. A name that was
 * never declared is an undefined identifier at compile time rather than a lookup
 * that quietly returns false - the failure mode to want, since a signature that
 * silently never matches looks exactly like one that works.
 *
 * No search happens in the module. The host owns the literals and answers these,
 * which is what allows one pass over the object to serve every module, and what
 * makes asking the same question twice free: an answer is memoised per (string,
 * range) for the object, so a module may ask in whatever order reads best.
 *
 *
 * WHERE ctx WENT
 *
 * These take no context argument. It is not passed by some hidden channel - the
 * expansion simply names `ctx`, which is in scope because the entry point takes it
 * and KOF_DEFINE_SCAN below names it that.
 *
 * That is a trade worth stating rather than discovering. What it buys is a call
 * that says only what the author decided - a range and some strings - instead of
 * repeating a parameter that is the same at every call site in the module and can
 * never be anything else. What it costs is that a helper function inside a module
 * must call its context parameter `ctx` too. That costs a compile error naming an
 * undeclared identifier, not a wrong answer, which is the only kind of cost this
 * layer is allowed to have.
 *
 * The C level accessors keep taking it: ctx->obj_size, kof_elf(ctx),
 * ctx->content->rd32(ctx, off). Those are plain C reading a plain struct, and
 * hiding the subject of a field access would be hiding the wrong thing. The line is
 * between the declarative layer, which turns names the build assigned into a
 * question about the object under scan, and the struct underneath it.
 */
#define KOF_PASTE2(a, b) a##b
#define KOF_PASTE(a, b)  KOF_PASTE2(a, b)

/*
 * Define the entry point.
 *
 *     KOF_DEFINE_SCAN
 *     {
 *             ...
 *     }
 *
 * Expands to the prototype the loader calls, which is what guarantees `ctx` exists
 * and is spelled the way the search macros expect. Writing that prototype by hand
 * still works; this exists so the one name the DSL depends on is not a convention
 * anybody has to remember.
 *
 * It is also the only place the entry symbol is spelled. The kind of a module - a
 * detector or an unpacker - is derived at build time from which entry point it
 * exports, so a misspelling here is a module that packs as the wrong kind rather
 * than one that fails to link.
 */
#define KOF_DEFINE_SCAN void kof_scan(const struct kof_obj_ctx *ctx)

/*
 * Define an unpacker.
 *
 *     KOF_DEFINE_UNPACK
 *     {
 *             const struct kof_pe_info *pe = kof_pe(ctx);
 *
 *             if (pe->overlay_len)
 *                     kunp_rcstruct_window(pe->overlay_off, pe->overlay_len);
 *     }
 *
 * Same shape as KOF_DEFINE_SCAN and the same reason: it is the only place the
 * entry symbol is spelled, so a misspelling is a link error rather than a module
 * that packs as the wrong kind.
 */
#define KOF_DEFINE_UNPACK void kof_unpack(const struct kof_obj_ctx *ctx)

/*
 * WHICH STEP OF THE ANALYSIS A MODULE BELONGS TO.
 *
 * THE ORDER IS THE POINT. An object is opened by steps, in this order, and the
 * chain stops at the first step that produces something: what came out is the
 * thing worth looking at, and it goes round again on its own.
 *
 *     KOF_ANALYZE_UNWRAP    bases/decomp/  zip, tar, gzip, 7z, rar, xz
 *                           Reads a TABLE. The container says where its members
 *                           are and the module goes and gets them.
 *
 *                           UNWRAP and not DECOMP, though the directory is
 *                           called decomp: half of what lives there does not
 *                           compress anything. tar only concatenates, and a zip
 *                           entry can be stored. What every one of them does do
 *                           is take a wrapper off something that was already
 *                           whole inside it. Compression is the step below.
 *
 *     KOF_ANALYZE_UNPACK    bases/unp/     upx, midgetpack
 *                           Decompresses an image that was compressed to stop
 *                           it being read.
 *
 *     KOF_ANALYZE_DECRYPT   bases/decoders/ msf_xor, msf_sub, msf_dword,
 *                                          msf_ctxkey, msf_evasion; and
 *                           bases/unp/     ezuri
 *                           Undoes a cipher or an encoder. An msf encoder is a
 *                           cipher with a short key and belongs here, not with
 *                           the packers: nothing about it is compression.
 *
 *     KOF_ANALYZE_CARVE     bases/unp/     embedded files
 *                           SEARCHES. Nothing declared where this content is -
 *                           there is no table to read - so it is found by
 *                           looking. That is the line between this and DECOMP.
 *
 *     KOF_ANALYZE_RECOVER   bases/unp/     the APIs a PE resolves for itself
 *                           Produces NOTHING. It recovers what a program hides
 *                           about ITSELF - the names behind the hashes it calls
 *                           through - and reports it on the object, with
 *                           kunp_sym_import.
 *
 *                           A STEP OF ITS OWN BECAUSE IT IS NOT AN OPENING STEP.
 *                           The four above open an object, and an object that
 *                           already has a name - a rule fired on it before any
 *                           of them ran - is not opened: asking them about it
 *                           would be digging out what is already known. This
 *                           is the other way round. A convicted program is
 *                           exactly the one whose description is worth
 *                           completing, and a decrypt module that produced a
 *                           child has not made it any less true that the
 *                           parent calls what it calls. So it runs FIRST, on
 *                           every object, before any rule reads the symbols it
 *                           completes, and the opening steps never stand in
 *                           front of it.
 *
 *     KOF_ANALYZE_NORMZ     the host itself
 *                           The same object said plainly - see norm_emit in
 *                           scan.c. Last, because it is about the data INSIDE a
 *                           file and everything above it is about getting the
 *                           file's real data out in the first place.
 *
 * THE MEMBERS ARE VERBS, and that is deliberate: they name what the ANALYSER
 * does, not what a module is. The old kind PACKER named the module and five
 * different jobs ended up wearing it - UPX, an AES decryptor, three shellcode
 * decoders and a payload finder - because it was the only label there was.
 *
 * NOT SPELLED KOF_HEUR_PHASE AND NOT CALLED ONE. That name is taken, by
 * EXAMINE and VERDICT, which are about when a heuristic gets to speak. These
 * are steps of opening an object and the two have nothing to do with each
 * other.
 */
enum kof_analyze {
	KOF_ANALYZE_UNWRAP = 0,
	KOF_ANALYZE_UNPACK,
	KOF_ANALYZE_DECRYPT,
	KOF_ANALYZE_CARVE,
	KOF_ANALYZE_NORMZ,
	/*
	 * Last in the enum so no stored step moves; the pipeline's own table, and
	 * not this order, says it runs FIRST - see KOF_ANALYZE_RECOVER above.
	 */
	KOF_ANALYZE_RECOVER,
	KOF_ANALYZE_COUNT
};

/* The word for a step, as a name carries it: "Unwrap:LHA". */
static inline const char *kof_analyze_word(uint32_t step)
{
	switch (step) {
	case KOF_ANALYZE_UNWRAP:  return "Unwrap";
	case KOF_ANALYZE_UNPACK:  return "Unpack";
	case KOF_ANALYZE_DECRYPT: return "Decrypt";
	case KOF_ANALYZE_CARVE:   return "Carve";
	case KOF_ANALYZE_NORMZ:   return "Normalize";
	case KOF_ANALYZE_RECOVER: return "Recover";
	}
	return "";
}

/*
 * WHICH STEP OF OPENING AN OBJECT AN UNPACK MODULE IS - declared, and the only
 * thing it declares about its kind.
 *
 *     KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);    - UPX, Ezuri: it hid a program
 *     KOF_ANALYZE_STEP(KOF_ANALYZE_UNWRAP);    - zip, tar, rar: it carried files
 *
 * Required of every unpack module and meaningless on a detector or a rule. One
 * word replaces two: there was a KOF_UNPACK_KIND with PACKER, CONTAINER and
 * CARVE beside the step enum above, saying the same thing in a coarser
 * vocabulary, and a module that moved had to be changed in both. The step is
 * what the engine runs by - the steps are tried in enum order, each over exactly
 * the modules that declared it - and the three facts the old kind carried are
 * read off it:
 *
 *   it hid a program (UNPACK, DECRYPT)   a layer of packing, which a heuristic
 *                                        may weigh; a container is not one
 *   it searched (CARVE)                  the host is still the subject
 *   it read a table (UNWRAP)             the members are the subject
 *
 * The distinction is EVIDENCE, not tidiness. A file wrapped in an executable
 * packer is saying something about itself: the wrapping exists to stop the file
 * being read, and a heuristic that weighs "this was packed" is weighing that. A
 * file that arrived inside a zip is saying nothing - archives are how software
 * is shipped - and counting a zip as a layer of packing is how a heuristic ends
 * up scoring an installer like a dropper. DECLARED rather than guessed, and the
 * guesses were tried: naming children looked like it separated packers from
 * containers and does not (xz and overlay name nothing either).
 *
 * A CARVE is found by looking, not by reading a table, so what it carves out is
 * not a replacement for its host: an 8.6 MB ELF with 4.2 MB appended had the
 * appendix extracted and then no normalised view of itself at all, because the
 * chain stopped at the first step that produced a child.
 */
#define KOF_ANALYZE_STEP(step)

/*
 * The other entry point a DETECTOR may export: how to undo what kof_scan
 * found. Called by the host, never from inside the module, and only on an
 * object whose scan offered one - see KOF_SCAN_CURABLE.
 */
void kof_cure(const struct kof_obj_ctx *ctx);

#endif /* KOFENG_KOFDEFINE_H */
