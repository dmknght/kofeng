/*
 * wtext.h - turning a provider's string bytes into UTF-8, with no Windows in it.
 *
 * SPLIT OUT OF wevt_decode.c ON PURPOSE, and the purpose is testability rather
 * than tidiness.
 *
 * wevt_decode.h says this conversion is "the part with no Windows API in it and
 * the part most worth testing directly" - and it then lived in a translation
 * unit that opens with #include <windows.h>, so no host could compile it and
 * nothing ever did. A claim about what is testable is only worth the file
 * boundary that makes it true.
 *
 * These two are also the only arithmetic in the decode: a surrogate pair, a
 * four-byte encoding, a buffer that runs out mid-codepoint. That is where the
 * bugs are, and it is now the part a Linux CI compiles and runs.
 */

#ifndef KOFGRILLE_WTEXT_H
#define KOFGRILLE_WTEXT_H

#include <stdint.h>
#include <stddef.h>

/*
 * UTF-16 to UTF-8, into a fixed buffer, with control characters replaced.
 *
 * Returns bytes written, never including the NUL; sets *cut when the input did
 * not fit. `cut` may be NULL.
 *
 * Control characters become '.', for the reason the engine sanitises an archive
 * entry name: an image path is chosen by whoever created the file, it is
 * printed to a terminal, and a terminal escape in it is a report that lies
 * about what it says.
 */
size_t kofw_utf16_to_utf8(const uint16_t *src, size_t src_chars,
			  char *dst, size_t dst_cap, int *cut);

/*
 * The same, for a payload that carries its string as bytes rather than UTF-16.
 *
 * WHICH IS NOT HYPOTHETICAL AND IS WHY THIS EXISTS: on the build this was
 * written against, Kernel-Process spells ImageName as UNICODESTRING in
 * ProcessStart and as ANSISTRING in ProcessStop. A decoder that handled only
 * the first got a complete image path from every start and nothing at all from
 * any stop, and reported it as an absent field rather than as an unhandled
 * type - which is the right failure and still took a shape dump to explain.
 *
 * A byte at or above 0x80 becomes '?'. The provider does not say which codepage
 * these bytes are in, so there is no correct interpretation available; turning
 * them into plausible-looking text would invent one, and leaving them raw would
 * emit a string that is not valid UTF-8 into everything downstream. Marking
 * them unknown is the only one of the three that claims nothing.
 */
size_t kofw_ansi_to_text(const uint8_t *src, size_t n, char *dst,
			 size_t dst_cap, int *cut);

#endif /* KOFGRILLE_WTEXT_H */
