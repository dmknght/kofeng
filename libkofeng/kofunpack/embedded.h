/*
 * embedded.h - whole executables carried inside another object.
 *
 * A dropper does not always compress what it carries. Sometimes it simply
 * appends it, or lays several of them out inside its own code segment and picks
 * one at run time - measured on `bc5c2358e58876be...`, five ELF files in CODE,
 * one each for ARM, ARM, x86, MIPS and x86-64. Nothing unpacks those: there is
 * nothing to unpack, the bytes are already the file. They are simply never
 * offered to the scanner as objects, so a signature that would name the payload
 * never sees it and the region partition files the whole thing under CODE.
 *
 * WHY A STRICT HEADER CHECK IS THE WHOLE DESIGN
 *
 * A four-byte magic occurs by accident in any large file, and a scanner that
 * emitted a child for every "\x7fELF" would spend its budget on noise. So a
 * candidate is accepted only when the fields that a real header must agree on
 * do agree: the class, the byte order, the version, an e_type that exists, an
 * e_machine this decade uses, and a header size matching the class. Measured
 * with exactly those tests: 0 of 1 328 clean binaries carry one, against 6 of
 * 215 malware samples. That gap is what makes the pass worth making.
 *
 * WHAT IT DOES NOT DO
 *
 * It does not decide what the object IS - that is the collector's job once the
 * bytes are handed over as a child - and it does not repair anything. An
 * embedded header that lies about its own length yields a child bounded by the
 * parent, because the parent's end is a fact and the length field is not.
 */

#ifndef KOFENG_EMBEDDED_H
#define KOFENG_EMBEDDED_H

#include <stdint.h>

struct kof_embedded {
	uint64_t off;      /* where it starts in the parent           */
	uint64_t len;      /* how far it reaches, bounded by the parent */
	uint8_t  fmt;      /* enum kof_format: ELF or PE               */
};

/*
 * Is there a whole executable at `off` in [p, p+n), and how long is it.
 *
 * Returns non-zero and fills `out` when the header at that offset passes every
 * test; zero otherwise, which is the answer for nearly every occurrence of the
 * magic. `off` of zero is refused: that is the object itself.
 */
int kof_embedded_at(const uint8_t *p, uint64_t n, uint64_t off,
		    struct kof_embedded *out);

#endif /* KOFENG_EMBEDDED_H */
