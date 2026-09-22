/*
 * pe_rebuild.h - turn an unpacked PE image back into a PE file.
 *
 * What a packer hands back when it is done is the IMAGE, not the file: sections
 * laid out at their virtual addresses, with the headers wherever the stub kept them
 * and no MZ at the front. That is enough to search for strings and it is not enough
 * for anything else - the object does not identify as PE, so it gets no format, no
 * regions, and no module that targets PE ever runs on it. Measured on unpacked UPX
 * output: every child came back KOF_FMT_UNKNOWN.
 *
 * This puts the file back together. It is host code and not a module's job for the
 * same reason the decompressors are: it is one implementation shared by every
 * packer that leaves an image behind, and it works over whole buffers rather than
 * through the module ABI's byte accessors. Kaspersky drew the line in the same
 * place - their unpacker kernel carries _pe_rte.c beside _nrv.c and _lzma.c, and
 * the per-packer modules call into it.
 *
 * It lives here rather than with the collectors because it is not a parse. A
 * collector READS structure out of bytes and changes nothing; this WRITES bytes,
 * and the structure it reads is a means to that. The two are next to each other in
 * subject and opposite in direction, and putting a thing that rewrites objects
 * among the things that only describe them is how a reader ends up expecting the
 * collectors to have side effects.
 *
 * The boundary with kofdecomp is the other one worth stating: kofdecomp turns
 * compressed bytes into bytes, and this turns a packer's output into something the
 * scanner can identify. Reversing a packer's branch-target filter will belong here
 * for the same reason.
 *
 *
 * WHAT IT IS GIVEN AND WHAT IT LOOKS FOR
 *
 * The buffer is the image starting at the first section's virtual address, which is
 * how UPX leaves it: buffer[x] is what would be at RVA first + x once loaded. The
 * original PE header is somewhere inside - UPX keeps it at the end - and it is
 * found by scanning for a signature that is followed by a header that makes sense,
 * not by an offset anybody wrote down.
 *
 * Every field it then reads is attacker controlled, so the rebuilt file is bounded
 * by what was actually in the buffer rather than by what the header claims.
 */

#ifndef KOFENG_PE_REBUILD_H
#define KOFENG_PE_REBUILD_H

#include <stdint.h>

#include "../core/kofcore.h"

/*
 * Rebuild `img` into a PE file.
 *
 * On success *out is a malloc'd file the caller owns and *out_len its length.
 * Returns zero and touches neither when the buffer holds nothing that can be
 * rebuilt - which is the ordinary answer for a packer this does not fit, and is
 * not an error.
 *
 * `cap` bounds the file it will build. A section table can describe a file far
 * larger than the image it came from, and that number came out of the object being
 * scanned, so the caller says how much it is willing to hold.
 */
int kof_pe_rebuild(kof_buf img, uint64_t cap, uint8_t **out, uint64_t *out_len);

#endif /* KOFENG_PE_REBUILD_H */
