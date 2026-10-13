#ifndef KUNCOAT_UNCOAT_H
#define KUNCOAT_UNCOAT_H

/*
 * uncoat.h - the one public header of kuncoat, the algorithms that grow without
 * a forecast. Buffers and a budget in, bytes and a status out; the lib reads no
 * engine state and writes no global state.
 *
 * THREE PARTS, and no fourth:
 *
 *   decompressors/  inflate, bzip2, lzma (and LZMA2), lzx, lzhuf, lzw, ppmd,
 *                   rar3, rar5, nrv2, aplib, lzmat, ovba, aspack, and the branch
 *                   and call filters that go with decompression (bcj, bcj2,
 *                   the MPRESS call filter). Each has its own header with its
 *                   own entry points.
 *   decryptors/     the keyed ciphers - XOR_KEY, XOR_COUNTER, XOR_ADD32,
 *                   PLACEHOLDER_SUB, X86_SUB_CHAIN, RC4 - run through
 *                   kuncoat_transform.
 *   decoders/       the text codings - B64, HEX, URL, ADD, CAESAR, REVERSE, run
 *                   through kuncoat_transform, and textcode (a85, ahx, rle).
 *
 * Unpacking a packer statically is a routine in bases/ that calls these
 * algorithms; a packer-specific algorithm (ASPack's block decoder, MPRESS's call
 * filter, UPX's unfilter) is still an algorithm and lives with the
 * decompressors.
 *
 * <status.h> is the status every part reports (enum kuncoat_status);
 * kuncoat_transform (transform.h) is the single entry point for the decryptors
 * and the decoders. A caller that needs one decompressor may include its header
 * (<decompressors/inflate.h>) alone; a caller that uses more than one part
 * includes this.
 */

#include "status.h"
#include "transform.h"

#include "decompressors/aplib.h"
#include "decompressors/aspack.h"
#include "decompressors/bcj.h"
#include "decompressors/bcj2.h"
#include "decompressors/bzip2.h"
#include "decompressors/inflate.h"
#include "decompressors/lzhuf.h"
#include "decompressors/lzma.h"
#include "decompressors/lzmat.h"
#include "decompressors/lzw.h"
#include "decompressors/lzx.h"
#include "decompressors/nrv2.h"
#include "decompressors/ovba.h"
#include "decompressors/ppmd.h"
#include "decompressors/rar3.h"
#include "decompressors/rar5.h"

#include "decryptors/ciphers.h"

#include "decoders/codings.h"
#include "decoders/textcode.h"

#endif /* KUNCOAT_UNCOAT_H */
