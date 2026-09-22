/*
 * ppmd.h - PPMd variant H, as RAR 2.9/3.x uses it.
 *
 * WHY THIS IS ITS OWN FILE AND ITS OWN OBJECT
 *
 * RAR picks between two compressors per block and says which in the first bit of
 * each block header. The LZ half lives in rar3.c; this is the other half, and the
 * two share nothing - not a table, not a bit reader, not a notion of what a symbol
 * is. What they do share is a stream: a PPM block reads its bytes from the same
 * cursor the LZ block left off at, and can hand control back at any symbol.
 *
 * So this is a driven object rather than a decode-this-buffer function. rar3.c
 * owns the stream and asks for one symbol at a time, because RAR's escape symbol
 * is not a byte of output - it introduces an end of block, a filter, or a new
 * file, and only the caller knows what to do with those.
 *
 *
 * THE MODEL IS SHKARIN'S AND THE FRAMING IS RAR'S
 *
 * The model - contexts, suballocator, SEE - is PPMd variant H unchanged. The bytes
 * that start it are RAR's, and were established by reading them out of 1189 real
 * blocks rather than from memory:
 *
 *     byte 0   MaxOrder, and bit 7 of it IS the flag that selected PPM, because
 *              the caller peeked that bit without consuming it
 *                bit 5   restart the model
 *                bit 6   an escape character byte follows
 *                bits 0-4  the order, less one
 *     byte 1   the suballocator size in MB, less one - only when restarting
 *     byte 2   the escape character - only when bit 6 said so
 *
 * Of those 1189 blocks, 965 are "a7 18": restart, order 8, 25MB, which is what
 * every default WinRAR command line produces. The rest run to order 32 and 251MB,
 * and the size is clamped here rather than trusted - it is a byte out of the file
 * and it sizes an allocation.
 */

#ifndef KOFENG_PPMD_H
#define KOFENG_PPMD_H

#include <stdint.h>
#include "decomp.h"

struct kof_ppmd;

/*
 * Room for the model's fixed part. The suballocator's arena is separate and is
 * taken from the caller, so this object can live on a stack the way the rest of
 * this engine's decoders do.
 */
struct kof_ppmd *kof_ppmd_new(void);
void kof_ppmd_free(struct kof_ppmd *);

/*
 * How much arena a block header asks for, clamped to what this build will give.
 *
 * Separate from the start so a caller can refuse before allocating: the number
 * comes out of the file and 251MB of it is an ordinary value in the wild.
 */
uint64_t kof_ppmd_arena_want(uint8_t max_mb_byte);

/*
 * Start a block. `max_order` and `arena` come from the block header the caller
 * read; `in_at` is where in the caller's buffer the range coder should begin.
 * Returns 0 when the model could not be built, which is a refusal rather than a
 * failure - the arena is bounded here and a header may ask for more.
 */
int kof_ppmd_start(struct kof_ppmd *, int max_order, uint64_t arena,
		   const uint8_t *in, uint64_t in_len, uint64_t in_at);

/* A later block that does not restart the model continues the one already
 * built, with the range coder started afresh at `in_at`. */
int kof_ppmd_resume(struct kof_ppmd *, const uint8_t *in, uint64_t in_len,
		    uint64_t in_at);

/* One symbol, 0..255, or -1 when the stream or the model gave out. RAR maps one
 * of those symbols onto its own control codes, which is why this hands back a
 * symbol rather than writing output itself. */
int kof_ppmd_next(struct kof_ppmd *);

/* How far the model has read, so the caller's cursor can follow it. */
uint64_t kof_ppmd_at(const struct kof_ppmd *);

#endif /* KOFENG_PPMD_H */
