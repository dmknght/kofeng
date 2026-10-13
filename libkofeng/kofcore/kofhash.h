/*
 * kofhash.h - SHA-256 over bytes and files, and the status codes the core
 * functions return. In core so that libkofeng and the libs under it share one
 * declaration; <kofeng.h> includes it, so a host sees the same names as before.
 */
#ifndef KOFENG_KOFHASH_H
#define KOFENG_KOFHASH_H

#include <stdint.h>

/* Error returns, distinct from a finding count of zero. */
#define KOF_ERR_OPEN (-1)      /* could not be opened, or is not a regular file */
#define KOF_ERR_READ (-2)      /* could not be mapped */
#define KOF_ERR_ARG  (-3)

/* ------------------------------------------------------------------- digest */

/*
 * SHA-256, AND WHY A SCANNING ENGINE HANDS ONE OUT.
 *
 * Because naming bytes is not a detection question and every tool around this
 * one has it. An event report names a file a traced process created; kofeditor
 * writes a `Test sample:` line into every generated signature source; a
 * verdict cache keys on an identity its caller supplies; a walk that meets the
 * same bytes by two paths has to notice. Four callers, one answer, and four
 * private copies would be four chances to print a digest nobody reproduces.
 *
 * It sits beside kentropy_eighths for the same reason that does: a
 * primitive over bytes that says nothing about malice, useful to a host
 * precisely because it is not a verdict. See core/kofhash.c for why SHA-256 is
 * the only one here and why there are no intrinsics behind it.
 */
struct kof_sha256 {
	uint32_t h[8];
	uint64_t len;          /* bytes fed, before padding */
	uint32_t n;            /* bytes sitting in buf */
	uint8_t  buf[64];
};

/*
 * Streaming, because the thing worth hashing does not always fit and is not
 * always in one place: a file arrives in chunks, and a region of a mapped
 * image is several ranges of one object.
 *
 * A state that has been through khash_sha256_final is FINISHED, not resumable -
 * the padding has been folded in. Init again for another digest.
 */
void khash_sha256_init(struct kof_sha256 *);
void khash_sha256_update(struct kof_sha256 *, const void *bytes, uint64_t n);
void khash_sha256_final(struct kof_sha256 *, uint8_t out[32]);

/* The 32 bytes as 64 lower-case hex characters plus a NUL. Lower case is not
 * a preference - see core/kofhash.c. */
void khash_sha256_hex(const uint8_t digest[32], char out[65]);

/* One buffer, straight to hex. Returns 0, or KOF_ERR_ARG. */
int  khash_sha256_bytes(const void *bytes, uint64_t n, char out[65]);

/*
 * One file, straight to hex, with the size it hashed when `size` is not NULL.
 *
 * Returns 0, KOF_ERR_OPEN, or KOF_ERR_READ - and a read error is returned
 * rather than hashing what arrived, because a digest over part of a file names
 * bytes that were never the artefact. That is the case a tool hashing a file
 * some other process is still writing will actually hit.
 */
int  khash_sha256_file(const char *path, char out[65], uint64_t *size);

#endif /* KOFENG_KOFHASH_H */
