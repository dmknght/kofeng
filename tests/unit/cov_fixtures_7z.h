/*
 * cov_fixtures_7z.h - a writer of 7z archives, for the tests that need one (cov_sevenzip_real.c, cov_oom_formats.c).
 *
 * Written from the format document: the signature header with its CRCs, packed streams, and a header naming the
 * folders, coders and files; the coded streams are made by the system's xz and gzip (via_tool) so the writer's
 * reading of the format is not the only check on the decoders. Nothing is written to a file: the tools read an
 * anonymous memory file.
 */
#ifndef COV_FIXTURES_7Z_H
#define COV_FIXTURES_7Z_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../../libkofeng/kofcore/kofcore.h"
#include "../lib/uncoat/hostile_enc.h"

/* ---- the archive writer ---------------------------------------------------------------------- */

struct wb {
	uint8_t *p;
	size_t   n, cap;
};

static inline void wb_put(struct wb *b, const void *d, size_t n)
{
	if (b->n + n <= b->cap)
		memcpy(b->p + b->n, d, n);
	b->n += n;
}

static inline void wb_u8(struct wb *b, unsigned v)
{
	uint8_t c = (uint8_t)v;

	wb_put(b, &c, 1);
}

/* 7-Zip's variable length number: the high bits of the first byte count the bytes that follow */
static inline void wb_num(struct wb *b, uint64_t v)
{
	uint8_t first = 0, mask = 0x80;
	unsigned i, k;

	for (i = 0; i < 8; i++) {
		if (v < (1ull << (7 * (i + 1)))) {
			first |= (uint8_t)(v >> (8 * i));
			break;
		}
		first |= mask;
		mask >>= 1;
	}
	wb_u8(b, first);
	for (k = 0; k < i; k++)
		wb_u8(b, (unsigned)(v >> (8 * k)) & 0xffu);
}

static inline void wb_le32(struct wb *b, uint32_t v)
{
	uint8_t c[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };

	wb_put(b, c, 4);
}

static inline void wb_le64(struct wb *b, uint64_t v)
{
	wb_le32(b, (uint32_t)v);
	wb_le32(b, (uint32_t)(v >> 32));
}

enum { ID_END = 0, ID_HEADER = 1, ID_MAINSTREAMS = 4, ID_FILES = 5, ID_PACKINFO = 6, ID_UNPACK = 7, ID_SUBSTREAMS = 8,
       ID_SIZE = 9, ID_CRC = 10, ID_FOLDER = 11, ID_CODERSSIZE = 12, ID_NUMUNPACK = 13, ID_EMPTYSTREAM = 14,
       ID_EMPTYFILE = 15, ID_NAMES = 17, ID_ENCODED = 23 };

/* one coder of a folder */
struct coder {
	uint8_t  id[4];
	unsigned idlen;
	uint8_t  props[8];
	unsigned plen;
};

static const struct coder C_COPY = { { 0x00 }, 1, { 0 }, 0 };
static const struct coder C_LZMA2 = { { 0x21 }, 1, { 0x18 }, 1 };                          /* dictionary 1 MiB */
static const struct coder C_LZMA = { { 0x03, 0x01, 0x01 }, 3, { 0x5d, 0x00, 0x00, 0x10, 0x00 }, 5 };  /* lc3 lp0 pb2, 1 MiB */
static const struct coder C_DEFLATE = { { 0x04, 0x01, 0x08 }, 3, { 0 }, 0 };
static const struct coder C_BCJ = { { 0x03, 0x03, 0x01, 0x03 }, 4, { 0 }, 0 };

static inline void wb_coder(struct wb *b, const struct coder *c)
{
	wb_u8(b, c->idlen | (c->plen ? 0x20u : 0u));
	wb_put(b, c->id, c->idlen);
	if (c->plen) {
		wb_num(b, c->plen);
		wb_put(b, c->props, c->plen);
	}
}

/* one folder of the archive: its coders (a chain is listed from the packed stream outward), the packed bytes, the files in it */
#define MAXF 6
struct folder {
	const struct coder *coder[2];
	unsigned            n_coders;
	const uint8_t      *packed;
	size_t              packed_len;
	size_t              unpack_len;      /* the folder's decoded length */
	unsigned            n_files;         /* substreams */
	size_t              file_len[MAXF];
};

struct afile {
	const char    *name;
	int            empty_stream;         /* a directory entry or an empty file: no substream */
	int            empty_file;
};

static inline void wb_names(struct wb *b, const struct afile *f, unsigned n)
{
	size_t at;
	unsigned i;
	struct wb tmp;
	uint8_t scratch[1024];

	tmp.p = scratch;
	tmp.n = 0;
	tmp.cap = sizeof scratch;
	wb_u8(&tmp, 0);                          /* external = 0 */
	for (i = 0; i < n; i++) {
		const char *s = f[i].name;

		for (; *s; s++) {
			wb_u8(&tmp, (unsigned char)*s);
			wb_u8(&tmp, 0);
		}
		wb_u8(&tmp, 0);
		wb_u8(&tmp, 0);
	}
	wb_u8(b, ID_NAMES);
	wb_num(b, tmp.n);
	for (at = 0; at < tmp.n; at++)
		wb_u8(b, scratch[at]);
}

/* the plain header: streams info of the folders, then the file list */
static inline size_t build_header(uint8_t *out, size_t cap, const struct folder *fo, unsigned n_fo, const struct afile *files,
			   unsigned n_files)
{
	struct wb b = { out, 0, cap };
	unsigned i, k, n_empty = 0;

	wb_u8(&b, ID_HEADER);
	if (n_fo) {
		wb_u8(&b, ID_MAINSTREAMS);
		wb_u8(&b, ID_PACKINFO);
		wb_num(&b, 0);                       /* packPos */
		wb_num(&b, n_fo);
		wb_u8(&b, ID_SIZE);
		for (i = 0; i < n_fo; i++)
			wb_num(&b, fo[i].packed_len);
		wb_u8(&b, ID_END);
		wb_u8(&b, ID_UNPACK);
		wb_u8(&b, ID_FOLDER);
		wb_num(&b, n_fo);
		wb_u8(&b, 0);                        /* external */
		for (i = 0; i < n_fo; i++) {
			wb_num(&b, fo[i].n_coders);
			for (k = 0; k < fo[i].n_coders; k++)
				wb_coder(&b, fo[i].coder[k]);
			if (fo[i].n_coders == 2) {
				wb_num(&b, 1);               /* a bind pair: coder 1's input (the filter's) */
				wb_num(&b, 0);               /* is fed by coder 0's output (the decoder's) */
			}
		}
		wb_u8(&b, ID_CODERSSIZE);
		for (i = 0; i < n_fo; i++)
			for (k = 0; k < fo[i].n_coders; k++)
				wb_num(&b, fo[i].unpack_len);
		wb_u8(&b, ID_END);
		wb_u8(&b, ID_SUBSTREAMS);
		wb_u8(&b, ID_NUMUNPACK);
		for (i = 0; i < n_fo; i++)
			wb_num(&b, fo[i].n_files);
		wb_u8(&b, ID_SIZE);
		for (i = 0; i < n_fo; i++)
			for (k = 0; k + 1 < fo[i].n_files; k++)
				wb_num(&b, fo[i].file_len[k]);
		wb_u8(&b, ID_END);
		wb_u8(&b, ID_END);
	}
	wb_u8(&b, ID_FILES);
	wb_num(&b, n_files);
	for (i = 0; i < n_files; i++)
		n_empty += files[i].empty_stream != 0;
	if (n_empty) {
		unsigned bytes = (n_files + 7u) / 8u;
		uint8_t bits[32] = { 0 }, ef[32] = { 0 };
		unsigned any_ef = 0;

		for (i = 0; i < n_files; i++) {
			if (files[i].empty_stream)
				bits[i / 8] |= (uint8_t)(0x80u >> (i % 8));
		}
		wb_u8(&b, ID_EMPTYSTREAM);
		wb_num(&b, bytes);
		wb_put(&b, bits, bytes);
		{
			unsigned e = 0, eb;

			for (i = 0; i < n_files; i++)
				if (files[i].empty_stream) {
					if (files[i].empty_file) {
						ef[e / 8] |= (uint8_t)(0x80u >> (e % 8));
						any_ef = 1;
					}
					e++;
				}
			eb = (n_empty + 7u) / 8u;
			if (any_ef) {
				wb_u8(&b, ID_EMPTYFILE);
				wb_num(&b, eb);
				wb_put(&b, ef, eb);
			}
		}
	}
	wb_names(&b, files, n_files);
	wb_u8(&b, ID_END);
	wb_u8(&b, ID_END);
	return b.n;
}

static inline uint32_t crc32(const uint8_t *p, size_t n)
{
	return kof_crc32(p, n);
}

/* signature header + packed streams + next header; returns the archive length */
static inline size_t assemble(uint8_t *out, size_t cap, const uint8_t *packed, size_t packed_len, const uint8_t *hdr, size_t hdr_len)
{
	struct wb b = { out, 0, cap }, start;
	uint8_t sh[20];
	struct wb s2 = { sh, 0, sizeof sh };

	if (32 + packed_len + hdr_len > cap)
		return 0;
	wb_put(&b, "7z\xbc\xaf\x27\x1c", 6);
	wb_u8(&b, 0);
	wb_u8(&b, 4);
	wb_le64(&s2, packed_len);
	wb_le64(&s2, hdr_len);
	wb_le32(&s2, crc32(hdr, hdr_len));
	wb_le32(&b, crc32(sh, 20));
	wb_put(&b, sh, 20);
	(void)start;
	wb_put(&b, packed, packed_len);
	wb_put(&b, hdr, hdr_len);
	return b.n;
}

/* ---- the tools ------------------------------------------------------------------------------- */

static inline int have(const char *path)
{
	return access(path, X_OK) == 0;
}

static inline size_t via_tool(const char *cmd, const uint8_t *plain, size_t n, uint8_t *out, size_t cap)
{
	int fd = memfd_create("kofeng-7z", 0);
	char full[400];
	FILE *f;
	size_t got = 0, k;

	if (fd < 0)
		return 0;
	if (n && write(fd, plain, n) != (ssize_t)n) {
		close(fd);
		return 0;
	}
	snprintf(full, sizeof full, "%s < /proc/%d/fd/%d 2>/dev/null", cmd, (int)getpid(), fd);
	f = popen(full, "r");
	if (f) {
		while ((k = fread(out + got, 1, cap - got, f)) > 0)
			got += k;
		pclose(f);
	}
	close(fd);
	return got;
}

static inline size_t gzip_raw(const uint8_t *p, size_t n, uint8_t *out, size_t cap)
{
	static uint8_t gz[1 << 16];
	size_t got = via_tool("/usr/bin/gzip -9 -n -c", p, n, gz, sizeof gz), off = 0, raw = hv_gzip_raw(gz, got, &off);

	if (!raw || raw > cap)
		return 0;
	memcpy(out, gz + off, raw);
	return raw;
}

/* ---- the plaintext files ------------------------------------------------------------------------ */

static inline size_t text_file(uint8_t *p, unsigned k, size_t lines)
{
	size_t n = 0, i;

	for (i = 0; i < lines; i++)
		n += (size_t)sprintf((char *)p + n, "file %u line %zu: a 7z folder holds this, solid, behind one coder\n", k, i);
	return n;
}

static inline size_t x86_file(uint8_t *p, size_t calls)
{
	size_t n = 0, i;
	uint64_t s = 0xfeedfaceull;

	for (i = 0; i < calls; i++) {
		int32_t rel;

		s ^= s << 13; s ^= s >> 7; s ^= s << 17;
		p[n++] = 0x55; p[n++] = 0x89; p[n++] = 0xe5; p[n++] = 0xe8;
		rel = (int32_t)((s >> 33) % 3000u) - 1500;
		memcpy(p + n, &rel, 4);
		n += 4;
		p[n++] = 0xc3;
	}
	return n;
}


#endif /* COV_FIXTURES_7Z_H */
