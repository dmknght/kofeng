#ifndef KGENOME_IMAGE_EMBED_H
#define KGENOME_IMAGE_EMBED_H

#include <stdint.h>
#include <kofcore.h>
#include "../../kgenome_status.h"
#include "obj.h"

/*
 * WHERE AN OBJECT HELD IN A VARIABLE STARTS (embed-var-1, embed-sniff-1).
 *
 * A payload compiled into a program as data is reached by the program through a pointer
 * to it, or through the symbol of its variable. Measured over 5855 ELF and PE hosts: 95% of the 1227
 * real embedded objects start at the target of a pointer stored in the host's data, 7 start at
 * a sized OBJECT symbol, and none sits inside a variable at an offset above zero. So the
 * candidates are those starts, and what sits at one is the caller's question (the caller owns
 * the format chain; the lib knows only the image).
 *
 * THE PRODUCT, computed once per object: the file offsets that are the target of an aligned
 * word of the host's data (4 or 8 bytes by the class, in the file's byte order) and, when
 * asked, the start of each sized OBJECT symbol of an ELF, that fall inside the data spans.
 * Each one is handed to the caller's `emit` as it is found (so the table that holds them is the
 * caller's and is charged to its budget, and it grows with the candidates, which are a few
 * percent of the words, not with the words); the lib sorts nothing and holds nothing. A pointer
 * stored twice is emitted twice: the caller sorts and drops duplicates once it has them all.
 *
 * NOT SEEN, by construction and said so: a pointer that exists only after relocation (a
 * position independent host stores zero and a relocation addend), a variable reached by
 * computed address, an object encoded in its variable. Next algorithm: the relocation
 * addends (kgenome_elf_reloc_table) as a second source of the same product.
 */

/*
 * WHERE THE VARIABLES ARE: the host's data as the measurement defined it, bytes of the file that are loaded and are not
 * executable. The segments say it first (a PT_LOAD without X, a non-code section of a PE) and the sections correct the
 * segments (an alloc, non-exec section is data even inside an R-X segment: .rodata is, and the Mirai arrays of
 * ELF headers are in it; an exec section is code even inside a writable one). A host that cannot tell
 * code from data - an ELF with no section table (UPX, a stripped static bot) - or has no data at all (one RWX segment, a dump)
 * answers ALL its loaded bytes: there the code IS the data (329 of the 2159 real objects of the measurement).
 * Ascending, disjoint, inside the file. KGENOME_EMBED_SPANS_MAX is what the parse's own tables can name, so the answer
 * is never cut and `out` needs no more room than that.
 */
#define KGENOME_EMBED_SPANS_MAX 512u

struct kgenome_embed_span {
	uint64_t off, len;                  /* a range of the file */
};

uint32_t kgenome_image_embed_spans(const struct kgenome_obj *obj, kof_buf file, struct kgenome_embed_span *out);

/* Also the start of every sized OBJECT symbol (ELF with a symbol table). */
#define KGENOME_EMBED_SYMBOLS 1u

struct kgenome_embed_req {
	const struct kgenome_obj *obj;      /* a parsed ELF or PE */
	kof_buf file;
	const struct kgenome_embed_span *data;  /* where candidates may start: ascending, disjoint */
	uint32_t n_data;
	uint32_t flags;                     /* KGENOME_EMBED_* */
	int (*emit)(void *user, uint64_t off);  /* one candidate; 0 stops the walk (a budget) */
	void *user;
};

struct kgenome_embed_res {
	uint64_t n;                         /* candidates emitted */
	enum kgenome_status status;         /* TRUNCATED when `emit` refused one: partial and true */
};

void kgenome_image_embed_starts(const struct kgenome_embed_req *rq, struct kgenome_embed_res *res);

/* The bytes at the start of `f` read as the header of an ELF held in a variable: the whole header
 * validated (class, data, version, EXEC or DYN, header sizes, a program header table, a machine the
 * parse names), which the four magic bytes are not. */
int kgenome_elf_hdr_valid(kof_buf f);

/* The first 8 bytes of an ELF: the magic, a class, a data order, the version. The cheap half of kgenome_elf_hdr_valid, which a
 * caller that decodes a candidate under a key asks of 8 decoded bytes before it decodes the rest. */
int kgenome_elf_ident_valid(const uint8_t id[8]);

/* How many bytes the ELF at the start of `f` owns by its own headers, each part whole inside `f`; 0 when
 * it is not an ELF. */
uint64_t kgenome_elf_extent(kof_buf f);

/* How many bytes the object of format `fmt` (KGENOME_FMT_ELF / _PE) at the start of `f` owns by
 * its own headers: 0 when the format has no such answer or `f` is not one. */
uint64_t kgenome_image_embed_extent(uint8_t fmt, kof_buf f);

#endif /* KGENOME_IMAGE_EMBED_H */
