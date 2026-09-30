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
 * The boundary with decomp is the other one worth stating: decomp turns
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

#include "../../kofcore/kofcore.h"

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



/*
 * ---- A HEADER WRITTEN FROM A DECLARATION, NOT FROM A SECOND IMAGE -----------
 *
 * kof_pe_layout_of below reads structure out of bytes a stub left behind. This
 * is the other direction and the one a module needs: it has just BUILT an image
 * and knows its layout exactly, so nothing should have to be read back out of
 * it.
 *
 * Until now a module said its layout by synthesising a PE header itself - see
 * the three modules that include bases/unp/pe_reassemble.h - and the engine
 * parsed that header back to recover what the module already knew. The round
 * trip loses whatever the header has no field for, and the losses are measured
 * in `section` in kofsig.h: hollowness, alignment padding, and whether a
 * section was read, recovered or invented.
 *
 * So the module declares, the engine writes. `tmpl` is the object the child came
 * out of, which supplies the things a layout does not say - machine, bitness,
 * image base, subsystem, and the data directories that still point at something.
 */
/* A directory a module rebuilt, which overrides whatever `tmpl` had. */
struct kof_dir_decl { uint64_t rva, size; int set; };

struct kof_sec_decl {
	char     name[9];
	uint64_t rva, vsize;
	uint32_t perm;       /* KOF_PE_PERM_*, as the parser reports them */
	uint32_t flags;      /* KOF_SECF_*, see kofsig.h */
};

/*
 * Writes into [out, out + cap) and returns the bytes written, or 0.
 *
 * `cap` is the span before the first declared section - the header has to fit in
 * front of the content, and a caller that laid its sections out too tightly is
 * told rather than allowed to overwrite them.
 */
/*
 * The layout an image carries in its own header, as a declaration - see the
 * note beside the definition. Returns how many sections it wrote.
 */
uint32_t kof_pe_layout_of(kof_buf img, struct kof_sec_decl *out, uint32_t cap,
			  uint64_t *entry, uint64_t *base,
			  struct kof_dir_decl *dir);

uint64_t kof_pe_write_hdr(uint8_t *out, uint64_t cap,
			  const struct kof_pe_info *tmpl,
			  const struct kof_sec_decl *sec, uint32_t n,
			  uint64_t entry_rva, uint64_t image_end,
			  const struct kof_dir_decl *dir);


/*
 * ---- AN IMPORT DIRECTORY WRITTEN FROM DECLARATIONS -------------------------
 *
 * The same direction as kof_pe_write_hdr and the same argument for it: a module
 * that rebuilds imports knows the library, the function and the thunk, and had
 * to encode all three into PE structures so the engine could parse them back.
 * See `import` in kofsig.h, where that round trip is described.
 *
 * ONE BINDING. `dll` and `fn` are offsets into `pool`, a NUL-separated blob the
 * caller owns; `fn_off` is ignored when `ordinal` is non-zero. `iat_rva` is the
 * thunk the loader binds into, and 0 means the caller did not know one - the
 * entry is still described, it simply has no slot to fill.
 */
struct kof_imp_decl {
	uint64_t iat_rva;
	uint32_t dll_off, fn_off;
	uint16_t ordinal;
	uint16_t _pad;
};

/*
 * How many bytes the table needs at `base`, or 0 when it cannot be built.
 *
 * Asked before anything is written, because the caller owns the layout and has
 * to reserve the room - see import_bytes in kofsig.h.
 */
uint64_t kof_pe_imports_size(const struct kof_imp_decl *imp, uint32_t n,
			     const char *pool, uint64_t pool_n, int is64);

/*
 * Write it into `img` - the WHOLE child image, addressed by RVA, because the
 * thunks this fills are anywhere in it and the table itself is at `base`.
 *
 * `img_n` bounds every write. Returns the bytes the table occupies at `base`,
 * or 0 when anything did not fit - in which case nothing of the child has been
 * changed, so a caller can refuse rather than hand over a half-written table.
 */
uint64_t kof_pe_write_imports(uint8_t *img, uint64_t img_n, uint64_t base,
			      const struct kof_imp_decl *imp, uint32_t n,
			      const char *pool, uint64_t pool_n, int is64);


#endif /* KOFENG_PE_REBUILD_H */
