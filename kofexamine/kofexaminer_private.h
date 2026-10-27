/*
 * kofexaminer_private.h - what the units of kofexaminer share.
 *
 * The examiner printed everything from one file; it is the same program in the same
 * order of functions, cut by job. This header holds the includes, the two macros more
 * than one unit uses, and the printers and state one unit offers another.
 *
 *   kofexaminer         main, usage, examine of a file and of its bytes
 *   kofexaminer_out     colour, the shared line printers (put_off, put_type, notes)
 *   kofexaminer_elfpe   ELF and PE views, the symbol block, the declared regions
 *   kofexaminer_cont    containers and documents, and print_view that picks one
 *   kofexaminer_blocks  --blocks / --hashes / --scfind
 *   kofexaminer_unpack  what the unpackers recover: the callbacks and the pass
 *
 * Not installed, not part of any surface. Names a unit shares are kex_.
 */
#ifndef KOF_KOFEXAMINER_PRIVATE_H
#define KOF_KOFEXAMINER_PRIVATE_H

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h (below),
 * whose POSIX branch defines kof_memmem by calling the real memmem - a
 * GNU/BSD extension the compiler must still see declared to compile that
 * inline function, whether or not this file itself calls it. _POSIX_C_SOURCE
 * alone does not just omit memmem on glibc, it suppresses it (any of
 * _POSIX_C_SOURCE/_XOPEN_SOURCE defined without _GNU_SOURCE/_DEFAULT_SOURCE
 * opts into strict POSIX) - missed originally because every build so far ran
 * on Windows, where kof_memmem never touches the real memmem. Before any
 * include, not after: a feature test macro placed later has no effect. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/kofcore/kofplatform.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/kofsym.h>
#include "../libkofeng/analyzers/parsers/binaries/elf/elf_sym.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include <kofmod/pe.h>
#include <kofmod/gzip.h>
#include <kofmod/docole.h>
#include <kofmod/zip.h>
#include <kofmod/tar.h>
#include <kofmod/sevenzip.h>
#include <kofmod/rar.h>
#include <kofmod/xz.h>
#include <kofmod/bz2.h>
#include <kofmod/chm.h>
#include <kofmod/cab.h>
#include <kofmod/lha.h>
#include <kofmod/arj.h>
#include <kofmod/lnk.h>
#include <kofmod/reg.h>
#include <kofmod/rtf.h>

#include "../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../libkofeng/analyzers/parsers/binaries/funcs.h"
#include <celllysis/trueline.h>
#include "../libkofeng/detectors/linkage/kofdiag.h"
#include "../libkofeng/analyzers/genome_obj.h"
#include "../libkofeng/detectors/mutations/kofmutation.h"
#include "../libkofeng/scanners/scan.h"
#include "kofinspect.h"
#include "kofscfind.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../libkofeng/analyzers/parsers/containers/docole_parse.h"
#include "../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include "../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../libkofeng/analyzers/parsers/containers/rtf_parse.h"
#include "../libkofeng/analyzers/parsers/containers/pdf_parse.h"

#include "kofinspect.h"
#include "../libkofeng/databases/pack/hexprog.h"
/*
 * A region name with its KOF_SCAN_<FMT>_ prefix skipped, for the summary column.
 *
 * The full identifier is what a file is named, because that is what somebody
 * greps for. Six of them on one line is not something anybody reads, so the part
 * that is the same on every one is dropped here rather than kept in a second
 * table that could disagree with the first.
 */
/* Was short_region here. Moved to kofinspect.c so kofviewer shares it
 * rather than keeping a second one that disagreed - see kofinspect.h. */
#define short_region kof_region_label

/*
 * Where a dump goes, what goes in it and how it is named are all in kofinspect
 * now: kofviewer writes the same directories from its File menu, and two
 * implementations of "what is in CODE" would be two answers to the question the
 * dump exists to settle. What stayed here is the printing.
 */
#define PATH_ROOM KOF_DUMP_PATH_ROOM

/* kofexaminer.c */
int kex_examine_bytes(kof_buf buf, const char *display, const char *dir);

/* kofexaminer_out.c: colour and line printers */
int kex_stdout_is_tty(void);
void kex_colour_enable(int on);
void kex_note_bad(const char *what);
void kex_note_warn(const char *what);
void kex_note_note(const char *what);
void kex_print_claimed(const char *label, uint32_t have, uint32_t claimed);
void kex_put_off(const char *label, uint64_t v);
void kex_put_perm(uint32_t p);
void kex_put_type(const char *(*name)(uint32_t), uint32_t t, int width);

/* kofexaminer_elfpe.c */
uint32_t kex_declared_regions(const struct kof_obj_ctx *ctx,
				 uint32_t scan_mask, struct kof_range *out,
				 uint32_t max_out);
void kex_print_elf(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf);
void kex_print_pe(const void *view, const struct kof_obj_ctx *ctx,
		      kof_buf buf);

/* kofexaminer_cont.c */
void kex_print_view(uint8_t format, const void *view,
		       const struct kof_obj_ctx *ctx, kof_buf buf);

/* kofexaminer_blocks.c */
void kex_print_blocks(kof_buf buf, const struct kof_obj_ctx *ctx);
void kex_print_scfind(kof_buf buf, const struct kof_obj_ctx *ctx);

/* kofexaminer_unpack.c */
int kex_unpack_pass(kof_engine *eng, const char *path, const char *dump_dir,
		       int verbose);

/* state one unit owns and another reads */
extern uint8_t kex_g_parent_format;
extern const char *kex_C_OFF;
extern const char *kex_C_NAME;
extern const char *kex_C_BAD;
extern const char *kex_C_WARN;
extern const char *kex_C_NOTE;
extern const char *kex_C_DIM;
extern const char *kex_C_ID;
extern const char *kex_C_LOC;
extern const char *kex_C_SIZE;
extern const uint8_t *kex_g_decl_syms;
extern uint32_t kex_g_decl_syms_n;
extern const struct kof_range *kex_g_decl_fixed;
extern uint32_t kex_g_decl_fixed_n;
extern struct kof_scan_region kex_g_decl_rgn[KOF_MAX_REGIONS];
extern uint8_t kex_g_decl_lang;
extern uint8_t kex_g_decl_subtype;
extern uint8_t kex_g_decl_subfam;
extern uint32_t kex_g_decl_rgn_n;
extern int kex_g_blocks;
extern int kex_g_hashes;
extern int kex_g_scfind;
extern int kex_g_decl_view;
extern const char *kex_g_root_path;

#endif /* KOF_KOFEXAMINER_PRIVATE_H */
