/*
 * script_sym.h - see script_sym.c. The builder for a script's symbol block, called by the one place that picks a builder for
 * an object (binaries/sym_any.c).
 */

#ifndef KOF_SCRIPT_SYM_H
#define KOF_SCRIPT_SYM_H

#include <stdint.h>
#include <kofcore.h>
#include <kofmod/kofsym.h>
#include <kofmod/script.h>

/* The block for `b`, in `out` (`cap` bytes): the names the script calls that its language's table has, as imports. Returns the
 * block's length, 0 when `out` is too small for a header. A language with no table gives a block with no records. */
uint32_t kof_script_syms(kof_buf b, const struct kof_script_info *info, uint8_t *out, uint32_t cap);

/*
 * The same block from a SOURCE of names: `feed` calls `put` once for each name (the table's spelling and its length) - a scan of the text that the caller has made for
 * another reason, or the one kof_script_syms makes. A NULL `feed` is a script with no names.
 */
typedef void (*kof_script_names_fn)(void *user, void (*put)(void *, const char *, uint32_t), void *put_user);
uint32_t kof_script_syms_with(kof_script_names_fn feed, void *feed_user, uint8_t *out, uint32_t cap);

#endif /* KOF_SCRIPT_SYM_H */
