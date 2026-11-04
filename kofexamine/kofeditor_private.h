/*
 * kofeditor_private.h - what the parts of the draft model share: the includes they
 * all need, the types two of them use, and the prototypes of what one part offers
 * another.
 *
 * kofeditor.c (the draft as one thing) and kofeditor_<part>.c (vocab, range, decl,
 * cond, group, block, units, form, tree, links, save) were one file of 3795 lines.
 * The public prototypes of the model are in kofeditor_proto_fn.h; here is only
 * what is private to the parts. Not installed, not part of the surface: the viewer
 * and the tests include kofeditor.h.
 */
#ifndef KOF_KOFEDITOR_PRIVATE_H
#define KOF_KOFEDITOR_PRIVATE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>
/* KOF_PROC_OS_LIST: the platform a process record is from, which is its
 * subtype - see the note on that list. */
#include <kofmod/proc.h>
/* For the object facts - see "what an object IS". */
#include <phenotype/emu_unpack.h>
#include <celllysis/mutation.h>

#include "kofeditor.h"
#include "../libkofeng/databases/diagsrc.h"
#include "../libkofeng/databases/pack/hexprog.h"
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/kofcore/kofplatform.h"

/*
 * Rewrite a condition's id list, applying one edit to one matcher.
 *
 * Drop, negate and switch are the same walk - read the ids in order, decide
 * what the new list says about each, write them back joined with the
 * condition's own operator - so they are one function with a verb rather than
 * three copies of the loop.
 *
 * Rewritten from the ids that are left rather than edited in place, because
 * removing "2" from "1&2|3" by deleting characters leaves "1&|3" - and an
 * expression that has to be repaired by hand after every removal is one nobody
 * will use the buttons on. Anything the author typed that is not a plain list -
 * parentheses, a mix of & and | - is preserved only in so far as the join it
 * was written with; that is the price of a list and a text box being the same
 * field.
 *
 * The room check is not decoration. A negation ADDS a character, so this is the
 * one edit that can make an expression longer than the one it replaces, and
 * "sizeof out - at" underflows to an enormous size_t the moment at passes the
 * end. Twenty-two columns is the widest one id can be written in - a "!", a
 * join, and every digit of an unsigned long somebody typed by hand.
 */
enum kofeditor_cnd_verb { KOFEDITOR_CND_DROP = 0, KOFEDITOR_CND_NEG, KOFEDITOR_CND_SWAP, KOFEDITOR_CND_SHIFT };

/* A file name of a unit that is being worked out: only the part the numbering reads. */
struct kofeditor_unit_out {
	char  fn[200];
	char *text;
	size_t n;
	char  label[40];        /* "condition 2", "block matcher 3": what a refusal names */
};


/* ---- cond (used by group) ---- */
void kofeditor_cnd_rewrite(struct cond *c, uint32_t id, uint32_t to, int verb);

/* ---- units ---- */
const char *kofeditor_draft_unit_gap(const struct kof_editor *e, uint8_t utype, const char *tag);
void kofeditor_tag_prefix(const struct kof_editor *e, uint8_t utype, const char *tag, char *out, size_t cap);
uint32_t kofeditor_unit_free_number(const char *dir, const char *prefix, const struct kofeditor_unit_out *u, uint32_t k);
void kofeditor_unit_name_in(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct kofeditor_unit_out *u);

/* ---- tree ---- */
int kofeditor_link_name_ok(const char *n);
int kofeditor_text_identity(const char *text, size_t n, const char *name, struct kof_dsrc *d, uint64_t *hash);
char *kofeditor_tree_file(const char *dir, const char *name, size_t *n, mode_t *mode);
int kofeditor_tree_missing(const char *dir, const char *name);
int kofeditor_unit_in_file(const struct kof_editor *e, const char *stem, const struct draft_unit *ul, uint32_t k, const char *have, size_t on, int with_form, struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, struct draft_loaded *id);
int kofeditor_unit_resolve(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct kofeditor_unit_out *u, int with_form, struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, int *present, char *why, size_t cap);
char *kofeditor_unit_text(const struct kof_editor *e, const char *stem, const struct draft_unit *u, struct kof_dsrc *d, size_t *n, int with_form, char *why, size_t cap);

/* ---- links ---- */
uint32_t kofeditor_link_carriers(const struct kof_editor *e, uint32_t id);
int kofeditor_loaded_find(const struct kof_editor *e, uint32_t id);
uint32_t *kofeditor_unit_link_of(struct kof_editor *e, const struct draft_unit *u);

#endif /* KOF_KOFEDITOR_PRIVATE_H */
