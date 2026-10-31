/*
 * diagsrc_int.h - what the units of the diagnose-source reader share (diagsrc.c,
 * diagsrc_parse.c, diagsrc_resolve.c). Private to databases/.
 */

#ifndef KOFENG_DIAGSRC_INT_H
#define KOFENG_DIAGSRC_INT_H

#include "../analyzers/diseases/kofdisease.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofdiagtree.h>
#include "../kofcore/kofcore.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <celllysis/nucleo.h>
#include "diagsrc.h"

int kof_dsrc_when_value(const char *w, uint64_t *out);
int kof_dsrc_kind_of(const char *w, uint8_t *out);
int kof_dsrc_flag_of(const char *w, uint16_t *out);
void kof_dsrc_say_warn(const struct kof_dsrc_report *r, const char *msg);
char *kof_dsrc_blanked(const char *t, size_t n);

/* One more item of `d`, zeroed and not yet counted (the caller fills it and does d->n++), or NULL with the error said
 * when the list is full. Shared by the graph's line handlers and the form's. */
struct kof_dsrc_item *kof_dsrc_add_item(struct kof_dsrc *d, int *errs, const struct kof_dsrc_report *r,
					unsigned line, unsigned kind);

/* The detection form (diagsrc_form.c). kof_dsrc_form_line reads one line if it is a form declaration (1: it was, and
 * any error is said), kof_dsrc_form_print writes one item (0: it cannot be written), kof_dsrc_form_item_same compares
 * the texts of two items, kof_dsrc_form_resolve turns the items into a form (NULL with *has 0 when the source has none,
 * NULL with *nerr raised when it does not resolve). */
int kof_dsrc_form_line(struct kof_dsrc *d, const struct kof_dsrc_report *r, int *errs, unsigned lineno, const char *line);
size_t kof_dsrc_form_print(const struct kof_dsrc_item *it, char *out, size_t cap);
int kof_dsrc_form_item_same(const struct kof_dsrc_item *a, const struct kof_dsrc_item *b);
struct kof_form *kof_dsrc_form_resolve(const struct kof_dsrc *d, const struct kof_dsrc_report *r, int *nerr, int *has);

#endif /* KOFENG_DIAGSRC_INT_H */
