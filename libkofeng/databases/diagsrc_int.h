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

#endif /* KOFENG_DIAGSRC_INT_H */
