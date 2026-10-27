/*
 * kofinspect_private.h - what the units of kofinspect share.
 *
 * kofinspect.h is the surface; this is only what the .c files give one another:
 * the includes (the parsers by their internal headers, see kofinspect.c). No helper is
 * shared between the units - each static stayed with the unit that calls it - so a
 * new shared helper takes the family prefix kinsp_ and a prototype here. Not
 * installed, not part of any surface.
 *
 *   kofinspect           names, declare/identify a format, PDF text, hex spacing, symbol names, mutation
 *   kofinspect_dump      writing an object and its regions out (kof_dump_*)
 *   kofinspect_locate    the region map and where a marker is (kof_locate_str)
 *   kofinspect_describe  describing a collected event and what built an object
 */
#ifndef KOF_KOFINSPECT_PRIVATE_H
#define KOF_KOFINSPECT_PRIVATE_H

/* _GNU_SOURCE, not _POSIX_C_SOURCE: this file includes kofplatform.h, whose
 * kof_memmem calls memmem() from an inline function whether or not anything
 * here does. _POSIX_C_SOURCE alone hides it and the inline stops compiling -
 * the same reason kofexamine.c and kofviewer.c both say _GNU_SOURCE. */
#include <kofmod/kofsym.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "kofinspect.h"
#include "../libkofeng/kofcore/kofplatform.h"
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/scanners/scan.h"
#include <kofmod/script.h>
/* KOF_PROC_OS_LIST: the platform a process record is from, which is its
 * subtype - see the note on that list. */
#include <kofmod/proc.h>
#include "../libkofeng/analyzers/parsers/kofformat.h"

/*
 * The parsers, by their internal headers.
 *
 * Same reach kofexamine's own comment defends and for the same reason: there is
 * no public "parse this and hand me the view" surface, because no host has ever
 * wanted one. What changed is that there are now two consumers of it in this
 * tree rather than one, so the reach lives here once instead of in each.
 */
#include "../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_parse.h"
#include "../libkofeng/analyzers/parsers/events/amsi_parse.h"


#endif /* KOF_KOFINSPECT_PRIVATE_H */
