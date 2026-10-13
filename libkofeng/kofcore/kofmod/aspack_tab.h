/*
 * aspack_tab.h - the ASPack coding tables, as a module sees them.
 *
 * THE ABI RE-EXPORTS kuncoat's TABLE. The decoder (libuncoat/decompressors/aspack.c)
 * indexes it and the module (bases/unp/aspack_pe.c) compares the stub's copy
 * against it, so it is defined once, in libuncoat/decompressors/aspack_tab.h.
 */
#ifndef KOFENG_ASPACK_TAB_H
#define KOFENG_ASPACK_TAB_H

#include <decompressors/aspack_tab.h>

/* module-facing names: the lib defines KUNCOAT_*, the ABI keeps the old spelling */
#define KOF_ASPACK_OFF_BASE KUNCOAT_ASPACK_OFF_BASE
#define KOF_ASPACK_OFF_N    KUNCOAT_ASPACK_OFF_N
#define KOF_ASPACK_TAB_N    KUNCOAT_ASPACK_TAB_N
#define kof_aspack_tab      kuncoat_aspack_tab

#endif /* KOFENG_ASPACK_TAB_H */
