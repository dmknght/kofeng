/*
 * kv.h - the one interface between the translation units of kofviewer.
 *
 * kofviewer used to be one 32,000 line file. It is the same program in the same
 * order of functions, cut along the lines below; nothing was rewritten to make
 * the cut. This header holds what the pieces share: the types (struct view is
 * the whole state of a session), the macros, the prototypes of the functions
 * that more than one unit calls, and the few globals that more than one unit
 * touches. A function used by a single unit is `static` in it and is not here.
 *
 *   kv_main        command line, opening a file or a pid, closing, main()
 *   kv_events      the event loop's handlers: handle(), mouse drag/release/wheel
 *   kv_keys        per-modal key handlers (field, bar, chooser, symbols, ...)
 *   kv_click       click dispatch: every pane's click, the hit table
 *   kv_input       terminal input: keys, mouse reports, bracketed paste
 *   kv_screen      redraw(): the frame, in layer order
 *   kv_view        the pane model: which object/region/bytes a pane shows
 *   kv_collect     objects: the scan callback, process snapshot, object table
 *   kv_tree        the tree: rows, labels, the log window
 *   kv_tree_draw   painting the tree pane and the frame
 *   kv_hex         the hex pane
 *   kv_text        the text pane, symbol cell strings
 *   kv_hit         what a byte under the cursor is (declared)
 *   kv_disasm      the disassembler panel
 *   kv_evt         the event-log view (load, boxes, the event panel)
 *   kv_decl        the draft panel: head, strings, matchers, conditions, blocks
 *   kv_marker      the status line
 *   kv_mutation    mutation blocks: segment, mark, rescore
 *   kv_draft       draft lifecycle: wipe
 *   kv_declact     adding a declaration from a selection
 *   kv_chooser     the chooser popup (every pick-one list)
 *   kv_field       text fields and the panel rows around them
 *   kv_menu        the context menus and menu_run
 *   kv_bar         the menu bar: items, enabled/shown rules, run
 *   kv_clip        copy and paste
 *   kv_find        Find
 *   kv_dialogs     the framed dialogs: Decoder, Goto, Find
 *   kv_dlgsel      the text selection of every recorded page
 *   kv_props       the properties page (rows, per-format blocks); _table the table widget, _tab the Layout/Imports/Exports pages
 *   kv_page        the page layer (properties/help) drawing
 *   kv_help        the About / help text
 *   kv_actions     actions that reopen or rescan: emulate, dump, step file, rebuild
 *   kv_paint       colours and glyphs
 *   kv_state       the shared globals
 *
 * THIS FILE IS AN UMBRELLA. What the units share is cut by purpose into parts that sit
 * beside it, listed at the end in dependency order; a unit keeps including "kv.h":
 *
 *   kv_colour.h      every colour the viewer paints
 *   kv_consts.h      limits, widths and edit codes
 *   kv_chooser.h     the chooser popup's kinds and state
 *   kv_objects.h     the tree node, a hit, the object limits
 *   kv_view.h        struct view (one struct, its body in kv_view_<region>.inc fragments: see its header)
 *   kv_panel.h       the event panel, panel division, format categories, the page
 *   kv_barmenu.h     the menu bar and the properties tabs
 *   kv_input.h       keys, navigation, the framed dialogs
 *   kv_shared.h      the prototypes more than one unit calls, and the globals
 *   kv_proto_decl.h  the diagnose-draft panel and the tag sources: PROTOTYPES, kept together
 *
 * The units that define those prototypes are named in kv_proto_decl.h.
 */
/*
 * IMPROVE kx-restructure-1 (owner, 2026-11-03: "kofexamine thì note comment lại xử lý sau"; DEFERRED, nothing of it is being built now). The restructure of
 * kofexamine/ was started and then parked so that the ENGINE's function/decode/sniff pipeline is rewritten first (the viewer only shows what the engine returns).
 * DONE and merged: kofeditor.c split (kofeditor_*.c), struct view split into kv_view_<region>.inc (18 pieces, members unchanged), kv_decl.c / kv_chooser.c / kv_bar.c /
 * kofview.c / kv_graph.c / kv_evt.c / kv_tree.c split by responsibility, the chooser's open/take tables unified into one struct ch_kind, the marker table (MAX_DECL) made dynamic.
 * NOT DONE (plan: /mnt/games/normtest/fix_vsplit_plan/plan.md, packages by disjoint file sets): P5 disasm/hex/text (kv_disasm.c 1396, kv_hex.c, kv_text.c), P7 dashboard/props
 * (kv_dashdata.c 1261, kv_dash_dialog, kv_props*), P8 catalog/forms/dialogs (kv_families.c, kv_form*, kv_dialogs.c 1053, kv_find.c), P9 input/dispatch/state (kv_click.c 1155,
 * kv_events.c, kv_keys.c, kv_input.c, kv_main.c, kv_collect.c 1357, kv_view.c, kv_proto_decl.h), P10 the CLI (kofexaminer*.c, kofinspect*.c, kofscfind.c), and the model's other
 * caps (MAX_GROUP 8, GRP_SIM_MAX 8, MAX_RANGE 8, DRAFT_LOADED_MAX; the strings table has no scroll window of its own; MAX_OBJ 128 and HIT_MAX 512 drop silently, rule 4);
 * `.inc` regions may become named sub-structs one at a time (text, find, props, catalog, menu first). Viewer-side work the engine rewrite will make unnecessary or must feed:
 * dis_func_at (kv_disasm.c) filters the engine's function set by NAME (audit FP-13: a stripped or PE function with no symbol is not a function there), kv_mutation.c computes
 * mtn_segment / mtn_rescore / mtn_mark on its own (rule 11), KXV-EVT-1 (kv_evt_load.c), P3-1 (kv_bar_items.c). When the engine publishes ONE function table per object
 * (see IMPROVE func-size-1 and the fntab note in libgenome/phenotype/diag_scan.c), every function row of the viewer reads that table and nothing else. */

#ifndef KV_H
#define KV_H

/*
 * kofviewer - the engine's view of a file, navigable.
 *
 *   kofviewer [--db <dir>] [--sources <dir>] <file|folder>
 *
 * kofexamine prints everything at once and is right to: piped into grep or
 * diffed against yesterday, a dump is the useful shape. This is the other half
 * of the same job - the same facts, but reachable one at a time, because writing
 * a signature is not reading a report. It is looking at a region, at some bytes
 * inside it, and at what the database already says about them, and moving
 * between the three until the marker is obvious.
 *
 * Both front ends stand on kofinspect, so neither owns a parser and the two
 * cannot drift about what an object is.
 *
 *
 * WHY NO CURSES
 *
 * The panes here are three rectangles of text with a cursor line in one of
 * them. Curses solves problems this does not have - overlapping windows,
 * terminals whose escape sequences are unknown, output that must be diffed
 * against the previous frame because the link is slow - and costs a dependency
 * in a tree whose modules are built -nostdlib and whose platform layer carries
 * its own memmem rather than assume one. A full repaint of a 24 line screen is
 * two kilobytes; there is nothing to optimise and so nothing for a library to
 * do.
 *
 *
 * WHAT IT DOES NOT DO YET
 *
 * Recovered objects are not in the tree. The engine produces them through a scan
 * and the tree here is built from one parse, so putting them in means holding a
 * scan's output as a tree - which is the next thing, not a missing thing.
 * Selection, and turning a selection into a declaration, likewise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#endif
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/wait.h>
#endif
#include "kofplat.h"
#include <sys/stat.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/kofcore/kofplatform.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include "../libkofeng/analyzers/parsers/binaries/elf/elf_sym.h"
#include "../libkofeng/detectors/linkage/kofdiag.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>
/* kof_parser_of: the region NAMES are per format, and a multi-format draft has
 * to be able to ask each of its formats what a region bit means there. */
#include "../libkofeng/analyzers/parsers/kofformat.h"

#include "kofevtfmt.h"
#include "kofevtlog.h"
#include "kofinspect.h"
#include <genotype/image/infect.h>
#include "kofscfind.h"
#include "codec_ui.h"
#include <kofmod/kofmutation.h>
#include "kofview.h"
#include <celllysis/trueline.h>
#include "../libkofeng/kofcore/rangelist.h"
#include "kofwalk.h"
#include "kofproc.h"
#include <kofmod/proc.h>
/* The two targets a collected record can BE - see evt_decl_target. */
#include <kofmod/amsi.h>
#include "kofeditor.h"

/* The disassembler the emulator already carries: the viewer links the same
 * library, so this costs an include path and nothing else. */
#include <x86/x86.h>
#include "../libkofeng/scanners/scan.h"
#include "../libkofeng/scanners/objsrc.h"
#include <phenotype/emu_unpack.h>
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/databases/pack/hexprog.h"
#include "../libkofeng/analyzers/genome_obj.h"
#include "../libkofeng/databases/pack/dbcore.h"
#include "../libkofeng/databases/dbloader.h"


/* The parts, in dependency order: each needs what the ones above it declare. */
#include "kv_colour.h"
#include "kv_consts.h"
#include "kv_chooser.h"
#include "kv_objects.h"
#include "kv_table.h"
#include "kv_dash_dialog.h"
#include "kv_view.h"
#include "kv_panel.h"
#include "kv_barmenu.h"
#include "kv_input.h"
#include "kv_shared.h"
#include "kv_dashdata.h"
#include "kv_families.h"
#include "kv_proto_decl.h"

#endif /* KV_H */
