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
 *   kv_view.h        struct view (one struct, over 1000 lines on purpose: see its header)
 *   kv_panel.h       the event panel, panel division, format categories, the page
 *   kv_barmenu.h     the menu bar and the properties tabs
 *   kv_input.h       keys, navigation, the framed dialogs
 *   kv_shared.h      the prototypes more than one unit calls, and the globals
 *   kv_proto_decl.h  the diagnose-draft panel and the tag sources: PROTOTYPES, kept together
 *
 * The units that define those prototypes are named in kv_proto_decl.h.
 */
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
#include "../libkofeng/detectors/heur/kofheur.h"
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
