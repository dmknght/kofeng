# --------------------------------------------------------------- the scanner
#
# Written against the staged SDK, not the source tree: it includes <kofeng.h>,
# and the three core headers the SDK ships beside it (<kofcore.h>,
# <kofplatform.h>, <kofdebug.h>), and nothing of the engine's inner directories.
# CFLAGS above carries -Ilibkofeng/kofcore for the whole tree, so the compiler
# would not refuse a reach into one; `make check-rules` does (tools/check_layers.py,
# "TOOL INCLUDES"): no program under kofscanner/, ksigbuilder/, kofwatcher/ or
# tools/ names the engine's tree by a relative path.

SCANNER_SRC := kofscanner/kofscanner.c kofscanner/kofscan_out.c kofscanner/kofscan_procs.c

#
# THE SCANNER LINKS THE LINUX COLLECTOR ON LINUX.
#
# --scan-procs is the same scan over a different source of bytes, so it belongs
# in the scanner rather than in a tool of its own - see scan_procs. On Windows
# the collector is libkofgrille and that half is not wired here yet, so the
# option does not exist there and the sources are not linked.
#
# ANTARC_SRC and KOFPROC_SRC are set by mk/sources.mk, which the Makefile includes
# before this fragment, so the lists below may refer to them.
#
# THE WALK IS THE ONLY THING THAT DIFFERS, and it is one file each.
#
# libkoforbit/antarc/awalk.c and libkoforbit/grille/wwalk.c both define kof_walk_open; a
# host compiles exactly one of them and kofscanner.c is #ifdef-free for it. The
# collector sources come along because the walk calls them.
#
# NEITHER WALK IS IN ITS LIBRARY'S ARCHIVE. Both call engine code - wwalk.c
# un-maps a PE - and the archives are linked by tools that have no engine in
# them. Compiled into the scanner instead, where the engine already is.
ifeq ($(NATIVE_OS),windows)
#
# wfid.c is the Windows half of kof_fid_of, whose Linux half rides in
# $(ANTARC_SRC) - one name, one definition per host, the way the walk already
# works. Without it the scanner referenced a symbol only libkoforbit/antarc defined
# and this build did not get as far as the link: kofscanner.c included afid.h,
# which is not on the Windows include path at all.
SCANNER_EXTRA = libkoforbit/grille/wwalk.c libkoforbit/grille/wdiff.c libkoforbit/grille/wproc.c \
                libkoforbit/grille/wcmdline.c libkoforbit/grille/wtext.c \
                libkoforbit/grille/wfid.c \
                $(KOFPROC_SRC) $(KOFRIDGE_SRC) $(KOFEVT_SRC)
#
# -Ilibkofeng IS IN THIS LIST AND NOT LEFT TO $(SDK)/include.
#
# wwalk.c includes <image/pe_unmap.h> - it un-maps a hand-mapped image before
# handing it over, which is the whole point of it - and the module-side helpers are NOT among
# the headers copied into the SDK include directory. kofeng.h and kofmod/pe.h
# are, which is why those two resolved and this one did not, and why the failure
# read as a missing file rather than as a missing flag.
SCANNER_INC   = -Ilibkoforbit/grille -Ilibkofeng -Ilibkoforbit/evt \
                -Ilibkoforbit/mon \
                -Ilibkoforbit/proc -Ilibkoforbit/fridge \
                -Ilibkoforbit/walk
#
# NAMED HERE, NOT INHERITED. wproc.c enumerates modules through psapi and reads
# a token through advapi32, and this is the first rule outside the collector's
# own block that links it. $(WIN_LDLIBS) would have been the tempting thing to
# reach for and it is set by mk/grille.mk, included after this fragment, inside the cross-build
# guard - so it would expand to nothing here and the link would fail naming
# two symbols instead of the missing flag. See the note beside kofmemscan's
# old rule for the last time that happened.
SCANNER_LIBS  = -ladvapi32 -lpsapi
# The examiner links no collector at all, and still needs advapi32: kofeditor
# asks the caller's own token for the account name to sign a draft with (see
# meta_user), which is where the environment variable it used to read went.
EXAMINE_LIBS  = -ladvapi32
else
SCANNER_EXTRA = $(ANTARC_SRC) libkoforbit/antarc/awalk.c $(KOFPROC_SRC) \
                $(KOFRIDGE_SRC) $(KOFEVT_SRC)
SCANNER_INC   = -Ilibkoforbit/antarc -Ilibkoforbit/evt -Ilibkoforbit/mon \
                -Ilibkoforbit/proc -Ilibkoforbit/fridge \
                -Ilibkoforbit/walk
SCANNER_LIBS  =
EXAMINE_LIBS  =
endif

$(OUT)/bin/kofscanner$(EXE): $(SCANNER_SRC) $(SCANNER_EXTRA) $(LIB) \
                             $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(SCANNER_INC) \
	      $(SCANNER_SRC) $(SCANNER_EXTRA) $(LIB) -o $@ $(LDFLAGS) \
	      $(SCANNER_LIBS)

# --------------------------------------------------------------- the examiner
#
# Unlike the scanner, this links the internal collectors: it prints the parsed
# view, and no public surface offers one. The reason that is not a lapse is
# written at the top of the file.

# kofinspect is the half of this tool that is not printing: it asks the loaded
# database what it already knows about an object. Separate because a second
# consumer is coming - the viewer - and because the two halves reach for
# different things: the printer wants the parse, this wants the engine.

$(OUT)/bin/kofexaminer$(EXE): $(EXAMINE_SRC) $(KOFEVT_SRC) $(LIB) $(SDK_HDR) \
                            $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include $(EXAMINE_SRC) $(KOFEVT_SRC) \
	      $(LIB) -o $@ $(LDFLAGS) $(EXAMINE_LIBS)

# The other front end onto the same layer. Two binaries from one directory, and
# the directory is the toolchain rather than the tool: what they share is
# kofinspect, and what differs is only how a pane and a line are drawn.
#

#
# THE VIEWER NOW LINKS THE HOST'S COLLECTOR, which it did not before.
#
# It can open a running process - see proc_collect - and that needs the same
# kof_walk_open the scanner uses: libkoforbit/antarc on Linux, libkofgrille on
# Windows. The walk is the only thing it takes from there, and it is the same
# file kofscanner compiles, so the two cannot disagree about what a region is.
ifeq ($(NATIVE_OS),windows)
VIEWER_PROC := libkoforbit/grille/wwalk.c libkoforbit/grille/wdiff.c libkoforbit/grille/wproc.c \
               libkoforbit/grille/wcmdline.c libkoforbit/grille/wtext.c $(KOFPROC_SRC)
# -Ilibkofeng for the same reason SCANNER_INC needs it: wwalk.c reaches
# libkofeng's own headers, which the SDK include directory does not carry.
VIEWER_PROC_INC := -Ilibkoforbit/grille -Ilibkofeng
VIEWER_PROC_LIB := -ladvapi32 -lpsapi
else
VIEWER_PROC := $(ANTARC_SRC) libkoforbit/antarc/awalk.c $(KOFPROC_SRC)
VIEWER_PROC_INC := -Ilibkoforbit/antarc
VIEWER_PROC_LIB :=
endif
VIEWER_PROC_INC += -Ilibkoforbit/walk -Ilibkoforbit/proc \
                   -Ilibkoforbit/mon

# The viewer is one program in several translation units: kofexamine/kv.h is the
# one interface between them (the view, the object model, and the prototypes the
# units share).
VIEWER_UNITS := kofexamine/kv_actions.c \
                kofexamine/kv_bar.c \
                kofexamine/kv_chooser.c \
                kofexamine/kv_click.c \
                kofexamine/kv_clip.c \
                kofexamine/kv_collect.c \
                kofexamine/kv_decl.c \
                kofexamine/kv_declact.c \
                kofexamine/kv_dialogs.c \
                kofexamine/kv_disasm.c \
                kofexamine/kv_draft.c \
                kofexamine/kv_events.c \
                kofexamine/kv_evt.c \
                kofexamine/kv_field.c \
                kofexamine/kv_find.c \
                kofexamine/kv_help.c \
                kofexamine/kv_hex.c \
                kofexamine/kv_hit.c \
                kofexamine/kv_input.c \
                kofexamine/kv_keys.c \
                kofexamine/kv_list.c \
                kofexamine/kv_main.c \
                kofexamine/kv_marker.c \
                kofexamine/kv_menu.c \
                kofexamine/kv_mutation.c \
                kofexamine/kv_page.c \
                kofexamine/kv_paint.c \
                kofexamine/kv_props.c \
                kofexamine/kv_screen.c \
                kofexamine/kv_state.c \
                kofexamine/kv_symd.c \
                kofexamine/kv_text.c \
                kofexamine/kv_tree.c \
                kofexamine/kv_tree_draw.c \
                kofexamine/kv_view.c
VIEWER_SRC := $(VIEWER_UNITS) kofexamine/kofview.c kofexamine/kofinspect.c kofexamine/kofeditor.c \
              kofexamine/kofscfind.c kofexamine/codec_ui.c $(VIEWER_PROC)

# EMU_INC because the viewer disassembles: the decoder is already inside $(LIB),
# so what is missing is only the header.
#
# kofevt is linked in because the viewer BROWSES an event log: it reads the
# header, counts the records, and asks where each one is so a hex pane can be
# pointed at it. The engine cannot answer any of that - a log is not a scanned
# object - which is why the format lives beside the engine and not inside it.
$(OUT)/bin/kofviewer$(EXE): $(VIEWER_SRC) kofexamine/kv.h $(KOFEVT_SRC) $(LIB) $(SDK_HDR) \
                            $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -I$(SDK)/include -Ilibkoforbit/evt $(EMU_INC) \
	      $(VIEWER_PROC_INC) \
	      $(VIEWER_SRC) $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS) \
	      $(VIEWER_PROC_LIB)

# ----------------------------------------------------- the database toolchain
#
# One binary with two modes: --extract reads the declarations out of a signature
# source, and the default mode packs compiled artefacts into .ksig. Build-time
# only, and deliberately not linked into anything that runs on an endpoint.

#
# kofwatchman: THE ONE TOOL IN THIS FAMILY THAT IS NOT PLATFORM SPECIFIC.
#
# kofwatchtower and kofmontrace link libkofgrille and only build for Windows,
# because collecting is where the platform lives. kofwatchman does not collect
# - it reads a recorded log and decides - so it links the ENGINE and kofevt and
# nothing else, and it builds wherever the engine does.
#
# That is not a convenience, it is the point of the record having been
# normalised: a log written on Windows is analysed here, on the CI, by the same
# binary a Windows machine would run. Every event rule that ever exists becomes
# testable because of this line.
#
# On Windows it also links the collector, for the live channel - which is a
# Windows transport, so off Windows the recording path is the whole program.
# See the note at the top of kofwatchman.c.
#
# `=` AND NOT `:=`, AND THAT IS THE WHOLE OF THIS COMMENT.
#
# WINLIB and WIN_LDLIBS are set by the Windows block a hundred lines BELOW
# this. A `:=` here expands them immediately, which is to say to nothing, and
# the link then succeeds at finding no collector - undefined kofw_chan_* and a
# reader with no reason to suspect the Makefile. Deferred, they expand when the
# recipe runs, by which time the block has been read.
#
# This is the same trap the note on `tools:` further down describes. It has now
# caught two things in this file, so: anything referring to a variable the
# Windows block sets must be deferred, or must be inside the block.
#
# ONE CONTRACT, TWO BACKENDS, AND THE HOST PICKS. Until the channel moved into
# libkoforbit this was "Windows or nothing", because the only transport there
# had was CreateFileMapping. chan_posix.c is a real one, so a Linux build now
# attaches to a Linux sensor instead of being recording-only - which is the
# whole thing the move was for.
#
# KOF_HAVE_CHAN is what the client tests. Not _WIN32: that asked which OS this
# is, and what the code meant was whether a backend is linked.
ifeq ($(NATIVE_OS),windows)
WATCHMAN_CHAN = -DKOF_HAVE_CHAN -Ilibkoforbit/chan \
                libkoforbit/chan/chan_win.c $(WINLIB) $(WIN_LDLIBS)
else
WATCHMAN_CHAN = -DKOF_HAVE_CHAN -Ilibkoforbit/chan \
                libkoforbit/chan/chan_posix.c -lrt
endif

$(OUT)/bin/kofwatchman$(EXE): kofwatcher/kofwatchman.c $(KOFEVT_SRC) \
                              $(KOFPROC_SRC) $(KOFFID_SRC) \
                              $(KOFRIDGE_SRC) $(LIB) $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng -Ilibkoforbit/evt \
	      -Ilibkoforbit/proc -Ilibkoforbit/fridge $< \
	      $(KOFEVT_SRC) $(KOFPROC_SRC) $(KOFFID_SRC) $(KOFRIDGE_SRC) \
	      $(LIB) -o $@ $(LDFLAGS) $(WATCHMAN_CHAN)

kofwatchman: $(OUT)/bin/kofwatchman$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

#
# kofmemscan WAS HERE, and it is gone rather than renamed.
#
# It was the engine and the snapshot in one program: walk the processes, read
# what is mapped, scan it. `kofscanner --scan-procs` is now that same program
# on both platforms, and the decisions kofmemscan held - which regions are
# worth reading, how runs group back into allocations, when a mapped image has
# to be un-mapped first - moved into libkoforbit/grille/wwalk.c, beside the Linux
# answers in libkoforbit/antarc/awalk.c. Two tools holding one set of decisions is
# how the two drift apart.
#
# kofmontrace is built like this one and for the same reason - it links the
# engine now - but its rule cannot live here: the target name needs $(WIN_EXE)
# and $(WINLIB), which the Windows block (mk/grille.mk, included after this fragment) sets. See the
# note beside `tools:` down there, where it is.

# -Ilibkofeng IS THE ENGINE'S INCLUDE ROOT, for this tool alone: the builder reads
# the pack's layout and the parsers' region lists, which the SDK does not ship
# (it is the one program that is built with the engine and is not a client of
# it). Its includes say <databases/dbpacker.h>, not a path out of its directory.
#
# The builder is several units behind one private header, ksigbuilder/ksb.h:
# one file per mode and per responsibility (CLAUDE.md, "Where code lives"). A
# new ksb_*.c is picked up by the wildcard.
$(OUT)/bin/ksigbuilder$(EXE): $(KSB_SRC) ksigbuilder/ksb.h $(LIB) $(SDK_HDR) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkofeng $(KSB_SRC) $(LIB) -o $@ $(LDFLAGS)

