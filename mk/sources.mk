# ----------------------------------------------------- what the tools link in
#
# EVERY SOURCE LIST A TOOL OR A TEST NAMES IS SET HERE, IN ONE FRAGMENT.
#
# A variable used before it is set expands to NOTHING, and in a prerequisite
# list that is silent: the rule still builds, because the recipe is expanded
# later and names the files, but make no longer knows the target depends on
# them. That caught this file three times, and the third was the worst of
# them - $(KOFRIDGE_SRC) was empty in kofscanner's prerequisites, so editing
# the verdict cache never relinked the scanner and a measurement of the change
# measured the previous build.
#
# The Makefile includes this fragment after the libs and the sdk and BEFORE
# mk/tools.mk, mk/grille.mk, mk/packs.mk and mk/tests.mk, so the order of the
# include lines is what guarantees it; nothing below has to be written "above
# the first rule that names it" any more. Keep a new list here, not beside the
# first tool that wants it.

# The event-log format, linked into anything that reads one.
KOFEVT_SRC := libkoforbit/evt/kofevt.c libkoforbit/evt/kofevtfmt.c \
              libkoforbit/evt/kofevtlog.c

# The verdict cache. Orbit, not the engine, for the reason koffridge.h gives:
# what an answer is keyed on and how long it stays good are a host's policy.
KOFRIDGE_SRC := libkoforbit/fridge/koffridge.c \
                libkoforbit/fridge/koffridge_seen.c \
                libkoforbit/fridge/fidset.c

# The process record builder, shared by both collectors - see kofproc.h.
KOFPROC_SRC := libkoforbit/proc/kofproc.c

#
# THE PLATFORM HALF OF kof_fid_of, AS A NAME ANY TOOL CAN LINK.
#
# fidset.h declares kof_fid_of and does not define it: the answer is one stat
# on Linux and one GetFileInformationByHandle on Windows, so each platform
# supplies its own, exactly as kof_walk_open does. It was reachable only
# through a collector's source list, which is why kofwatchman - which links the
# cache and no collector - could not call it and grew a second, weaker identity
# of its own instead. That duplicate is gone; this is the line that lets the
# survivor be linked without dragging a collector in with it.
#
# afid.c is stat and string.h, wfid.c is windows.h. Neither pulls in the rest
# of its collector, which is the property that makes this a variable rather
# than a dependency on $(ANTARC_SRC).
ifeq ($(NATIVE_OS),windows)
KOFFID_SRC := libkoforbit/grille/wfid.c
else
KOFFID_SRC := libkoforbit/antarc/afid.c
endif

#
# THE LINUX COLLECTOR. Both halves: the snapshot walk over /proc and the
# fanotify stream. It is the mirror of libkofgrille and builds only on Linux,
# the way that one builds only for Windows - a collector is the one part of
# this tree that cannot be platform-neutral, which is why everything it hands
# over is.
ANTARC_SRC := libkoforbit/antarc/aproc.c \
              libkoforbit/antarc/aproc_pmem.c \
              libkoforbit/antarc/apagemap.c \
              libkoforbit/antarc/afan.c \
              libkoforbit/antarc/apev.c \
              libkoforbit/antarc/amon.c \
              libkoforbit/antarc/afid.c

ifeq ($(NATIVE_OS),windows)
ANTARC_INC :=
else
ANTARC_INC := -Ilibkoforbit/antarc -Ilibkoforbit/evt -Ilibkoforbit/mon
endif

# The report. Orbit for the same reason the cache is: it hashes artefacts and
# asks the engine what they are, so it depends on libkofeng - and libkofeng
# must be able to ship without knowing that anything called a report exists.
KOFREPORT_SRC := libkoforbit/report/kofreport.c \
                 libkoforbit/report/kofrepart.c \
                 libkoforbit/report/kofrepfmt.c

# The examiner. kofview.c and the viewer's own list stay with the viewer, in
# mk/tools.mk: nothing outside it names them.
EXAMINE_SRC := kofexamine/kofexaminer.c kofexamine/kofinspect.c kofexamine/kofeditor.c \
               kofexamine/kofscfind.c

# The signature builder: one file per mode and responsibility (ksb.h), a new
# ksb_*.c is picked up by the wildcard.
KSB_SRC := $(sort $(wildcard ksigbuilder/ksb_*.c))

# What the tests link besides the engine.
#
# CHAN_TEST_SRC: the channel with both ends in one process needs the POSIX
# backend and the event record it carries, and -lrt for shm_open. kofchan.h
# includes kofevt.h and stops there - the channel moves records and never asks
# what one means. -lrt is named because shm_open and sem_open are in librt on
# glibc older than 2.34 and in libc after it: harmless on the new ones, required
# on the old, which is the direction that fails.
CHAN_TEST_SRC := libkoforbit/chan/chan_posix.c $(KOFEVT_SRC)

# The editor's sources: the signature draft is what the viewer edits, not what the
# engine scans with, so kofeditor.c lives beside the tools rather than inside
# libkofeng, and a test over it compiles that source. kofinspect describes events
# as well as objects, so whatever links it needs the event record with it.
EDITOR_SRC := kofexamine/kofeditor.c kofexamine/kofinspect.c $(KOFEVT_SRC)

# THE ETW-FREE HALF OF libkofgrille, TESTED ON WHATEVER HOST IS RUNNING. Not
# linked against $(LIB): libkofgrille is a SIBLING of libkofeng and nothing in
# either includes the other's header, so a test that pulled the engine in would be
# the first thing in the tree to cross that line. This list is exactly the files
# whose headers promise they call no OS API, and the promise is worth what
# compiles it: a file added here that includes windows.h stops the Linux build and
# names itself (it has already caught one - kofw_evt_image() and kofw_evt_object()
# were in wevt_decode.c, so wfilter.c could not link without the Windows half).
# chan_posix.c is not here: it left the collector for libkoforbit/chan, and the
# channel has its own test above.
GRILLE_HOST_SRC := libkoforbit/grille/wevt_ring.c libkoforbit/grille/wfilter.c \
                   libkoforbit/grille/wtext.c \
                   libkoforbit/evt/kofevt.c \
                   libkoforbit/evt/kofevtfmt.c \
                   libkoforbit/evt/kofevtlog.c

# kofmontrace: the main, the scan and spill half, and the tracer (one collector per
# platform). Private header kofwatcher/kofmontrace_int.h.
KOFMONTRACE_SRC := kofwatcher/kofmontrace.c kofwatcher/kofmontrace_scan.c \
                   kofwatcher/kofmontrace_tracer.c
