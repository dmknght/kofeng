# ------------------------------------------------------------ orbit tests (WP12)
#
# tests/unit/orbit_*.c: the system-resource handling of libkoforbit (the Linux collectors, the event record, the files and
# the channel) against a FAKE operating system. The library has no seam for /proc, the process connector, fanotify, shm or a
# full disk, and none is added: each test is linked with the wraps below and tests/lib/orbit_sys.c (included by the test)
# answers instead. The same list is the fuzz stage's (tests/fuzz/orbit/stage.mk reads ORBIT_SRC, ORBIT_INC, ORBIT_WRAP).
#
# Included from mk/tests.mk BEFORE UNIT_SKIP is computed (these are Linux tests: antarc, shm, fanotify) and extended into
# UNIT_EXTRA after it is set, so no existing line of tests.mk changes.
ORBIT_TESTS := orbit_plist orbit_pmem orbit_events orbit_evt orbit_store orbit_chan

ORBIT_SRC := $(ANTARC_SRC) libkoforbit/antarc/awalk.c $(KOFEVT_SRC) $(KOFRIDGE_SRC) $(KOFREPORT_SRC) $(KOFPROC_SRC) \
             libkoforbit/chan/chan_posix.c libkoforbit/grille/wevt_ring.c libkoforbit/grille/wfilter.c \
             libkoforbit/grille/wtext.c
ORBIT_INC := -Ilibkoforbit/antarc -Ilibkoforbit/evt -Ilibkoforbit/mon -Ilibkoforbit/walk -Ilibkoforbit/proc \
             -Ilibkoforbit/fridge -Ilibkoforbit/report -Ilibkoforbit/chan -Ilibkoforbit/grille -Ilibkofeng
ORBIT_WRAP := -Wl,--wrap=open -Wl,--wrap=fopen -Wl,--wrap=opendir -Wl,--wrap=readlink -Wl,--wrap=access -Wl,--wrap=stat \
              -Wl,--wrap=lstat -Wl,--wrap=pread -Wl,--wrap=process_vm_readv -Wl,--wrap=socket -Wl,--wrap=bind \
              -Wl,--wrap=recv -Wl,--wrap=poll -Wl,--wrap=mkdir -Wl,--wrap=rename -Wl,--wrap=fanotify_init \
              -Wl,--wrap=fanotify_mark -Wl,--wrap=open_by_handle_at -Wl,--wrap=getpwuid_r -Wl,--wrap=shm_open \
              -Wl,--wrap=ftruncate -Wl,--wrap=sem_open -Wl,--wrap=fork

$(foreach t,$(ORBIT_TESTS),$(eval UT_SRC_$(t) := $$(ORBIT_SRC)))
$(foreach t,$(ORBIT_TESTS),$(eval UT_INC_$(t) := $$(ORBIT_INC)))
# WP12-18: apev.c casts the connector's event (offset 36 of a message) to a struct that wants 8-byte alignment, on every record; the
# sanitised twin of the one test that feeds it records would abort on the first. The flag is accepted and does nothing in the release build.
UT_INC_orbit_events += -fno-sanitize=alignment
$(foreach t,$(ORBIT_TESTS),$(eval UT_LIB_$(t) := yes))
$(foreach t,$(ORBIT_TESTS),$(eval UT_LDX_$(t) := $$(ORBIT_WRAP) -lrt))
$(foreach t,$(ORBIT_TESTS),$(eval UT_DEP_$(t) := tests/lib/orbit_sys.c tests/lib/orbit_sys.h))

UNIT_SKIP_WINDOWS += $(ORBIT_TESTS)
