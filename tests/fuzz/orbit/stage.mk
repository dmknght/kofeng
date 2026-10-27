# Stage "orbit" (WP12): system-resource handling, libkoforbit (the Linux collectors, the event record and its readers, the
# clean-file set, the verdict cache, the report, the channel, the host-pure part of grille).
#
# The library has no seam for /proc, the process connector, fanotify, shared memory or a full disk, so the binary is linked
# with the wraps of tests/lib/orbit_sys.c (the same list the unit tests use: mk/tests_orbit.mk) and the adapters feed the
# fake. The collector sources are compiled into this binary from source (FZ_LIBS_orbit), sanitised like the rest; the engine
# archive is for the hash and the platform helpers they call.
#
# The collector sources are compiled to objects of their own (they set _GNU_SOURCE themselves, and the stage's command line sets
# it for the adapters): same flags and sanitisers, no -D. The engine archive is named again after them because a linker reads
# an archive once, in order.
ORBIT_FZ_OBJ := $(addprefix $(FZB)/orbit_obj/,$(ORBIT_SRC:.c=.o))

$(FZB)/orbit_obj/%.o: %.c $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(ORBIT_FZ_EXTRA) $(ORBIT_INC) -c $< -o $@

# FINDING WP12-18 (tests_wp12/findings): apev.c reads a struct proc_event (8-byte aligned: its timestamp is a u64) from the
# connector message at offset 36, which is 4 mod 8, in prefetch() and stream_next() on EVERY record the kernel sends. UBSAN's
# alignment check aborts on the first one, so the object that holds those reads is built without that one check until the library
# copies the event out instead of casting. Remove the line to see the report: it fires on the first well-formed message.
$(FZB)/orbit_obj/libkoforbit/antarc/apev.o: ORBIT_FZ_EXTRA := -fno-sanitize=alignment
# FINDING WP12-22: afan.c walks the info records of a fanotify event by their own `len` (afan.c:443), which the kernel keeps a
# multiple of 4 but a record need not: an odd len makes the next header pointer misaligned for a 2-byte-aligned struct.
$(FZB)/orbit_obj/libkoforbit/antarc/afan.o: ORBIT_FZ_EXTRA := -fno-sanitize=alignment

FZ_LIB_orbit    := engine
FZ_LIBS_orbit   := $(ORBIT_FZ_OBJ) $(FZB)/libkofeng.a -lrt
FZ_CFLAGS_orbit := $(ORBIT_INC)
FZ_WRAP_orbit   := $(ORBIT_WRAP)

$(FZB)/fuzz_orbit: $(ORBIT_FZ_OBJ) tests/lib/orbit_sys.c tests/lib/orbit_sys.h tests/fuzz/orbit/orbit_fx.h
