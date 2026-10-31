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
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(ORBIT_INC) -c $< -o $@

FZ_LIB_orbit    := engine
FZ_LIBS_orbit   := $(ORBIT_FZ_OBJ) $(FZB)/libkofeng.a -lrt
FZ_CFLAGS_orbit := $(ORBIT_INC)
FZ_WRAP_orbit   := $(ORBIT_WRAP)

$(FZB)/fuzz_orbit: $(ORBIT_FZ_OBJ) tests/lib/orbit_sys.c tests/lib/orbit_sys.h tests/fuzz/orbit/orbit_fx.h
