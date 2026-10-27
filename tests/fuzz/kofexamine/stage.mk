# Stage "kofexamine" (phase B of the examiner suite): the terminal-free API of kofexamine/ - kofinspect*.c (identify, declare, the
# region map, where a marker is, the describers, the dump), kofscfind.c (the shellcode-loader finder), codec_ui.c and goto_parse.h
# (what a person types). The units are compiled here from source, sanitised like the libs, and linked beside the sanitised
# engine archive; the engine archive is named again after them because a linker reads an archive once, in order.
KX_FZ_SRC := $(KOFINSPECT_SRC) kofexamine/kofscfind.c kofexamine/codec_ui.c $(KOFEVT_SRC)
KX_FZ_OBJ := $(addprefix $(FZB)/kx_obj/,$(KX_FZ_SRC:.c=.o))

$(FZB)/kx_obj/%.o: %.c $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -I$(SDK)/include -Ilibkoforbit/evt $(EMU_INC) -c $< -o $@

FZ_LIB_kofexamine    := engine
FZ_LIBS_kofexamine   := $(KX_FZ_OBJ) $(FZB)/libkofeng.a
FZ_CFLAGS_kofexamine := -I$(SDK)/include -Ilibkoforbit/evt $(EMU_INC)

$(FZB)/fuzz_kofexamine: $(KX_FZ_OBJ) $(wildcard tests/fuzz/kofexamine/*.h) tests/lib/scf_img.h tests/lib/ctr_writers.h

-include $(KX_FZ_OBJ:.o=.d)
