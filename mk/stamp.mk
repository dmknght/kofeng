
# ------------------------------------------------------------ the flag stamp
#
# An object file does not record the flags it was built with, and make compares
# timestamps. So `make` followed by `make SAN=1` rebuilt nothing: every object was
# newer than its source, and the "sanitizer" run was a release binary reporting
# green. Same failure as missing header dependencies - a safety net that silently
# is not there - and it was caught by checking `ldd` for the sanitizer runtime,
# not by anything failing.
#
# Written while the makefile is being read rather than by a recipe. That timing
# is the whole point: make decides what is out of date before it runs any
# recipe, so a stamp updated by a recipe updates it too late to matter.
#
# Read and written with make's own $(file), not with a shell. It used to be a
# $(shell) running `[`, `cat` and `printf` - three POSIX tools for a
# compare-and-write make can do itself, and three more reasons the build
# needed MSYS2. The comparison is ifneq rather than $(filter-out) because a
# flag list is one string here and not a list of words: filter-out would
# compare word by word and call a reordering equal.
#
# DEBUG=1 PUTS THE SYMBOLS BACK, AND `make debug` IS THAT SPELLED SHORTER.
#
# Same shape as SAN=1 above, and for the same reason: it is a switch on the
# flags rather than a second tree of objects, so FLAGSIG below picks it up and
# every object rebuilds when it changes. Nobody has to remember to clean.
#
# WIN_CFLAGS is `:=` and is set in mk/grille.mk, included AFTER this fragment, so appending to it
# here appends to nothing and the later assignment throws it away. The flag is
# carried in a variable it pastes in itself.
KOF_DEBUG_CFLAGS :=
ifeq ($(DEBUG),1)
KOF_DEBUG_CFLAGS  := -g
override CFLAGS += $(KOF_DEBUG_CFLAGS)
endif

FLAGSIG := $(CC) $(CFLAGS) $(LDFLAGS)
STAMP   := $(INT)/.flags

$(shell $(call MKDIR,$(INT)))

STAMP_WAS := $(if $(wildcard $(STAMP)),$(file < $(STAMP)))
ifneq ($(STAMP_WAS),$(FLAGSIG))
$(file > $(STAMP),$(FLAGSIG))
endif

$(STAMP): ;

