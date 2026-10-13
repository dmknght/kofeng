
#
# The second warning tier, now that the probe knows what to read - see
# kof_probe above for why it is a probe rather than a list.
#
# ASKED ONCE. := is not a style choice here, it is the difference between two
# compiler runs and a hundred and eighteen of them.
#
# CFLAGS is recursively expanded - `CFLAGS ?= -O2 -g` makes it so, and every
# += after that keeps it that way - which means a `$(call kof_probe,...)`
# appended to it is not a result, it is a recipe for getting one, re-run in
# full every single time anything expands $(CFLAGS). Every compile line does.
# Measured on this tree: 102 seconds of a 310 second `make sdk`, spent asking
# the same compiler the same two questions once per object file. Answering
# them into a simply-expanded variable first costs the two runs it should.
#
# WHAT IS OFF, AND EXACTLY WHAT IT WOULD SAY IF IT WERE ON.
#
# Turning the portable list back on (see kof_probe_each) showed 24 warnings
# that had never been seen, because the all-or-nothing probe had been dropping
# the flags that produce them. They are pre-existing and none of them is a
# defect in what this build was changed for, so they are held here rather than
# fixed in passing OR left to print 24 lines on every build - which would bury
# the next real one, and burying is the fault this whole note exists to undo.
#
# Held off, with the count as of the build that found them:
#
#   -Wcast-align               9   uint8_t* cast to a wider type. Fine on x86
#                                  and on the ARM64 this targets; real on a
#                                  strict-alignment target, so it is a port
#                                  question rather than a bug here.
#                                  dbpacker.c, emu_interp.c, kofeditor.c,
#                                  kofviewer.c, wevt_etw.c, wchan.c
#   -Wdouble-promotion         6   float reaching a double parameter.
#                                  emu_interp.c, dbpacker.c
#   -Wformat-nonliteral       10   printf handed a format built at run time.
#                                  Deliberate in these callers - a column
#                                  width or a label is chosen and then used -
#                                  so this is the one of the four most likely
#                                  to stay off. It is still counted, because
#                                  a NEW one is worth seeing and a count is
#                                  the only way to notice the number moved.
#                                  ksb_*.c, kofviewer.c
#   -Wmissing-format-attribute 9   printf wrappers with no format attribute,
#                                  which is the one of the three that a caller
#                                  can be hurt by: without it the compiler
#                                  cannot check the format string AT the call.
#                                  Suppressed as a sub-warning rather than by
#                                  dropping -Wformat=2, because the rest of
#                                  that flag - format-security above all - is
#                                  worth keeping on.
#
# Each line is a thing to fix and then delete from here. A flag that is off
# with a count beside it is a decision; a flag that is off because a probe
# threw it away is what this replaced.
#
KOF_WARN_PENDING := -Wno-missing-format-attribute -Wno-format-nonliteral

# Probed one at a time, so the two lists above are a statement of WHERE each
# flag is expected to work rather than a mechanism - a compiler that lacks any
# one of them loses that one and nothing else. The pending suppressions come
# after, so they win over whatever enabled them.
KOF_WARN_EXTRA := $(call kof_probe_each,$(KOF_WARN_PORTABLE) $(KOF_WARN_GCC)) \
                  $(call kof_probe_each,$(KOF_WARN_PENDING))
override CFLAGS  += $(KOF_WARN_EXTRA)

# Header dependencies, emitted as a side effect of every compile and included
# below. Without them a header edit rebuilds nothing: the object files are newer
# than the .c that did not change, so make has nothing to do and the tests run
# against the previous header. That is not a theoretical failure - a deliberately
# broken _Static_assert in a header was compiled away to a passing build here.
override CFLAGS  += -MMD -MP

# Where the dependency files go.
#
# -MMD writes the .d beside the -o output, which for a linked binary means beside
# the PRODUCT. Intermediates in build/release defeat the only thing that directory
# is for - being copyable as-is - so every link redirects its .d into build/temp.
# The library objects already compile into build/temp and need no help.
DEPTO    = -MF $(INT)/dep-$(notdir $@).d
LDFLAGS ?=

# Address and UB sanitizers are the default for development: the whole parser
# runs on untrusted input, so the cheapest way to find the bug class that
# matters is to make a corpus run trip over it.
# -fno-sanitize-recover is not optional here. UndefinedBehaviorSanitizer defaults
# to printing a finding and carrying on, so a misaligned load or a signed overflow
# showed up as noise on stderr while every test still reported success - a safety
# net that reports green whatever it catches. Halting turns a finding into a failed
# build, which is the only form of it anyone acts on.
ifeq ($(SAN),1)
SAN_CFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all \
              -fno-omit-frame-pointer -g
override CFLAGS  += $(SAN_CFLAGS)
LDFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=all
endif

# SAN=thread instead, for the parallel walk. A separate switch rather than a
# third value folded into the one above, because ThreadSanitizer cannot be
# combined with AddressSanitizer - asking for both is a build that does not
# link, and a build system should refuse that by construction rather than at
# the link step.
ifeq ($(SAN),thread)
override CFLAGS  += -fsanitize=thread -fno-omit-frame-pointer
LDFLAGS += -fsanitize=thread
endif

BUILD := build
OUT   := $(BUILD)/release
INT   := $(BUILD)/temp
TEST  := $(BUILD)/test
SDK   := $(OUT)

