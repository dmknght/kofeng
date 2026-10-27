# ------------------------------------------------------------------- testing
#
# Exhaustive differential checks over small inputs, for the routines where a
# corpus run would pass while the code is still wrong on an input the corpus does
# not happen to contain. Each is a standalone program that exits non-zero on
# failure, so this target is usable from CI. Not part of `all`.

# The binaries the collectors are tested against, built from source rather than
# committed. What each one is for is written in tests/fixtures/*.c; what the local
# toolchain could not build is printed, because a format silently absent from the
# fixture directory is a format silently untested - which is exactly how PE
# coverage reached zero here without anything failing.
FIXTURES := $(TEST)/fixtures

fixtures: | $(TEST)
	@$(MKFIXTURES) $(FIXTURES)

#
# A WILDCARD, MINUS THE TESTS THIS HOST CANNOT BUILD.
#
# The wildcard is right - a test added to tests/unit is a test that runs, with
# nothing to remember to edit - and it was picking up two that cannot compile
# here. antarc_fan drives fanotify and antarc_walk forks children and reads
# /proc; both link libkoforbit/antarc, which is the LINUX collector. On Windows they
# are not failing tests, they are tests for another platform, and `make unit`
# stopping on them is a gate that cannot pass rather than a finding.
#
# NAMED, NOT GUESSED FROM THE FILENAME. A prefix rule - "anything called
# antarc_* is Linux" - is the kind of convention that silently excludes the
# first test somebody names badly, and a test that never runs is worse than a
# test that fails. Adding a row here is the cost of that.
#
# The reverse list is empty today: every test that exercises the Windows
# collector does it through the parts with no Windows API in them - see
# tests/unit/grille_host.c - so it builds and runs on either host. When one
# genuinely needs Windows, it goes in UNIT_SKIP_POSIX.
#
# msf_xor IS HERE BECAUSE DEFENDER EATS IT, AND THAT IS NOT A BUILD FAILURE.
#
# The test builds the output of Metasploit's XOR shellcode encoder and scans it,
# which is the point of it. Defender watches the build directory, recognises
# what was just linked, and takes the binary away between the link and the run.
# make then stops at the first target it cannot run - and because that target is
# in the middle of the list, the forty-odd tests after it never ran either. A
# developer on a default Windows install saw the suite abort and no summary.
#
# SKIPPED EXPLICITLY RATHER THAN TOLERATED AT RUN TIME. The obvious fix - run it
# and forgive a failure that looks like a missing binary - was written, measured
# and thrown away: Defender blocks the EXECUTION before it removes the file, so
# "the binary is still there" is true at the moment of the check and false a
# moment later. Any rule built on that distinction is a coin flip, and the side
# it lands on when it is wrong is a REAL test failure reported as a skip. A
# suite that sometimes forgives a genuine failure is worse than one that stops.
#
# TO RUN IT: add build/test to Defender's exclusions and take this out of the
# list. The test is not broken and it passes on Linux, where nothing removes it.
#
# ko_anomalies IS SKIPPED FOR A DIFFERENT REASON FROM THE THREE ABOVE, and it
# is the ordinary one: there is nothing here for it to measure. It walks
# /lib/modules and reports which anomalies the ET_REL objects on THIS machine
# trip, so on Windows it would have no population to look at even if it built -
# and it does not build, because lstat is not a function mingw declares.
#
# It is not a test that could be made portable. A kernel module is a Linux
# object and the false positive it guards against is a Linux one.
#
# antarc_pev JOINS THE TWO ABOVE IT FOR THE SAME REASON, which is the ordinary
# one: it is a test of libkoforbit/antarc, the LINUX collector. It includes
# sys/wait.h and sys/uio.h and links aproc.c - none of which exist here - so it
# is not a test that could be made portable, any more than the fanotify one
# beside it is.
#
# chan_ring drives chan_posix.c - shm_open, fork and a SIGSEGV it expects to
# see. The Windows backend is the same contract over CreateFileMapping and
# is a test of its own to write, not a define away.
UNIT_SKIP_WINDOWS := antarc_fan antarc_walk antarc_pev msf_xor ko_anomalies \
                     chan_ring
include mk/tests_orbit.mk
include mk/tests_kx.mk
#
# thread_region IS THE FIRST ENTRY IN THE REVERSE LIST, and the paragraph above
# that said the reverse list was empty was wrong rather than out of date. It
# links wwalk.c, wproc.c and wcmdline.c - libkofgrille, the WINDOWS collector -
# and its rule ends in -ladvapi32 -lpsapi. There is no Linux host it can link
# on, so on this side it is a test for another platform exactly as antarc_fan
# is on the other, and not a failing test.
#
# It went unnoticed because `make unit` aborted before reaching it: the fixture
# race at the bottom of this file stopped the suite in the b's, and this is a t.
UNIT_SKIP_POSIX   := hostile_mem reg_event thread_region

ifeq ($(NATIVE_OS),windows)
UNIT_SKIP := $(UNIT_SKIP_WINDOWS)
else
UNIT_SKIP := $(UNIT_SKIP_POSIX)
endif

UNIT_SRC := $(filter-out $(addprefix tests/unit/,$(addsuffix .c,$(UNIT_SKIP))),\
                         $(wildcard tests/unit/*.c))
UNIT_BIN := $(patsubst tests/unit/%.c,$(TEST)/unit_%$(EXE),$(UNIT_SRC))

#
# THE SANITISED BUILD'S NAMES, SET HERE AND NOT BESIDE THE TARGET THAT RUNS IT.
#
# They were set two hundred lines below the first test rule that names
# $(ASAN_LIB) in its PREREQUISITES, and a variable used before it is set expands
# to nothing: six asan binaries - proc_rule, out_clip, fridge, report_model,
# codec_forms, cond_expr - therefore did not depend on the sanitised library at
# all. Touching libkofeng-asan.a and asking for one of them answered "up to
# date", so `make unit-asan` could run a STALE binary against library code it
# had never linked and report it as passing. A sanitiser suite that can do that
# is worse than none, because it is believed.
#
# This is the third time this file has been caught by the same rule - see the
# note above the shared source lists - so the fix is the same one: the names go
# above every rule that uses them.
#
# -g here and not in CFLAGS: see the note beside the release CFLAGS. A report
# without file and line is a stack of addresses.
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer \
              -fno-sanitize-recover=undefined -g
ASAN_BIN := $(patsubst tests/unit/%.c,$(TEST)/asan_%$(EXE),$(UNIT_SRC))
ASAN_LIB := $(TEST)/libkofeng-asan.a

# Linked against the library, so a unit test can exercise it rather than only
# whatever it can compile in on its own.
#
# UNIT_LIBS_<name> adds what one test needs. Only the differential decompressor
# test uses it: it links zlib as an ORACLE, to check our decoder against, which is
# the one thing the library must never do itself.
#
# Statically on Windows, for the reason winpthread is static above: a
# dynamically linked zlib1.dll is only ever on PATH inside an MSYS2 shell, and
# from anywhere else the test does not report an error - Windows refuses to
# start the process before main() runs, so there is nothing to print. It comes
# back as exit code 0xC0000135 and no output at all, which reads like a crash
# in the test rather than a missing DLL.
# parse_once counts calls into the lib by wrapping them at link time (see tests/unit/parse_once.c);
# the production code carries no counter for it.
UNIT_LIBS_parse_once := -Wl,--wrap=kgenome_elf_image_parse -Wl,--wrap=kgenome_pe_image_parse -Wl,--wrap=kgenome_true_find_object -Wl,--wrap=kof_exe_norm_masked -Wl,--wrap=kgenome_elf_symtab_of -Wl,--wrap=kofpix_sweep -Wl,--wrap=kof_exe_decode_ex -Wl,--wrap=kof_exe_decode_would_change -Wl,--wrap=kof_script_sniff -Wl,--wrap=kof_script_sniff_keep -Wl,--wrap=kof_script_parse -Wl,--wrap=kof_script_parse_keep
# diag_graph_bin counts work and NULL arguments at link time, with no counter or hook in the production code:
# how many times the wrapper fixpoint asked whether a function could come out differently (C1), and every
# mem*/qsort call that was handed a NULL pointer, whatever the length (U1: memcmp(NULL, NULL, 0)).
UNIT_LIBS_diag_graph_bin := -Wl,--wrap=kgenome_diag_wrapper_tseen_retry -Wl,--wrap=memcmp -Wl,--wrap=memcpy -Wl,--wrap=memmove -Wl,--wrap=memset -Wl,--wrap=qsort -Wl,--wrap=kgenome_cell_next -Wl,--wrap=kgenome_diag_funcs
# The normalise-defect tests count work and inject faults at link time, with no counter or hook in the
# production code: norm_defect_image counts the bytes any compare is asked for (N2), norm_defect_plan the bytes
# memmove is asked to move (N4), norm_defect_engine makes the decode of one escape run fail (N8).
UNIT_LIBS_norm_defect_image := -Wl,--wrap=memcmp -Wl,--wrap=bcmp
UNIT_LIBS_norm_defect_plan := -Wl,--wrap=memmove
UNIT_LIBS_norm_defect_engine := -Wl,--wrap=kof_exe_decode_run
# diag_text_oom refuses every allocation of a scan in turn (G9: an allocation that fails must not leave a shorter graph with a clean status); -rdynamic so that the
# trace it prints for an allocation whose refusal was silent has the names of the functions that made it.
UNIT_LIBS_diag_text_oom := -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -rdynamic
# diag_bin_oom does the same for the BINARY route (the sweep, symbol, emulate, API-hash and lineage routes, the function table, the code map): every allocation refused in turn,
# free wrapped as well so that an allocation left behind after a refused call is counted without a sanitiser.
UNIT_LIBS_diag_bin_oom := -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free -rdynamic
# diag_text_ops refuses every allocation of a scan over the list, cast and operator shapes in turn (the evaluator's lists: a refusal must be said, never a shorter set of constants with a clean
# status): malloc, calloc and realloc wrapped, armed only around the scan. text_scan_once counts, at the one call every stage makes, how many times the TEXT route scans a script through the
# whole pipeline (scans per distinct text: 1): kgenome_diag_scan_text wrapped, no counter in the engine.
UNIT_LIBS_diag_text_ops := -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc
UNIT_LIBS_text_scan_once := -Wl,--wrap=kgenome_diag_scan_text
# diag_text_nullargs counts the memory-function calls that are handed a NULL pointer (memcpy(d, NULL, 0) is undefined) over texts that make an empty value reach a copy
UNIT_LIBS_diag_text_nullargs := -Wl,--wrap=memcpy -Wl,--wrap=memmove -Wl,--wrap=memcmp -Wl,--wrap=memset
# diag_text_work counts the basic blocks the TEXT route executes on its hostile shapes (tests/lib/work_count.h). The route is in the archive, uninstrumented, so the test is
# built with the route's own sources compiled with the instrumentation and linked AHEAD of the archive (every symbol an archive member of them defines is defined by these
# objects, so the member is not pulled in). An explicit rule: the pattern rule above links the archive alone.
DTX_WORK_SRC := $(wildcard libgenome/phenotype/diag_text*.c)
$(TEST)/libtest_genome_diag_text_work$(EXE): tests/lib/genome/diag_text_work.c $(DTX_WORK_SRC) $(KGENOME_LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) -fsanitize-coverage=trace-pc $< $(DTX_WORK_SRC) $(KGENOME_LIB) -o $@ $(LDFLAGS)

# The lexer WORK tests (tests/lib/*/*_work_*.c, *_defect_work_*.c) count the basic blocks a lexer executes and assert a bound on them, not a time: gcc's
# trace-pc instrumentation calls __sanitizer_cov_trace_pc at every block of the test's own translation unit, and the test #includes the lexer under test (see
# tests/lib/genome/textual_work.h). A test that counts libc's memchr too wraps it.
LEXWORK_FLAGS := -fsanitize-coverage=trace-pc
UNIT_LIBS_textual_defect_work_sh_lex := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_vb := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_clike := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_perl_lex := $(LEXWORK_FLAGS) -Wl,--wrap=memchr
UNIT_LIBS_textual_defect_work_ruby := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_py := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_tcl := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_psh := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_cfm := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_lua := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_bat := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_php := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_ecma := $(LEXWORK_FLAGS)
UNIT_LIBS_textual_defect_work_page := $(LEXWORK_FLAGS)
UNIT_LIBS_strfn_defect_work := $(LEXWORK_FLAGS) -Wl,--wrap=memcmp -Wl,--wrap=memmem
UNIT_LIBS_textual_defect_work_form := $(LEXWORK_FLAGS) -Wl,--wrap=kgenome_textual_c_block_end
ifeq ($(NATIVE_OS),windows)
UNIT_LIBS_inflate_diff := -Wl,-Bstatic -lz -Wl,-Bdynamic
UNIT_LIBS_cab_mszip    := -Wl,-Bstatic -lz -Wl,-Bdynamic
UNIT_LIBS_script_decode_inflate := -Wl,-Bstatic -lz -Wl,-Bdynamic
else
UNIT_LIBS_inflate_diff := -lz
# The same oracle, used the other way round: cab_mszip COMPRESSES its fixture
# with zlib, so what the engine hands back is compared against the bytes that
# went in. Nothing else on this host writes a cabinet.
UNIT_LIBS_cab_mszip    := -lz
UNIT_LIBS_script_decode_inflate := -lz
endif

#
# $(EXE) AND NOT $(WIN_EXE). These two used to name the cross-built PE
# unconditionally, which on Linux meant `make kofwatchtower` demanded mingw and
# `make kofmontrace` was a Windows-only line in the help - both tools now build
# for the host, and the name has to follow the host or the native binary has no
# way to be asked for. On Windows $(EXE) IS .exe, so the cross build is
# unchanged.
kofwatchtower: $(OUT)/bin/kofwatchtower$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

kofmontrace: $(OUT)/bin/kofmontrace$(EXE)
	$(info $(SP)  $<)
	@$(NOOP)

#
# THE SAME TOOLS, BUILT NATIVELY, ON A HOST THAT HAS A COLLECTOR FOR ITSELF.
#
# ONE SOURCE FILE EACH, NOT TWO. kofwatchtower.c and kofmontrace.c each carry a
# single adapter block that names the host's collector and how a subject is
# started and contained; everything below it is the same code on both. What
# changes between these recipes is therefore the LIBRARY and the INCLUDES, not
# the file - which is the only arrangement in which a fix to the drain loop
# cannot land on one platform and miss the other.
ifneq ($(NATIVE_OS),windows)

POSIX_TOOL_INC = -Ilibkoforbit/antarc -Ilibkoforbit/evt -Ilibkoforbit/mon \
                 -Ilibkoforbit/chan

$(OUT)/bin/kofwatchtower$(EXE): kofwatcher/kofwatchtower.c $(ANTARC_SRC) \
                                libkoforbit/chan/chan_posix.c \
                                $(KOFEVT_SRC) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) $(POSIX_TOOL_INC) \
	      kofwatcher/kofwatchtower.c $(ANTARC_SRC) \
	      libkoforbit/chan/chan_posix.c $(KOFEVT_SRC) \
	      -o $@ $(LDFLAGS) -lrt

# Links the ENGINE for the same reason the Windows recipe below does: the
# report hashes what the traced program created and asks what those files are.
$(OUT)/bin/kofmontrace$(EXE): $(KOFMONTRACE_SRC) $(ANTARC_SRC) \
                              $(KOFREPORT_SRC) $(KOFEVT_SRC) $(LIB) $(STAMP)
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) $(DEPTO) $(POSIX_TOOL_INC) -Ilibkofeng \
	      -Ilibkofeng/kofcore -Ilibkoforbit/report -Ikofwatcher \
	      $(KOFMONTRACE_SRC) $(ANTARC_SRC) $(KOFREPORT_SRC) \
	      $(KOFEVT_SRC) $(LIB) -o $@ $(LDFLAGS)

endif

$(TEST)/unit_%$(EXE): tests/unit/%.c $(LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $< $(LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

#
# ONE HARNESS PER LIB, linked against that lib's archive ALONE.
#
# tests/lib/genome/*.c is linked with libkgenome.a and nothing else, and
# tests/lib/uncoat/*.c with libkuncoat.a: a unit test of the engine could resolve
# a symbol of the lib through the engine's own archive and never say so, and these
# cannot. Neither lib may depend on the engine (CLAUDE.md section 12), and a link
# that has no engine to take a symbol from is the only test of that which a header
# check cannot fake. A test that belongs to ONE lib lives here and not in
# tests/unit/ (which links the whole engine): it is the lib's own proof, and it
# gets the lib's archive alone. UNIT_LIBS_<name> applies to these too (the zlib
# oracle of inflate_diff). Tests that need the engine - the object context, the
# parsers, a database - stay in tests/unit/.
LIBTEST_GENOME_SRC := $(wildcard tests/lib/genome/*.c)
LIBTEST_UNCOAT_SRC := $(wildcard tests/lib/uncoat/*.c)
LIBTEST_BIN := $(patsubst tests/lib/genome/%.c,$(TEST)/libtest_genome_%$(EXE),$(LIBTEST_GENOME_SRC)) \
               $(patsubst tests/lib/uncoat/%.c,$(TEST)/libtest_uncoat_%$(EXE),$(LIBTEST_UNCOAT_SRC))
LIBTEST_ASAN_BIN := $(patsubst tests/lib/genome/%.c,$(TEST)/asan_libtest_genome_%$(EXE),$(LIBTEST_GENOME_SRC)) \
                    $(patsubst tests/lib/uncoat/%.c,$(TEST)/asan_libtest_uncoat_%$(EXE),$(LIBTEST_UNCOAT_SRC))

$(TEST)/libtest_genome_%$(EXE): tests/lib/genome/%.c $(KGENOME_LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $< $(KGENOME_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

$(TEST)/libtest_uncoat_%$(EXE): tests/lib/uncoat/%.c $(KUNCOAT_LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) $< $(KUNCOAT_LIB) -o $@ $(LDFLAGS) $(UNIT_LIBS_$*)

# The Windows-only tests: explicit rules, because they differ in the libraries they
# link (advapi32, psapi, tdh), not in their shape.
#
# hostile_mem drives the WINDOWS memory comparison, so it compiles the collector
# alongside the engine the way kofscanner does - see SCANNER_EXTRA.
#
# Named in UNIT_SKIP_POSIX rather than guarded inside the file with an #ifdef,
# because a test that compiles to an empty main on the other platform is a test
# that LOOKS like it ran. A skipped one is visibly absent.
$(TEST)/unit_hostile_mem$(EXE): tests/unit/hostile_mem.c \
                                libkoforbit/grille/wdiff.c libkoforbit/grille/wproc.c \
                                libkoforbit/grille/wcmdline.c libkoforbit/grille/wtext.c \
                                $(KOFEVT_SRC) $(LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkoforbit/grille -Ilibkofeng \
	      -Ilibkoforbit/evt \
	      tests/unit/hostile_mem.c libkoforbit/grille/wdiff.c \
	      libkoforbit/grille/wproc.c libkoforbit/grille/wcmdline.c \
	      libkoforbit/grille/wtext.c $(KOFEVT_SRC) $(LIB) -o $@ \
	      $(LDFLAGS) -ladvapi32 -lpsapi

#
# THE THREAD CORRELATION, which needs the WALK and not just the collector.
#
# wwalk.c is the file under test here and it is not in libkofgrille.a - it
# calls kgenome_pe_unmap, so it is compiled into whoever needs it, exactly as the
# scanner does. That is why this is a rule rather than a line in the wildcard:
# the same sources the scanner links, minus the scanner.
#
$(TEST)/unit_thread_region$(EXE): tests/unit/thread_region.c \
                                  libkoforbit/grille/wwalk.c libkoforbit/grille/wdiff.c \
                                  libkoforbit/grille/wproc.c \
                                  libkoforbit/grille/wcmdline.c \
                                  libkoforbit/grille/wtext.c \
                                  $(KOFPROC_SRC) $(KOFEVT_SRC) $(LIB) \
                                  $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkoforbit/grille -Ilibkofeng \
	      -Ilibkoforbit/evt -Ilibkoforbit/proc \
	      -Ilibkoforbit/walk \
	      tests/unit/thread_region.c libkoforbit/grille/wwalk.c \
	      libkoforbit/grille/wdiff.c libkoforbit/grille/wproc.c \
	      libkoforbit/grille/wcmdline.c libkoforbit/grille/wtext.c \
	      $(KOFPROC_SRC) $(KOFEVT_SRC) $(LIB) -o $@ \
	      $(LDFLAGS) -ladvapi32 -lpsapi

#
# THE REGISTRY DECODE, over records built by hand.
#
# -ltdh is the whole reason this is a rule of its own: the test hands a
# synthetic EVENT_RECORD to kofw_decode, which asks TdhGetEventInformation to
# describe it against the manifest Windows already has registered. That is the
# real learn path against the real template, which is what makes a hand-built
# record worth anything - a test that carried its own idea of the shape would
# agree with itself forever and say nothing about what the provider sends.
$(TEST)/unit_reg_event$(EXE): tests/unit/reg_event.c \
                              libkoforbit/grille/wevt_decode.c libkoforbit/grille/wtext.c \
                              $(KOFEVT_SRC) $(LIB) $(STAMP) | $(TEST)
	$(CC) $(CFLAGS) $(DEPTO) -Ilibkoforbit/grille -Ilibkofeng \
	      -Ilibkoforbit/evt \
	      tests/unit/reg_event.c libkoforbit/grille/wevt_decode.c \
	      libkoforbit/grille/wtext.c $(KOFEVT_SRC) $(LIB) -o $@ \
	      $(LDFLAGS) -ltdh -ladvapi32

#
# THE TESTS THAT NEED MORE THAN THE ENGINE ARCHIVE: one table, one template.
#
# The generic unit_% and asan_% patterns link a test against the library and
# nothing else. A test that also compiles a tool or orbit source - the draft
# model, the verdict cache, the collector - is described here by what it adds:
#
#   UT_SRC_<name>   the extra sources, compiled into the test
#   UT_INC_<name>   the extra include paths
#   UT_LIB_<name>   `yes` when it links the engine archive (the sanitised twin
#                   links the sanitised archive); nothing when it must NOT -
#                   the collector and the channel are orbit, and linking the
#                   engine would hide a dependency creeping the other way
#   UT_DEP_<name>   what else it is rebuilt for (the staged SDK headers)
#   UT_LDX_<name>   what else it links (-lrt)
#
# and UNIT_EXTRA names the tests. The template gives each one its unit_ and its
# asan_ rule together, so a sanitised twin cannot be forgotten (they were: `make
# unit-asan` stopped at the first test that needed an extra source, and one twin
# named two variables that did not exist). The Windows-only rules above stay
# explicit: they differ in their libraries, not in their shape.
#
# The asan_ twin carries no $(DEPTO): it has no dependency file.
#
# The Linux collector's own tests. They fork, write files in a scratch directory
# and read the events back, so they need the collector's sources rather than the
# library - libkoforbit/antarc is not in $(LIB), for the same reason libkofgrille
# is not: a collector belongs to one platform and the engine belongs to neither.
# THEY RUN UNPRIVILEGED, AND THAT IS THE POINT. fanotify's unprivileged mode
# reports dirent events and hides the actor - see afan.h - which is useless as a
# sensor and exactly enough to exercise the event walk, the name assembly, the
# verb mapping and the record. A CI has no root and this still tests. antarc_pev
# tests the refusal rather than the stream: the connector needs CAP_NET_ADMIN and
# refuses SILENTLY, so what an unprivileged run checks is that kofa_pev_open
# discovers that by probing and hands back nothing; as root the same test drains
# a real exec. antarc_walk forks children into known shapes - a memfd exec, a
# socket on stdin, a deleted binary - and checks the /proc walk reports them.
UT_SRC_antarc_fan  := $(ANTARC_SRC) $(KOFEVT_SRC)
UT_SRC_antarc_pev  := $(UT_SRC_antarc_fan)
UT_SRC_antarc_walk := $(UT_SRC_antarc_fan)
UT_INC_antarc_fan  := $(ANTARC_INC)
UT_INC_antarc_pev  := $(ANTARC_INC)
UT_INC_antarc_walk := $(ANTARC_INC)

# The string codings are an API rather than a dialog - see kofinspect.h - and are
# linked against kofinspect.c and codec_ui.c alone: nothing in them touches the
# terminal, and a test that had to drag the panel in would be saying the opposite.
UT_SRC_codec_forms := $(KOFINSPECT_SRC) kofexamine/codec_ui.c $(KOFEVT_SRC)
UT_INC_codec_forms := -I$(SDK)/include
UT_LIB_codec_forms := yes
UT_INC_code_notes   := -Ilibkofeng -Ilibkofeng/kofcore -Ilibgenome
UT_LIB_code_notes   := yes
UT_DEP_codec_forms := $(SDK_HDR)

# The examiner's shellcode-loader finder is tool code, not library code, so the
# test over it compiles that source beside the engine.
UT_SRC_kofscfind := kofexamine/kofscfind.c
UT_INC_kofscfind := -I$(SDK)/include
UT_LIB_kofscfind := yes
UT_DEP_kofscfind := $(SDK_HDR)

# One test over the editor's model: the condition parser, the tabs and the tag.
UT_SRC_cond_expr      := $(EDITOR_SRC)
UT_INC_cond_expr      := -I$(SDK)/include
UT_LIB_cond_expr      := yes
UT_DEP_cond_expr      := $(SDK_HDR)

# The terminal writer is a tool source: kofview.c is the viewer's drawing layer, it
# lives beside the tool because nothing that scans needs it, so a test over it
# compiles that source the way the draft-model tests compile kofeditor.c.
UT_SRC_out_clip := kofexamine/kofview.c
UT_LIB_out_clip := yes

# The clean-file set is its own source beside the fridge - see fidset.h - and
# needs nothing of the engine.
UT_SRC_fidset := libkoforbit/fridge/fidset.c

# The verdict cache. $(KOFEVT_SRC) IS NOT OPTIONAL: koffridge_seen_evt takes a
# struct kof_evt and asks kof_evt_object for the name to key on, so the cache does
# not link without the event library.
UT_SRC_fridge := $(KOFRIDGE_SRC) $(KOFEVT_SRC)
UT_LIB_fridge := yes

# The process record builder is orbit's too, so the test that drives a process
# end to end compiles it.
UT_SRC_proc_rule := $(KOFPROC_SRC)
UT_INC_proc_rule := -Ilibkoforbit/proc -I$(SDK)/include
UT_LIB_proc_rule := yes
UT_DEP_proc_rule := $(SDK_HDR)

# The channel, both ends in one process: no engine, -lrt.
UT_SRC_chan_ring := $(CHAN_TEST_SRC)
UT_INC_chan_ring := -Ilibkoforbit/chan -Ilibkoforbit/evt
UT_LDX_chan_ring := -lrt

# The report, over synthetic records and NOT over a trace. kofmontrace needs an
# elevated prompt, a live sample and an ETW session, so the report cannot be
# exercised by running the tool - and the collector is not the half worth testing
# anyway. What this covers is everything that happens after an event arrives, and
# it covers it by writing struct kof_evt by hand: a rule that cannot be run
# against a recorded trace cannot be regression tested, and these records are a
# recorded trace that never needed a machine.
#
# NO -D_GNU_SOURCE HERE, and that is the fix rather than the omission:
# kofplatform.h reaches for memmem, lstat and realpath and this test calls rmdir;
# none of those is declared under a bare -std=c11. The declaration lives INSIDE the
# sources that need it, where it cannot be left off a new recipe.
UT_SRC_report_model := $(KOFREPORT_SRC) $(KOFEVT_SRC)
UT_INC_report_model := -Ilibkoforbit/report -Ilibkoforbit/evt -Ilibkofeng -Ilibkofeng/kofcore
UT_LIB_report_model := yes

# The module helper headers under kofmod/ and analyzers/diseases/ are tested through a fake host.
# msf_elf32.h includes <kofshared/msf_pe.h>, which is where the SDK stages the shared
# declarations (mk/sdk.mk), so the one test that includes it needs the staged include path -
# the same one codec_forms and kofscfind take. msf_elf64.h and msf_pe.h alone did not.
UT_INC_api_engine_modhelpers := -I$(SDK)/include
UT_LIB_api_engine_modhelpers := yes
UT_DEP_api_engine_modhelpers := $(SDK_HDR)

UT_SRC_grille_host := $(GRILLE_HOST_SRC)
UT_INC_grille_host := -Ilibkoforbit/grille -Ilibkoforbit/evt

UNIT_EXTRA := antarc_fan antarc_pev antarc_walk codec_forms kofscfind cond_expr \
              out_clip fidset fridge proc_rule \
              chan_ring report_model grille_host api_engine_modhelpers code_notes
UNIT_EXTRA += $(ORBIT_TESTS) $(KX_TESTS)

define UNIT_EXTRA_RULES
$$(TEST)/unit_$(1)$$(EXE): tests/unit/$(1).c $$(UT_SRC_$(1)) $$(if $$(UT_LIB_$(1)),$$(LIB)) \
                          $$(UT_DEP_$(1)) $$(STAMP) | $$(TEST)
	$$(CC) $$(CFLAGS) $$(DEPTO) $$(UT_INC_$(1)) tests/unit/$(1).c $$(UT_SRC_$(1)) \
	      $$(if $$(UT_LIB_$(1)),$$(LIB)) -o $$@ $$(LDFLAGS) $$(UT_LDX_$(1))

$$(TEST)/asan_$(1)$$(EXE): tests/unit/$(1).c $$(UT_SRC_$(1)) $$(if $$(UT_LIB_$(1)),$$(ASAN_LIB)) \
                          $$(UT_DEP_$(1)) $$(STAMP) | $$(TEST)
	@$$(CC) $$(CFLAGS) $$(ASAN_FLAGS) $$(UT_INC_$(1)) tests/unit/$(1).c $$(UT_SRC_$(1)) \
	       $$(if $$(UT_LIB_$(1)),$$(ASAN_LIB)) -o $$@ $$(LDFLAGS) $$(UT_LDX_$(1))
endef
$(foreach t,$(UNIT_EXTRA),$(eval $(call UNIT_EXTRA_RULES,$(t))))

# The engine's own signature set is BUILT here, not merely present.
#
# It is not part of `make db`, so nothing else compiles it - and a rename that
# missed it went unnoticed until somebody tried. A signature set that is never
# built is a signature set that has already rotted; building it with the tests is
# what keeps the module ABI's own examples honest about the ABI.
#
# AND A SECOND, tests/shape: the diagnoses whose own declaration ASKS for the
# interpreter on a stager's shape. They are kept out of tests/sigs because that shape is
# every synthetic stager's, and a database that asks about all of them moves every other
# test's counts (see tests/shape/diagnoses/stager_shape.c).
test-sigs:
	@$(MAKE) --no-print-directory databases BASEDIR=tests/sigs
	@$(MAKE) --no-print-directory databases BASEDIR=tests/shape

#
# ONE TARGET PER TEST, rather than one recipe looping over all of them.
#
# The loop was sh - `for`, `if`, a shell variable holding the tally - and none
# of it survives a shell that is not sh. A target per binary is what make is
# for: it needs no shell control flow, it names the failing test in make's own
# error line, and `make -j` can run them at once.
#
# The one thing that changes is that the run now STOPS at the first failing
# test instead of running the rest and summarising. `make -k unit` restores
# the old behaviour where that is wanted, and a first failure is usually the
# one worth reading anyway.
UNIT_RUN := $(addprefix run-,$(UNIT_BIN)) $(addprefix run-,$(LIBTEST_BIN))

#
# A TEST BINARY THAT IS NOT THERE STOPS THE RUN, AND ON WINDOWS THAT IS NOT A
# BUILD FAILURE - IT IS DEFENDER.
#
# Some of these tests are ABOUT malware: msf_xor builds the Metasploit XOR
# shellcode encoder's output and scans it. Defender watches the build directory,
# recognises what was just linked and deletes the binary between the link and
# the run. make then stops at the first missing target, which is the FIRST test
# alphabetically that this happens to - so a developer on a default Windows
# install sees the suite abort a third of the way through and the remaining
# forty tests never run at all.
#
# That is what happens: a test binary that is missing stops the run, naming it.
# NOT reported-and-continued - nothing here implements that - and `make -k unit`
# is the way to run the rest. A test that did not run is not a test that passed,
# and the one thing worse than a suite that stops is a suite that says ok about
# work it did not do, so the stop is kept and the summary line only prints when
# every test ran.
#
# ORDER-ONLY ON THE FIXTURES, AND IT HAS TO BE HERE RATHER THAN ON `unit`.
#
# `unit: fixtures test-sigs $(UNIT_RUN)` names all three as prerequisites, and
# prerequisites of one target have NO order among themselves - so under -j a
# run-% starts while mkfixtures is still writing build/test/fixtures. The test
# then opens a file that is not there yet and reports the honest thing it sees:
# "the .bz2 was not scanned at all". It passes when run again, alone, which is
# the signature that made this look like flakiness rather than a missing edge.
#
# Order-only (|) and not ordinary: the fixtures are regenerated on every run, so
# an ordinary prerequisite would make every test look out of date every time.
$(UNIT_RUN): run-%: % | fixtures test-sigs
	$(info == $(notdir $*))
	@$(call EXEC,$*)

unit: fixtures test-sigs $(UNIT_RUN)
	$(info all $(words $(UNIT_BIN) $(LIBTEST_BIN)) test(s) passed)
	$(info $(SP)not built on this host: $(if $(UNIT_SKIP),$(UNIT_SKIP),none))
	@$(NOOP)

