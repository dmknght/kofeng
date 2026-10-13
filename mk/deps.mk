# Everything -MMD wrote. Missing on a clean tree, which is why it is a soft
# include: nothing to rebuild yet, and the first compile creates them.
#
# A PREREQUISITE THAT ONLY A STALE DEPENDENCY FILE STILL BELIEVES IN.
#
# -MMD -MP already covers headers: -MP emits a phony target for each one, so a
# header that moves does not stop the build. It does NOT cover sources, because
# a link rule's .d lists the .c files it was built from - and when one of those
# moves, make refuses with "No rule to make target '<old path>', needed by
# <binary>" until somebody works out that the answer is to delete build/temp.
#
# That has now cost this tree two file moves, and the second one was worse than
# the first: the build had been broken for an hour while every test appeared to
# pass, because the tools being run were the last ones that linked.
#
# Named per library rather than as a bare "%.c", which was tried and is too
# greedy: it let make believe it could produce tests/unit/<anything>.c, so a
# pattern rule matched a name that was never a source and the compiler was
# handed "elf_rebuild.d.c". These match only the trees that hold sources.
#
# What is lost: a source deleted by accident now fails at the compiler with
# "No such file or directory" naming the file, rather than at make. That is the
# better error of the two - it names what is missing rather than what wanted it.
#
# EVERY TREE THAT HOLDS SOURCES is named here, so a move in any of them is
# covered: a stem may contain '/', so one pair of rules per top-level directory
# also covers its subdirectories. (This used to list four of them, and a moved
# file under libgenome/, libuncoat/, ksigbuilder/ or tests/ failed the way the
# note above describes.)
SOURCE_TREES := libkofeng libkoforbit libgenome libuncoat kofexamine kofwatcher \
                kofscanner ksigbuilder tools tests
define EMPTY_SOURCE_RULES
$(1)/%.c: ;
$(1)/%.h: ;
endef
$(foreach t,$(SOURCE_TREES),$(eval $(call EMPTY_SOURCE_RULES,$(t))))

#
# A DEPENDENCY FILE IS DATA, NEVER A TARGET.
#
# The include below is soft, so a missing .d is not an error - but make still
# asks whether it could MAKE one, and left to its built-in rules it decides
# that it can. `%: %.o` is built in, the object rules above match anything in
# their own tree, and the chain that falls out is: to get
# build/temp/lib_databases/dbloader.d, first build dbloader.d.o, which needs
# dbloader.d.c. The empty source rules just above then tell make that file is
# fine, so nothing stops it, and the compiler is handed a name no source ever
# had - "no such file or directory: libkofeng/databases/dbloader.d.c", once per
# library, naming a file nobody wrote.
#
# Reached whenever such a .d exists at all, because the intermediate .o it
# would be built from never does - so it is not a stale-tree problem that a
# clean would fix. It stays latent on the cmd build only because `dir /s /b`
# answers in absolute paths with backslashes, which match no pattern rule;
# POSIX FIND_DEPS answers in relative ones and they match at once.
#
# One empty rule ends it: a .d under the build tree is up to date by
# definition, so make stops hunting for a way to produce one. The files
# themselves are untouched and header tracking is unaffected - this says
# nothing about their CONTENT, only that they are not products.
$(BUILD)/%.d: ;

-include $(shell $(FIND_DEPS))

