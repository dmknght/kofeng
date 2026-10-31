# THE RULES THAT A GREP CAN CHECK - see CLAUDE.md for the ones it cannot.
#
# They are PROGRAMS (tools/check_rules.py, tools/check_layers.py) and not shell
# pipelines: grep, backticks and `if [ ]; fi` do not exist under cmd or PowerShell, and
# the Makefile's rule is that a recipe names a program and nothing of any shell's dialect.
#
# A written rule is a hope; this one is a build failure. getenv() kept coming
# back - as a trace switch, as a limit, as a path - and each time it put an
# environment lookup on a hot path and let a shipped binary be talked into
# behaving differently. kofmontrace is the one stated exception: it reproduces
# execvp's search and has to look where the exec will look.
#
.PHONY: check-rules
check-rules:
	@$(PYTHON) tools/check_rules.py
	@$(PYTHON) tools/check_layers.py
	@$(MAKE) --no-print-directory check-catalog
	@$(MAKE) --no-print-directory gate-test

# EVERY REFERENCE OF EVERY DIAGNOSE SOURCE against the two catalogs: a family, variant, type or tag
# that does not exist, a variant of another family, a type the variant does not declare, Packer,
# two diagnoses that collide. The builder's own mode, so the rule is one piece of code for this and
# for the pack (which runs it again); it needs the built ksigbuilder, hence its own target.
.PHONY: check-catalog
check-catalog: $(OUT)/bin/ksigbuilder$(EXE)
	@$(call EXEC,$(OUT)/bin/ksigbuilder$(EXE)) --catalog $(BASEDIR)/diagnoses \
	    --pathogens $(BASEDIR)/pathogens --syndromes $(BASEDIR)/syndromes
