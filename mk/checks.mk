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
