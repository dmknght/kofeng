# THE RULES THAT A GREP CAN CHECK - see CLAUDE.md for the ones it cannot.
#
# A written rule is a hope; this one is a build failure. getenv() kept coming
# back - as a trace switch, as a limit, as a path - and each time it put an
# environment lookup on a hot path and let a shipped binary be talked into
# behaving differently. kofmontrace is the one stated exception: it reproduces
# execvp's search and has to look where the exec will look.
#
.PHONY: check-rules
check-rules:
	@bad=`grep -rn 'getenv *(' --include=*.c --include=*.h \
	        libkofeng libgenome libuncoat libkoforbit kofexamine kofscanner \
	        kofwatcher ksigbuilder 2>/dev/null \
	      | grep -v 'kofwatcher/kofmontrace' \
	      | grep -v '^[^:]*:[0-9]*: *\*'` ; \
	if [ -n "$$bad" ]; then \
	  echo 'getenv() is not allowed in the engine - see CLAUDE.md:' ; \
	  echo "$$bad" ; \
	  exit 1 ; \
	fi ; \
	echo 'check-rules: no getenv in the engine'
	@bad=`grep -L KOF_TARGET_CONTENT bases/unp/*.c bases/decomp/*.c bases/decoders/*.c` ; \
	if [ -n "$$bad" ]; then \
	  echo 'a module must declare what it takes out (KOF_TARGET_CONTENT) - see CLAUDE.md:' ; \
	  echo "$$bad" ; \
	  exit 1 ; \
	fi ; \
	echo 'check-rules: every unpack and unwrap module declares its content'
	@python3 tools/check_layers.py || exit 1
