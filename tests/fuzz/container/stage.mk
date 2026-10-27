# Stage "container" (WP2): the container parsers (zip rar 7z tar lha arj cab chm docole pdf gzip bz2 xz rtf lnk reg) and the
# engine's walk over them. Linked against the sanitised engine archive. The walk adapter opens the release database
# (build/release/databases) once per child, so the run targets of this stage need `make databases` first.
FZ_LIB_container  := engine
FZ_LIBS_container :=

run-fuzz-smoke-container run-fuzz-container: | databases
