# kofeng - build the SDK, the scanner, and the database toolchain.
#
# Three products and nothing else:
#
#   sdk         libkofeng.a plus the public headers, staged under build/release
#   kofscanner  the scanner, built against that SDK and nothing else
#   db          bases compiled and packed into .ksig
#
#
# WHERE THINGS LAND
#
#   build/release  the product. Everything shippable and nothing else, so
#                  packaging is a copy of one directory rather than a list of
#                  paths that has to be kept in step with this file.
#   build/temp     intermediates: object files, dependency files, compiled base
#                  artefacts. Disposable by definition - deleting it costs a
#                  rebuild and nothing else.
#   build/test     test binaries and their working directories, kept out of the
#                  product so a test artefact cannot be shipped by accident.
#
# One caveat about the name: SAN=1 builds into these same directories, so
# build/release then holds sanitizer binaries. The flag stamp below makes sure they
# are REBUILT rather than mixed, so nothing is ever half one and half the other -
# but the directory is named after what it is for, not after how it was compiled.
#
# Signature modules are NOT built with these flags: they are freestanding,
# position independent blobs produced by ksigbuilder with its own
# flag set, and mixing the two sets in one place is how they end up applied to the
# wrong target.

# The build is split by responsibility into mk/*.mk, included below IN THE
# ORDER THAT MATTERS: a variable has to be set by an earlier fragment than the
# first rule that names it in a prerequisite list (an unset one expands to
# nothing there, silently), so the order of this list is the dependency order
# and a fragment may use what the ones above it define.
#
#   platform  which make and which host, the compiler, the cross target
#   shell     the file operations a recipe may use, per shell
#   flags     warning flags, sanitizers, the build directories
#   entry     the tool entry targets, help, the directory rules
#   stamp     the flag stamp (every object depends on it)
#   libs      the engine and the three libs, and their archives
#   sdk       the public headers and the sdk target
#   sources   source lists shared by tools and tests (set before any rule)
#   tools     the host tools
#   grille    libkofgrille and the Windows-only tools
#   packs     the signature databases
#   tests     fixtures and unit tests
#   deps      dependency files and the source-move guards
#   asan      the sanitised twins of the tests
#   fuzz      the fuzz kit's binaries, make fuzz-smoke (needs asan's flags and NL)
#   misc      tui-test, population, debug, clean
#   checks    check-rules
#
# `all` is the first rule of the whole file and stays so: it is written here,
# after the fragments that set variables and before the ones that hold rules.

include mk/platform.mk
include mk/shell.mk
include mk/flags.mk

# check-rules first, so a rule a grep can see cannot reach a build - see
# CLAUDE.md. It is a grep over the tree and costs nothing beside the compile.
all: check-rules sdk tools databases

include mk/entry.mk
include mk/stamp.mk
include mk/libs.mk
include mk/sdk.mk
include mk/sources.mk
include mk/tools.mk
include mk/grille.mk
include mk/packs.mk
include mk/tests.mk
include mk/deps.mk
include mk/asan.mk
include mk/fuzz.mk
include mk/misc.mk
include mk/checks.mk
