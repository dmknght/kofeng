#!/usr/bin/env bash
#
# ksigcompiler.sh - compile one signature source into a loadable blob.
#
#   ./ksigbuilder/ksigcompiler.sh bases/signatures/mirai.c
#   KEEP=1 ./ksigbuilder/ksigcompiler.sh bases/signatures/mirai.c
#
# One half of the toolchain; ksigbuilder is the other. This compiles a source into
# an artefact, that packs artefacts into a database, and neither does the other's
# job. They live in the same directory because they are one toolchain, and apart
# from bases/ because that holds inputs, not tools.
#
# The declarations in the source are read by ksigbuilder --extract rather than by
# this script, because reading them is parsing and shell is not what parsing is
# written in.
#
# Shell rather than C, and not for lack of ambition: compiling a module means a
# specific set of freestanding flags, then ld, then nm and readelf and size to
# prove the result needs no relocation and carries no state. That is a wrapper
# around five tools. Written in C it would spawn the same five and be longer.
#
# It does three jobs, and none of them can be recovered from by a check at load
# time:
#
#   compile   freestanding, position independent, nothing from libc
#   validate  reject anything that would need relocation or carry state
#   emit      link to raw bytes, so the database stores code and nothing else
#
# Intermediates go to a temporary directory that is removed on exit, and only
# the packaged blob lands in the artefact directory. That is not tidiness: while developing
# this, a stray .elf sitting next to the .blob got handed to the loader, which
# happily copied an ELF header into executable memory and jumped to it. An
# artifact that cannot be picked up by accident is worth more than a note in a
# README telling people not to.

set -euo pipefail

src=${1:-}
if [ -z "$src" ] || [ ! -f "$src" ]; then
	echo "usage: $0 <signature.c>" >&2
	exit 2
fi

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/.." && pwd)
# Where the public headers live. Overridable so the script works against a
# checkout or against an installed SDK without changing anything in it.
incdir=${KOF_INCLUDE:-$root/build/release/include}

# The artefact name, taken from the path BELOW the content tree rather than from
# the file name alone.
#
# bases/decomp/gzip.c and bases/unp/gzip.c are both reasonable names for real
# modules - one opens the container, one would unpack something else about it -
# and with a bare basename the second silently overwrites the first's artefacts.
# ksigbuilder packs a directory, so the loser simply is not in the database and
# nothing reports it. Encoding the kind removes the collision and makes the
# artefact directory say where each blob came from.
name=$(basename "$src" .c)
# Where this source lives inside the bases tree, kept as well as flattened.
# The flattened form names the artefact; this one is the module's PROVENANCE and
# goes into the database, so a tool holding a scan result can open the file the
# module was written in without going looking for it. Empty when the source is
# outside the tree, which is a hand compile and has no tree relative name.
srcpath=""
if [ -n "${KOF_BASEDIR:-}" ]; then
	abs=$(cd -- "$(dirname -- "$src")" && pwd)/$(basename -- "$src")
	case "$abs" in
	"$KOF_BASEDIR"/*)
		rel=${abs#"$KOF_BASEDIR"/}
		name=$(printf '%s' "${rel%.c}" | tr '/' '_')
		srcpath=$rel
		;;
	esac
fi
# Where the artefacts land.
#
# Every driver sets this, and the default is deliberately a scratch directory that
# no packer reads. ksigbuilder packs a DIRECTORY rather than a list of files, so a
# shared default is a way for a signature compiled by hand to end up in the next
# release database without anyone choosing that. The Makefile derives one directory
# per signature set; a hand run gets its own.
outdir=${KOF_OUTDIR:-$root/build/temp/sig-scratch}
blob=$outdir/$name.blob
namefile=$outdir/$name.names
metafile=$outdir/$name.meta
# The declared strings. Beside the blob, not inside it: the host searches, so the
# literals are data and the blob carries only logic.
strfile=$outdir/$name.strs
mkdir -p "$outdir"

tmp=$(mktemp -d)
if [ "${KEEP:-0}" = "1" ]; then
	trap 'echo "   intermediates kept in $tmp"' EXIT
else
	trap 'rm -rf "$tmp"' EXIT
fi

# Which OS this blob is built for, decided once and used for every tool choice
# below - never mixed, because an ELF validator run over a COFF object or the
# reverse is not "no problems found", it is "wrong tool, so nothing was checked".
#
# Overridable rather than hardwired to uname: KOF_TARGET_OS is what lets a build
# host produce the other platform's blob on purpose, and it is what a future CI
# matrix sets instead of relying on where the runner happens to be.
case "${KOF_TARGET_OS:-$(uname -s)}" in
MINGW*|MSYS*|Windows*|windows) os=windows ;;
*)                              os=linux ;;
esac

# Which machine the blob's own code is for - a different axis from KOF_TARGET_OS
# above (the format the blob is linked as) and from a signature's own
# KOF_TARGET_ARCH(...) declaration (which CPU architecture of SCANNED OBJECT the
# module applies to - a question about the sample, not about the blob). Default
# x86_64 so every existing build (and every reference to this script that does
# not set the variable) keeps producing exactly what it always has.
case "${KOF_TARGET_MACH:-x86_64}" in
x86_64) mach=x86_64 ;;
arm64)  mach=arm64 ;;
*)
	echo "FAIL: KOF_TARGET_MACH=${KOF_TARGET_MACH} names no known machine (x86_64, arm64)" >&2
	exit 1
	;;
esac

obj=$tmp/$name.o
raw=$tmp/$name.raw

if [ "$os" = windows ]; then
	# clang is a cross compiler by construction - one binary already
	# targets x86_64-w64-windows-gnu regardless of which architecture the
	# host itself is, which matters here because the host is not
	# guaranteed to be x86_64. lld and llvm-objcopy/nm/readobj are the
	# same story: format-aware, not host-arch-aware, and ship together with
	# clang rather than as a separate binutils that would need its own
	# per-target build.
	CC=${CC:-clang}
	LD=${LD:-ld.lld}
	NM=${NM:-llvm-nm}
	OBJDUMP=${OBJDUMP:-llvm-objdump}
	OBJCOPY=${OBJCOPY:-llvm-objcopy}
	READOBJ=${READOBJ:-llvm-readobj}
	img=$tmp/$name.dll
else
	CC=${CC:-gcc}
	LD=${LD:-ld}
	NM=${NM:-nm}
	READOBJ=${READOBJ:-readelf}
	img=$tmp/$name.elf
fi
# The other half of the toolchain, in its --extract mode: it reads the declarations
# out of the source. Same binary that packs the artefacts, so the region names it
# accepts and the pack it later writes cannot disagree about anything.
#
# .exe on Windows, unconditionally: the Makefile links every host tool with that
# suffix there and never strips it, because PowerShell and cmd.exe both refuse to
# start a program with no recognised extension at all - so the default here has to
# name the file that is actually on disk, not the name Linux would have given it.
ksigbin=ksigbuilder
[ "$os" = windows ] && ksigbin=ksigbuilder.exe
ksigbuilder=${KOF_KSIGBUILDER:-$root/build/release/bin/$ksigbin}
if [ ! -x "$ksigbuilder" ]; then
	echo "ksigcompiler.sh: $ksigbuilder missing (run: make)" >&2
	exit 2
fi

# Each group here removes a specific way the object could stop being loadable
# by a plain copy:
#
#   freestanding/nostdlib  no hosted-environment assumptions, no libc symbols
#   fPIC                   self references become PC relative, so no absolute
#                          relocation and the blob runs at any address - ELF
#                          only, see below
#   no-unwind/no-ident/g0  strip the metadata that dwarfs the actual code
#   no-jump-tables         a switch would otherwise emit a table in .rodata
#                          referenced by absolute address
#   no-stack-protector     avoids an implicit __stack_chk_fail import
#   function/data-sections plus --gc-sections lets ld drop what is unreachable
#   cf-protection=none     drops .note.gnu.property - x86 only, see below
CFLAGS=(
	-std=c11 -Os
	-ffreestanding -fno-builtin -nostdlib
	-fno-asynchronous-unwind-tables -fno-unwind-tables
	-fno-ident -g0
	-fno-stack-protector
	-fno-jump-tables
	-ffunction-sections -fdata-sections
	-Wall -Wextra -Werror
	# The staged SDK, not the source tree. A module gets exactly the module
	# ABI and nothing else, so reaching for a host internal is a compile
	# error here rather than a habit that shows up in a signature later.
	"-I$incdir"
)
# CET shadow-stack/branch-tracking is an x86 feature; clang rejects this flag
# outright when targeting a non-x86 machine, so it is only ever offered where
# it means something.
if [ "$mach" = x86_64 ]; then
	CFLAGS+=(-fcf-protection=none)
fi
if [ "$os" = windows ]; then
	# Windows probes the stack one page at a time past a threshold, via a
	# call to __chkstk_ms - a real CRT symbol this freestanding blob has
	# none of. Raised well past anything a signature module's own locals
	# could plausibly need (verified: a real module with a 4KB local
	# buffer needs this - the tight instruction/size budget these modules
	# already run under means genuinely exceeding 1MB of stack in one
	# frame is not a real module, it is a different bug).
	CFLAGS+=(-mstack-probe-size=1000000)
	# No -fPIC: it is an ELF concept (GOT-indirect addressing) that this
	# target does not have a matching flag for. Every reference clang emits
	# for either Windows machine here is already PC/page relative by
	# default (RIP-relative on x86_64, ADRP+ADD on AArch64) - so the
	# zero-relocation property comes for free once the linker below is
	# told to lay .text and .rdata out as one contiguous region, the same
	# job module.ld does for the ELF side.
	# x86_64 verified against this exact flag set with clang 22.1.8: the
	# linked image carries an empty relocation table and an empty base
	# relocation directory. arm64 is new ground - not assumed equivalent
	# without the same check; see the "== validate image" step below,
	# which asserts it either way.
	case "$mach" in
	x86_64) CFLAGS+=(-target x86_64-w64-windows-gnu) ;;
	arm64)  CFLAGS+=(-target aarch64-w64-windows-gnu) ;;
	esac
else
	CFLAGS+=(-fPIC)
fi

# Target, and the two checks that keep it honest.
#
# The target has exactly one source: the KOF_TARGET_FORMAT declaration. Deriving it from
# the includes instead made a module that only searches bytes in ELF files carry
# an include it never used, which reads as dead code because that is what it was.
#
# Multiple KOF_TARGET_FORMAT lines are rejected rather than merged. Merging would work,
# but "head -1" was taking the first and silently dropping the rest, and a rule
# where a second declaration is either honoured or ignored depending on the
# implementation is worse than one that says use a single declaration with "|".
ndecl=$(grep -c 'KOF_TARGET_FORMAT(' "$src" || true)
if [ "$ndecl" -gt 1 ]; then
	echo "FAIL: $ndecl KOF_TARGET_FORMAT declarations; use one with '|'" >&2
	echo "      e.g. KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_PE);" >&2
	exit 1
fi
targets=$(sed -n 's/.*KOF_TARGET_FORMAT(\([^)]*\)).*/\1/p' "$src")
if [ -z "$targets" ]; then
	echo "FAIL: no KOF_TARGET_FORMAT(...) declaration" >&2
	echo "      a module must say what it applies to, e.g. KOF_TARGET_FORMAT(KOF_FMT_ELF);" >&2
	exit 1
fi

target_mask=0
ntargets=0
# KOF_FMT_ANY is every format. Spelled out rather than left implicit so that a
# module which really does apply to everything says so, and so that the count
# still trips the format-header check below.
#
# The mask is derived from the enum rather than written as a number. It WAS 127,
# which meant "every format" quietly stopped covering each format added after it -
# a module declaring ANY would have been ruled out for compound files and archives
# by the prefilter, and a detection that does not happen is not something a test
# notices.
fmt_count=$(sed -n 's/.*KOF_FMT_COUNT *= *\([0-9]*\).*/\1/p' \
	"$(dirname "$0")/../libkofeng/core/kofmod/kofsig.h")
[ -n "$fmt_count" ] || { echo "FAIL: cannot read KOF_FMT_COUNT" >&2; exit 1; }
case "$targets" in
*KOF_FMT_ANY*)
	target_mask=$(( (1 << fmt_count) - 1 ))
	ntargets=$fmt_count
	;;
esac
# Every other target is one bit, and WHICH bit comes from the enum rather than from
# a copy of it kept here.
#
# There was a copy here, a list of twelve names each with its bit written out as a
# number, and it was the same shape of mistake as the 127 above: a format added to
# the header and not to this list compiles to a mask of zero and the build stops -
# or worse, is added with the wrong number and every module targeting it is filtered
# against something else. Reading the header is what makes those two impossible.
if [ "$target_mask" -eq 0 ]; then
	for def in $(sed -n 's/^[\t ]*KOF_FMT_\([A-Z0-9_]*\) *= *\([0-9]*\).*/\1:\2/p' \
		"$(dirname "$0")/../libkofeng/core/kofmod/kofsig.h"); do
		t=${def%%:*}
		n=${def#*:}
		[ "$t" = COUNT ] && continue
		case "$targets" in
		*KOF_FMT_$t*)
			target_mask=$((target_mask | (1 << n)))
			ntargets=$((ntargets + 1))
			;;
		esac
	done
fi
if [ "$target_mask" -eq 0 ]; then
	echo "FAIL: KOF_TARGET_FORMAT($targets) names no known format" >&2
	exit 1
fi

# A module may include exactly one format header. The reason is kof_elf() and
# its siblings: they cast ctx->file_header, and the cast is sound only because
# the host never invokes a module for a format its target does not cover. A
# module that claims two formats has to branch correctly on every access, which
# is N places that can forget instead of one that can be tested. Cross-format
# detections are written as two modules and joined at the record layer, which
# also prefilters better than one module that runs on both.
#
# The header a module includes and the target bit it must therefore declare, in
# one list. It was three checks with the paths written out separately, and every
# one of them looked for <kofeng/...> while modules have always included
# <kofmod/...> - so nfmt was always zero, and NONE of the three rules below has
# ever fired. They were not weak checks, they were absent ones, which is the
# failure mode a check that cannot be seen to run always has. One list, so a
# format added here cannot be half-added.
fmt_hdrs="elf:2 pe:4 macho:8 gzip:64 docole:128 tar:1024 sevenzip:2048"
# zip.h is deliberately absent: it is the one header two formats share, because a
# zip and a zip that is a document differ in what is INSIDE them and not in how
# they are read. The one-header-one-format rule below would refuse a module that
# targets both, which is the ordinary case for an archive module.

nfmt=0
for pair in $fmt_hdrs; do
	hdr=${pair%:*}
	bit=${pair#*:}
	grep -qE "^[[:space:]]*#[[:space:]]*include[[:space:]]*<kofmod/$hdr\\.h>" "$src" \
		|| continue
	nfmt=$((nfmt + 1))
	if [ $((target_mask & bit)) -eq 0 ]; then
		echo "FAIL: includes kofmod/$hdr.h but does not target that format" >&2
		echo "      the view it gives is only sound for objects of that format" >&2
		exit 1
	fi
done
if [ "$nfmt" -gt 1 ]; then
	echo "FAIL: module includes $nfmt format headers; exactly one is allowed" >&2
	echo "      split it into one module per format" >&2
	exit 1
fi

# A format view means casting ctx->file_header, and that cast is sound only when
# the object is guaranteed to be that format. So a view requires a single matching
# target, while a module with no view may target several.
if [ "$nfmt" -eq 1 ] && [ "$ntargets" -gt 1 ]; then
	echo "FAIL: a format header with $ntargets targets is unsound" >&2
	echo "      kof_<fmt>() casts ctx->file_header; with more than one target" >&2
	echo "      there is no single view it can return" >&2
	exit 1
fi
echo "   target=$targets (mask $target_mask)"

# ---------------------------------------------------------- the subtype axis
#
# Which kinds of the declared format, in that format's own vocabulary. Absent
# means unconstrained, which is what every module written before this axis existed
# gets - so adding it changed no existing signature.
#
# The values of two formats deliberately collide: KOF_ELF_REL and KOF_PE_DLL are
# both 1, because the prefilter tests the format first and can only reach the
# subtype test for a format the module already declared. That is safe and it is
# also exactly the kind of thing that stops being safe the moment somebody names
# one format's values while targeting another - so that is refused here, where it
# is a build error with a filename rather than a signature that quietly matches
# the wrong things.
#
# What sort of unpacker this is: 0 container, 1 packer. See KOF_UNPACK_KIND in
# kofsig.h for why the difference is evidence rather than bookkeeping. Required
# of an unpack module and refused on a detector, because a detector that declares
# it has misunderstood what it is writing.
unp_kind=0

nkind=$(grep -c 'KOF_UNPACK_KIND(' "$src" || true)
if [ "$nkind" -gt 1 ]; then
	echo "FAIL: $nkind KOF_UNPACK_KIND declarations; a module is one kind" >&2
	exit 1
fi
if [ "$nkind" -eq 1 ]; then
	kindname=$(sed -n 's/.*KOF_UNPACK_KIND(\([^)]*\)).*/\1/p' "$src")
	case "$kindname" in
	*KOF_UNP_PACKER*)    unp_kind=1 ;;
	*KOF_UNP_CONTAINER*) unp_kind=0 ;;
	*)
		echo "FAIL: KOF_UNPACK_KIND($kindname) names no known kind" >&2
		exit 1
		;;
	esac
fi

# A heuristic rule's phase and its declared engine request. Zero on every other
# kind; the checks that make them required, and that refuse them where they do
# not belong, live beside the entry-point detection below - there and not here,
# because which kind this module is is not known until the object exists.
heur_phase=0
heur_want=0
heur_name=""
# The lowest --heur level the rule runs at. 0 here means UNSTATED, which the
# engine reads as level 1 - so a rule that declares nothing behaves as every
# rule did before the declaration existed.
heur_level=0
nlevel=$(grep -c 'KOF_HEUR_LEVEL(' "$src" || true)
if [ "$nlevel" -gt 1 ]; then
	echo "FAIL: $nlevel KOF_HEUR_LEVEL declarations; a rule has one level" >&2
	exit 1
fi
if [ "$nlevel" -eq 1 ]; then
	heur_level=$(sed -n 's/.*KOF_HEUR_LEVEL(\([^)]*\)).*/\1/p' "$src" | tr -d ' ')
	case "$heur_level" in
	1|2) ;;
	0)
		echo "FAIL: KOF_HEUR_LEVEL(0) - level 0 gathers nothing, so no" >&2
		echo "      rule can opt into it. Use 1 (the default) or 2." >&2
		exit 1 ;;
	*)
		echo "FAIL: KOF_HEUR_LEVEL($heur_level) is not a level; use 1 or 2" >&2
		exit 1 ;;
	esac
fi
nphase=$(grep -c 'KOF_HEUR_PHASE(' "$src" || true)
if [ "$nphase" -gt 1 ]; then
	echo "FAIL: $nphase KOF_HEUR_PHASE declarations; a rule runs at one point" >&2
	exit 1
fi
if [ "$nphase" -eq 1 ]; then
	phasename=$(sed -n 's/.*KOF_HEUR_PHASE(\([^)]*\)).*/\1/p' "$src")
	case "$phasename" in
	*KOF_HEUR_EXAMINE*) heur_phase=0 ;;
	*KOF_HEUR_VERDICT*) heur_phase=1 ;;
	*)
		echo "FAIL: KOF_HEUR_PHASE($phasename) names no known phase" >&2
		echo "      KOF_HEUR_EXAMINE - before the object is opened" >&2
		echo "      KOF_HEUR_VERDICT - after it has been" >&2
		exit 1 ;;
	esac
fi
for w in $(sed -n 's/.*KOF_HEUR_WANT(\([^)]*\)).*/\1/p' "$src" | tr '|' ' '); do
	case "$w" in
	*KOF_ENG_USE_EMU*) heur_want=$((heur_want | 1)) ;;
	*)
		echo "FAIL: KOF_HEUR_WANT($w) names nothing the engine offers" >&2
		exit 1 ;;
	esac
done
heur_name=$(sed -n 's/.*KOF_HEUR_NAME("\([^"]*\)").*/\1/p' "$src" | head -1)
# The predicted family, if the rule declares one. Optional - a rule may report a
# shape without guessing an identity.
heur_predict=$(sed -n 's/.*KOF_HEUR_PREDICT("\([^"]*\)").*/\1/p' "$src" | head -1)

subtype_mask=0        # 0 == any kind of the declared format

nsub=$(grep -c 'KOF_TARGET_SUBTYPE(' "$src" || true)
if [ "$nsub" -gt 1 ]; then
	echo "FAIL: $nsub KOF_TARGET_SUBTYPE declarations; use one with '|'" >&2
	exit 1
fi
if [ "$nsub" -eq 1 ]; then
	subnames=$(sed -n 's/.*KOF_TARGET_SUBTYPE(\([^)]*\)).*/\1/p' "$src")
	# Asked, not restated - see KOF_TARGET_ARCH above for what a shell-side
	# copy of a header's list cost last time. ksigbuilder answers with the
	# mask and with WHICH format's vocabulary was used, because the two
	# formats' subtype values collide on purpose; it also rejects a
	# declaration that mixes them.
	if ! sub=$("$ksigbuilder" --subtype-mask "$subnames"); then
		echo "FAIL: KOF_TARGET_SUBTYPE($subnames)" >&2
		exit 1
	fi
	subtype_mask=${sub% *}
	subfmt=${sub#* }
	# 2 is the ELF target bit, 4 the PE one - the same numbers the format loop
	# above assigns.
	if [ "$subfmt" = ELF ] && [ $((target_mask & 2)) -eq 0 ]; then
		echo "FAIL: names KOF_ELF_* subtypes but does not target ELF" >&2
		exit 1
	fi
	if [ "$subfmt" = PE ] && [ $((target_mask & 4)) -eq 0 ]; then
		echo "FAIL: names KOF_PE_* subtypes but does not target PE" >&2
		exit 1
	fi
	echo "   require subtype=$subnames (mask $subtype_mask)"
fi

# Patterns are compiled before the C is, so a malformed pattern fails with a file
# and line rather than becoming an array that matches nothing. The generated
# header is injected with -include so the source needs no generated include of
# its own and still reads correctly on its own.
# Declared preconditions. Same principle as the target: the host must be able to
# rule the module out without loading or running it, so the condition has to be
# readable from outside the blob. A check written only in the body is correct and
# useless for filtering, because reaching it costs exactly what filtering saves.
#
# Absent means unconstrained, which is the right default: a module that declares no
# size range applies at any size.
size_min=0            # 0 == no minimum
arch_mask=0           # 0 == any architecture

# Minimum object size. There is no maximum on purpose - see kofsig.h: an upper
# bound is bypassed by appending padding, so declaring one would let a sample have
# the module skipped rather than have it fail to match.
nsz=$(grep -c 'KOF_TARGET_SIZE_MIN(' "$src" || true)
if [ "$nsz" -gt 1 ]; then
	echo "FAIL: $nsz KOF_TARGET_SIZE_MIN declarations; a module has one minimum" >&2
	exit 1
fi
if [ "$nsz" -eq 1 ]; then
	szarg=$(sed -n 's/.*KOF_TARGET_SIZE_MIN(\([^)]*\)).*/\1/p' "$src")
	# Checked before it is ever handed to $((...)), not after: shell arithmetic
	# expansion recursively re-expands a bareword operand, which includes command
	# substitution - a source file spelling KOF_TARGET_SIZE_MIN(`cmd`) would run
	# cmd when this line evaluated szarg unchecked (backticks have no ')', so
	# they survive the sed capture above intact, unlike $(...) which the capture
	# already truncates at its first ')'). A signature is developer-authored, not
	# attacker-authored, but this file's own convention is to fail loudly on
	# anything that isn't the plain arithmetic expression it claims to be, and an
	# expression is not plain if it can run a command.
	case "$szarg" in
	*[![:space:]0-9+*/\(\)-]*)
		echo "FAIL: KOF_TARGET_SIZE_MIN($szarg) is not a plain arithmetic expression" >&2
		exit 1
		;;
	esac
	# Evaluated by the shell so an expression like 4 * 1024 reads naturally in the
	# source instead of being written out as a literal.
	size_min=$((szarg))
	if [ "$size_min" -lt 1 ]; then
		echo "FAIL: KOF_TARGET_SIZE_MIN($szarg) constrains nothing; omit it" >&2
		exit 1
	fi
	echo "   require size>=$size_min"

	# The declaration is what the host trusts, so the body must not carry a
	# second copy of the same lower bound. Two copies are two things that can
	# disagree, and the one the host cannot see is the one that wins silently.
	if grep -qE 'ctx->obj_size[[:space:]]*<' "$src"; then
		echo "FAIL: obj_size has a lower-bound test in the body and also a" >&2
		echo "      KOF_TARGET_SIZE_MIN declaration; the declaration is" >&2
		echo "      authoritative, so remove the check from kof_scan" >&2
		exit 1
	fi
fi

narch=$(grep -c 'KOF_TARGET_ARCH(' "$src" || true)
if [ "$narch" -gt 1 ]; then
	echo "FAIL: $narch KOF_TARGET_ARCH declarations; use one with '|'" >&2
	exit 1
fi
if [ "$narch" -eq 1 ]; then
	archnames=$(sed -n 's/.*KOF_TARGET_ARCH(\([^)]*\)).*/\1/p' "$src")
	# Asked, not restated.
	#
	# This used to hold its own ordered list of the architectures and match
	# them with a glob. KOF_ARCH_X86 is a PREFIX of KOF_ARCH_X86_64, so
	# naming the 64 bit one set both bits and every x86-64-only rule also ran
	# on x86 objects; ARM inside ARM64 was the same shape. The list had also
	# stopped three architectures short of kofsig.h, so naming one of those
	# failed the build. A shell cannot include the header, so it asks the
	# program that can.
	if ! arch_mask=$("$ksigbuilder" --arch-mask "$archnames"); then
		echo "FAIL: KOF_TARGET_ARCH($archnames)" >&2
		exit 1
	fi
	echo "   require arch=$archnames (mask $arch_mask)"
fi

# Patterns are compiled before the C is, so a malformed pattern fails with a file
# and line rather than becoming an array that matches nothing. The generated
# header is injected with -include so the source needs no generated include of
# its own and still reads correctly on its own.
#
# This step also derives the scan mask - the OR of every region the module
# searches - which is a precondition nobody had to declare, because it is read out
# of the searches themselves.
echo "== patterns"
pat=$tmp/$name.pat.h
pre=$tmp/$name.pre
"$ksigbuilder" --extract "$src" "$pat" "$namefile" "$pre" "$strfile"
scan_mask=$(sed -n 's/^scan_mask=//p' "$pre")
nstr=$(sed -n 's/^nstr=//p' "$pre")
family=$(sed -n 's/^family=//p' "$pre")
maltype=$(sed -n 's/^maltype=//p' "$pre")
: "${scan_mask:=0}"
: "${nstr:=0}"
: "${maltype:=0}"

if [ "$os" = windows ]; then
	# module.ld gives the ELF build one guarantee for free: the linker
	# script lists .text.kof_scan/.text.kof_unpack first, so whichever one
	# the source defines lands at offset 0 by construction. COFF has no
	# equivalent script; what it has instead is section grouping by name -
	# "name$suffix" sections sharing "name" are concatenated in ascending
	# suffix order. A digit sorts before every letter a C identifier can
	# start with, so re-declaring the two entry points into ".text$0" here
	# forces whichever one the source goes on to define into that same
	# leading slot, without the source ever seeing this file.
	#
	# Declared, not defined - the source still provides the only body, this
	# only adds an attribute to a symbol the source is about to redeclare.
	# kofsig.h's own declaration comes later in translation-unit order and
	# carries no section attribute of its own, which is fine: an attribute
	# from an earlier declaration of the same symbol still applies. Kept as
	# a forward reference to an incomplete struct, same as the real
	# prototype - the field layout is never used by name here.
	{
		echo 'struct kof_obj_ctx;'
		echo '__attribute__((section(".text$0"))) void kof_scan(const struct kof_obj_ctx *);'
		echo '__attribute__((section(".text$0"))) void kof_unpack(const struct kof_obj_ctx *);'
		echo '__attribute__((section(".text$0"))) void kof_heur(const struct kof_obj_ctx *);'
	} >> "$pat"
fi

#
# WHAT A RULE MAY NOT BE, checked in the source rather than hoped for.
#
# One function because the kind is worked out in two places - the COFF build
# reads the object, the ELF build reads the linked image - and a check that
# exists in one of them is a check that half the builds do not run.
#
#
# WHAT A DETECTOR AND AN UNPACKER MAY NOT BE.
#
# Functions rather than inline code because the entry-point dispatch exists
# TWICE - once for the PE image and once for the ELF one - and the two had
# already drifted: the Windows copy refused an unpack module with no
# KOF_UNPACK_KIND and a detector that declared one, the ELF copy refused
# neither. Since almost every build is the ELF one, both checks were
# effectively off, and bases/decomp/gzip.c shipped for that long without
# declaring its kind at all.
#
# Two copies of a refusal are one refusal and one hole.
#
detect_checks() {
	if [ "$nphase" -ne 0 ] || [ -n "$heur_name" ] ||
	   [ "$heur_want" -ne 0 ]; then
		echo "FAIL: heuristic declarations on a detector; a rule" >&2
		echo "      exports kof_heur and includes kofmod/heur.h" >&2
		exit 1
	fi
	if [ "$nkind" -ne 0 ]; then
		echo "FAIL: KOF_UNPACK_KIND on a detector; it describes an" >&2
		echo "      unpacker, and a detector declaring one has" >&2
		echo "      misunderstood what it is writing" >&2
		exit 1
	fi
}

unpack_checks() {
	# An unpacker that does not say what sort it is leaves the heuristic to
	# guess, and the guess is worth score. Refused rather than defaulted,
	# because the default that is usually right - container - is the one
	# that silently loses evidence on the modules where it is wrong.
	if [ "$nkind" -eq 0 ]; then
		echo "FAIL: an unpack module must declare KOF_UNPACK_KIND" >&2
		echo "      KOF_UNPACK_KIND(KOF_UNP_PACKER)    - it hid a program" >&2
		echo "      KOF_UNPACK_KIND(KOF_UNP_CONTAINER) - it carried files" >&2
		exit 1
	fi
}

heur_checks() {
	#
	# WHAT A RULE MAY NOT BE, checked in the source rather than
	# hoped for.
	#
	# heur.h includes kofsig.h, so the detector's macros are all
	# still in scope and every one of these WOULD compile. They are
	# refused because the difference between a heuristic and a
	# signature is not a matter of degree: a family name is a claim
	# about identity, and a rule that made one would be a signature
	# filed in the wrong place and reported in the wrong words.
	#
	if [ "$nphase" -eq 0 ]; then
		echo "FAIL: a heuristic rule must declare KOF_HEUR_PHASE" >&2
		echo "      KOF_HEUR_PHASE(KOF_HEUR_EXAMINE) - what it IS" >&2
		echo "      KOF_HEUR_PHASE(KOF_HEUR_VERDICT) - how it was reached" >&2
		exit 1
	fi
	if [ -z "$heur_name" ]; then
		echo "FAIL: a heuristic rule must declare KOF_HEUR_NAME(\"word\")" >&2
		exit 1
	fi
	if [ "$heur_want" -ne 0 ] && [ "$heur_phase" -ne 0 ]; then
		echo "FAIL: KOF_HEUR_WANT at KOF_HEUR_VERDICT; the object has" >&2
		echo "      already been opened by then, so there is nothing" >&2
		echo "      left to ask for" >&2
		exit 1
	fi
	if grep -qE 'KOF_SCAN_(INFECT|SUSPECT|MATCH)\(' "$src"; then
		echo "FAIL: a heuristic rule reports KOF_HEUR_HIT and nothing" >&2
		echo "      above it; naming a family is what a signature does" >&2
		exit 1
	fi
	if grep -q 'KOF_TARGET_NAME(' "$src"; then
		echo "FAIL: KOF_TARGET_NAME on a heuristic rule; it names a" >&2
		echo "      family, and a rule recognises a shape - use" >&2
		echo "      KOF_HEUR_NAME" >&2
		exit 1
	fi
	if grep -qE 'kof_(emit|child|child_window|gather)\(' "$src"; then
		echo "FAIL: a heuristic rule produces no child objects; that" >&2
		echo "      is an unpacker" >&2
		exit 1
	fi
	if [ "$nkind" -ne 0 ]; then
		echo "FAIL: KOF_UNPACK_KIND on a heuristic rule" >&2
		exit 1
	fi
}

echo "== compile"
"$CC" "${CFLAGS[@]}" -include "$pat" -c "$src" -o "$obj"

echo "== validate object"
if [ "$os" = windows ]; then
	# COFF has no single writable/non-writable section pair the way ELF's
	# .data/.bss read cleanly off size(1): .rdata is legitimately "DATA" by
	# objdump's own Type column and must not trip this, only a section that
	# is actually writable may. .data and .bss are emitted as empty stub
	# sections even when nothing uses them, so a name match plus a nonzero
	# size is the same "held no state" guarantee, read from the section
	# table instead of size(1)'s triad. Verified against a module carrying
	# a real global: it lands in .bss$<name> and this sum catches it.
	datasz=$("$OBJDUMP" -h "$obj" \
		| awk '$2 ~ /^\.(data|bss)/ {n += strtonum("0x" $3)} END {print n+0}')
	if [ "$datasz" != "0" ]; then
		echo "FAIL: module has writable data ($datasz byte(s) in .data/.bss)" >&2
		echo "      modules must hold no state; use locals or ask the host" >&2
		exit 1
	fi
	echo "   data+bss=$datasz"
else
	# A module with writable data is not reentrant, and .bss in particular would
	# occupy no file bytes yet be expected to exist at runtime. Check the object,
	# where the sections are still visible and attributable.
	# size(1) prints: text data bss dec hex filename
	read -r text data bss _ < <(size "$obj" | tail -1)
	if [ "$data" != "0" ] || [ "$bss" != "0" ]; then
		echo "FAIL: module has writable data (.data=$data .bss=$bss)" >&2
		echo "      modules must hold no state; use locals or ask the host" >&2
		exit 1
	fi
	echo "   text=$text data=$data bss=$bss"
fi

echo "== link"
if [ "$os" = windows ]; then
	# -dll -noentry: nothing here is ever loaded as a PE image, so the PE
	# header's own entry field is never read by anything - the host copies
	# raw bytes into its own arena and jumps in by offset, same as the ELF
	# side. -dll is only what -noentry requires lld-link to be paired with;
	# it changes a header bit nobody reads, not the code this emits.
	#
	# The three -merge flags are module.ld's job for this target: without
	# them .rdata lands in its own, separately page-aligned section, and
	# the RIP-relative loads clang emits to reach it are only correct at
	# THAT gap - dumping .text and .rdata apart and concatenating them
	# later would carry code whose data references point past the end of
	# what got copied. Merging first makes the linker resolve every
	# reference assuming byte-for-byte adjacency, so the single section
	# that remains is self-contained at any load address, not just the one
	# it was linked at.
	"$LD" -flavor link -dll -noentry -subsystem:native -nodefaultlib \
		-merge:.rdata=.text -merge:.data=.text -merge:.bss=.text \
		"$obj" -out:"$img"
else
	ld -T "$here/module.ld" --gc-sections "$obj" -o "$img"
fi

echo "== validate image"
if [ "$os" = windows ]; then
	if "$READOBJ" -r "$img" | grep -q "IMAGE_REL"; then
		echo "FAIL: relocations remain:" >&2
		"$READOBJ" -r "$img" >&2
		exit 1
	fi

	# Only .text should carry content once the merge above has run. Anything
	# else means the merge and the compiler flags have drifted apart.
	extra=$("$READOBJ" -S "$img" \
		| sed -n 's/^ *Name: \([^ ]*\).*/\1/p' \
		| grep -v '^\.text$' || true)
	if [ -n "$extra" ]; then
		echo "FAIL: unexpected sections in image: $extra" >&2
		exit 1
	fi
	echo "   no relocations, no unexpected sections"

	# lld strips the symbol table from the linked image by default, so by
	# the time $img exists there is no longer anything to ask which entry
	# point it carries or at what offset - unlike readelf/nm on the ELF
	# side, which read that off the linked file directly. The object still
	# has full symbol visibility, and it is enough: nothing here depends
	# on where the LINKER placed the entry section, only on what the
	# COMPILER named it, and that is already decided by the time $obj
	# exists.
	undef=$("$NM" -u "$obj" 2>/dev/null | grep -vE 'kof_scan|kof_unpack|kof_heur' || true)
	if [ -n "$undef" ]; then
		echo "FAIL: undefined symbols (module reached outside its blob):" >&2
		echo "$undef" >&2
		exit 1
	fi

	# The two entry points have different ABIs: a detector reports findings, an
	# unpacker yields a child object. So a module cannot be written for one and
	# picked up as the other by mistake - it would not compile. Exactly one must
	# be present. A symbol that is only declared and never referenced (the other
	# of the pair) carries no entry in the object's symbol table at all, defined
	# or undefined, so this needs no extra filtering.
	scan_row=$("$NM" "$obj" | awk '$2 == "T" && $3 == "kof_scan" {print $1}')
	unp_row=$("$NM" "$obj" | awk '$2 == "T" && $3 == "kof_unpack" {print $1}')
	heur_row=$("$NM" "$obj" | awk '$2 == "T" && $3 == "kof_heur" {print $1}')
	nentry=0
	[ -n "$scan_row" ] && nentry=$((nentry + 1))
	[ -n "$unp_row" ]  && nentry=$((nentry + 1))
	[ -n "$heur_row" ] && nentry=$((nentry + 1))
	if [ "$nentry" -gt 1 ]; then
		echo "FAIL: exports more than one of kof_scan, kof_unpack," >&2
		echo "      kof_heur; the three ABIs differ and a module is" >&2
		echo "      one kind" >&2
		exit 1
	fi
	if [ -n "$heur_row" ]; then
		entry_hex=$heur_row; kind=2; kindname=heur
		heur_checks
	elif [ -n "$scan_row" ]; then
		entry_hex=$scan_row; kind=0; kindname=detect
		detect_checks
	elif [ -n "$unp_row" ]; then
		entry_hex=$unp_row;  kind=1; kindname=unpack
		unpack_checks
	else
		echo "FAIL: no kof_scan, kof_unpack or kof_heur symbol; a module" >&2
		echo "      must export exactly one" >&2
		exit 1
	fi
	entry=$((16#$entry_hex))

	# Zero by construction - see the .text$0 forcing above - and asserted
	# rather than assumed for the same reason the ELF side asserts it: the
	# guarantee lives in two places (the injected declaration here, the
	# compiler's own section-per-symbol behaviour) and either one drifting
	# should fail the build, not ship a blob nothing verified.
	if [ "$entry" -ne 0 ]; then
		echo "FAIL: the entry point is at section offset 0x$entry_hex, expected 0" >&2
		echo "      check the .text\$0 forcing near the '== patterns' step" >&2
		exit 1
	fi
else
	if readelf -r "$img" | grep -q "^Relocation section"; then
		echo "FAIL: relocations remain:" >&2
		readelf -r "$img" >&2
		exit 1
	fi

	undef=$(nm -u "$img" 2>/dev/null || true)
	if [ -n "$undef" ]; then
		echo "FAIL: undefined symbols (module reached outside its blob):" >&2
		echo "$undef" >&2
		exit 1
	fi

	# Only .blob should carry content. Anything else means the linker script and
	# the compiler flags have drifted apart.
	#
	# The name is pulled with sed rather than by field number: readelf writes the
	# index as "[ 1]" or "[10]", so the column the name lands in shifts once there
	# are ten sections.
	extra=$(readelf -S "$img" \
		| sed -n 's/^ *\[ *[0-9][0-9]*\] \([^ ][^ ]*\).*/\1/p' \
		| grep -vE '^(\.blob|\.symtab|\.strtab|\.shstrtab)$' || true)
	if [ -n "$extra" ]; then
		echo "FAIL: unexpected sections in image: $extra" >&2
		exit 1
	fi
	echo "   no relocations, no undefined symbols, no unexpected sections"

	# Entry offset is zero by construction, but assert it rather than assume: the
	# loader is told where to enter, and a linker script edit could move it.
	# The kind of module this is comes from which entry point it exports, and is
	# recorded rather than declared. A KOF_KIND(...) in the source would be a second
	# statement of a fact the code already makes - and the copy the host cannot see is
	# the one that wins silently, which is the same reason a body check duplicating
	# KOF_TARGET_SIZE_MIN is rejected above.
	#
	# The two entry points have different ABIs: a detector reports findings, an
	# unpacker yields a child object. So a module cannot be written for one and picked
	# up as the other by mistake - it would not compile. Exactly one must be present.
	scan_hex=$(nm "$img" | awk '$3 == "kof_scan" {print $1}')
	unp_hex=$(nm "$img" | awk '$3 == "kof_unpack" {print $1}')
	heur_hex=$(nm "$img" | awk '$3 == "kof_heur" {print $1}')
	nentry=0
	[ -n "$scan_hex" ] && nentry=$((nentry + 1))
	[ -n "$unp_hex" ]  && nentry=$((nentry + 1))
	[ -n "$heur_hex" ] && nentry=$((nentry + 1))
	if [ "$nentry" -gt 1 ]; then
		echo "FAIL: exports more than one of kof_scan, kof_unpack," >&2
		echo "      kof_heur; the three ABIs differ and a module is" >&2
		echo "      one kind" >&2
		exit 1
	fi
	if [ -n "$heur_hex" ]; then
		entry_hex=$heur_hex; kind=2; kindname=heur
		heur_checks
	elif [ -n "$scan_hex" ]; then
		entry_hex=$scan_hex; kind=0; kindname=detect
		detect_checks
	elif [ -n "$unp_hex" ]; then
		entry_hex=$unp_hex;  kind=1; kindname=unpack
		unpack_checks
	else
		echo "FAIL: no kof_scan, kof_unpack or kof_heur symbol; a module" >&2
		echo "      must export exactly one" >&2
		exit 1
	fi
	entry=$((16#$entry_hex))

	if [ "$entry" -ne 0 ]; then
		echo "FAIL: entry point is at 0x$entry_hex, expected 0" >&2
		echo "      the loader enters at offset 0; check module.ld" >&2
		exit 1
	fi
fi

echo "== emit"
if [ "$os" = windows ]; then
	"$OBJCOPY" --dump-section .text="$raw" "$img" /dev/null
else
	ld -T "$here/module.ld" --gc-sections --oformat binary "$obj" -o "$raw"
fi
cp "$raw" "$blob"

# The record the host filters on. Everything here is evaluable against facts the
# collector already produced, so a module can be ruled out for an object without
# the blob being read, let alone entered.
#
# It is also the only evidence that the blob beside it is a blob. The loader enters
# raw code at offset 0 and cannot tell a module from any other file, so it refuses a
# blob that has no record here - which is why this file is written for every blob
# and why blob_len is in it: a half written or truncated blob still has an intact
# record, and the length is what catches that.
{
	# %s, not %d: the unbounded marker is 2^64-1, which the shell's printf cannot
	# represent as a signed integer. These values are already decimal text and the
	# host parses them with strtoull, so passing them through unconverted is both
	# correct and the only thing that works.
	printf 'target=%s\n'    "$target_mask"
	printf 'scan_mask=%s\n' "$scan_mask"
	printf 'size_min=%s\n'  "$size_min"
	printf 'arch_mask=%s\n' "$arch_mask"
	printf 'subtype_mask=%s\n' "$subtype_mask"
	printf 'unp_kind=%s\n' "$unp_kind"
	printf 'heur_phase=%s\n' "$heur_phase"
	printf 'heur_want=%s\n'  "$heur_want"
	printf 'heur_level=%s\n' "$heur_level"
	# A rule's predicted family, if it declared one. Empty on every other kind.
	printf 'heur_predict=%s\n' "$heur_predict"
	# What KOF_TARGET_NAME declared - empty/0 for an unpack-kind module, where
	# it is not required. ksigbuilder's --extract already validated these; this
	# is a straight copy through .pre, same as scan_mask above.
	# A heuristic rule has no family; its word goes in the same slot, and the
	# engine writes "Heur" where a maltype would be. See finding_str.
	if [ "$kind" -eq 2 ]; then
		family=$heur_name
		maltype=0
	fi
	printf 'family=%s\n'    "$family"
	printf 'maltype=%s\n'   "$maltype"
	printf 'nstr=%s\n'      "$nstr"
	printf 'blob_len=%s\n'  "$(stat -c%s "$blob")"
	# Derived from the exported entry point, never authored - see above.
	printf 'kind=%s\n'      "$kind"
	# What this module is called, as opposed to where its artefacts live.
	#
	# The artefact name above carries the directory in front of it so that two
	# sources with the same basename cannot overwrite each other's blobs. That
	# prefix is disambiguation and not identity: "unp_upx_elf" is the UPX ELF
	# unpacker, and the "unp_" says only which tree it was found in. ksigbuilder
	# names a pack after what is inside it, so it needs the identity - and the
	# basename is known here and nowhere else, because the flattening above has
	# already destroyed the boundary by the time the .meta is read.
	printf 'label=%s\n'     "$(basename "$src" .c)"
	printf 'srcpath=%s\n'   "$srcpath"
} > "$metafile"

printf '== ok  %s  %s bytes  kind=%s  names=%s  strs=%s  target=%d scan=0x%x\n' \
	"$blob" "$(stat -c%s "$blob")" "$kindname" "$(wc -l <"$namefile")" \
	"$nstr" "$target_mask" "$scan_mask"
