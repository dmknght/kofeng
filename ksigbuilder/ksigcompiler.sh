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
if [ -n "${KOF_BASEDIR:-}" ]; then
	abs=$(cd -- "$(dirname -- "$src")" && pwd)/$(basename -- "$src")
	case "$abs" in
	"$KOF_BASEDIR"/*)
		rel=${abs#"$KOF_BASEDIR"/}
		name=$(printf '%s' "${rel%.c}" | tr '/' '_')
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

obj=$tmp/$name.o
elf=$tmp/$name.elf
raw=$tmp/$name.raw

CC=${CC:-gcc}
# The other half of the toolchain, in its --extract mode: it reads the declarations
# out of the source. Same binary that packs the artefacts, so the region names it
# accepts and the pack it later writes cannot disagree about anything.
ksigbuilder=${KOF_KSIGBUILDER:-$root/build/release/bin/ksigbuilder}
if [ ! -x "$ksigbuilder" ]; then
	echo "ksigcompiler.sh: $ksigbuilder missing (run: make)" >&2
	exit 2
fi

# Each group here removes a specific way the object could stop being loadable
# by a plain copy:
#
#   freestanding/nostdlib  no hosted-environment assumptions, no libc symbols
#   fPIC                   self references become PC relative, so no absolute
#                          relocation and the blob runs at any address
#   no-unwind/no-ident/g0  strip the metadata that dwarfs the actual code
#   no-jump-tables         a switch would otherwise emit a table in .rodata
#                          referenced by absolute address
#   no-stack-protector     avoids an implicit __stack_chk_fail import
#   function/data-sections plus --gc-sections lets ld drop what is unreachable
#   cf-protection=none     drops .note.gnu.property
CFLAGS=(
	-std=c11 -Os
	-fPIC
	-ffreestanding -fno-builtin -nostdlib
	-fno-asynchronous-unwind-tables -fno-unwind-tables
	-fno-ident -g0
	-fno-stack-protector
	-fno-jump-tables
	-fcf-protection=none
	-ffunction-sections -fdata-sections
	-Wall -Wextra -Werror
	# The staged SDK, not the source tree. A module gets exactly the module
	# ABI and nothing else, so reaching for a host internal is a compile
	# error here rather than a habit that shows up in a signature later.
	"-I$incdir"
)

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
[ "$target_mask" -eq 0 ] && for t in UNKNOWN ELF PE MACHO SCRIPT TEXT GZIP DOCOLE ZIP DOCZIP; do
	case "$targets" in
	*KOF_FMT_$t*)
		case $t in
		UNKNOWN) bit=1  ;;
		ELF)     bit=2  ;;
		PE)      bit=4  ;;
		MACHO)   bit=8  ;;
		SCRIPT)  bit=16 ;;
		TEXT)    bit=32 ;;
		GZIP)    bit=64 ;;
		DOCOLE)  bit=128 ;;
		ZIP)     bit=256 ;;
		DOCZIP)  bit=512 ;;
		esac
		target_mask=$((target_mask | bit))
		ntargets=$((ntargets + 1))
		;;
	esac
done
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
fmt_hdrs="elf:2 pe:4 macho:8 gzip:64 docole:128"
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
subtype_mask=0        # 0 == any kind of the declared format

nsub=$(grep -c 'KOF_TARGET_SUBTYPE(' "$src" || true)
if [ "$nsub" -gt 1 ]; then
	echo "FAIL: $nsub KOF_TARGET_SUBTYPE declarations; use one with '|'" >&2
	exit 1
fi
if [ "$nsub" -eq 1 ]; then
	subnames=$(sed -n 's/.*KOF_TARGET_SUBTYPE(\([^)]*\)).*/\1/p' "$src")
	saw_elf=0
	saw_pe=0
	for pair in NONE:0 REL:1 EXEC:2 DYN:3 CORE:4; do
		nm=${pair%:*}
		bit=${pair#*:}
		case "$subnames" in
		*KOF_ELF_$nm*)
			subtype_mask=$((subtype_mask | (1 << bit)))
			saw_elf=1
			;;
		esac
	done
	for pair in EXE:0 DLL:1 SYS:2; do
		nm=${pair%:*}
		bit=${pair#*:}
		case "$subnames" in
		*KOF_PE_$nm*)
			subtype_mask=$((subtype_mask | (1 << bit)))
			saw_pe=1
			;;
		esac
	done
	if [ "$subtype_mask" -eq 0 ]; then
		echo "FAIL: KOF_TARGET_SUBTYPE($subnames) names no known subtype" >&2
		exit 1
	fi
	if [ "$saw_elf" -eq 1 ] && [ "$saw_pe" -eq 1 ]; then
		echo "FAIL: KOF_TARGET_SUBTYPE mixes ELF and PE subtypes" >&2
		echo "      their values collide on purpose and mean different" >&2
		echo "      things; a module applies to one format's kinds" >&2
		exit 1
	fi
	# 2 is the ELF target bit, 4 the PE one - the same numbers the format loop
	# above assigns.
	if [ "$saw_elf" -eq 1 ] && [ $((target_mask & 2)) -eq 0 ]; then
		echo "FAIL: names KOF_ELF_* subtypes but does not target ELF" >&2
		exit 1
	fi
	if [ "$saw_pe" -eq 1 ] && [ $((target_mask & 4)) -eq 0 ]; then
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
	i=0
	for a in ANY X86 X86_64 ARM ARM64 RISCV64 MIPS PPC64; do
		case "$archnames" in
		*KOF_ARCH_$a*) arch_mask=$((arch_mask | (1 << i))) ;;
		esac
		i=$((i + 1))
	done
	if [ "$arch_mask" -eq 0 ]; then
		echo "FAIL: KOF_TARGET_ARCH($archnames) names no known architecture" >&2
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
: "${scan_mask:=0}"
: "${nstr:=0}"

echo "== compile"
"$CC" "${CFLAGS[@]}" -include "$pat" -c "$src" -o "$obj"

echo "== validate object"
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

echo "== link"
ld -T "$here/module.ld" --gc-sections "$obj" -o "$elf"

echo "== validate image"
if readelf -r "$elf" | grep -q "^Relocation section"; then
	echo "FAIL: relocations remain:" >&2
	readelf -r "$elf" >&2
	exit 1
fi

undef=$(nm -u "$elf" 2>/dev/null || true)
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
extra=$(readelf -S "$elf" \
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
scan_hex=$(nm "$elf" | awk '$3 == "kof_scan" {print $1}')
unp_hex=$(nm "$elf" | awk '$3 == "kof_unpack" {print $1}')
if [ -n "$scan_hex" ] && [ -n "$unp_hex" ]; then
	echo "FAIL: exports both kof_scan and kof_unpack; a module is one kind" >&2
	exit 1
fi
if [ -n "$scan_hex" ]; then
	entry_hex=$scan_hex; kind=0; kindname=detect
elif [ -n "$unp_hex" ]; then
	entry_hex=$unp_hex;  kind=1; kindname=unpack
else
	echo "FAIL: no kof_scan or kof_unpack symbol; a module must export one" >&2
	exit 1
fi
entry=$((16#$entry_hex))

if [ "$entry" -ne 0 ]; then
	echo "FAIL: entry point is at 0x$entry_hex, expected 0" >&2
	echo "      the loader enters at offset 0; check module.ld" >&2
	exit 1
fi

echo "== emit"
ld -T "$here/module.ld" --gc-sections --oformat binary "$obj" -o "$raw"
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
	printf 'nstr=%s\n'      "$nstr"
	printf 'blob_len=%s\n'  "$(stat -c%s "$blob")"
	# Derived from the exported entry point, never authored - see above.
	printf 'kind=%s\n'      "$kind"
} > "$metafile"

printf '== ok  %s  %s bytes  kind=%s  names=%s  strs=%s  target=%d scan=0x%x\n' \
	"$blob" "$(stat -c%s "$blob")" "$kindname" "$(wc -l <"$namefile")" \
	"$nstr" "$target_mask" "$scan_mask"
