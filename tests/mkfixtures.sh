#!/bin/sh
#
# mkfixtures.sh - build the binaries the collectors are tested against.
#
# Compiled here rather than committed as blobs. Binary test data in a source tree
# is opaque - nobody can see what makes a fixture interesting, nobody can change
# one without a toolchain anyway, and the reason it exists lives in a comment
# somewhere else if it is written down at all. The sources beside this script say
# what each file is FOR, and the object is whatever the local toolchain makes of
# them.
#
# It also removes a failure this tree has already had: deleting the checked-in PE
# corpus took PE coverage to zero, and nothing failed, because the tests report an
# empty corpus honestly and an empty corpus passes.
#
# WHAT IT WILL AND WILL NOT BUILD
#
# Each toolchain is probed and skipped when absent, and what was skipped is printed
# rather than passed over: a fixture directory with no PE in it must not look like
# a fixture directory that was fully built. Nothing here fails the build - a
# developer without mingw still gets ELF coverage - but the tests that consume this
# report what they actually exercised, so the gap stays visible where it matters.
#
#   ELF64   cc                          nearly always present
#   ELF32   cc -m32                     needs 32 bit runtime libraries
#   PE64    x86_64-w64-mingw32-gcc      needs mingw-w64
#   PE32    i686-w64-mingw32-gcc        needs mingw-w64
#
# The container fixtures are made the same way and for the same reason. PDF and RTF
# are written out directly because both are text and a hand written one says what it
# contains; the archives are made by the tool that owns the format, so what the
# collectors are read against is what a real writer produces and not this script's
# idea of it.
#
#   pdf     written here                always
#   rtf     written here                always
#   tar     tar                         nearly always present
#   gz      gzip                        nearly always present
#   xz      xz
#   zip     zip
#   7z      7z / 7za
#   rar     rar                         rarely installed
#
# usage: tests/mkfixtures.sh <output-dir>

set -eu

out=${1:-build/test/fixtures}
here=$(cd -- "$(dirname -- "$0")" && pwd)
src=$here/fixtures

mkdir -p "$out"
rm -f "$out"/*.bin "$out"/*.exe "$out"/*.so "$out"/*.dll "$out"/*.ovl \
      "$out"/*.pdf "$out"/*.rtf "$out"/*.tar "$out"/*.gz "$out"/*.xz \
      "$out"/*.zip "$out"/*.7z "$out"/*.rar 2>/dev/null || true

built=0
skipped=""

# Does this compiler exist and can it actually link? Presence on PATH is not
# enough: cc -m32 is present on every machine and links on few of them, and a
# fixture directory holding a half-linked object is worse than one holding nothing.
can_build() {
	_cc=$1
	shift
	command -v "$_cc" >/dev/null 2>&1 || return 1
	printf 'int main(void){return 0;}\n' > "$out/.probe.c"
	if "$_cc" "$@" "$out/.probe.c" -o "$out/.probe.out" >/dev/null 2>&1; then
		rm -f "$out/.probe.c" "$out/.probe.out"
		return 0
	fi
	rm -f "$out/.probe.c" "$out/.probe.out"
	return 1
}

build_set() {
	_cc=$1 _tag=$2 _exe=$3 _lib=$4 _flags=$5

	# shellcheck disable=SC2086
	"$_cc" $_flags "$src/plain.c"    -o "$out/plain-$_tag$_exe"
	# shellcheck disable=SC2086
	"$_cc" $_flags "$src/sections.c" -o "$out/sections-$_tag$_exe"
	# shellcheck disable=SC2086
	"$_cc" $_flags -shared -fPIC "$src/shared.c" -o "$out/shared-$_tag$_lib"
	built=$((built + 3))

	# An overlay: bytes past everything any structure in the file claims.
	#
	# The one region that cannot be produced by a compiler, and the one an
	# unpacker acts on - installers, droppers and self-extractors all put their
	# payload here. Appending it is how the region gets exercised at all.
	cp "$out/plain-$_tag$_exe" "$out/overlay-$_tag$_exe"
	printf 'kofeng-fixture-overlay' >> "$out/overlay-$_tag$_exe"
	dd if=/dev/urandom bs=1024 count=4 >> "$out/overlay-$_tag$_exe" 2>/dev/null
	built=$((built + 1))
}

if can_build "${CC:-cc}"; then
	build_set "${CC:-cc}" elf64 "" ".so" ""
else
	skipped="$skipped ELF64"
fi

if can_build "${CC:-cc}" -m32; then
	build_set "${CC:-cc}" elf32 "" ".so" "-m32"
else
	skipped="$skipped ELF32(no-32bit-runtime)"
fi

if can_build x86_64-w64-mingw32-gcc; then
	build_set x86_64-w64-mingw32-gcc pe64 ".exe" ".dll" ""
else
	skipped="$skipped PE64(no-mingw-w64)"
fi

if can_build i686-w64-mingw32-gcc; then
	build_set i686-w64-mingw32-gcc pe32 ".exe" ".dll" ""
else
	skipped="$skipped PE32(no-mingw-w64)"
fi

# ---- containers ---------------------------------------------------------------
#
# The payload every archive holds: an ELF if one was built, so an archive fixture
# also exercises the path where a child object is a format in its own right.
payload=$out/plain-elf64
[ -f "$payload" ] || payload=$here/fixtures/plain.c

# A PDF with the two halves a scan treats differently - a dictionary in the clear
# that declares an action, and a stream that is opaque until a filter is undone.
{
	printf '%%PDF-1.7\n'
	printf '1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n'
	printf '2 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\)) >>\nendobj\n'
	printf '3 0 obj\n<< /Length 26 /Filter /FlateDecode >>\nstream\n'
	printf 'kofeng-fixture-stream-data\nendstream\nendobj\n'
	printf 'xref\n0 4\ntrailer\n<< /Size 4 /Root 1 0 R >>\n'
	printf 'startxref\n9\n%%%%EOF\n'
} > "$out/sample.pdf"
built=$((built + 1))

# An RTF with an embedded object in hex, which is the shape the format is abused
# through: \objupdate opens it without a click and \objdata carries the payload.
{
	printf '{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}\n'
	printf '{\\object\\objemb\\objupdate{\\*\\objclass Package}\n'
	printf '{\\*\\objdata 0105000002000000060000006b6f66656e670000}}\n'
	printf '{\\pict\\wmetafile8\\bin8 kofeng!}\\par done}\n'
} > "$out/sample.rtf"
built=$((built + 1))

arc() {
	_tool=$1 _name=$2
	shift 2
	command -v "$_tool" >/dev/null 2>&1 || { skipped="$skipped $_name"; return 0; }
	if "$@" >/dev/null 2>&1; then
		built=$((built + 1))
	else
		skipped="$skipped $_name(failed)"
	fi
}

arc tar  tar  tar -cf "$out/sample.tar" -C "$(dirname "$payload")" "$(basename "$payload")"
if [ -f "$out/sample.tar" ]; then
	arc gzip gz  sh -c "gzip  -kf '$out/sample.tar' && mv '$out/sample.tar.gz' '$out/sample.gz'"
	arc xz   xz  sh -c "xz    -kf '$out/sample.tar' && mv '$out/sample.tar.xz' '$out/sample.xz'"
fi
arc zip  zip  zip -qj "$out/sample.zip" "$payload"
if command -v 7z >/dev/null 2>&1; then
	arc 7z  7z  7z a -bso0 -bsp0 "$out/sample.7z" "$payload"
else
	arc 7za 7z  7za a -bso0 -bsp0 "$out/sample.7z" "$payload"
fi
arc rar  rar  rar a -inul "$out/sample.rar" "$payload"

printf 'fixtures: %d file(s) in %s' "$built" "$out"
if [ -n "$skipped" ]; then
	printf '   NOT BUILT:%s' "$skipped"
fi
printf '\n'

# Not an error. A tree with no toolchain for a format still builds and still tests
# the formats it can; what must not happen is the absence going unmentioned.
exit 0
