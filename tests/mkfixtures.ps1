#
# mkfixtures.ps1 - the Windows half of tests/mkfixtures.sh.
#
# Same contract, same output line, same promise: build every fixture this host
# can, name every one it cannot, and never fail the build. Read that script
# first - it is where WHY each fixture exists is written, and none of it is
# repeated here.
#
# WHY A SECOND SCRIPT RATHER THAN ONE THAT RUNS ANYWHERE
#
# Because it was already two scripts and only one of them was written down. The
# Makefile now drives PowerShell on Windows so the build needs no POSIX
# toolchain, and PowerShell handed `tests/mkfixtures.sh` to Windows's file
# association for .sh: nothing ran, nothing was built, and the recipe reported
# success. That is the exact failure this fixture set exists to prevent - the
# .sh header records PE coverage silently reaching zero once already - and it
# is worse from a shell that cannot fail, so the Windows path is a program
# Windows can actually execute.
#
# What differs is only what the host can produce, and each difference is
# reported rather than assumed:
#
#   PE      clang, per target triple    the compiler is a cross compiler
#   ELF     needs a Linux sysroot       normally absent here, so normally skipped
#   tar     tar.exe                     ships in Windows 10+ (bsdtar)
#   gz      .NET GZipStream             always
#   zip     .NET ZipFile                always
#   xz/7z/rar                           only if the tool is installed
#
# usage: powershell -File tests/mkfixtures.ps1 <output-dir>

param([string]$Out = "build/test/fixtures")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $here "fixtures"

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path

foreach ($pat in '*.bin','*.exe','*.so','*.dll','*.ovl','*.pdf','*.rtf',
                 '*.tar','*.gz','*.xz','*.zip','*.7z','*.rar') {
    Get-ChildItem -Path $Out -Filter $pat -ErrorAction SilentlyContinue |
        Remove-Item -Force
}

$built   = 0
$skipped = @()

# Write bytes, not text: Set-Content and Out-File both bring an encoding and a
# newline convention with them, and a fixture is a byte sequence. LF throughout,
# so the PDF and RTF written here are byte-identical to the ones the .sh writes.
function Write-Ascii([string]$Path, [string]$Text) {
    $lf = $Text -replace "`r`n", "`n"
    [System.IO.File]::WriteAllBytes($Path,
        [System.Text.Encoding]::ASCII.GetBytes($lf))
}

# Run the compiler and report its exit code, and nothing else.
#
# Every compiler call here has to go through this, because of what Windows
# PowerShell 5.1 does to a native program whose stderr is redirected: each line
# comes back as an ErrorRecord, and under $ErrorActionPreference = 'Stop' that
# is a terminating error even when the program exited 0. The build died on the
# -shared probe below - a probe whose whole point is that it is allowed to fail.
# So the preference is lifted for the duration of the call and the exit code is
# read directly, which is the only thing a compiler's success was ever in.
function Invoke-Cc([string]$Cc, [string[]]$Argv, [switch]$Quiet) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Quiet) {
            & $Cc @Argv 2>&1 | Out-Null
        } else {
            & $Cc @Argv 2>&1 | ForEach-Object { Write-Host $_ }
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
}

# The .sh's can_build, and for its reason: a compiler that is on PATH is not a
# compiler that can link. Here the usual reason is a missing sysroot rather than
# a missing 32 bit runtime, and it is the same question - so it is asked the same
# way, by building something and seeing.
function Test-Toolchain([string]$Cc, [string[]]$Flags) {
    if (-not (Get-Command $Cc -ErrorAction SilentlyContinue)) { return $false }
    $probeC   = Join-Path $Out ".probe.c"
    $probeOut = Join-Path $Out ".probe.out"
    Write-Ascii $probeC "int main(void){return 0;}`n"
    $ok = (Invoke-Cc $Cc ($Flags + @($probeC, "-o", $probeOut)) -Quiet) -eq 0
    Remove-Item -Force -ErrorAction SilentlyContinue $probeC, $probeOut
    return $ok
}

function Build-Set([string]$Cc, [string[]]$Flags, [string]$Tag,
                   [string]$ExeExt, [string]$LibExt) {
    foreach ($unit in "plain", "sections") {
        $rc = Invoke-Cc $Cc ($Flags + @((Join-Path $src "$unit.c"),
                                        "-o", (Join-Path $Out "$unit-$Tag$ExeExt")))
        if ($rc -ne 0) { throw "$Cc failed on $unit.c for $Tag" }
        $script:built += 1
    }

    # Allowed to fail, exactly as in the .sh, and for a reason that bites harder
    # here: -shared against a mingw target drags in dllcrt2.o beside the startup
    # the object already has, and the whole fixture set used to die on the
    # resulting duplicate DllMainCRTStartup. A missing shared object is named;
    # it is not a build failure.
    $lib = Join-Path $Out "shared-$Tag$LibExt"
    $rc = Invoke-Cc $Cc ($Flags + @("-shared", "-fPIC",
                                    (Join-Path $src "shared.c"), "-o", $lib)) -Quiet
    if ($rc -eq 0) {
        $script:built += 1
    } else {
        Remove-Item -Force -ErrorAction SilentlyContinue $lib
        $script:skipped += "shared($Tag)"
    }

    # The overlay: bytes past everything any structure in the file claims, which
    # is the one region no compiler emits and the one an unpacker acts on.
    $ovl = Join-Path $Out "overlay-$Tag$ExeExt"
    Copy-Item -Force (Join-Path $Out "plain-$Tag$ExeExt") $ovl
    $rand = New-Object byte[] 4096
    (New-Object System.Random 20260906).NextBytes($rand)
    $fs = [System.IO.File]::Open($ovl, 'Append', 'Write')
    $tail = [System.Text.Encoding]::ASCII.GetBytes('kofeng-fixture-overlay')
    $fs.Write($tail, 0, $tail.Length)
    $fs.Write($rand, 0, $rand.Length)
    $fs.Close()
    $script:built += 1
}

$cc = $env:CC
if (-not $cc) { $cc = "clang" }

# The sysroots are the same ones the Makefile names, and overridable the same
# way, so a fixture is built against the toolchain the tools were built with
# rather than a second guess at where MSYS2 lives.
$arm64Root = $env:KOF_ARM64_SYSROOT; if (-not $arm64Root) { $arm64Root = "C:/msys64/clangarm64" }
$x86Root   = $env:KOF_X86_SYSROOT;   if (-not $x86Root)   { $x86Root   = "C:/msys64/mingw64" }
$x32Root   = $env:KOF_X86_SYSROOT32; if (-not $x32Root)   { $x32Root   = "C:/msys64/mingw32" }

# Tag, extra flags, exe suffix, shared-library suffix. Every entry is probed by
# linking, so an absent sysroot costs a skipped line and nothing else.
$sets = @(
    @{ tag = "pe64";  flags = @("--target=x86_64-w64-windows-gnu",  "--sysroot=$x86Root",   "-fuse-ld=lld"); exe = ".exe"; lib = ".dll" },
    @{ tag = "pearm64"; flags = @("--target=aarch64-w64-windows-gnu", "--sysroot=$arm64Root", "-fuse-ld=lld"); exe = ".exe"; lib = ".dll" },
    @{ tag = "pe32";  flags = @("--target=i686-w64-windows-gnu",    "--sysroot=$x32Root",   "-fuse-ld=lld"); exe = ".exe"; lib = ".dll" },
    @{ tag = "elf64"; flags = @("--target=x86_64-unknown-linux-gnu");                                        exe = "";     lib = ".so"  },
    @{ tag = "elf32"; flags = @("--target=i386-unknown-linux-gnu");                                          exe = "";     lib = ".so"  }
)

foreach ($s in $sets) {
    if (Test-Toolchain $cc $s.flags) {
        Build-Set $cc $s.flags $s.tag $s.exe $s.lib
    } else {
        $skipped += "$($s.tag)(no-toolchain)"
    }
}

# ---- containers ---------------------------------------------------------------
#
# The payload every archive holds: a built binary if there is one, so an archive
# fixture also exercises the path where a child object is a format in its own
# right; the fixture source otherwise, which is at least a real file.
$payload = $null
foreach ($cand in "plain-elf64", "plain-pe64.exe", "plain-pearm64.exe", "plain-pe32.exe") {
    $p = Join-Path $Out $cand
    if (Test-Path $p) { $payload = $p; break }
}
if (-not $payload) { $payload = Join-Path $src "plain.c" }

Write-Ascii (Join-Path $Out "sample.pdf") (
    "%PDF-1.7`n" +
    "1 0 obj`n<< /Type /Catalog /OpenAction 2 0 R >>`nendobj`n" +
    "2 0 obj`n<< /S /JavaScript /JS (app.alert(1)) >>`nendobj`n" +
    "3 0 obj`n<< /Length 26 /Filter /FlateDecode >>`nstream`n" +
    "kofeng-fixture-stream-data`nendstream`nendobj`n" +
    "xref`n0 4`ntrailer`n<< /Size 4 /Root 1 0 R >>`n" +
    "startxref`n9`n%%EOF`n")
$built += 1

Write-Ascii (Join-Path $Out "sample.rtf") (
    "{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}`n" +
    "{\object\objemb\objupdate{\*\objclass Package}`n" +
    "{\*\objdata 0105000002000000060000006b6f66656e670000}}`n" +
    "{\pict\wmetafile8\bin8 kofeng!}\par done}`n")
$built += 1

function Add-Archive([string]$Name, [scriptblock]$Make) {
    try {
        & $Make
        $script:built += 1
    } catch {
        $script:skipped += "$Name(failed)"
    }
}

$tar = Join-Path $Out "sample.tar"
if (Get-Command tar -ErrorAction SilentlyContinue) {
    Add-Archive "tar" {
        #
        # A RELATIVE archive name, written from inside the output directory.
        #
        # Not tidiness: GNU tar parses the name after -f as host:path, so an
        # ordinary Windows path is a remote archive on a machine called "D" -
        # it fails with "Cannot connect to D: resolve failed" and builds
        # nothing. Windows ships bsdtar in System32, which has no such idea,
        # but Git for Windows puts GNU tar on PATH ahead of it and which one
        # answers is a matter of PATH order. A name with no colon in it is the
        # one thing both agree on. -C keeps its full path: only -f is parsed
        # that way.
        Push-Location $Out
        try {
            & tar -cf 'sample.tar' -C (Split-Path -Parent $payload) `
                  (Split-Path -Leaf $payload)
            if ($LASTEXITCODE -ne 0) { throw "tar failed" }
        } finally {
            Pop-Location
        }
    }
} else {
    $skipped += "tar"
}

# gzip and zip come from .NET rather than from a tool that may not be installed:
# both formats are ones the collectors are expected to handle everywhere, and a
# host without gzip.exe is still a host that must test the gzip path.
if (Test-Path $tar) {
    Add-Archive "gz" {
        $in  = [System.IO.File]::OpenRead($tar)
        $out = [System.IO.File]::Create((Join-Path $Out "sample.gz"))
        $gz  = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionMode]::Compress)
        $in.CopyTo($gz); $gz.Close(); $out.Close(); $in.Close()
    }
}

Add-Archive "zip" {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipPath = Join-Path $Out "sample.zip"
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, $payload, (Split-Path -Leaf $payload)) | Out-Null
    $zip.Dispose()
}

foreach ($t in @(
    @{ name = "xz";  tool = "xz";  args = { & xz  -kf $tar; Move-Item -Force (Join-Path $Out "sample.tar.xz") (Join-Path $Out "sample.xz") } },
    @{ name = "7z";  tool = "7z";  args = { & 7z  a -bso0 -bsp0 (Join-Path $Out "sample.7z")  $payload } },
    @{ name = "rar"; tool = "rar"; args = { & rar a -inul     (Join-Path $Out "sample.rar") $payload } })) {
    if (Get-Command $t.tool -ErrorAction SilentlyContinue) {
        Add-Archive $t.name $t.args
    } else {
        $skipped += $t.name
    }
}

$line = "fixtures: $built file(s) in $Out"
if ($skipped.Count -gt 0) { $line += "   NOT BUILT: " + ($skipped -join " ") }
Write-Host $line

# Not an error, for the reason the .sh gives: what must not happen is the
# absence going unmentioned.
exit 0
