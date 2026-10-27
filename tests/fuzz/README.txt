tests/fuzz - hostile-input fuzzing of the kofeng pipeline (kit, drivers, adapters)

THE PARTS
  tests/lib/fuzz_kit.h   the kit: header only. seeded rng, guard-page buffers, fork isolation with a mailbox, structure-aware
                         mutators, corpus loader, failing sinks / read / write seams, process limits, step counter.
                         tests/lib/genome/hk.h and tests/lib/uncoat/hostile_common.h are thin users of it.
  tests/lib/fuzz_drv.h   what an adapter file sees (struct fz_adapter, FZ_ADAPTER, FZ_CHECK, fz_digest).
  tests/lib/fuzz_drv.c   linked only by the fuzz binaries: the allocation wrap (--wrap malloc, calloc, realloc, free,
                         posix_memalign, mmap), the per-shape drivers, main().
  tests/fuzz/<stage>/    one directory per stage; every *.c in it is an adapter file; stage.mk names the lib archive
                         (FZ_LIB_<stage> = kuncoat | kgenome | engine | none) and extra link flags (FZ_LIBS_<stage>).
  tests/fuzz/exempt/     the tables the coverage check reads (see "EVERY PUBLIC FUNCTION").
  mk/fuzz.mk             make fuzz-smoke, fuzz, fuzz-selftest, fuzz-mutants, fuzz-build, fuzz-clean. Build dir: build/fuzz.

RUNNING (Linux; heavy: run under  flock /mnt/games/normtest/heavy.lock )
  make fuzz-smoke                          selftest + every adapter, ASAN+UBSAN, seed 1, 2000 iterations each, ~10 s for the
                                           three stages that exist; budget for all adapters: under about 90 s
  make fuzz SEED=7 ITERS=300000 ONLY=kuncoat/inflate        longer; ONLY is an adapter-name prefix
  make fuzz-selftest                       the planted defects must be CAUGHT, the seam / limit adapters must pass
  make fuzz-mutants                        the kit itself broken four ways: the selftest must then FAIL
  build/fuzz/fuzz_<stage> --list           the rows of a stage
  build/fuzz/fuzz_<stage> --seed S --only I [--adapter NAME] [--inline]
                                           replay ONE case (the per-iteration seed is mix(S, I)); --inline: no fork, gdb sees it
  A failing or killing input is saved as build/fuzz/found/<adapter>_<iter>.bin and the line says adapter, iteration, seed.
  A summary line per adapter ("adapter NAME: iters N digest H status ...") is deterministic: two runs of one seed give the same
  line, so a change of behaviour shows as a changed digest. Limits are COUNTERS (allocation caps, step bounds); the wall clock
  is only the hang backstop of a child (60 s, never an assertion).

ADDING AN ADAPTER (a work package: new file tests/fuzz/<stage>/<name>.c; nothing else is edited except the package's own
exempt file and, when it needs a flag or a library, its own stage.mk)
  1. Pick the shape (fuzz_drv.h): FZ_BYTES (decoder with a sink and an exact output buffer), FZ_REQ (request built from the
     bytes), FZ_PARSE (parse + walk every accessor + drop), FZ_SEQ (ops decoded from the bytes over a handle), FZ_TWO (size
     then write).
  2. Write seeds(): valid inputs from builders (fz_corpus_add; fz_corpus_add_map when the builder knows its fields: LEN, COUNT,
     OFFSET, RVA, and one array of records). Optional .dict tokens.
  3. Write the callback; state the invariants with FZ_CHECK and feed what must not change into fz_digest. Bound the work
     with fz_step in loops (default bound 1M + 64 per input byte; .steps_base / .steps_per_byte).
  4. Register: FZ_ADAPTER(id, .name = "kuncoat/xxx", .covers = "kuncoat_xxx ...", .shape = FZ_BYTES, .seeds = seeds, .run = run);
     .covers lists every public function the row drives, and the file must CALL each of them.
  5. Delete those functions' lines from your tests/fuzz/exempt/wp<N>.txt.
  See tests/fuzz/decomp/inflate.c (a decoder against an oracle) and tests/fuzz/image/pe_parse.c (parse and walk).
  Flags: FZ_MAY_HIT_CAP (a declared size may reach the allocation caps), FZ_KEEPS_STATE (a cache survives the call), FZ_NONDET,
  FZ_NO_FAILK, FZ_POST_REFUSAL. A planted defect row (FZ_PLANTED) is for the kit's own selftest only.
  What the driver checks for every row: a crash / hang / RSS kill is attributed (adapter, iteration, seed, the input is saved);
  a cap hit; a leak (net allocation after the call); the step bound; two calls on one input give one digest; the call again with
  the k-th allocation failing (the OOM paths); for FZ_BYTES the sink is not called after it refused and the output buffer's
  margins are intact.

STAGE orbit: the collectors' operating system is FAKED by link-time wraps (tests/lib/orbit_sys.h: /proc redirected to a fixture,
  a fake process connector and fanotify descriptor, failing open / fopen / rename / mkdir, /dev/full for ENOSPC, a fake home, fork)
  because the library has no seam; the same wrap list (mk/tests_orbit.mk) links the tests/unit/orbit_*.c tests.

EVERY PUBLIC FUNCTION HAS A ROW OR AN EXEMPT ENTRY (make check-rules, tools/check_layers.py, "fuzz coverage")
  The surface is every function of <kgenome.h> and <uncoat.h> and the part headers they name, plus the core helpers they
  expose (465 when the pass was added), and every function of the public headers of libkoforbit/ (the collectors, the event
  record, the verdict cache, the report, the channel, the host-pure part of grille: stage "orbit", added by WP12; 214). A function needs `.covers` on an adapter row (and a call in that file) or a line
  "function<TAB>reason" in tests/fuzz/exempt/*.txt. permanent.txt: what bytes cannot drive (a wall clock, a path), each with its
  reason. wp12.txt: the libkoforbit functions that live in Windows-only files (they include windows.h and cannot be built here:
  the reason names the file) and the two grants that change who owns a shared-memory object. wp<N>.txt: pending work package N (its lines are the work list). A function that is covered AND still listed fails
  too, and so does an entry naming a function that is gone: the tables cannot go stale. A new public function with neither
  fails the build.

LIMITS OF THE KIT (read before trusting a green run)
  - The allocation wrap sees malloc, calloc, realloc, free, posix_memalign and anonymous mmap called through the PLT. It does
    not see strdup, aligned_alloc, memalign or an allocation made inside libc. An mmap is capped but not counted as live.
  - ASAN cannot start under ulimit -v / RLIMIT_AS (the kit skips RLIMIT_AS under ASAN); the child's resident size is polled by
    the parent (2048 MiB) and the ASAN ceilings are in __asan_default_options. RLIMIT_CPU, _FSIZE, _NOFILE and _NPROC are
    applied in the child also under ASAN (the selftest checks that each is felt).
  - Mutation without a field map is blind; a seed that knows its structure should bring a map.
  - Coverage feedback (trace-pc) and valgrind runs are not in the kit yet.
