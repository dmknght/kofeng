container - fuzz adapters and writers of the container stage (work package 2): zip, rar (3 and 5), 7z, tar, lha, arj, cab, chm, OLE,
PDF, gzip, bz2, xz, rtf, lnk, reg, and the engine's walk over them.

FILES
  parse.c     one adapter per format (container/parse_<fmt>, shape FZ_PARSE): sniff, parse into a zeroed view with the caller's room, walk the
              rows, release. Written out per format so that each format's own functions are called by name (the coverage pass of
              tools/check_layers.py reads `.covers`, and this stage's names - kof_<fmt>_sniff, _parse, _mem, _row, _release of
              libkofeng/analyzers/parsers/containers/*_parse.h - are in the surface since this work package).
  sniff.c     container/sniff: every recogniser on prefixes of every length 0..64 and on each seed, copied into a heap block of exactly that
              length (AddressSanitizer's redzone is the guard).
  walk.c      container/walk (FZ_REQ): kscan_bytes through the real engine and database (build/release/databases: `make databases` first;
              stage.mk makes the run targets depend on it). Seeds are the writers' archives, nested chains and polyglots.
  ctr_seeds.h the seed corpus: tests/lib/ctr_writers.h archives, valid and with each lie, with the field map each writer publishes.

THE WRITERS (tests/lib/ctr_writers.h) make a valid archive or a lying one deterministically, no opaque blobs:
  struct cw_ent    name (any bytes, any length), data, kind (file, directory, symlink, hardlink), what the headers CLAIM (claim_packed,
                   claim_unpacked), share (overlap), method
  struct cw_lies   COUNT, OFFSET, CYCLE, NOEND, and per format EXTRA (zip: zip64, descriptor, comments; tar: pax and GNU records; lha:
                   header levels 1 and 2; cab: MSZIP; 7z: digests, times, a coded header; pdf: catalog, filespec, info, xref stream; rar5:
                   encrypted members) and CRYPT (zip, pdf, rar5, 7z: encrypted; cab: reserve area and next cabinet)
  struct cw_map    where each size, count and offset field is, so a mutator aims at it

KNOWN DEFECTS carved out of the invariants, each COUNTED in the digest and held by a KM_CHECK in tests/unit (known_miss.h: green while the
engine has it, RED the day it is fixed): WP2-D9, D10, D11 (regions and entries of cab and chm, tests/lib/ctr_check.h), WP2-D12 (the PPMd
arena: the walk adapter is FZ_MAY_HIT_CAP for it). When the engine is fixed delete
the carve-out and turn the KM_CHECK into a CK.

RUNNING (heavy: under flock /mnt/games/normtest/heavy.lock)
  make fuzz-smoke
  make fuzz SEED=2 ITERS=200000 ONLY=container/walk
