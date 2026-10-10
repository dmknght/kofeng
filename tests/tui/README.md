# tests/tui - end-to-end tests for `kofviewer`

Black-box tests: each case starts the real `kofviewer` in a pseudo-terminal,
feeds it keys and SGR mouse events, and reads the emulated screen (pyte).
Nothing here is hooked into the Makefile (`make unit` does not run it).

## Requirements
* Python 3 with `pyte` (`pip install pyte`) - the interpreter used for the
  development of these tests had it already.
* A built viewer.  By default the tests use a **copy** at
  `/mnt/games/kofscratch/vt/kofviewer`; override with `KOFVIEWER=/path/to/kofviewer`
  or `run_all.py --viewer ...`.
* The database `build/release/databases` of the repository (read only).

## Rules the harness enforces
* All scratch files live under `/mnt/games/kofscratch/vt` (never `/tmp`).
* The viewer can patch files in place, so samples are **copied** and made
  read-only first (`tui.prep_sample`).
* `--bases` always points at a **private copy** of `bases/` (`tui.bases_dir()`),
  one per test process, because the viewer writes signatures into that tree and
  `Analysis > Rebuild database` runs `make` in the first directory above it that
  has a Makefile.  Never pass the repository's own `bases` to the viewer in a
  test: Rebuild would rebuild the real database.

## Running
```
python3 run_all.py                 # every t_*.py, 4 modules in parallel, summary at the end
python3 run_all.py -j 8 menu tree  # only modules whose name contains "menu" or "tree"
python3 run_all.py -k find         # only cases whose name contains "find"
python3 t_symbols.py -k regex      # one module directly
python3 fuzz.py ko 7 300 bias      # replay / explore random input (seed, events)
```
Exit status is 1 when any case is FAIL or ERROR.

## Statuses
`PASS`, `FAIL` (assertion), `ERROR` (harness exception), `SKIP`,
`XFAIL` - a **known bug** still failing (the case carries `known_bug='BUG-n ...'`; `UX-n` marks a usability nit),
`FIXED?` - a known-bug case that passes now: delete its `known_bug=` marker.

## Layout
| file | covers |
|---|---|
| `tui.py` | the library: `Viewer` (spawn, pump, key, type, click, rclick, dclick, drag, wheel, hwheel, motion, resize, screen helpers, popup/dialog finders, OSC52 capture), `case`/`check`/`eq`, sample and fixture helpers |
| `dl.py` | helpers for the draft panel (grip, add_string, add_matcher, fold_plague, ...) |
| `mkfixtures.py`, `evtgen.c` | synthetic inputs: zip/tar.gz/gz/php/long-line/64 MiB/empty/1-byte and event logs (`.ktr`, written by the repository's own kofevt log writer) |
| `t_menu.py` | menu bar, items, enabled/disabled, keyboard navigation, Analysis actions |
| `t_tree.py` | tree pane |
| `t_hex.py` | hex pane and text pane |
| `t_disasm.py` | disassembler panel |
| `t_events.py` | event log tree, event panel, Filter events |
| `t_symbols.py` | Symbols dialog |
| `t_dialogs.py` | properties page, help boxes, find, goto, decoder, context menus, repaint-after-input sweep |
| `t_draft.py` | draft panel: Type, Family, Comment, Format, Region, Options, Strings |
| `t_plague.py` | plague block table |
| `t_rules.py` | matchers, thresholds, Similarity, Conditions, Diagnose table |
| `t_sig.py` | Generate / Save / Save As / Discard, rule loading, Next/Previous with and without a draft |
| `t_switch.py` | Switch-File Next / Previous over a folder (menu and Ctrl+\\ / Ctrl+]) |
| `t_resize.py` | terminal resize |
| `t_input.py` | malformed / unusual terminal input, bursts, quit, signals |
| `t_cli.py` | command line |
| `t_fuzz.py`, `fuzz.py` | seeded random input |

Coordinates are 1-based `(x = column, y = row)`, like the SGR mouse protocol.

## Proposed fixes
`proposed_fixes.diff` (apply from the repository root with `patch -p1 < tests/tui/proposed_fixes.diff`)
holds the patches that were verified against a scratch rebuild: every XFAIL it covers
turns into `FIXED?` with `run_all.py --viewer <rebuilt kofviewer>`.
