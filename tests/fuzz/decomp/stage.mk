# Stage "decomp" (WP5 adds its adapters as more files in this directory): the decompressors and decoders of kuncoat.
# FZ_LIB_<stage> names the archive the stage's binary is linked against (kuncoat | kgenome | engine | none),
# FZ_LIBS_<stage> the extra link flags (zlib, libbz2 and liblzma are the differential oracles of the inflate, bunzip, lzma, lzma2 and bcj adapters), FZ_WRAP_<stage> more --wrap flags.
FZ_LIB_decomp  := kuncoat
FZ_LIBS_decomp := -lz -lbz2 -llzma

# The adapters include the header they share and the script writers of tests/lib/uncoat (hostile_*enc.h, hostile_*vec.h):
# a change to one rebuilds the binary.
$(FZB)/fuzz_decomp: $(wildcard tests/fuzz/decomp/*.h tests/lib/uncoat/hostile_*.h)

# Seeds from Python's own compressors for the adapters that have an oracle (tools/decomp_seeds.py): the fuzz binary takes them with
# --corpus (build/fuzz/fuzz_decomp --seed 1 --iters 100000 --corpus build/fuzz/seeds_decomp). Not needed by make fuzz-smoke.
.PHONY: fuzz-decomp-seeds
fuzz-decomp-seeds:
	@$(PYTHON) -I tools/decomp_seeds.py seeds $(FZB)/seeds_decomp
