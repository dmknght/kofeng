# Stage "decomp" (WP5 adds its adapters as more files in this directory): the decompressors and decoders of kuncoat.
# FZ_LIB_<stage> names the archive the stage's binary is linked against (kuncoat | kgenome | engine | none),
# FZ_LIBS_<stage> the extra link flags (zlib is the differential oracle of the inflate adapter), FZ_WRAP_<stage> more --wrap flags.
FZ_LIB_decomp  := kuncoat
FZ_LIBS_decomp := -lz
