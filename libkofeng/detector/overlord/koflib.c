/*
 * koflib.c - the marker span.
 *
 * ONE TIER, BECAUSE ONE TIER IS WHAT WAS MEASURED. See the note in koflib.h.
 */

#include "koflib.h"

#include <stdlib.h>
#include <string.h>

#include <kofmod/elf.h>
#include "../../kofcore/rangelist.h"

/* ELF's own value; the parser keeps p_type verbatim. Defined here for the same
 * reason every other file that needs it defines it: there is no ELF constants
 * header, and one line beats a dependency. */
#define PT_LOAD 1u

/* ELF's own values again, for the same reason: the section type of .symtab and
 * the three symbol types this reads. */
#define SHT_SYMTAB_ 2u
#define STT_OBJECT_ 1u
#define STT_FUNC_   2u
#define STT_FILE_   4u
#define STB_LOCAL_  0u

/*
 * THE MARKERS.
 *
 * Text the library owns and a program does not write for itself: strerror's
 * table, the dynamic loader's complaints, the allocator's abort messages.
 * Covering glibc, uclibc and musl.
 *
 * MEASURED COVERAGE, so nobody has to guess what this reaches: a span was found
 * in 100% of 638 /usr/bin objects and 100% of 574 packed clean ones, cutting a
 * mean 7.6% and 8.3% of the file; in 70% of 472 malware objects, cutting 12.6%;
 * and in only 14% of 514 IoT-botnet ELFs, cutting 0.5%. That last figure is the
 * known hole and it is the one that matters most - a stripped static uclibc
 * build has no strerror table to find. Closing it needs a tier this does not
 * have yet.
 */
static const char *const markers[] = {
	"No such file or directory", "Permission denied", "Bad address",
	"Cannot allocate memory", "Invalid argument", "Broken pipe",
	"Connection refused", "Resource temporarily unavailable",
	"Operation not permitted", "Interrupted system call",
	"No space left on device", "Too many open files", "Unknown error",
	"malloc(): ", "free(): ", "double free", "__libc_", "GLIBC_",
	"_dl_", "uClibc", "musl", "/lib/ld", "ld-linux",
	"Assertion", "assertion", "stack smashing", "buffer overflow"
};

/*
 * A SPAN, NOT THE MATCHES. One marker says a byte belongs to the library; what
 * is wanted is the run of bytes around it, and the linker puts a library's
 * read-only data down in one piece. So the span runs from the lowest hit to the
 * highest and everything between is cut - including whatever the author
 * happened to put there. That is the wide cut koflib.h says it makes.
 *
 * THREE HITS, NOT ONE. "Permission denied" is a string malware writes too, and
 * a span taken from a single match would cut a region because of one string.
 * Three distinct positions is a table, and a table is the library's.
 */
/* How much span one marker may account for - see the measurement below. */
#define LIB_SPAN_PER_MARKER 5120u

/*
 * How many marker hits one segment's walk records before it stops clustering
 * them and falls back to the single span from the first to the last.
 *
 * The fallback is the conservative direction: it is the rule this function had
 * before clusters existed, and it refuses more than it accepts. A segment with
 * more hits than this is a large static build whose strings are dense anyway,
 * which is the case the global rule already handled.
 */
#define LIB_MAX_HITS 256u

struct lib_hit { uint64_t at; uint32_t len; };

/* Ordered by position, which is what clustering needs and what the per-marker
 * scan above does not produce: each marker is searched over the whole segment
 * before the next one starts. Insertion sort, because the array is small and
 * very nearly sorted in the common case - one marker's hits arrive in order. */
static void hit_sort(struct lib_hit *h, uint32_t n)
{
	uint32_t i, j;

	for (i = 1; i < n; i++) {
		struct lib_hit v = h[i];

		for (j = i; j && h[j - 1].at > v.at; j--)
			h[j] = h[j - 1];
		h[j] = v;
	}
}

/* One run of markers that are close enough to be the same table. */
static void cluster_emit(const struct lib_hit *h, uint32_t a, uint32_t b,
			 uint64_t base, struct kof_rlist *l, uint64_t obj)
{
	uint64_t lo = h[a].at, hi = 0;
	uint32_t i, hits = b - a;

	if (hits < 3u)
		return;
	for (i = a; i < b; i++)
		if (h[i].at + h[i].len > hi)
			hi = h[i].at + h[i].len;
	if (hi <= lo)
		return;
	if (hi - lo > (uint64_t)hits * LIB_SPAN_PER_MARKER)
		return;
	kof_rl_add(l, obj, base + lo, hi - lo);
}

static void marker_span(const uint8_t *p, uint64_t n, uint64_t base,
			struct kof_rlist *l, uint64_t obj)
{
	struct lib_hit hit[LIB_MAX_HITS];
	uint32_t n_hit = 0;
	uint64_t lo = (uint64_t)-1, hi = 0;
	uint32_t k, hits = 0;

	if (n < 64)
		return;
	for (k = 0; k < sizeof markers / sizeof markers[0]; k++) {
		uint64_t mlen = (uint64_t)strlen(markers[k]);
		const uint8_t *q = p;
		uint64_t left = n;

		while (left >= mlen) {
			const uint8_t *f = (const uint8_t *)memchr(q, markers[k][0],
							(size_t)(left - mlen + 1));
			uint64_t at;

			if (!f)
				break;
			if (!memcmp(f, markers[k], (size_t)mlen)) {
				at = (uint64_t)(f - p);
				if (at < lo)
					lo = at;
				if (at + mlen > hi)
					hi = at + mlen;
				if (n_hit < LIB_MAX_HITS) {
					hit[n_hit].at = at;
					hit[n_hit].len = (uint32_t)mlen;
					n_hit++;
				}
				hits++;
			}
			left = n - (uint64_t)(f - p) - 1;
			q = f + 1;
		}
	}
	if (hits < 3 || hi <= lo)
		return;
	/*
	 * ONE TABLE PER RUN OF MARKERS, AND NOT ONE SPAN PER SEGMENT.
	 *
	 * Everything below is about density, and it used to be asked of a
	 * single span from the segment's FIRST marker to its LAST. That makes
	 * one stray hit a veto over the whole segment: measured on
	 * HEUR-Trojan.Linux.Agent.vn (MIPS, 279 KB, static), the errno table
	 * sits in 585 bytes at 0x3f937 and one `__libc_` lies at 0x178a, so the
	 * span asked about was 249 KB and needed fifty hits to pass. It had
	 * four. Nothing was cut, and the whole of uclibc stayed in CODE.
	 *
	 * The markers are clustered instead: a gap wider than one marker's
	 * allowance starts a new run, and each run is judged on its own. That
	 * is the SAME rule - "a library whose strings are five kilobytes apart
	 * is not one library" - asked where it means something.
	 *
	 * IT DOES NOT WEAKEN THE SCATTERED-MARKER TEST. Twelve copies of
	 * "GLIBC_2.2.5" spread over 150 KB become twelve runs of one hit each,
	 * and a run of one never reaches the three-hit floor. That input cut
	 * nothing before and cuts nothing now; what changed is only the case
	 * where a real table shares a segment with a distant stray.
	 */
	if (n_hit >= 3u && hits <= LIB_MAX_HITS) {
		uint32_t a, i;

		hit_sort(hit, n_hit);
		a = 0;
		for (i = 1; i < n_hit; i++) {
			if (hit[i].at - hit[i - 1].at <= LIB_SPAN_PER_MARKER)
				continue;
			cluster_emit(hit, a, i, base, l, obj);
			a = i;
		}
		cluster_emit(hit, a, n_hit, base, l, obj);
		return;
	}
	/*
	 * AND THE MARKERS HAVE TO BE PACKED, not merely present.
	 *
	 * The span runs from the first marker to the last and takes everything
	 * between, which is right for a static library - it IS one contiguous
	 * run, and its strings are packed into a few kilobytes of rodata. It is
	 * wrong, and exploitable, for markers that are SCATTERED: three copies
	 * of "GLIBC_2.2.5" placed at the two ends of a segment and anywhere in
	 * the middle bracket the whole program, and everything the author wrote
	 * is subtracted as somebody else's.
	 *
	 * Measured, and it is not hypothetical. Over 5248 real ELF samples the
	 * marker span claims a median of 2% of its segment and 32% at the 95th
	 * percentile - but 115 spans claimed 70% or more, and every one of those
	 * held about twelve markers spread over some 150KB. Density tells the
	 * two apart with a gap and no overlap:
	 *
	 *     hits per KB of span      spans    of which claim >=70%
	 *     under 0.20                 124                     115
	 *     0.20 and over             3427                       0
	 *
	 * The bucket from 0.10 to 0.15 is empty, so the threshold sits in a
	 * valley rather than on a slope.
	 *
	 * SPELLED AS BYTES PER MARKER, which is the same rule read the way it
	 * is enforced: at most five kilobytes of span for each marker found. A
	 * library whose strings are five kilobytes apart is not a library.
	 *
	 * REFUSED ENTIRELY RATHER THAN TRIMMED. "These bytes are the library"
	 * and "some of these bytes are" are different claims, and this function
	 * can only make the first - see the note at the top of koflib.h on why
	 * finding nothing is the honest answer when nothing can be found.
	 */
	if (hi - lo > (uint64_t)hits * LIB_SPAN_PER_MARKER)
		return;
	kof_rl_add(l, obj, base + lo, hi - lo);
}

/* ---- the symbol tier -------------------------------------------------------
 *
 * WHAT THE MARKERS CANNOT REACH, AND WHY A SECOND TIER IS THE ONLY WAY TO IT.
 *
 * Every marker is a STRING, so a marker span is a span of read-only DATA. The
 * library's CODE carries none of them, and in a static build that code is most
 * of the file: measured on a 3.2MB static glibc binary, the marker tier cuts
 * 27KB - 0.84% - and leaves half a megabyte of libc .text where it was.
 * Cutting the library whatever region it sits in cannot be done by finding
 * more strings.
 *
 * WHAT THE FILE ITSELF SAYS. A static link keeps one STT_FILE symbol per input
 * object file, and every symbol after it belongs to that file until the next
 * one. That grouping is the LINKER'S and not a guess made here, and it answers
 * exactly the question this asks: which bytes came out of somebody else's
 * archive.
 *
 * ONE INTERNAL NAME CONVICTS THE WHOLE GROUP, which is the point of using the
 * groups at all. `__GI_execve` is glibc's internal alias and `_dl_` is the
 * loader's - names no application author writes - but the same object file
 * also defines plain `memcpy`, `strlen` and `malloc`, which an author might.
 * Taking only the prefixed names would leave most of the library behind;
 * taking the group takes what the prefixed name PROVES is somebody else's.
 *
 * AND A GROUP WITH NO SUCH NAME IS LEFT ALONE, which is the test this has to
 * pass: a static binary built for the purpose keeps its own main in the view
 * and loses its libc.
 *
 * EXACT RANGES, SO ANY REGION. st_value and st_size are what a symbol covers,
 * translated through the segment holding them, so this cuts CODE as readily as
 * DATA and needs no opinion about which region a byte is in. That is the
 * difference from the marker tier, which can only cut the run it found.
 *
 * WHERE IT DOES NOT REACH: a stripped file. Of 154 statically linked samples
 * in the malware corpus 103 keep a .symtab; the other 51 have the markers and
 * nothing else, and for those the coverage is what it always was.
 */

/*
 * A NAME THE IMPLEMENTATION RESERVED, WHICH IS A LANGUAGE RULE AND NOT A LIST
 * OF LIBRARIES.
 *
 * ISO C 7.1.3, and the whole of it: "All identifiers that begin with an
 * underscore are always reserved for use as identifiers with file scope." A
 * symbol in .symtab carrying a type and a size IS a file-scope identifier, so a
 * conforming program did not define it and the definition came out of the
 * toolchain - true of glibc, uClibc, musl, bionic and a libc this has never
 * met, without knowing one of their names.
 *
 * THE WHOLE RULE AND NOT THE FAMOUS HALF OF IT. This tested only the stricter
 * clause - a second underscore or an uppercase letter - which catches
 * `__libc_start_main`, `_IO_putc` and `__GI_execve` and misses everything a
 * small libc names with one underscore and a lowercase letter. Measured on a
 * uclibc bot: `_fpmaxtostr`, `_vfprintf_internal`, `_ppfs_parsespec` and
 * `_string_syserrmsgs` are kilobytes of library the narrow test left in, and
 * the object files they belong to were never convicted either, so their local
 * symbols stayed as well.
 *
 * WHAT IT COSTS is an author who gives a file-scope function a leading
 * underscore: their object file is then taken for the library's. That is a name
 * the standard told them not to use, and it is the direction this is
 * deliberately wrong in - see the note at the top of koflib.h.
 *
 * DEFINED, AND NOT MERELY REFERENCED. A program that CALLS memcpy has an
 * undefined symbol for it and has not written anything - the caller's own
 * bytes are the author's. The check on st_shndx is in the caller.
 */
static int reserved_name(const char *s, uint64_t n);

/* The same test applied to a name still in the string table. */
static int sym_reserved(kof_buf file, const struct kof_elf_sec *str,
			uint32_t nm)
{
	const char *s;
	uint64_t room, len = 0;

	if (!nm || nm >= str->file_size)
		return 0;
	s = (const char *)file.p + str->file_off + nm;
	room = str->file_size - nm;
	while (len < room && s[len])
		len++;
	return reserved_name(s, len);
}

static int reserved_name(const char *s, uint64_t n)
{
	return n >= 2u && s[0] == '_';
}

/*
 * An address to a file offset, through the segment that holds it.
 *
 * file_size and not mem_size: .bss is mapped from nothing, so a symbol past
 * the file half of a segment covers no bytes of the file and must not become
 * an offset that lands on whatever follows it.
 */
static int addr_to_off(const struct kof_elf_info *e, uint64_t va, uint64_t sz,
		       uint64_t *off)
{
	uint32_t s;

	for (s = 0; s < e->seg_count && s < KOF_ELF_MAX_SEGMENTS; s++) {
		const struct kof_elf_seg *g = &e->seg[s];

		if (g->type != PT_LOAD || !g->file_size)
			continue;
		if (va < g->mem_addr || va - g->mem_addr >= g->file_size)
			continue;
		if (sz > g->file_size - (va - g->mem_addr))
			return 0;       /* it runs past the file half */
		*off = g->file_off + (va - g->mem_addr);
		return 1;
	}
	return 0;
}

/*
 * The file bytes one symbol covers, or nothing.
 *
 * FUNC and OBJECT only: a SECTION or NOTYPE symbol names a place rather than an
 * extent somebody wrote, and a zero size states no extent at all.
 */
static int sym_extent(kof_buf file, const struct kof_elf_info *e, int be,
		      int is64, uint64_t ent, uint8_t info,
		      uint64_t *lo, uint64_t *hi)
{
	uint64_t va, sz, off;

	if ((info & 0xfu) != STT_OBJECT_ && (info & 0xfu) != STT_FUNC_)
		return 0;
	if (is64) {
		if (!kof_rd_u64(file, ent + 8, be, &va) ||
		    !kof_rd_u64(file, ent + 16, be, &sz))
			return 0;
	} else {
		uint32_t v32 = 0, s32 = 0;

		if (!kof_rd_u32(file, ent + 4, be, &v32) ||
		    !kof_rd_u32(file, ent + 8, be, &s32))
			return 0;
		va = v32;
		sz = s32;
	}
	if (!sz || !addr_to_off(e, va, sz, &off))
		return 0;
	*lo = off;
	*hi = off + sz;
	return 1;
}

/*
 * ADD, COMPACTING WHEN THE LIST IS FULL RATHER THAN DROPPING THE REST.
 *
 * kof_rl_add goes quiet when it has no room. That is right for a tier
 * producing one range per segment and wrong for one producing a range per
 * symbol: a static libc names over a thousand, and a list that fills at the
 * five hundredth keeps whichever happened to come first. Measured before this
 * existed: 155KB of library code cut where the symbols named 555KB of it.
 *
 * A static link lays each object file out in one run, so the ranges are mostly
 * adjacent and normalising a full list nearly always makes room. When it does
 * not, the drop is what it always was.
 *
 * SAFE ONLY WHERE NOTHING IS STILL READING BY INDEX, because normalising
 * sorts. The marker ranges are read by index in the first pass, which adds
 * nothing; this is called from the second, which adds and reads nothing.
 */
static void lib_add(struct kof_rlist *l, uint64_t obj, uint64_t off,
		    uint64_t n)
{
	if (l->n >= l->cap)
		kof_rl_normalise(l);
	kof_rl_add(l, obj, off, n);
}

/* Does [lo,hi) meet any of the first `n` ranges already in the list - which,
 * when this is called, are the marker tier's and nothing else. */
static int hits_marker(const struct kof_rlist *l, uint32_t n,
		       uint64_t lo, uint64_t hi)
{
	uint32_t i;

	for (i = 0; i < n && i < l->n; i++) {
		uint64_t a = l->v[i].off, b = a + l->v[i].len;

		if (lo < b && a < hi)
			return 1;
	}
	return 0;
}

/*
 * EXACT RANGES, ONE PER SYMBOL - AND NOT ONE PER OBJECT FILE, WHICH IS WHAT
 * THIS TRIED FIRST AND WHAT THE MEASUREMENT REFUSED.
 *
 * The obvious economy is to reduce each convicted object file to its lowest and
 * highest offset and add that one range: it is the linker's own unit, it
 * collapses a thousand ranges into a hundred, and the padding between an
 * object's own functions is the toolchain's anyway. It rests on each object
 * being laid out in ONE RUN per section, and that is not true of a modern libc.
 * Measured on a static glibc build: the local symbols of unwind-c.c alone span
 * 488KB of a 502KB .text, because the library is compiled with function
 * sections and the linker interleaves them. Every object file then covers
 * almost the whole section, so the widened claim covers the author's code too -
 * the binary's own `main` sat inside the span and 100% of .text was cut.
 *
 * So a symbol contributes exactly what st_value and st_size say it does, and
 * the list is sized for that.
 */

/*
 * How many object-file groups this tracks. Real static binaries carry 158 to
 * 326 of them. Past the bound a group is simply never convicted, which can only
 * leave library bytes in - it can never take somebody's own.
 */
#define GRP_MAX 4096u

static const struct kof_elf_sec *sec_named(const struct kof_elf_info *e,
					   const char *name)
{
	uint32_t i;

	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
		if (!strcmp(e->sec[i].name, name))
			return &e->sec[i];
	return NULL;
}

/* The same, for a FILE offset, which is what the span lists hold. */
static uint32_t sec_at_off(const struct kof_elf_info *e, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		const struct kof_elf_sec *c = &e->sec[i];

		if (!c->file_size || c->type == 8u /* NOBITS */)
			continue;
		if (off >= c->file_off && off - c->file_off < c->file_size)
			return i;
	}
	return KOF_ELF_MAX_SECTIONS;
}

/*
 * THE GAPS BETWEEN LIBRARY RUNS THAT NOTHING THE AUTHOR WROTE FALLS INTO.
 *
 * WHY THERE ARE GAPS AT ALL. A symbol's extent is exact, so the tier claims
 * only the bytes a symbol covers - and a library object also contributes
 * things no symbol names: alignment padding, a plainly named global whose own
 * object file gave no evidence, a literal pool. Measured on one uclibc bot:
 * the symbols convicted 24KB of a 47KB .text, and among what was left were
 * `malloc`, `memmove` and `gethostbyname_r`.
 *
 * WHY WIDENING IS NORMALLY WRONG, and why this is not that. Reducing a
 * convicted object file to its lowest and highest offset claims everything
 * between them, and in a libc compiled with function sections the objects
 * interleave - so every object spans the whole section and the claim swallows
 * the program. That was measured too: 100% of a glibc build's .text, with its
 * own main inside.
 *
 * SO THE FILE DECIDES, PER GAP. An unconvicted local group is an object file
 * the linker named and this found no evidence against - the author's own, in
 * every real case. Its symbols are positive evidence of authorship. A gap with
 * one in it is refused; a gap with none is the library's, because a run of
 * bytes between two library functions, in one section, that nobody's own
 * object file lays claim to, is what the library's padding and unnamed pieces
 * look like.
 *
 * It is self-checking, which is the point: on the interleaved glibc build every
 * gap contains author symbols and nothing is widened at all, and on the uclibc
 * bot the gaps are clean and the library closes up. No list, and no constant.
 */
static void fill_gaps(const struct kof_elf_info *e, struct kof_rlist *lib,
		      struct kof_rlist *mine, uint64_t obj)
{
	uint32_t i, j, n0;

	if (lib->n < 2u)
		return;
	kof_rl_normalise(mine);
	/*
	 * THE RUNS AS THEY WERE, because this loop adds to the list it is
	 * reading. Without the snapshot the bound grows as gaps are appended
	 * and the walk goes on to compare one new gap's end against the next
	 * one's start - two unsorted entries - and fills the space between
	 * them, which is any distance at all. And kof_rl_add is used rather
	 * than lib_add for the other half of the same reason: lib_add
	 * compacts a full list, and a sort moves every entry this loop is
	 * indexing. A list with no room simply stops filling.
	 */
	n0 = lib->n;
	for (i = 0; i + 1u < n0; i++) {
		uint64_t a = lib->v[i].off + lib->v[i].len;
		uint64_t b = lib->v[i + 1u].off;
		int clean = 1;

		if (b <= a)
			continue;
		/* One section, both sides - see sec_at_off. */
		if (sec_at_off(e, a) == KOF_ELF_MAX_SECTIONS ||
		    sec_at_off(e, a) != sec_at_off(e, b - 1u))
			continue;
		for (j = 0; j < mine->n; j++) {
			uint64_t s = mine->v[j].off;

			if (a < s + mine->v[j].len && s < b) {
				clean = 0;
				break;
			}
		}
		if (clean)
			kof_rl_add(lib, obj, a, b - a);
	}
	kof_rl_normalise(lib);
}

static void symbol_spans(kof_buf file, const struct kof_elf_info *e,
			 struct kof_rlist *l, struct kof_rlist *mine)
{
	const struct kof_elf_sec *sym = NULL, *str;
	uint8_t grp_lib[GRP_MAX / 8u];
	uint32_t i, entsz, count, pass, n_mark = l->n;
	int is64, be;

	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type == SHT_SYMTAB_) { sym = &e->sec[i]; break; }
	str = sec_named(e, ".strtab");
	if (!sym || !str)
		return;                 /* stripped: the markers are all there is */
	if (str->file_off >= file.n || str->file_size > file.n - str->file_off)
		return;
	if (sym->file_off >= file.n || sym->file_size > file.n - sym->file_off)
		return;

	is64  = e->elf_class == KOF_ELFCLASS_64;
	be    = e->elf_data  == KOF_ELFDATA_BE;
	entsz = is64 ? 24u : 16u;
	count = (uint32_t)(sym->file_size / entsz);
	if (!count)
		return;

	memset(grp_lib, 0, sizeof grp_lib);

	/*
	 * TWICE OVER THE TABLE, because a group is convicted by a name that can
	 * come after the symbols it convicts. Buffering each group instead needs
	 * a bound on its size, and a group that overran the bound would be the
	 * one case that quietly kept its library.
	 */
	for (pass = 0; pass < 2u; pass++) {
		uint32_t grp = 0;

		for (i = 0; i < count; i++) {
			uint64_t ent = sym->file_off + (uint64_t)i * entsz;
			uint64_t lo = 0, hi = 0;
			uint32_t nm = 0;
			uint8_t info = 0;
			int local;

			if (!kof_rd_u32(file, ent, be, &nm) ||
			    !kof_rd_u8(file, ent + (is64 ? 4u : 12u), &info))
				break;
			if ((info & 0xfu) == STT_FILE_) {
				grp++;
				continue;
			}
			/*
			 * A LOCAL SYMBOL BELONGS TO THE FILE NAMED ABOVE IT AND
			 * A GLOBAL ONE BELONGS TO NOBODY.
			 *
			 * ELF puts every local symbol after the STT_FILE that
			 * names its source and every global after all of them,
			 * so reading the table as one long sequence of groups
			 * hands the last group hundreds of symbols it never
			 * defined - the program's own `main` among them.
			 */
			local = (info >> 4) == STB_LOCAL_;
			if (local && grp >= GRP_MAX)
				continue;

			if (pass == 0) {
				uint16_t shndx = 0;
				int lib;

				if (!local)
					continue;   /* it convicts no group */
				if (!kof_rd_u16(file,
						ent + (is64 ? 6u : 14u),
						be, &shndx))
					break;
				if (!shndx)
					continue;   /* referenced, not written */
				lib = sym_reserved(file, str, nm);
				/*
				 * OR IT SITS IN WHAT THE MARKERS ALREADY PROVED.
				 *
				 * A second evidence, independent of the first
				 * and of any name: the marker tier has found a
				 * run that belongs to the library, and a symbol
				 * defined inside that run says which object
				 * file the run came out of. The group is then
				 * convicted by its own data, and the CODE of
				 * that object - which carries no strings, so
				 * the marker tier can never see it - goes too.
				 */
				if (!lib &&
				    sym_extent(file, e, be, is64, ent, info,
					       &lo, &hi) &&
				    hits_marker(l, n_mark, lo, hi))
					lib = 1;
				if (lib)
					grp_lib[grp >> 3] |=
						(uint8_t)(1u << (grp & 7u));
				continue;
			}

			if (local) {
				if (!(grp_lib[grp >> 3] &
				      (uint8_t)(1u << (grp & 7u)))) {
					/*
					 * SOMEBODY ELSE'S, AND WORTH SAYING SO.
					 * An object file the linker named that
					 * this found no evidence against is the
					 * author's, and its symbols are what
					 * stops a gap being closed over them -
					 * see fill_gaps.
					 */
					if (sym_extent(file, e, be, is64, ent,
						       info, &lo, &hi))
						kof_rl_add(mine, file.n, lo,
							   hi - lo);
					continue;
				}
			} else if (!sym_reserved(file, str, nm)) {
				/*
				 * A global has no group, so its own name is the
				 * only thing that can speak for it - and when
				 * it says nothing, the symbol is UNKNOWN, not
				 * the author's and not the library's.
				 *
				 * AN UNKNOWN SYMBOL STILL BLOCKS A GAP, which
				 * is the difference between this being safe and
				 * being a bug. `main` is a global, so it is not
				 * in any object-file group this could convict
				 * or acquit; with only local symbols guarding
				 * the gaps, a glibc build's `main` sat in one
				 * that looked clean and was cut. Measured, and
				 * it is why every symbol that is not positively
				 * the library's goes in here.
				 *
				 * It costs coverage: `malloc` and `memmove` in
				 * a uclibc build are library and unknown, so
				 * the gaps around them stay. That is the right
				 * way round - the two mistakes are not worth
				 * the same.
				 */
				if (sym_extent(file, e, be, is64, ent, info,
					       &lo, &hi))
					kof_rl_add(mine, file.n, lo, hi - lo);
				continue;
			}
			if (sym_extent(file, e, be, is64, ent, info, &lo, &hi))
				lib_add(l, file.n, lo, hi - lo);
		}
	}
	kof_rl_normalise(l);
	fill_gaps(e, l, mine, file.n);
}

/*
 * IS THE THING AT THIS ADDRESS THE LIBRARY'S, by the spans already found?
 *
 * For a caller holding a SYMBOL rather than a file offset - the normaliser,
 * deciding which records belong in a view's symbol block. It exists so that the
 * address-to-offset step lives in one place: a second copy of addr_to_off in the
 * scanner would be a second set of rules about which segment a symbol lands in,
 * and the two would answer differently the first time one of them was fixed.
 *
 * A symbol the segments cannot place - .bss, an absolute value, a section index
 * this build does not carry - is NOT the library's. That is the same direction
 * every other unknown is resolved in here: what cannot be attributed stays with
 * the author, so a view never loses a record on a guess.
 */
int kof_lib_has_addr(const struct kof_elf_info *e,
		     const struct kof_lib_all *lib, uint64_t va, uint64_t size)
{
	uint64_t off, end;
	uint32_t i;

	if (!e || !lib || !lib->n || !size)
		return 0;
	if (!addr_to_off(e, va, size, &off))
		return 0;
	end = off + size;
	for (i = 0; i < lib->n; i++) {
		uint64_t a = lib->span[i].off;
		uint64_t b = a + lib->span[i].len;

		if (off < b && a < end)
			return 1;
	}
	return 0;
}

void kof_lib_find(kof_buf file, const struct kof_elf_info *e,
		  struct kof_lib_result *out)
{
	struct kof_rlist l;
	uint32_t s;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!file.p || !file.n || !e || !e->valid)
		return;
	kof_rl_init(&l, out->span, KOF_LIB_MAX_SPANS);

	/* Per loadable segment, so a hit in one cannot cut another. */
	for (s = 0; s < e->seg_count && s < KOF_ELF_MAX_SEGMENTS; s++) {
		const struct kof_elf_seg *g = &e->seg[s];
		uint64_t len;

		if (g->type != PT_LOAD || !g->file_size)
			continue;
		if (g->file_off >= file.n)
			continue;
		len = file.n - g->file_off;
		if (len > g->file_size)
			len = g->file_size;
		marker_span(file.p + g->file_off, len, g->file_off, &l, file.n);
	}
	out->n = kof_rl_normalise(&l);
}

static void lib_find_tiered(kof_buf file, const struct kof_elf_info *e,
			    struct kof_lib_all *out, int with_markers)
{
	struct kof_rlist l;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (with_markers) {
		struct kof_lib_result marks;

		kof_lib_find(file, e, &marks);
		memcpy(out->span, marks.span, marks.n * sizeof marks.span[0]);
		out->n = marks.n;
	}
	if (!file.p || !file.n || !e || !e->valid)
		return;
	/*
	 * THE MARKER SPANS ARE ALREADY IN, so the list is re-opened over them
	 * rather than rebuilt: the symbol tier reads them as evidence - a
	 * symbol defined inside a marker run says which object file that run
	 * came out of - and then adds its own beside them.
	 */
	kof_rl_init(&l, out->span, KOF_LIB_MAX_SPANS_ALL);
	l.n = out->n;
	{
		/*
		 * The author's own extents, kept only for the length of this
		 * call: they are not an answer anybody asked for, they are what
		 * decides which gaps in the library may be closed.
		 *
		 * ON THE HEAP AND NOT static, WHICH IS NOT A STYLE POINT. The
		 * engine scans on several threads and they share this function;
		 * one static buffer would have two objects writing each other's
		 * author extents, and the visible result would be a library
		 * span over somebody else's file. Nor on the stack: it is 32KB,
		 * and this is reached from the scanner's own frame.
		 *
		 * A failed allocation costs the widening and nothing else - the
		 * exact symbol extents are already in `l`.
		 */
		struct kof_range *mine_v =
			malloc(KOF_LIB_MAX_SPANS_ALL * sizeof *mine_v);
		struct kof_rlist mine;

		kof_rl_init(&mine, mine_v, mine_v ? KOF_LIB_MAX_SPANS_ALL : 0u);
		symbol_spans(file, e, &l, &mine);
		free(mine_v);
	}
	out->n = kof_rl_normalise(&l);
}

void kof_lib_find_all(kof_buf file, const struct kof_elf_info *e,
		      struct kof_lib_all *out)
{
	lib_find_tiered(file, e, out, 1);
}

/* PT_INTERP is 3. A file the loader has to fill in is not a static build. */
static int lib_object_is_static(const struct kof_elf_info *e)
{
	uint32_t i;

	if (!e)
		return 0;
	for (i = 0; i < e->seg_count; i++)
		if (e->seg[i].type == 3u)
			return 0;
	return 1;
}

void kof_lib_find_object(kof_buf file, const struct kof_elf_info *e,
			 struct kof_lib_all *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!e || !file.p || !file.n)
		return;
	if (lib_object_is_static(e))
		kof_lib_find_all(file, e, out);
	else
		kof_lib_find_syms(file, e, out);
}

void kof_lib_find_syms(kof_buf file, const struct kof_elf_info *e,
		       struct kof_lib_all *out)
{
	lib_find_tiered(file, e, out, 0);
}
