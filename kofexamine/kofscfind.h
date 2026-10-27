/*
 * kofscfind.h - where a shellcode loader keeps its payload, as an analysis the
 * examiner offers on an ELF object.
 *
 * A TOOL FEATURE, NOT AN ENGINE ONE. The engine does not look for shellcode in
 * general - that cannot be covered - and loaders are detected by signatures
 * somebody wrote. This is what a person looking at a file can ask for: it says
 * where the blob is and how it was found, nothing more.
 *
 * WHAT IT FINDS. A small program that is mostly data, carrying one global whose
 * contents are neither text nor a table, which the CODE then EXECUTES - or, in
 * the pointer-shaped variant, whose pointer the code executes and whose target
 * is a cleartext blob that makes a syscall. The shape is a heuristic and not a
 * verdict, because a legitimate program can look like it.
 *
 * kofscfind_find is the whole analysis. kofscfind_run is the same search with
 * the answer to "how does the code refer to this range" supplied by the caller,
 * which is what lets a test exercise each gate alone.
 */
#ifndef KOFSCFIND_H
#define KOFSCFIND_H

#include <stdint.h>
#include <kgenome_status.h>
#include <kofcore.h>
#include <celllysis/range_facts.h>

struct kgenome_obj;

/* The payload sizes considered: shorter is a string, longer is a table. */
#define KOFSCFIND_SIZE_MIN  64u
#define KOFSCFIND_SIZE_MAX  8192u

struct kofscfind {
	/* Non-zero when a payload was found; every other field is meaningful only
	 * then. */
	int      found;
	/* `at` is a file offset; `va` is the symbol's own value and is what a
	 * report shows. `len` is the size of the blob AS IT SITS in the object. */
	uint64_t at;
	uint64_t va;
	uint64_t len;
	/* 32 or 64 where the payload said so (the way it reaches the kernel), 0
	 * where nothing did. */
	unsigned bits;
	/* A loader may keep the payload base64 encoded: non-zero here says `dec`
	 * holds the decoded bytes and how many. `at` and `len` still describe the
	 * encoded text. */
	uint32_t dec_n;
	uint8_t  dec[KOFSCFIND_SIZE_MAX];
};

/* `xref` answers how the code refers to [va, va + size), as the
 * KGENOME_XREF_* flags of <celllysis/xref.h>; NULL means "no sweep", and the
 * byte tests decide alone. */
struct kofscfind_in {
	const struct kgenome_obj *obj;
	const uint8_t *data;
	uint64_t       n;
	uint32_t     (*xref)(void *user, uint64_t va, uint64_t size);
	void          *xref_user;
};

/* The search, with the caller's answer to the xref question. KGENOME_UNSUPPORTED
 * is an object that is not an ELF, KGENOME_OK a finished search; `out` is
 * written whole and `out->found` says whether there is a payload. */
enum kgenome_status kofscfind_run(const struct kofscfind_in *in,
				  struct kofscfind *out);

/* The analysis as the examiner runs it: the sweep over the object's own code is
 * made here with the genome's decoder and xref map. On x86 and x86-64 only; any
 * other architecture answers "not analysed" to the xref question and the byte
 * tests decide. */
enum kgenome_status kofscfind_find(const struct kgenome_obj *obj,
				   const uint8_t *data, uint64_t n,
				   struct kofscfind *out);

/*
 * THE LIST OF WHERE SHELLCODE COULD SIT, as rows: the table the examiner's Infection dialog shows on its Shellcode tab.
 *
 * Three kinds of row, in this order. FINDER: the payload kofscfind located (the caller hands in the answer it cached on the
 * object, so the sweep is not run again), flagged, with the finder's own words. SYMBOL: an object symbol (a variable) that lives
 * in memory the loader marks executable - ELF only, as a PE has no variable symbols; the finder's own symbol is the FINDER row
 * and is not repeated. RANGE: a data range inside executable memory - an ELF section that is not code but sits in an executable
 * segment, a segment or section that is writable AND executable, a PE section with execute permission that is data or writable.
 * Each row carries the address (virtual address, or RVA in a PE), the file offset (KGENOME_NA when the file holds none), the size
 * and the permission as KGENOME_PERM_* bits; the verdict text is the finder's and is empty on the other rows.
 *
 * THE FACTS COME FROM kgenome (the parsed view, the symbol reader, the loader's segment lookup); nothing is searched here.
 * Bounded by KOFSCFIND_ROWS_MAX rows: more is KGENOME_TRUNCATED with `total` the number there would have been, so a cut is said.
 * On an object that is not a valid ELF or PE the answer is KGENOME_UNSUPPORTED with no rows (the finder row excepted: it is
 * the caller's own evidence and is returned whenever it was given).
 */
#define KOFSCFIND_ROWS_MAX  1024u
/* The most bytes of code the lister's reference sweep reads (the library's budget.max_steps). The finder's own sweep keeps the
 * library default (KGENOME_XREF_MAX, 8192) it was measured with; the lister reads the whole code of an ordinary program
 * (/bin/ls: 130 KB) once. */
#define KOFSCFIND_LIST_CODE_MAX  (1u << 20)
#define KOFSCFIND_ROW_NAME  96u

enum kofscfind_what { KOFSCFIND_W_FINDER = 1, KOFSCFIND_W_SYMBOL, KOFSCFIND_W_RANGE };

struct kofscfind_row {
	char     name[KOFSCFIND_ROW_NAME];  /* a symbol's name (cut for display), or the range and why it is listed; control bytes shown as '?' */
	char     verdict[40];               /* the finder's verdict text, empty on the other rows */
	uint32_t what;                      /* enum kofscfind_what */
	uint32_t perm;                      /* KGENOME_PERM_* of the memory it is in, 0 when the place is not mapped */
	uint32_t flagged;                   /* 1: the finder flagged it */
	uint32_t bits;                      /* 32 or 64 where the payload said so, else 0 */
	uint64_t va, off, size;             /* off KGENOME_NA when the file holds no bytes for it */
	/* The library's facts about the range (kgenome_range_facts): references from the object's code by kind, decode share and
	 * system call, entropy, shape. `facts_ok` is 0 when the range has no file bytes (nothing was asked). `strong` is this
	 * lister's rule (see kofscfind_list in kofscfind.c); `flagged` is the finder OR strong. */
	struct kgenome_range_facts facts;
	uint32_t facts_ok;
	uint32_t strong;
	uint32_t seq;                       /* the order the candidates were found in: the sort's tie-break */
};

struct kofscfind_list_in {
	const struct kgenome_obj *obj;
	kof_buf                   file;
	uint64_t                  payload_va, payload_len;   /* the finder's cached answer; payload_len 0: none found */
	uint32_t                  payload_bits;
	struct kofscfind_row     *out;
	uint32_t                  cap;
};

struct kofscfind_list_res {
	uint32_t n;       /* rows written */
	uint32_t total;   /* rows there are */
};

enum kgenome_status kofscfind_list(const struct kofscfind_list_in *in, struct kofscfind_list_res *res);

/*
 * THE PAYLOAD AS AN OBJECT OF ITS OWN, built by the tool.
 *
 * A reader wants to look at the payload with every pane the examiner has - hex,
 * disassembly, Find, a draft - and those all work on an object. So the bytes
 * the analysis located (the decoded text where the loader keeps it base64) are
 * given a header and handed back as an ELF image: one PT_LOAD over the whole
 * file, no section table, no entry point (nothing ever jumped to the first
 * byte, so it is ET_DYN with e_entry 0), the machine from the way the payload
 * reaches the kernel or, where it did not say, from `parent_is64`.
 *
 * NOTHING HERE IS THE ENGINE'S. The engine never sees this object and does not
 * scan it; it exists in the viewer's object list beside the loader's own and
 * is dropped with it. Returns the bytes written into [out, out + cap), or 0
 * when `f` found nothing or the image does not fit. KOFSCFIND_IMAGE_MAX is
 * always enough.
 */
#define KOFSCFIND_HDR_ROOM   0x80u
#define KOFSCFIND_IMAGE_MAX  (KOFSCFIND_HDR_ROOM + KOFSCFIND_SIZE_MAX)

uint64_t kofscfind_image(const struct kofscfind *f, const uint8_t *data,
			 uint64_t n, int parent_is64, uint8_t *out,
			 uint64_t cap);

#endif /* KOFSCFIND_H */
