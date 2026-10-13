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
