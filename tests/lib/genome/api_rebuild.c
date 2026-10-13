/*
 * api_rebuild - the ELF header writer (kgenome_elf_hdr_write and its positional
 * wrapper kgenome_elf_write_hdr), which a module uses to say what an unpacked
 * image is. No test named either; the PE writers have pe_rebuild.c and
 * imports_fuzz.c.
 *
 * The contract, from elf_rebuild.h: the header goes into `out` and takes
 * eh + ph bytes (64 + 56 or 52 + 32); `cap` is the room before the first section
 * and a layout that leaves less is refused; the function returns the bytes it
 * wrote or 0, and a refusal writes nothing. What a writer must never do is touch
 * a byte outside [out, out + need): the buffer here ends at a guard page, with
 * marker bytes after `need` that must survive.
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

static struct hk_gb G;

static uint64_t write_req(uint8_t *out, uint64_t cap, int is64, uint16_t machine, uint64_t base,
			  const struct kgenome_sec_decl *sec, uint32_t n, uint64_t entry,
			  int has_entry, uint64_t end)
{
	struct kgenome_elf_hdr_req rq;

	memset(&rq, 0, sizeof rq);
	rq.out = out;
	rq.cap = cap;
	rq.is64 = is64;
	rq.machine = machine;
	rq.base = base;
	rq.sec = sec;
	rq.n = n;
	rq.entry_rva = entry;
	rq.has_entry = has_entry;
	rq.image_end = end;
	return kgenome_elf_hdr_write(&rq);
}

static void sec1(struct kgenome_sec_decl *s, uint64_t rva, uint32_t perm)
{
	memset(s, 0, sizeof *s);
	memcpy(s->name, ".text", 6);
	s->rva = rva;
	s->vsize = 0x100;
	s->perm = perm;
	s->flags = KGENOME_SECF_CODE;
}

static void t_header(void)
{
	unsigned is64;

	for (is64 = 0; is64 < 2; is64++) {
		uint64_t need = is64 ? 120u : 84u;
		uint8_t file[0x2000];
		struct kgenome_sec_decl s;
		struct kgenome_elf_info info;
		struct kgenome_obj o;
		uint64_t got;
		uint8_t *out;
		unsigned i;

		sec1(&s, 0x1000, KGENOME_PE_PERM_X | KGENOME_PE_PERM_R);
		/* written into a buffer whose tail is a guard page, with the room exactly `need` */
		out = gb_put(&G, NULL, (size_t)need);
		memset(out, 0xee, (size_t)need);
		got = write_req(out, need, (int)is64, 62, 0x400000, &s, 1, 0x1000, 1, 0x2000);
		CK(got == need);
		/* the parse of what it wrote, in a file padded to the image size */
		memset(file, 0, sizeof file);
		memcpy(file, out, (size_t)need);
		memset(&info, 0, sizeof info);
		CK(kgenome_elf_image_parse(kof_buf_make(file, sizeof file), &info, &o) == 1);
		CK(info.valid && info.elf_class == (is64 ? KGENOME_ELFCLASS_64 : KGENOME_ELFCLASS_32));
		CK(info.elf_data == KGENOME_ELFDATA_LE && info.e_type == KGENOME_ELF_EXEC && info.e_machine == 62);
		CK(info.entry_addr == 0x401000u);
		CK(info.seg_count == 1 && info.seg[0].type == KGENOME_ELF_PT_LOAD);
		CK(info.seg[0].mem_addr == 0x400000u && info.seg[0].file_size == 0x2000u && info.seg[0].file_off == 0);
		CK(info.seg[0].perm == (KGENOME_PERM_X | KGENOME_PERM_R));

		/* no entry: the object is ET_DYN with a zero entry, which is what a carved blob honestly is */
		got = write_req(file, need, (int)is64, 3, 0x1000, &s, 1, 0x1000, 0, 0x2000);
		CK(got == need);
		memset(&info, 0, sizeof info);
		CK(kgenome_elf_image_parse(kof_buf_make(file, sizeof file), &info, &o) == 1);
		CK(info.e_type == KGENOME_ELF_DYN && info.entry_addr == 0 && info.e_machine == 3);
		CK(!(info.anomalies & KGENOME_ELF_ANOM_ENTRY_ZERO));

		/* the room: exactly need is enough, one less is not; a first section inside the header is refused */
		out = gb_put(&G, NULL, (size_t)need);
		CK(write_req(out, need - 1u, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == 0);
		CK(write_req(out, need, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == need);
		CK(write_req(out, 0, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == 0);
		sec1(&s, need - 1u, KGENOME_PE_PERM_R);
		CK(write_req(out, need, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == 0);
		sec1(&s, need, KGENOME_PE_PERM_R);
		CK(write_req(out, need, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == need);
		sec1(&s, 0x1000, KGENOME_PE_PERM_R);
		/* a refusal writes nothing */
		memset(file, 0xab, sizeof file);
		CK(write_req(file, need - 1u, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == 0);
		CK(write_req(file, need, (int)is64, 62, 0x400000, &s, 0, 0, 1, 0x2000) == 0);
		CK(write_req(file, need, (int)is64, 62, 0x400000, NULL, 1, 0, 1, 0x2000) == 0);
		CK(write_req(file, need, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0) == 0);
		CK(write_req(NULL, need, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == 0);
		for (i = 0; i < sizeof file; i++)
			if (file[i] != 0xab)
				break;
		CK(i == sizeof file);
		/* bytes after the header, inside a larger cap, are never touched */
		memset(file, 0xab, sizeof file);
		CK(write_req(file, 0x1000, (int)is64, 62, 0x400000, &s, 1, 0, 1, 0x2000) == need);
		for (i = (unsigned)need; i < sizeof file; i++)
			if (file[i] != 0xab)
				break;
		CK(i == sizeof file);

		/* the permissions of the one PT_LOAD: the union of the sections', R when none says */
		{
			static const uint32_t perms[] = { 0, KGENOME_PE_PERM_W, KGENOME_PE_PERM_X, KGENOME_PE_PERM_R,
				KGENOME_PE_PERM_W | KGENOME_PE_PERM_X, 7, 0xffffffffu };
			static const uint32_t want[] = { 4, 2, 1, 4, 3, 7, 7 };
			unsigned k;
			for (k = 0; k < sizeof perms / sizeof perms[0]; k++) {
				struct kgenome_sec_decl a[2];
				sec1(&a[0], 0x1000, perms[k]);
				sec1(&a[1], 0x2000, 0);
				memset(file, 0, sizeof file);
				CK(write_req(file, need, (int)is64, 62, 0x400000, a, 2, 0, 1, 0x3000) == need);
				CK(hk_r(file + (is64 ? 64 + 4 : 52 + 0x18), 4, 0) == want[k]);
			}
			/* the union over several sections */
			{
				struct kgenome_sec_decl a[3];
				sec1(&a[0], 0x1000, KGENOME_PE_PERM_R);
				sec1(&a[1], 0x2000, KGENOME_PE_PERM_W);
				sec1(&a[2], 0x3000, KGENOME_PE_PERM_X);
				CK(write_req(file, need, (int)is64, 62, 0x400000, a, 3, 0, 1, 0x4000) == need);
				CK(hk_r(file + (is64 ? 64 + 4 : 52 + 0x18), 4, 0) == 7);
			}
		}

		/* the positional wrapper is the same function */
		{
			uint8_t a[0x200], b[0x200];
			memset(a, 0x11, sizeof a);
			memset(b, 0x11, sizeof b);
			CK(kgenome_elf_write_hdr(a, sizeof a, (int)is64, 62, 0x400000, &s, 1, 0x40, 1, 0x2000) == need);
			CK(write_req(b, sizeof b, (int)is64, 62, 0x400000, &s, 1, 0x40, 1, 0x2000) == need);
			CK(!memcmp(a, b, sizeof a));
		}

		/* hostile values: nothing outside the header, whatever the numbers */
		{
			static const uint64_t ex[] = { 0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x100000000ull,
				0x7fffffffffffffffull, 0x8000000000000000ull, UINT64_MAX - 1u, UINT64_MAX };
			unsigned a, b, c, d;
			for (a = 0; a < sizeof ex / sizeof ex[0]; a++)
			for (b = 0; b < sizeof ex / sizeof ex[0]; b++)
			for (c = 0; c < sizeof ex / sizeof ex[0]; c++)
			for (d = 0; d < 3; d++) {
				uint8_t *tight = gb_put(&G, NULL, (size_t)need);
				struct kgenome_sec_decl hs;

				sec1(&hs, need + (d == 1 ? 0 : ex[c] & 0xffffu), (uint32_t)ex[b]);
				hs.vsize = ex[a];
				(void)write_req(tight, need, (int)is64, (uint16_t)ex[a], ex[b], &hs, 1, ex[c], (int)(d & 1u), ex[(a + c) % 10u]);
			}
		}
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	gb_init(&G, 256);
	t_header();
	gb_free(&G);
	printf("api_rebuild: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
