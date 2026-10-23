/*
 * kofchild.h - producing a child object: declaring it, filling it, decoding
 * and decrypting into it, and saying it was not fully examined.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFCHILD_H
#define KOFENG_KOFCHILD_H

#include <stdint.h>
#include "kofctx.h"
#include "kofentry.h"

/*
 * YIELDING CHILD OBJECTS
 *
 *     kunp_rcstruct_window(off, len)     a range of this object, no copy
 *     kunp_rcstruct_write(bytes, n)             bytes that did not exist before
 *     kunp_rcstruct_done()                    close this child, start the next
 *
 * Every one returns zero when the engine will take no more - the budget is gone,
 * or the tree is as deep or as wide as it is allowed to get. A module must stop
 * when it sees that, and looping regardless costs nothing but achieves nothing:
 * the host has already stopped accepting.
 *
 * A decompressor therefore looks like this, and cannot be written to allocate
 * first and check afterwards:
 *
 *     while (more_input) {
 *             n = inflate_some(buf, sizeof buf);
 *             if (!kunp_rcstruct_write(buf, n))
 *                     return;              // budget gone; the scan says so
 *     }
 *     kunp_rcstruct_done();
 */
#define kunp_rcstruct_window(off, len)                                         \
	((ctx)->content->window ?                                          \
	 (ctx)->content->window((ctx), (uint64_t)(off), (uint64_t)(len)) : 0)

#define kunp_rcstruct_write(bytes, n)                                                 \
	((ctx)->content->emit ?                                            \
	 (ctx)->content->emit((ctx), (bytes), (uint32_t)(n)) : 0)

#define kunp_rcstruct_done()                                                        \
	((ctx)->content->child ? (ctx)->content->child((ctx)) : 0)

/*
 * Join a scattered region into the object being produced. See `gather` above.
 *
 * Does not close the child: a module gathering two regions into one object is a
 * legitimate thing to want, so where the object ends stays the module's decision.
 */
#define kunp_static_gather(region_mask, cap)                                   \
	((ctx)->content->gather ?                                          \
	 (ctx)->content->gather((ctx), (uint32_t)(region_mask),            \
				(uint64_t)(cap)) : 0)

/* Bounded by the host's ceiling alone. */
#define kunp_static_gather_all(region_mask) kunp_static_gather((region_mask), 0)

/*
 * Name the next child, from bytes already in this object.
 *
 *     kunp_rcstruct_name(e->name_off, e->name_len);
 *     kunp_rcstruct_window(e->data_off, e->size);
 *
 * Reporting only. Nothing in the engine reads a child's name back, and nothing
 * ever opens a path built from one - see the note in objsrc.h on why the produced
 * objects have no filename at all.
 */
/*
 * Declare what the next child is, when the structure said.
 *
 *     kunp_rcstruct_format(KOF_FMT_SCRIPT);
 *     kunp_rcstruct_window(off, len);
 *
 * See child_format for when a module may say this and when it must not.
 */
/*
 * Decode an entry's whole coding chain into a child.
 *
 *     kunp_static_decode_chain(e->index)
 *
 * For a container that has an entry table: the chain, its order and its
 * bounds are all the host's, and what the module supplies is which entry.
 */
/*
 * Would anything look inside a child of this format - ask before decoding.
 *
 *     if (!kof_fmt_wanted(KOF_FMT_FONT))
 *             continue;               // nothing targets fonts
 *
 * See fmt_wanted for why this is the module's decision and not the engine's,
 * and why a yes for KOF_FMT_UNKNOWN is not a loophole. Answers 1 when the host
 * offers no opinion, so a producer that asks is never worse off than one that
 * does not.
 */
#define kof_fmt_wanted(fmt)                                                \
	((ctx)->content->fmt_wanted ?                                      \
	 (ctx)->content->fmt_wanted((ctx), (uint8_t)(fmt)) : 1)

#define kunp_static_decode_chain(index)                                            \
	((ctx)->content->unpack_chain ?                                    \
	 (ctx)->content->unpack_chain((ctx), (uint32_t)(index)) : 0u)

/*
 * Declare what the next child is FOR.
 *
 *     kunp_rcstruct_kind(KOF_ENT_CONTENT);
 *     kunp_rcstruct_window(off, len);
 *
 * Also names it, when name_next found nothing to name it with.
 */
/*
 * Declare which entry the next child is the content of.
 *
 *     kunp_rcstruct_child_entry(e->index);
 *     kunp_static_decode_chain(e->index);
 */
#define kunp_rcstruct_child_entry(index)                                             \
	((void)((ctx)->content->child_entry ?                               \
		((ctx)->content->child_entry((ctx), (uint32_t)(index)), 0) : 0))

#define kunp_rcstruct_kind(kind)                                               \
	((void)((ctx)->content->child_kind ?                                \
		((ctx)->content->child_kind((ctx), (uint32_t)(kind)), 0) : 0))

#define kunp_rcstruct_format(fmt)                                              \
	((void)((ctx)->content->child_format ?                              \
		((ctx)->content->child_format((ctx), (uint8_t)(fmt)), 0) : 0))

/*
 * Which build of the packer this object is.
 *
 *     b = mp_build_of(ctx, pe);
 *     if (!b)
 *             return;              -- an unknown build is not read
 *     kunp_rcstruct_build(b->name);
 *
 * See `packer_build` for why this is settled before anything is unpacked.
 */
#define kunp_rcstruct_build(s)                                                \
	((void)((ctx)->content->packer_build ?                              \
		((ctx)->content->packer_build((ctx), (s)), 0) : 0))

/*
 * The declared image is to be written as a file of this format.
 *
 *     kunp_rcstruct_section(".text", HDR, n, ..., KOF_SECF_CODE);
 *     kunp_rcstruct_as(KOF_FMT_ELF, KOF_ARCH_X86, 0x08048000u);
 *     kunp_rcstruct_image();
 *     kunp_rcstruct_at(HDR);
 *
 * See `as_format` for when this is needed and when the parent answers.
 */
#define kunp_rcstruct_as(fmt, arch, base)                                     \
	((void)((ctx)->content->as_format ?                                 \
		((ctx)->content->as_format((ctx), (uint8_t)(fmt),           \
					   (uint8_t)(arch),                 \
					   (uint64_t)(base)), 0) : 0))

/*
 * This object is a wrapper and the child about to be closed is what was inside.
 *
 *     kunp_rcstruct_write(plain, n);
 *     kunp_rcstruct_supersedes();
 *     kunp_rcstruct_done();
 *
 * See `supersede` for what it does and does not stop.
 */
#define kunp_rcstruct_supersedes()                                            \
	((void)((ctx)->content->supersede ?                                 \
		((ctx)->content->supersede((ctx)), 0) : 0))

#define kunp_rcstruct_name(off, len)                                            \
	((void)((ctx)->content->name_next ?                                \
		((ctx)->content->name_next((ctx), (uint64_t)(off),         \
					   (uint64_t)(len)), 0) : 0))

/*
 * Decompress a DEFLATE stream at off into the object being produced.
 *
 * `len` bounds the input, not the output: the stream ends where DEFLATE says it
 * does, which is usually sooner. Returns bytes produced - zero when nothing could
 * be decoded, which is the answer for a corrupt stream and for a budget that was
 * already gone.
 *
 * It does not close the child. A module may want to put more after the
 * decompressed bytes, or decompress two streams into one object, so kunp_rcstruct_done()
 * stays the module's to call:
 *
 *     kof_unpack_deflate(gz->data_off, gz->data_len);
 *     kunp_rcstruct_done();
 */
#define kunp_static_decode(method, off, len, out_hint)                        \
	((ctx)->content->unpack ?                                          \
	 (ctx)->content->unpack((ctx), (uint32_t)(method), (uint64_t)(off),\
				(uint64_t)(len), (uint64_t)(out_hint)) : 0)

/* kunp_rcstruct_note("MPRESS 2.12-2.19 LZMA") - what this module worked out about
 * the container, carried on the child it is about to produce. */
#define kunp_rcstruct_note(text)                                                 \
	((ctx)->content->note_next ? (ctx)->content->note_next((ctx), (text)) \
				  : (void)0)

/* kunp_rcstruct_read(off, buf, cap) / kunp_rcstruct_poke(off, buf, n) - see
 * produced_read and produced_poke above. */
#define kunp_rcstruct_read(off, buf, cap)                                        \
	((ctx)->content->produced_read                                     \
	 ? (ctx)->content->produced_read((ctx), (uint64_t)(off), (buf),    \
					 (uint32_t)(cap)) : 0u)

/*
 * Start this child as a copy of the object being unpacked, then change it with
 * kunp_rcstruct_poke. See `derive` in struct kof_content.
 */
/*
 * WHAT A SECTION IS, BEYOND WHERE IT IS.
 *
 * Three axes, and they are independent: what the bytes are for, where they came
 * from, and whether they can be read yet.
 */
/*
 * WHAT A DECLARED SECTION MAY BE READ, WRITTEN OR RUN AS.
 *
 * Here and not in kofmod/pe.h because a declaration is not about PE: a module
 * that targets several formats, or none, still has to say what a range it
 * recovered is for - and including a format header would tie it to that one
 * format, which the build refuses for a good reason (kof_<fmt>() casts
 * ctx->file_header and there is no single view when there are several targets).
 *
 * Same bits as KOF_PE_PERM_*, which is what the PE parser already reports.
 */
/*
 * HOW MUCH ROOM THE ENGINE NEEDS IN FRONT OF THE CONTENT when it is asked to
 * write an ELF header - see kunp_rcstruct_as and kof_elf_write_hdr.
 *
 * The ELF header plus one program header, which is what that writer emits: one
 * PT_LOAD over the whole file. A module declaring its first section at this
 * address leaves exactly the room and no padding; declaring it further out is
 * allowed and the gap is padding; declaring it closer is refused, because a
 * header that does not fit in front of the content would have to overwrite it.
 *
 * Published rather than inferred because a module has to place its sections
 * BEFORE the engine writes anything, so it cannot ask afterwards how much was
 * used.
 */
#define KUNP_HDR_ELF32       0x54u
#define KUNP_HDR_ELF64       0x78u

#define KUNP_PERM_X          0x0001u
#define KUNP_PERM_W          0x0002u
#define KUNP_PERM_R          0x0004u

/* KOF_SECF_*: the section flags a declaration carries - defined by libgenome
 * (<genotype/image/section_flags.h>), included at the top of this file. */

#define kunp_rcstruct_at(off)                                                    \
	((ctx)->content->at ? (ctx)->content->at((ctx), (uint64_t)(off)) : 0)

#define kunp_rcstruct_image()                                                    \
	((ctx)->content->image ? (ctx)->content->image((ctx)) : 0)

#define kunp_rcstruct_section(name, rva, vsz, perm, flags)                       \
	((ctx)->content->section                                           \
	 ? (ctx)->content->section((ctx), (name), (uint64_t)(rva),         \
				   (uint64_t)(vsz), (uint32_t)(perm),      \
				   (uint32_t)(flags))                      \
	 : -1)

#define kunp_rcstruct_reset()                                           \
	((ctx)->content->sections_reset                                    \
	 ? (ctx)->content->sections_reset((ctx)) : 0)

/*
 * WHAT THE CHILD IMPORTS - see `import` in struct kof_content.
 *
 *     for (each entry the container lists)
 *             kunp_rcstruct_import(dll, fn, 0, slot_rva);
 *     need = kunp_rcstruct_import_bytes();
 *     kunp_rcstruct_section(".kofimp", at, need, KUNP_PERM_R,
 *                           KOF_SECF_DATA | KOF_SECF_SYNTHETIC);
 *     kunp_rcstruct_import_at(at);
 *
 * By ordinal: pass NULL for `fn` and the number for `ordinal`.
 */
#define kunp_rcstruct_import(dll, fn, ordinal, iat_rva)                     \
	((ctx)->content->import                                            \
	 ? (ctx)->content->import((ctx), (dll), (fn), (uint32_t)(ordinal), \
				  (uint64_t)(iat_rva)) : 0)

#define kunp_rcstruct_import_bytes()                                        \
	((ctx)->content->import_bytes                                      \
	 ? (ctx)->content->import_bytes((ctx)) : (uint64_t)0)

#define kunp_rcstruct_import_at(rva)                                        \
	((ctx)->content->import_at                                         \
	 ? (ctx)->content->import_at((ctx), (uint64_t)(rva)) : 0)

#define kunp_opened_already()                                           \
	((ctx)->content->opened_already                                    \
	 ? (ctx)->content->opened_already((ctx)) : 0)

/*
 * Recover and report the APIs a PE resolves for itself - see `api_resolved`
 * and `sym_import` in struct kof_content.
 *
 *     for (i = 0; kunp_api_resolved(i, dll, sizeof dll, fn, sizeof fn); i++)
 *             kunp_sym_import(dll, fn);
 */
#define kunp_api_resolved(i, dll, dll_cap, fn, fn_cap)                     \
	((ctx)->content->api_resolved                                      \
	 ? (ctx)->content->api_resolved((ctx), (uint32_t)(i), (dll),       \
					(uint32_t)(dll_cap), (fn),         \
					(uint32_t)(fn_cap)) : 0u)

#define kunp_sym_import(dll, fn)                                           \
	((ctx)->content->sym_import                                        \
	 ? (ctx)->content->sym_import((ctx), (dll), (fn)) : 0u)

#define kunp_rcstruct_layout_of_image()                                       \
	((ctx)->content->layout_of_produced                                \
	 ? (ctx)->content->layout_of_produced((ctx)) : (uint64_t)0)

#define kunp_rcstruct_dir(idx, rva, size)                                        \
	((ctx)->content->child_dir                                         \
	 ? (ctx)->content->child_dir((ctx), (uint32_t)(idx),               \
				     (uint64_t)(rva), (uint64_t)(size)) : 0)

#define kunp_rcstruct_entry(rva)                                             \
	((ctx)->content->child_entry_rva                                   \
	 ? (ctx)->content->child_entry_rva((ctx), (uint64_t)(rva)) : 0)

#define kunp_rcstruct_derive()                                                   \
	((ctx)->content->derive ? (ctx)->content->derive((ctx)) : 0)

#define kunp_rcstruct_poke(off, buf, n)                                          \
	((ctx)->content->produced_poke                                     \
	 ? (ctx)->content->produced_poke((ctx), (uint64_t)(off), (buf),    \
					 (uint32_t)(n)) : 0)

#define kof_unpack_at(method, off, len, out_hint)                          \
	kunp_static_decode((method), (off), (len), (out_hint))

/*
 * Decrypt a range of this object and produce what comes out:
 *
 *     struct kof_capsid c = { KOF_CAPSID_XOR_KEY, 0, key, key_len };
 *     kunp_decrypt(&c, ct_off, ct_len);
 *
 * The bytes are the result of the cipher over the range as it sits in the object,
 * in order, taken by the host in as many pieces as its budget allows - a module
 * does not chunk. Returns how many were produced; zero is a refusal or a
 * descriptor that names no cipher. See kofmod/kofdecode.h.
 */
#define kunp_decrypt(cipher, off, len)                                        \
	((ctx)->content->decrypt                                           \
	 ? (ctx)->content->decrypt((ctx), (cipher), (uint64_t)(off),       \
				    (uint64_t)(len)) : 0u)

/*
 * Run a cipher over the module's own bytes - the keystream of RC4 is what it
 * returns when `in` is zeros - into the module's own buffer:
 *
 *     n = kunp_capsid_apply(&c, zeros, 9, ks, sizeof ks);
 *
 * Available to a detector as well as an unpacker. Returns the bytes written.
 */
#define kunp_capsid_apply(cipher, in, n, out, cap)                            \
	((ctx)->content->capsid_apply ?                                    \
	 (ctx)->content->capsid_apply((cipher), (in), (uint32_t)(n), (out),  \
				      (uint32_t)(cap)) : 0u)

/*
 * The same, into the module's own buffer and producing nothing:
 *
 *     n = kunp_decrypt_peek(&c, off, len, buf, sizeof buf);
 *
 * Returns the bytes written, at most `cap`.
 */
#define kunp_decrypt_peek(cipher, off, len, buf, cap)                         \
	((ctx)->content->decrypt_peek ?                                    \
	 (ctx)->content->decrypt_peek((ctx), (cipher), (uint64_t)(off),    \
				      (uint64_t)(len), (buf), (uint32_t)(cap)) : 0u)

/*
 * Decode the front of a stream into `buf`, for a header that is compressed.
 *
 *     uint8_t hdr[512];
 *     n = kunp_static_peek(KOF_UNP_NRV2E_8, off, len, hdr, sizeof hdr);
 *
 * Reads; produces nothing. See `unpack_peek` above for why it exists.
 */
#define kunp_static_peek(method, off, len, buf, cap)                        \
	((ctx)->content->unpack_peek ?                                     \
	 (ctx)->content->unpack_peek((ctx), (uint32_t)(method),            \
				     (uint64_t)(off), (uint64_t)(len),     \
				     (buf), (uint32_t)(cap)) : 0u)

/* DEFLATE streams, so it needs no size: spelled out because a gzip or zip module
 * has nothing sensible to pass and should not have to invent one. */
#define kof_unpack_deflate(off, len)                                       \
	kof_unpack_at(KOF_UNP_DEFLATE, (off), (len), 0)

/* The same, for a stream that carries zlib framing - or might. The host checks
 * the header and falls back to raw DEFLATE when there is none, so a caller that
 * cannot tell the two apart names this one. Needs no size either. */
#define kof_unpack_zlib(off, len)                                          \
	kof_unpack_at(KOF_UNP_ZLIB, (off), (len), 0)

/*
 * Decode entry `index` of this object into the object being produced.
 *
 * For an entry whose bytes are scattered - a compound file stream is a chain, not
 * a range - which is why this takes an index and not an offset. See `unpack_entry`.
 *
 *     kunp_rcstruct_name(e->name_off, e->name_len);
 *     if (kunp_static_entry(KOF_UNP_OVBA, i, 0))
 *             kunp_rcstruct_done();
 */
#define kunp_static_entry(method, index, out_hint)                          \
	((ctx)->content->unpack_entry ?                                    \
	 (ctx)->content->unpack_entry((ctx), (uint32_t)(method),            \
				      (uint32_t)(index),                   \
				      (uint64_t)(out_hint)) : 0)

/*
 * Report that this object was not fully examined.
 *
 * For the case only the module knows about: a container it could open in part, a
 * compression method it does not implement, a structure that stopped making sense
 * part way through. Anything the host can see - budgets, ceilings, a corrupt
 * stream - it already records on its own.
 *
 * What it changes is the verdict: the object is reported as not fully examined
 * instead of as clean, with the reason given. Whether it also returns is the
 * caller's choice and is spelled by which of the two forms below is used.
 *
 *     KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);   - records and returns
 *     kunp_rcstruct_broken(KOF_UNP_DAMAGED);       - records and carries on
 */
/*
 * Reasons a module can give. The same set the host uses on its own account, so a
 * caller sees one vocabulary whoever noticed the problem.
 */
enum kunp_rcstruct_broken {
	KOF_UNP_LIMIT = 1,       /* a budget or ceiling stopped it */
	KOF_UNP_UNSUPPORTED = 2, /* a coding or version this build lacks */
	KOF_UNP_DAMAGED = 3,     /* the object's own structure is wrong */
	/*
	 * The content is encrypted and there is no key.
	 *
	 * Apart from UNSUPPORTED because they end differently: a coding this build
	 * lacks is a gap a later build closes, and this one never closes. Every
	 * container that carries encryption uses this value, so the reason reads the
	 * same whichever format noticed it.
	 */
	KOF_UNP_ENCRYPTED = 4
};

/*
 * Two forms, and the case is what tells them apart.
 *
 * KUNP_RCSTRUCT_BROKEN records the reason and RETURNS, which is what nearly every site
 * wants: the module has found out it cannot go on, and the `return` underneath was
 * a line that only ever said so again. Upper case because it changes control flow -
 * the same rule the other macros that end a function follow, and the reason a
 * reader can tell which ones do without looking any of them up.
 *
 * kunp_rcstruct_broken records and carries on, for the module that has recovered
 * something and means to keep it. That is now the commoner of the two - 37 call
 * sites against 18 - and every one of them is in a module that walks entries,
 * exactly as this note predicted when there were none: an entry in a zip whose
 * compression method this build lacks is a reason to record and move to the NEXT
 * entry, not to abandon the entries already recovered.
 */
#define kunp_rcstruct_broken(reason)                                             \
	((void)((ctx)->content->incomplete ?                               \
		((ctx)->content->incomplete((ctx), (uint32_t)(reason)), 0) : 0))

#define KUNP_RCSTRUCT_BROKEN(reason)                                             \
	do {                                                               \
		kunp_rcstruct_broken(reason);                                    \
		return;                                                    \
	} while (0)

#endif /* KOFENG_KOFCHILD_H */
