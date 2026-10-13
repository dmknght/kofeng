/*
 * section_flags.h - what a declared section is, beyond where it is.
 *
 * Defined by libgenome because the writers that rebuild an executable
 * (pe_rebuild.h, and the ELF one) take a flags word per section and read these
 * bits; the engine re-exports the header from <kofmod/kofsig.h>, where a module
 * declaring a section (kunp_rcstruct_section) has always found them.
 *
 * Not in pe_types.h although the first reader is the PE writer: these are the
 * vocabulary of a DECLARATION, shared by every format a module may rebuild, and
 * pe_types.h would hand every ELF-only module the PE view through kofsig.h.
 *
 * Three axes, and they are independent: what the bytes are for, where they came
 * from, and whether they can be read yet.
 */
#ifndef KGENOME_IMAGE_SECTION_FLAGS_H
#define KGENOME_IMAGE_SECTION_FLAGS_H

/* What it is. */
#define KGENOME_SECF_CODE        0x0001u
#define KGENOME_SECF_DATA        0x0002u
#define KGENOME_SECF_PAD         0x0004u  /* alignment fill; belongs to no one */
#define KGENOME_SECF_HOLLOW      0x0008u  /* declared with no bytes behind it */
/* Where it came from - see `section` in struct kof_content. */
#define KGENOME_SECF_READ        0x0000u  /* parsed from the file as written */
#define KGENOME_SECF_REBUILT     0x0010u  /* recovered from evidence */
#define KGENOME_SECF_SYNTHETIC   0x0020u  /* stood up because it had to exist */
#define KGENOME_SECF_ORIGIN_MASK 0x0030u
/* Whether it can be read yet. PLAIN is the absence of the others. */
#define KGENOME_SECF_PLAIN       0x0000u
#define KGENOME_SECF_COMPRESSED  0x0040u
#define KGENOME_SECF_CIPHERTEXT  0x0080u
#define KGENOME_SECF_VIRTUALISED 0x0100u
#define KGENOME_SECF_STATE_MASK  0x01c0u

#endif /* KGENOME_IMAGE_SECTION_FLAGS_H */
