/*
 * kofpackw.h - build a pack image.
 *
 * Takes modules already in memory and produces the bytes of one pack, laid out
 * exactly as kofpack.h describes. It does no file I/O and knows nothing about
 * where modules come from: reading sidecars, deciding which modules belong
 * together and writing the result are the toolchain's job, and keeping them out
 * of here is what lets the same builder serve a tool that writes a file and a
 * loader that keeps the image in memory.
 *
 * That second caller is the reason this lives in the library rather than in
 * tools/. Once a loose directory of .blob files is loaded by building a pack
 * image from it, there is one representation of a database instead of two, and
 * the loose path cannot drift from the packed one because it produces the same
 * bytes.
 *
 * What the builder decides, and the loader cannot check:
 *
 *   - the precondition union in the header. Derived here from the modules, never
 *     taken from a caller, because a union that claims more than its members do
 *     silently stops running them.
 *   - pool sharing. Two modules declaring the same literal get one run of bytes.
 *
 * What the builder does not decide: which modules belong in this pack. That is
 * grouping, it is the toolchain's design question, and a builder that grouped
 * would be a builder that could produce a pack nobody asked for.
 */

#ifndef KOFENG_KOFPACKW_H
#define KOFENG_KOFPACKW_H

#include <stddef.h>
#include <stdint.h>

/* Mirrors struct kof_pack_str: `kind` selects how `bytes` is read, and `flags`
 * is KOF_STR_ICASE / KOF_STR_FULLWORD and applies to a literal only. */
struct kof_pw_str {
	const uint8_t *bytes;
	uint16_t       len;
	uint8_t        kind;
	uint8_t        flags;
};

struct kof_pw_name {
	uint32_t    id;
	const char *text;
};

/*
 * One module as the builder needs it. Everything is borrowed: the builder copies
 * what it needs into the image and holds no pointer afterwards.
 */
struct kof_pw_mod {
	const uint8_t *code;
	uint32_t       code_len;

	uint32_t target_mask;
	uint32_t scan_mask;
	uint32_t arch_mask;
	uint32_t subtype_mask;
	uint64_t size_min;
	/* KOF_UNP_CONTAINER or KOF_UNP_PACKER; unread for a detector. */
	uint32_t unp_kind;
	/* A heuristic rule's phase and its declared engine request; see
	 * kofmod/heur.h. Zero on every other kind. */
	uint32_t heur_phase;
	uint32_t heur_want;
	/* Where the source lives inside the bases tree; NULL or empty when it
	 * was compiled from outside one. */
	const char *src;

	const struct kof_pw_str  *str;
	uint32_t                  n_str;
	const uint32_t           *rng;      /* one region mask per named range */
	uint32_t                  n_rng;
	const struct kof_pw_name *name;
	uint32_t                  n_names;

	/* What KOF_TARGET_NAME declared - see struct kof_pack_mod in kofpack.h.
	 * `family` may be NULL or empty for an unpack-kind module; the builder
	 * interns whatever it is given either way. */
	const char *family;
	uint32_t    maltype;      /* enum kof_maltype */
};

/*
 * Build one pack. `kind` is an enum kof_pack_kind and applies to every module in
 * it; the caller has already grouped by it, and passing it here rather than per
 * module is what makes a mixed pack unwriteable.
 *
 * Returns a malloc'd image of *out_len bytes, or NULL. The caller frees it.
 */
uint8_t *kof_pack_build(uint32_t kind, const struct kof_pw_mod *mods, uint32_t n,
			size_t *out_len);

#endif /* KOFENG_KOFPACKW_H */