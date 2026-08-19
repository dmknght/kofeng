#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Packed");

/*
 * A runtime packer, recognised by its shape rather than by its name.
 *
 * Nothing here is a string, and that is the point. A section called UPX0 is a
 * string whoever built the file chose, and a custom build of UPX changes it in
 * one line; the reason to detect a packer at all is usually that someone did not
 * want to be recognised. What cannot be changed is the arrangement the stub needs
 * in order to unpack itself:
 *
 *   a section with no file bytes and a large virtual size
 *       the buffer the unpacked image is written into. It cannot be in the file,
 *       because it does not exist until the stub runs.
 *
 *   a section that is writable and executable at once
 *       the stub writes decompressed code and then jumps into it. Compilers do
 *       not emit this, and modern linkers go out of their way to avoid it.
 *
 * Either alone is weak. Zero-raw sections appear in ordinary binaries as .bss,
 * and a writable-executable section shows up in old or unusual toolchains. Both
 * together is a program that intends to build itself at startup.
 *
 * Measured on tests/PE_FILES: fires on the UPX-packed sample, silent on the six
 * clean ones. The ASPack sample has the zero-raw section without the
 * writable-executable one, so it is reported at the weaker level rather than not
 * at all - which is the honest answer, since one of the two conditions holds.
 *
 * Here rather than in signatures/ because eight files is not a corpus. Both
 * conditions are plausible on software nobody would call packed - installers and
 * old toolchains do produce writable-executable sections - and shipping a rule
 * calibrated on eight samples is how a scanner earns a reputation for crying
 * wolf. It stays as the PE end of the automated test: it is what proves a module
 * can reach the PE view, ask structural questions and be reported under a name
 * the engine composed, and that is worth having wired up on every build.
 */
KOF_DEFINE_SCAN
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	int zero_raw = 0, wx = 0;
	uint32_t i;

	if (!pe->valid)
		return;

	for (i = 0; i < pe->sec_count; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		/* A page of virtual size is the threshold: smaller than that and
		 * a zero-raw section is alignment noise rather than a buffer. */
		if (s->file_size == 0 && s->mem_size >= 4096)
			zero_raw = 1;
		if ((s->perm & KOF_PE_PERM_W) && (s->perm & KOF_PE_PERM_X))
			wx = 1;
	}

	if (zero_raw && wx)
		KOF_SCAN_INFECT(KOF_MALVAR_GENERIC);
	if (zero_raw || wx)
		KOF_SCAN_SUSPECT("Weak");
}