/*
 * module.ld - layout for a signature blob.
 *
 * Everything the module needs lands in one output section starting at address
 * zero, with the entry point first so its offset is zero and the loader needs
 * no symbol table. ld resolves every internal reference here, which is the
 * whole reason the runtime has no relocation code.
 *
 * A module exports exactly one of kof_scan, kof_unpack and kof_heur, so all
 * three are named here and only one of the three input sections will ever
 * exist.
 *
 * KEEP, and no ENTRY. The two are connected:
 *
 *   ENTRY(kof_scan) made ld demand that symbol, so every unpacker failed to
 *   link with "undefined symbol kof_scan" - for a value that decides nothing,
 *   since the output is a raw binary with no ELF header to carry an entry
 *   address and the loader enters at offset zero regardless.
 *
 *   Dropping ENTRY alone then left --gc-sections with no root to keep from, and
 *   it collected the whole module. KEEP names the roots directly, which is what
 *   was meant all along: keep whichever entry section exists, collect the rest.
 *
 * Which symbol landed at offset zero is checked by the build with nm. That is
 * the check that matters, and it does not depend on anything in this file.
 *
 * .data and .bss are discarded rather than placed. A module is not allowed to
 * have either, and the build script rejects one that does by inspecting the
 * object before this script ever runs; discarding here is only a second line so
 * that a mistake cannot silently end up inside the blob and be executed as if
 * it were code.
 */

SECTIONS
{
	. = 0;

	.blob : {
		KEEP(*(.text.kof_scan))
		KEEP(*(.text.kof_unpack))
		KEEP(*(.text.kof_heur))
		/*
		 * AND THE SECOND ENTRY, WHICH NOTHING REFERENCES.
		 *
		 * kof_cure is called by the HOST, at an offset the build
		 * records - see kof_pack_mod.cure_off - so no code inside the
		 * blob ever names it and --gc-sections collected it. The
		 * symptom was quiet: the module linked, the offset came out
		 * zero, and a rule that plainly had a cure appeared to have
		 * none. It is a root like the three above, and for the same
		 * reason.
		 *
		 * AFTER them, deliberately. Whichever of the three exists has
		 * to be at offset zero, and a root placed before it would take
		 * that place.
		 */
		KEEP(*(.text.kof_cure))
		*(.text .text.*)
		*(.rodata .rodata.* .rodata1)
	}

	/DISCARD/ : {
		*(.comment)
		*(.note .note.*)
		*(.eh_frame .eh_frame_hdr)
		*(.data .data.* .data1)
		*(.bss .bss.*)
		*(.got .got.plt .plt)
	}
}
