/*
 * module.ld - layout for a signature blob.
 *
 * Everything the module needs lands in one output section starting at address
 * zero, with kof_scan first so the entry offset is zero and the loader needs
 * no symbol table. ld resolves every internal reference here, which is the
 * whole reason the runtime has no relocation code.
 *
 * .data and .bss are discarded rather than placed. A module is not allowed to
 * have either, and the build script rejects one that does by inspecting the
 * object before this script ever runs; discarding here is only a second line so
 * that a mistake cannot silently end up inside the blob and be executed as if
 * it were code.
 */

ENTRY(kof_scan)

SECTIONS
{
	. = 0;

	.blob : {
		*(.text.kof_scan)
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
