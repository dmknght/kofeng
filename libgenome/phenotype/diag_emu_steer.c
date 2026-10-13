/*
 * diag_emu_steer.c - the limits of a run, and the rules that steer a call to its successful branch.
 * Part of the emulate route; see diag_emu.c for what it is for and diag_emu_private.h for what the
 * files share.
 */
#include "diag_emu_private.h"





/*
 * IS THIS RETURN VALUE SOMETHING A LATER CALL COULD CARRY.
 *
 * Zero and the error range are excluded. write() returns a count and close()
 * returns 0, so a later read() on fd 0 would "link" to every one of them;
 * -1..-4095 is how Linux returns errno and a failed call produced no object.
 */
int kgenome_diag_emu_ret_is_carryable(uint64_t ret)
{
	return ret != 0u && (int64_t)ret > -4096;
}

/*
 * DOES THIS CALL HAND SOMETHING ON.
 *
 * Keyed on the CAPABILITY and never on the syscall's name: the name differs
 * between i386 and amd64 for the same act - socketcall against socket - and
 * between a syscall and the import that means the same thing. The capability
 * is what both resolve to, which is the whole reason it exists.
 */
int kgenome_diag_emu_cap_hands_on_value(uint16_t cap, const char *nm)
{
	/* The vocabulary's answer, not a second copy - see
	 * kgenome_nucleo_hands_on. */
	return kgenome_nucleo_hands_on(cap, nm);
}



enum kgenome_diag_emu_force_kind kgenome_diag_emu_cap_force_kind(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_NET_CONNECT:
	case KGENOME_NUCLEO_NET_BIND:
	case KGENOME_NUCLEO_NET_LISTEN:
	case KGENOME_NUCLEO_FD_REDIR:
	case KGENOME_NUCLEO_FD_NONBLOCK:
	case KGENOME_NUCLEO_NET_HDRINCL:
	/*
	 * AND THE KERNEL COPIES, WHOSE SUCCESS VALUE IS ZERO AND NOT A COUNT.
	 * copy_from_user and copy_to_user return the number of bytes they
	 * could NOT move, so every caller reads `if (err) goto out`.
	 *
	 * MEASURED: given a non-zero result these two were read as having
	 * failed, and Diamorphine's hooked getdents went straight from the
	 * first copy to its error path - freeing the buffer and leaving - so
	 * the second copy, which is the whole of the hiding, was never on the
	 * path the run took.
	 */
	case KGENOME_NUCLEO_COPY_FROM_USER:
	case KGENOME_NUCLEO_COPY_TO_USER:
		return KGENOME_DIAG_EMU_FORCE_ZERO;
	case KGENOME_NUCLEO_NET_OPEN:
	case KGENOME_NUCLEO_NET_RAW:
	case KGENOME_NUCLEO_NET_ACCEPT:
	case KGENOME_NUCLEO_FILE_OPEN:
	case KGENOME_NUCLEO_MEMFD:
	case KGENOME_NUCLEO_PIPE_OPEN:
		return KGENOME_DIAG_EMU_FORCE_HANDLE;
	/* The generic descriptor calls AND the file-specific ones: the role
	 * an argument plays is the same whatever the descriptor turns out to
	 * be, and the word is corrected later - see diag_refine. Listing only
	 * the file spelling is how the links vanished when read(2) was moved
	 * out of KGENOME_CG_FILE. */
	case KGENOME_NUCLEO_MEM_READ:
	case KGENOME_NUCLEO_MEM_WRITE:
	case KGENOME_NUCLEO_READ:
	case KGENOME_NUCLEO_WRITE:
	case KGENOME_NUCLEO_NET_READ:
	case KGENOME_NUCLEO_NET_WRITE:
		return KGENOME_DIAG_EMU_FORCE_COUNT;
	default:
		return KGENOME_DIAG_EMU_FORCE_NONE;
	}
}


/*
 * ---- FILLING A FORCED READ: KEPT, DISABLED, AND NOT DEPENDED ON ----------
 *
 * A read whose result is forced returns n without putting n bytes anywhere,
 * which is a state no real machine is ever in. The obvious repair is to write
 * the buffer, and this did - with nops.
 *
 * IT IS OFF BECAUSE IT IS NOT DURABLE. The content would be THIS ROUTINE'S,
 * and a finding resting on it rests on a fabrication an author defeats
 * without effort: a stager that looks at what it received before using it - a
 * magic byte, a declared length, a checksum, a decryption that has to produce
 * something - compares against nops, fails, takes the other arm, and never
 * reaches the handover. The evasion costs three instructions.
 *
 * AND IT TURNED OUT TO BE UNNECESSARY, which is the better reason. It was
 * added on the claim that control entering a region is noticed only once the
 * page has been written. That was wrong: what was missing was
 * kgenome_emu_hop_add, declaring the range. MEASURED with it off - meter1,
 * meter2, meter3_encoded, meter4_encoded, rc4_1 and shikata_ga_nai each still
 * yield 5 nodes and 4 links, exec-memory among them.
 *
 * Left in rather than deleted because a forced read that writes nothing is
 * still a lie about the machine, and a routine that needs the buffer to hold
 * something - one following a decryptor - will want it. Whatever turns it on
 * must not let a finding depend on the bytes.
 */
#define DIAG_EMU_FILL 4096u

#if KGENOME_DIAG_EMU_FILL_ON

void kgenome_diag_emu_fill_buffer(struct kgenome_emu *em, uint64_t at, uint64_t n)
{
	static const uint8_t nop[64] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};
	uint64_t done = 0;

	if (!at || n > DIAG_EMU_FILL)
		n = n > DIAG_EMU_FILL ? DIAG_EMU_FILL : n;
	while (done < n) {
		unsigned k = (unsigned)(n - done);

		if (k > sizeof nop)
			k = (unsigned)sizeof nop;
		if (!kgenome_emu_write(em, at + done, nop, k))
			return;         /* unmapped: nothing to fill */
		done += k;
	}
}
#endif /* KGENOME_DIAG_EMU_FILL_ON */


const unsigned kgenome_diag_emu_arg_reg64[6] = {
	KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RDX,
	KGENOME_EMU_R10, KGENOME_EMU_R8,  KGENOME_EMU_R9
};
const unsigned kgenome_diag_emu_arg_reg32[6] = {
	KGENOME_EMU_RBX, KGENOME_EMU_RCX, KGENOME_EMU_RDX,
	KGENOME_EMU_RSI, KGENOME_EMU_RDI, KGENOME_EMU_RBP
};
