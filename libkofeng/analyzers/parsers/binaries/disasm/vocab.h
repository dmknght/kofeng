/*
 * vocab.h - WHAT A NUMBER OR A NAME MEANS, and nothing about how code is read.
 *
 * This is the normalisation layer: syscall number -> capability, imported
 * name -> capability, and the words a reader sees for either. It was 1200
 * lines inside flow.c, which is a DISASSEMBLER, and the two have nothing to
 * do with each other - one knows how an instruction is spelled, the other
 * knows what `41` means on x86-64 and that it means something else on i386.
 *
 * WHY IT IS HERE AND NOT BESIDE pathogen, which is what consumes it: the
 * sweep reads these tables WHILE DECODING, so putting them a layer up would
 * have the decoder calling into its own caller. Keeping them beside it costs
 * one include; inverting the dependency costs a callback on the hot path and
 * a reader who cannot tell which way the arrows go.
 *
 * ADDING AN ABI IS ADDING A TABLE HERE. Nothing in flow.c has to change -
 * which is the whole point, and it was not true while MIPS n64 was missing:
 * the numbers had to go into the middle of a six thousand line file.
 */

#ifndef KOF_DISASM_VOCAB_H
#define KOF_DISASM_VOCAB_H

#include <stdint.h>

#include "../../../../kofcore/kofmod/kofsig.h"

/*
 * ONE ROW PER SYSCALL THE VOCABULARY HAS A WORD FOR.
 *
 * The NAME is in the row on purpose. A chain step read from a syscall used to
 * carry only the number, so a page showed `syscall_9` and a reader had to
 * know that 9 is mmap on x86-64 and link on i386. The number means nothing
 * without the table that resolved it, so the name travels with the answer.
 */
/*
 * WHICH ARGUMENT A CALL DECIDES ITSELF BY, or KOF_FLOW_ROLE_NONE. Here
 * rather than in flow.h because every user of it is a row in a table below.
 */
#define KOF_FLOW_ROLE_NONE  0u
#define KOF_FLOW_ROLE_MMAP  1u   /* prot is argument 2    */
#define KOF_FLOW_ROLE_CLONE 2u   /* flags is argument 0   */
#define KOF_FLOW_ROLE_SOCK  3u   /* domain 0, type 1      */

#define FLOW_AF_UNIX    1u
#define FLOW_SOCK_DGRAM 2u
#define FLOW_SOCK_RAW   3u

/* CLONE_THREAD: the bit that makes a clone a thread and not a process. */
#define FLOW_CLONE_THREAD  0x00010000u

struct sysrow { uint16_t nr; uint8_t cap; uint8_t role; const char *name; };

/*
 * The tables, one per ABI, with their lengths beside them.
 *
 * The length is a variable and not `sizeof`, because `sizeof` needs the
 * definition and these are declarations. Exporting the count is what lets
 * flow.c's FXN() keep working across the split.
 */
#define KOF_SYSTAB(t) extern const struct sysrow kof_##t[]; \
                      extern const uint32_t kof_##t##_n
KOF_SYSTAB(sys64);      /* Linux x86-64            */
KOF_SYSTAB(sys32);      /* Linux i386              */
KOF_SYSTAB(sockcall);   /* i386's socketcall demux */
KOF_SYSTAB(sys_a64);    /* AArch64 / asm-generic   */
KOF_SYSTAB(sys_arm);
KOF_SYSTAB(sys_mips);   /* o32, based at 4000      */
KOF_SYSTAB(sys_mips64); /* n64, based at 5000      */
KOF_SYSTAB(sys_ppc);
KOF_SYSTAB(sys_sparc);
#undef KOF_SYSTAB

/* The three register roles each ABI uses, so the sweep below reads one way. */
struct fxabi {
	const struct sysrow *tab;
	uint32_t             n_tab;
	/*
	 * A SECOND TABLE, because three of these ports are i386's numbering
	 * PLUS something of their own. Copying kof_sys32's forty rows into each
	 * would be three places to fix a number instead of one, and the row
	 * that got missed would be the one nobody notices - the table is
	 * consulted, finds nothing, and the object simply has no node.
	 */
	const struct sysrow *tab2;
	uint32_t             n_tab2;
	/*
	 * THE NUMBER THAT MULTIPLEXES EVERY SOCKET CALL, or 0.
	 *
	 * The ports that inherited i386's numbering inherited socketcall with
	 * it: one syscall, the operation in the first argument. Without
	 * reading that argument the whole network half of such a program is
	 * invisible - measured, 68% of the 32-bit PowerPC objects here use
	 * it, and PowerPC produced not one network behaviour until this was
	 * read. sweep_half has done this for SuperH and m68k since it was
	 * written; the word loop had not.
	 */
	uint8_t              sockcall;
	uint8_t              sel;        /* holds the syscall number     */
	uint8_t              ret;        /* holds the result             */
	uint8_t              arg0, n_arg;/* first argument register, how many */
	uint8_t              prot_arg;   /* which argument mmap's prot is */
};

const struct fxabi *kof_fx_abi_of(unsigned arch);

/* Linear, because the tables are tens of rows and a binary search would need
 * them sorted - which is a rule the next person adding a row would break
 * without the build saying so. */
/*
 * DOES THIS SYSCALL RETURN ZERO WHEN IT SUCCEEDS.
 *
 * An ABI fact, which is why it is here and not in the decoder: Linux returns
 * a negative errno on failure, and for this group of calls the success value
 * is exactly 0. For `socket` or `read` it is not - they return a descriptor
 * or a count - so the question has to be asked per name and cannot be
 * guessed from the capability (`net-open` covers socket, which returns a
 * descriptor, AND bind, which returns zero).
 *
 * WHAT IT IS FOR. A stager can then leave the number for its NEXT syscall in
 * rax and never write it: msfvenom's reverse_tcp does exactly that -
 * `connect` returns 0, the branch that continues is the one taken on
 * success, and the `syscall` three instructions later is therefore
 * `read` with nothing anywhere setting the 0. See the note on the success
 * branch in flow.c.
 */
int kof_sys_zero_on_success(const char *name);

/*
 * How many arguments the call takes, or 0 when it is not written down. The
 * sweep reads four argument registers whatever the call uses, so without
 * this a leftover register is displayed as an argument - see kof_sys_argc.
 */
uint8_t kof_sys_argc(const char *name);

/* Whether control continues after the call - see kof_sys_noreturn. The
 * instruction after `exit` is not its successor. */
int kof_sys_noreturn(unsigned bits, uint32_t nr);

uint8_t     kof_sys_look(const struct sysrow *t, uint32_t n, uint32_t nr);
const char *kof_sys_look_name(const struct sysrow *t, uint32_t n, uint32_t nr);
uint8_t     kof_sys_look_role(const struct sysrow *t, uint32_t n, uint32_t nr);

#endif
