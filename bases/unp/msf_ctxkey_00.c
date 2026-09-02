/*
 * msf_ctxkey_00.c - msfvenom's context-keyed encoders: name them, decode none.
 *
 * THIS MODULE RECOVERS NOTHING, ON PURPOSE, and that is the first thing to say
 * about it because it is unusual. The reason is a fact about these encoders
 * rather than a limit of this engine: THE KEY IS NOT IN THE FILE. Each of the
 * four derives it from something on the machine the payload is meant to run on,
 * so the sample carries the ciphertext and the recipe and nothing else. No
 * reader of the bytes can produce the key, and neither can the emulator - it
 * would have to guess the same hostname, the same CPU, the same file and the
 * same clock the encoder saw.
 *
 * The right answer is therefore to say so. Without this a context-keyed sample
 * reaches the end of every module, gets nothing, and is reported as an unknown
 * packer - which is wrong twice: the encoder is known, and trying is pointless.
 * With it the object is named and KOF_UNP_ENCRYPTED is on the record, which is
 * the value the ABI has for exactly this: content encrypted with no key
 * available. Same shape, and the same reasoning, as midgetpack_00.c.
 *
 *
 * THE FOUR, AND WHAT EACH KEYS ON
 *
 *   x64/xor_context      6a 3f 58 48 8d 3c 24 0f 05 48 8b 5f 41
 *     push 63; pop rax; lea rdi,[rsp]; syscall  - amd64 syscall 63 is uname(2),
 *     and 0x41 into struct utsname is `nodename`, the second 65-byte field. The
 *     key is EIGHT BYTES OF THE HOSTNAME.
 *
 *   x86/context_cpuid    31 f6 31 ff 89 f8 31 c9 0f a2
 *     cpuid. The key comes out of the registers it returns, so it is a property
 *     of the processor model the payload runs on.
 *
 *   x86/context_stat     d9 ee d9 74 24 f4 5b eb 07 "/bin/ls"
 *     an fnstenv GetPC, a jump over the literal path, then stat(2) on it. The
 *     key is a field of that file's inode on the target - its size or its mtime,
 *     depending on the build.
 *
 *   x86/context_time     31 db 8d 43 0d cd 80
 *     xor ebx,ebx; lea eax,[ebx+13]; int 0x80 - i386 syscall 13 is time(2). The
 *     key is the clock, coarsened, at the moment the payload runs. This one
 *     cannot even be decoded by capturing the target's state later: it has to be
 *     the same interval the encoder used.
 *
 * Each pattern is the syscall or instruction that FETCHES the key, which is the
 * one part of these stubs that cannot be moved without changing what they key
 * on. The bytes around it - register choices, the loop - vary between builds.
 */

#include <kofmod/kofsig.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

/*
 * ELF and the formatless children, like the decoders beside it: a
 * context-keyed layer can sit under another encoder, and the object it arrives
 * as then has no header.
 */
KOF_TARGET_FORMAT(KOF_FMT_ELF | KOF_FMT_PE | KOF_FMT_UNKNOWN);

/*
 * The family this recognises, so a heuristic predicting Meterp reaches it first.
 *
 * THIS WAS LEFT OFF ONCE, with the reasoning that a module producing no child
 * can never be the one that opens an object and so gains nothing by running
 * early. That missed the other way a module ends a pass: KOF_UNP_BROKEN goes
 * through the host's `incomplete` hook to sc->broken, and the general pass
 * begins each iteration with `if (sc->broken) break`. So recognising the
 * encoder in the family pass stops the remaining unpackers from being entered
 * at all - which on this database is fourteen modules that would each have
 * declined, on precisely the objects where nothing can be recovered.
 */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "Meterp");

/* Which of the four, for the log line. */
enum {
	K_UNAME = 1,
	K_CPUID = 2,
	K_STAT  = 3,
	K_TIME  = 4
};

/*
 * The key-fetch of each, flattened into one array so the table below can hold
 * an index rather than a pointer - a pointer needs a relocation and a module is
 * not allowed writable data. See the same note in msf_x86_dword_00.c.
 */
static const uint8_t fetch_pat[] = {
	/* --- K_UNAME, 13 --- */
	0x6a,0x3f,0x58,                /* push 63; pop rax    (uname)     */
	0x48,0x8d,0x3c,0x24,           /* lea rdi, [rsp]                  */
	0x0f,0x05,                     /* syscall                         */
	0x48,0x8b,0x5f,0x41,           /* mov rbx, [rdi+0x41] (nodename)  */
	/* --- K_CPUID, 10 --- */
	0x31,0xf6,0x31,0xff,           /* xor esi,esi; xor edi,edi        */
	0x89,0xf8,0x31,0xc9,           /* mov eax,edi; xor ecx,ecx        */
	0x0f,0xa2,                     /* cpuid                           */
	/* --- K_STAT, 16 --- */
	0xd9,0xee,                     /* fldz                            */
	0xd9,0x74,0x24,0xf4,           /* fnstenv [esp-0xc]               */
	0x5b,                          /* pop ebx                         */
	0xeb,0x07,                     /* jmp over the path               */
	0x2f,0x62,0x69,0x6e,0x2f,0x6c,0x73,   /* "/bin/ls"                */
	/* --- K_TIME, 7 --- */
	0x31,0xdb,                     /* xor ebx, ebx                    */
	0x8d,0x43,0x0d,                /* lea eax, [ebx+13]   (time)      */
	0xcd,0x80                      /* int 0x80                        */
};

static const struct {
	uint32_t at, n, code;
} fetch[] = {
	{  0u, 13u, K_UNAME },
	{ 13u, 10u, K_CPUID },
	{ 23u, 16u, K_STAT  },
	{ 39u,  7u, K_TIME  }
};

#define N_FETCH (sizeof fetch / sizeof fetch[0])

/* The rows have to cover the array exactly - see the same check, and the same
 * reason for it, in msf_x86_dword_00.c. */
typedef char fetch_rows_cover_pat[
	(39u + 7u) == (sizeof fetch_pat / sizeof fetch_pat[0]) ? 1 : -1];

/*
 * How far into the object the key-fetch may sit.
 *
 * Not at the entry point: three of the four put a register setup or a GetPC in
 * front of it, and a build with one more instruction would move it again. A
 * bounded scan from the entry is what makes the module survive that, and the
 * bound is what stops it being a search of the whole object for a two-byte
 * instruction - `cpuid` is two bytes and would otherwise be found in data.
 */
#define FETCH_WINDOW 64u

KOF_DEFINE_UNPACK
{
	uint64_t ep, at;
	uint32_t c, k;

	ep = ctx->entry_off;
	if (ep == KOF_NA || ep == KOF_BROKEN)
		ep = 0;

	for (at = ep; at < ep + FETCH_WINDOW; at++) {
		for (c = 0; c < N_FETCH; c++) {
			if (!kof_in_obj(at, fetch[c].n))
				continue;
			for (k = 0; k < fetch[c].n; k++)
				if (kof_u8(at + k) != fetch_pat[fetch[c].at + k])
					break;
			if (k != fetch[c].n)
				continue;

			/*
			 * Named before the reason is recorded, so the viewer's
			 * packer field says which of the four it is rather than
			 * leaving the object labelled by whichever module spoke
			 * last - the same ordering midgetpack_00.c uses.
			 */
			kof_debug("MSF.ctxkey", fetch[c].code);

			/*
			 * And that is the end of it: the reason, and no bytes.
			 *
			 * Emitting the ciphertext as a child was considered and
			 * rejected for the reason ezuri.c gives about a wrong
			 * tail offset - every module downstream would be run
			 * against noise, and the object panel would carry an
			 * entry that can never say anything.
			 */
			KOF_UNP_BROKEN(KOF_UNP_ENCRYPTED);
		}
	}
}
