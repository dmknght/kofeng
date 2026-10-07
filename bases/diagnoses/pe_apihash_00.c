#include <kofmod/kofpathogen.h>

/*
 * pe_apihash_00.c - a Windows program that finds the functions it calls by
 * walking the loader's module list instead of importing them.
 *
 *     mov rax, gs:[0x60]         ; the PEB
 *     mov rax, [rax+0x18]        ; PEB.Ldr
 *     ... walk InMemoryOrderModuleList, hash each export name, compare ...
 *     call rax                   ; whichever function the hash named
 *
 * WHAT THIS SAYS. The program READS THE LOADER DATA TO RESOLVE ITS OWN APIS,
 * which is a shape of Windows code and not a family: every Metasploit stager,
 * most packer stubs and a good deal of position-independent loaders do it.
 * The anchor is the read of the loader data. What the program then calls is
 * not in the import table and is named by the analysis this diagnose asks for.
 *
 * THE ALGORITHM IS NOT IN THIS FILE and cannot be. The hash, its seed, its
 * rotation and its combining step are what the author chooses and changes
 * between builds; the stub rebuilt with `ror 14` and a new seed resolves the
 * same calls. The route runs the program's own resolver against the modelled
 * loader and reads back which functions it arrived at - see diag_apihash.c.
 *
 *
 * ---- WHAT IT IS FOR, BESIDES A VERDICT ----------------------------------
 *
 * Nothing reads this diagnose by name yet, and it runs all the same, because
 * it SERVES the object's symbols: the functions the program resolved are put
 * into its symbol block as imports. A stager imports nothing, so without them
 * its normalised view says nothing about what it does.
 */

KOF_DIAG_NAME(DIAG_PE_APIHASH);

KOF_DIAG_VIA(KOF_DIAG_VIA_APIHASH);

KOF_DIAG_SERVES(KOF_SERVE_PE_SYMBOLS);

KOF_DIAG_WHEN(KOF_FACT_FORMAT, KOF_FMT_PE);

KOF_DIAG_ANCHOR(r, KOF_NUCLEO_SELF_RESOLVE, 0);
