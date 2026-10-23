/*
 * nucleo.h - WHAT A NUMBER OR A NAME MEANS, and nothing about how code is
 * read.
 *
 * Named for the nucleotide, the unit a gene is built from: one row here is
 * one base of what a detector later reads as a shape. It was vocab.h.
 *
 * This is the normalisation layer: syscall number -> capability, imported
 * name -> capability, and the words a reader sees for either. It was 1200
 * lines inside flow.c, which is a DISASSEMBLER, and the two have nothing to
 * do with each other - one knows how an instruction is spelled, the other
 * knows what `41` means on x86-64 and that it means something else on i386.
 *
 * WHY IT IS HERE AND NOT BESIDE THE DETECTOR that consumes it: whatever
 * reads these tables reads them WHILE DECODING, so putting them a layer up
 * would have the decoder calling into its own caller. Keeping them beside it costs
 * one include; inverting the dependency costs a callback on the hot path and
 * a reader who cannot tell which way the arrows go.
 *
 * ADDING AN ABI IS ADDING A TABLE HERE. Nothing that reads the code has to change -
 * which is the whole point, and it was not true while MIPS n64 was missing:
 * the numbers had to go into the middle of a six thousand line file.
 */

#ifndef KGENOME_NUCLEO_H
#define KGENOME_NUCLEO_H

#include <stdint.h>
#include <celllysis/capability.h>   /* KOF_NUCLEO_*, the capability words */


/*
 * ONE ROW PER SYSCALL THE VOCABULARY HAS A WORD FOR.
 *
 * The NAME is in the row on purpose. A chain step read from a syscall used to
 * carry only the number, so a page showed `syscall_9` and a reader had to
 * know that 9 is mmap on x86-64 and link on i386. The number means nothing
 * without the table that resolved it, so the name travels with the answer.
 */
/*
 * WHICH ARGUMENT A CALL DECIDES ITSELF BY, or KGENOME_NUCLEO_ROLE_NONE. Here
 * rather than with the decoder because every user of it is a row in a table
 * below.
 */
/*
 * WHICH ABI A SYSCALL TABLE BELONGS TO. Moved here from flow.h when the
 * chain backend was removed: the tables below are the only thing that ever
 * read it, and a vocabulary that needs a sweep to compile is a vocabulary
 * tied to one way of sweeping.
 */
enum kgenome_nucleo_arch {
	KGENOME_NUCLEO_A_MIPS32 = 1,
	/*
	 * AND MIPS64, WHICH IS A DIFFERENT ABI AND NOT A WIDER MIPS32.
	 *
	 * The instructions are the same - `li $v0,N` then `syscall` - so one
	 * decoder reads both. The NUMBERS are not: o32 bases its syscalls at
	 * 4000 and n64 at 5000, and they are not an offset apart either, so
	 * one table cannot serve. Reading an n64 object against the o32
	 * table resolves nothing at all: measured, 40 of 40 MIPS64 objects
	 * in the corpus produced ZERO capabilities while the sweep ran
	 * happily over every instruction.
	 *
	 * Corroborated before the table was written: every `li $v0`
	 * constant found across those 40 objects is >= 5000, and 5040,
	 * 5041, 5043 and 5044 - socket, connect, sendto, recvfrom - are the
	 * ones that recur, which is the profile of a network client and not
	 * of a mis-numbered table.
	 */
	KGENOME_NUCLEO_A_MIPS64,
	KGENOME_NUCLEO_A_ARM32,
	KGENOME_NUCLEO_A_ARM64,
	/*
	 * AND THE REST OF WHAT AN IoT BUILDER SHIPS. Measured over 20075
	 * executable objects of one Bazaar collection plus the lab here:
	 * 601 PowerPC, 349 SuperH, 345 m68k, 281 SPARC, 42 RISC-V - 8.8% of
	 * the corpus, and every one of them refused by the sweep before these
	 * existed. A botnet's build matrix is not a list of the architectures
	 * anyone develops on.
	 */
	KGENOME_NUCLEO_A_PPC32,
	KGENOME_NUCLEO_A_PPC64,
	KGENOME_NUCLEO_A_SPARC32,
	KGENOME_NUCLEO_A_RISCV,
	/*
	 * The two that are not four bytes wide. SuperH is two, and m68k is
	 * two to ten - so neither is swept by the word loop the four above
	 * share, and both get a reader of their own that reads HALFWORDS.
	 * Named here anyway, because what a caller has to say is still only
	 * "this is the architecture" - see kgenome_diag_cand_fixed.
	 */
	KGENOME_NUCLEO_A_SH,
	KGENOME_NUCLEO_A_M68K,
	/*
	 * AND THE TWO THE VARIABLE-LENGTH SWEEP HANDLES ITSELF.
	 *
	 * x86 and x86-64 never needed an entry here because the variable-length sweep
	 * takes `bits` and picks its own table. kgenome_nucleo_sys_name is asked
	 * from OUTSIDE the sweep, by something holding an object's
	 * architecture and a number, and "the architectures the fixed-width
	 * sweep knows" is not the question it is asking.
	 */
	KGENOME_NUCLEO_A_X86,
	KGENOME_NUCLEO_A_X86_64
};

#define KGENOME_NUCLEO_ROLE_NONE  0u
#define KGENOME_NUCLEO_ROLE_MMAP  1u   /* prot is argument 2    */
#define KGENOME_NUCLEO_ROLE_CLONE 2u   /* flags is argument 0   */
#define KGENOME_NUCLEO_ROLE_SOCK  3u   /* domain 0, type 1      */

#define KGENOME_NUCLEO_AF_UNIX    1u
#define KGENOME_NUCLEO_SOCK_DGRAM 2u
#define KGENOME_NUCLEO_SOCK_RAW   3u

/* CLONE_THREAD: the bit that makes a clone a thread and not a process. */
#define KGENOME_NUCLEO_CLONE_THREAD  0x00010000u

/*
 * WHICH TARGET A NAME IS READ AGAINST. An ELF object and a PE object do not spell what they ask the system for the same way,
 * and a script does not call the system at all: each has its own table of names, in the one vocabulary of capabilities.
 * What the caller holds is the object's format, which is the target.
 */
enum kgenome_nucleo_target {
	KGENOME_NUCLEO_T_ELF = 1,
	KGENOME_NUCLEO_T_PE,
	KGENOME_NUCLEO_T_PHP,
	/*
	 * THE OTHER SCRIPTING LANGUAGES, one table each (nucleo_names_<name>.c), in the order the tables are laid end to end. A language
	 * has its own table when it has its own runtime API: the names of one are not the names of another (python's os.system is not
	 * perl's system), and a row copied between two tables is a name that means something in a language that does not have it. Two
	 * lexer ids share a table when they are one API: VBS and ASP (classic asp runs vbscript; its Request/Response/Server objects are
	 * COM and are written the same in JScript), ASPX's C# and VB.NET (the .NET class library), JSP (Java) is its own.
	 *
	 *   JS     javascript: node, the browser and wsh/jscript. One table: the three share a lexer and a syntax and their names do not
	 *          collide (child_process.exec, document.cookie), so one lookup answers all of them; what WSH adds is COM, which is VBS's
	 *   PY     python                          PERL   perl                         RUBY   ruby
	 *   LUA    lua                             TCL    tcl                          SH     posix shell / bash
	 *   BAT    windows batch (cmd.exe)         PSH    powershell
	 *   VBS    vbscript, and the vbscript of a classic asp page (KGENOME_TEXTUAL_LANG_VBS and _ASP)
	 *   DOTNET c# and vb.net, as asp.net runs them (KGENOME_TEXTUAL_LANG_ASPX)
	 *   JAVA   java, as a jsp page runs it (KGENOME_TEXTUAL_LANG_JSP)
	 *   CFML   coldfusion: the functions and the tags (KGENOME_TEXTUAL_LANG_CFM)
	 */
	KGENOME_NUCLEO_T_JS,
	KGENOME_NUCLEO_T_PY,
	KGENOME_NUCLEO_T_PERL,
	KGENOME_NUCLEO_T_RUBY,
	KGENOME_NUCLEO_T_LUA,
	KGENOME_NUCLEO_T_TCL,
	KGENOME_NUCLEO_T_SH,
	KGENOME_NUCLEO_T_BAT,
	KGENOME_NUCLEO_T_PSH,
	KGENOME_NUCLEO_T_VBS,
	KGENOME_NUCLEO_T_DOTNET,
	KGENOME_NUCLEO_T_JAVA,
	KGENOME_NUCLEO_T_CFML
};

/*
 * HOW A ROW OF A SCRIPT TABLE IS SPELLED - one rule for all of them, because the step that reads call syntax reads it by this.
 *
 * A row's name is spelled the way the language spells it AT THE POINT OF THE CALL. Where the qualifier is part of the identity it is
 * in the row, joined with '.' whatever the language uses between them ("os.system", "subprocess.Popen", "WScript.Shell.Run",
 * "Request.Form", "System.Diagnostics.Process.Start" without its namespace as "Process.Start", "Runtime.exec"; perl's
 * `Socket::inet_aton` is "Socket.inet_aton", ruby's `Net::HTTP.get` is "Net.HTTP.get"); where the bare name is unambiguous the row is
 * bare ("eval", "exec", "system", "decode_base64"). A call on the result of a factory call is written without the factory:
 * `Runtime.getRuntime().exec(c)` is "Runtime.exec". For an object a program holds in a variable the qualifier is the CLASS of the
 * object (VBScript: the ProgID given to CreateObject, written without its version number, so `o.Run` after
 * `Set o = CreateObject("WScript.Shell")` is "WScript.Shell.Run", and "MSXML2.XMLHTTP.6.0" is "MSXML2.XMLHTTP"; .NET and Java: the
 * type; python: "socket.socket.connect" for `s.connect()` after `s = socket.socket()`). COM IS WRITTEN ONCE, in the VBS table, and is
 * looked up there by every language that reaches a COM object (JScript's `new ActiveXObject`, PowerShell's `New-Object -ComObject`,
 * ASP's Server.CreateObject): the other tables do not repeat it.
 *
 * A request source that is a variable or a member and not a call is a row too ("Request", "Request.QueryString", "request.args",
 * "form", "ENV.QUERY_STRING"); a CFML scope is the scope and its key is the matcher's. A language whose programs run COMMANDS and not
 * functions (sh, bat, and tcl's and powershell's commands) has a row per command word as written, without the extension of the
 * program (.exe, .com, .bat, .cmd), where a command is the first word of a command line; the ensemble commands of tcl are the
 * command and its subcommand joined ("file.delete"); powershell writes a static member as "Class.Member" without "System."
 * ("Convert.FromBase64String"). A CFML tag is its name without the angle brackets ("cfexecute", "cfinclude", "cffile") and a function
 * is its name. Case is the table's `fold`: VBScript, batch, PowerShell, CFML and .NET do not care, the rest do.
 *
 * WHERE ONE NAME IS TWO CAPABILITIES BY ITS ARGUMENTS (python's eval and exec of a literal or of a value, os.system, certutil,
 * cffile, `sh -c`) the row holds the dominant or the weaker one and says so at the row; the argument is the matcher's.
 */
/* The row every script table has for a call whose callee is a value (data-call): not a name in any language, so it cannot be written
 * by a program and cannot collide with one. */
#define KGENOME_NUCLEO_DYNAMIC_NAME "(dynamic)"
/* And the one for a class that is a value (data-load). */
#define KGENOME_NUCLEO_DYNLOAD_NAME "(load)"

struct kgenome_sysrow { uint16_t nr; uint16_t cap; uint8_t role; const char *name; };

/*
 * The per-ABI syscall tables are private to nucleo.c: a caller asks a question
 * (kgenome_nucleo_sys_name, kgenome_nucleo_sys_name_abi, the cap lookups) and never holds a
 * table, because a table handed out is a table that gets copied.
 */

/* The three register roles each ABI uses, so the sweep below reads one way. */
struct kgenome_nucleo_abi {
	const struct kgenome_sysrow *tab;
	uint32_t             n_tab;
	/*
	 * A SECOND TABLE, because three of these ports are i386's numbering
	 * PLUS something of their own. Copying the i386 table's forty rows into each
	 * would be three places to fix a number instead of one, and the row
	 * that got missed would be the one nobody notices - the table is
	 * consulted, finds nothing, and the object simply has no node.
	 */
	const struct kgenome_sysrow *tab2;
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

const struct kgenome_nucleo_abi *kgenome_nucleo_abi_of(unsigned arch);
/* 1 when every syscall table is strictly ascending in number - the search relies on it. Tests only. */
int kgenome_nucleo_sys_ordered(void);

/* The same two answers as kgenome_nucleo_cap_of_syscall and kgenome_nucleo_sys_name, for a port
 * described by its kgenome_nucleo_abi. `arg` indexes from the port's first argument. */
uint16_t kgenome_nucleo_cap_of_syscall_abi(const struct kgenome_nucleo_abi *fx, uint32_t nr,
				     const uint64_t *arg, uint8_t *flags);
const char *kgenome_nucleo_sys_name_abi(const struct kgenome_nucleo_abi *fx, uint32_t nr);

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
 * `read` with nothing anywhere setting the 0. The sweep (diag_site.c) and the wrapper
 * analysis (diag_wrapper_calls.c) read this table for it; the old note in flow.c went with the chain backend.
 */
int kgenome_nucleo_sys_zero_on_success(const char *name);
/* Whether argument `idx` is a flag set for which "this bit is set" is enough
 * to refine the call - see the note at its definition. */
int kgenome_nucleo_arg_is_flags(unsigned bits, uint32_t nr, unsigned idx);
/* Whether a socket call asks for SOCK_NONBLOCK in its type - see the definition. */
int kgenome_nucleo_sock_nonblock(unsigned bits, uint32_t nr, const uint64_t *arg,
			   unsigned have);
int kgenome_nucleo_sockcall_nonblock(uint32_t sub, const uint64_t *arg, unsigned have);
/* One operation of i386's socketcall, from the arguments found in its array. */
uint16_t kgenome_nucleo_cap_of_sockcall(uint32_t sub, const uint64_t *arg,
				  unsigned have, uint8_t *flags);

/*
 * THE NAME OF A SYSCALL NUMBER ON x86, or NULL.
 *
 * Here rather than at the one caller because the caller would need the
 * table, and handing a table out is handing out the thing that must not be
 * copied.
 */
const char *kgenome_nucleo_sys_name(unsigned bits, uint32_t nr);

/*
 * THE NAME OF ANY LINUX SYSCALL NUMBER, x86-64 (`bits` 64) or i386 (anything else), or NULL for a number the kernel does not have. Not the
 * vocabulary's: kgenome_nucleo_sys_name answers only for the syscalls that carry a capability, and this one for every number, from the
 * kernel's own table (nucleo_sysnames.c, generated). What a reader of code asks about a number; what a matcher asks is the other.
 */
const char *kgenome_nucleo_sys_name_all(unsigned bits, uint32_t nr);


/*
 * THE LOOKUPS THEMSELVES, declared here because flow.h is gone.
 *
 * They were prototyped in the decoder's header, which was the only caller.
 * With that file deleted the definitions had no declaration at all and the
 * build said so six times over - a definition no header names is one every
 * new caller has to spell for itself, and two spellings of one signature is
 * how an argument type drifts.
 */

/* Syscall number -> capability, for a caller that has a RUN rather than
 * code. `arg` may be NULL; `flags`, when given, receives the flow flags the
 * arguments imply (a WX mapping, an exec'able allocation). */
uint16_t kgenome_nucleo_cap_of_syscall(unsigned bits, uint32_t nr,
				 const uint64_t *arg, uint8_t *flags);

/* Imported or exported name -> capability, and KGENOME_NUCLEO_NONE when the name is
 * not one of the words. An `@` ends the comparison, so "socket@GLIBC_2.4"
 * reads as "socket". */
uint16_t kgenome_nucleo_cap_of_name(unsigned target, const char *sym);
/* Does any name in that table mean this capability (or a case of it)? A
 * capability nobody can name can never be found by its imports. */
int kgenome_nucleo_cap_named(uint16_t cap);
/* The capability this one is a special case of, or KGENOME_NUCLEO_NONE. See the
 * note at the definition: a rule names the level it means, and the matcher
 * accepts anything more specific. */
uint16_t kgenome_nucleo_cap_generic(uint16_t cap);

/*
 * DOES A CALL OF THIS CAPABILITY HAND BACK THE OBJECT IT MADE, so a later
 * call using that value is linked to it.
 *
 * ONE STATEMENT OF IT, HERE, because the question is the vocabulary's and
 * not any one walk's. It was answered in three places and they disagreed:
 * the symbol route said a credential constructor and a symbol lookup hand
 * one back and a W+X mapping does not, the emulator said the opposite, and
 * the syscall sweep asked by NAME with a third list again. Which link could
 * form then depended on which route had run rather than on the program.
 *
 * `nm` IS THE ONE PLACE A NAME STILL DECIDES, and it is needed: mmap and
 * mprotect are one capability - an executable mapping - and only the first
 * is a constructor. mprotect is HANDED a mapping and returns a status, so
 * recording its return value as the object would link everything after it
 * to a zero. NULL means the caller has no name, and the common case for a
 * capability that constructs is that it constructs.
 */
int kgenome_nucleo_hands_on(uint16_t cap, const char *nm);

/*
 * DOES A CALL OF THIS CAPABILITY BE GIVEN A NAME, and in which argument.
 *
 * The name of a kernel symbol the call is about - "sys_call_table",
 * "do_exit" - which is the one part of a hook that says WHAT is being
 * reached for and survives every change of how it is reached. The
 * vocabulary says only WHERE the name is carried:
 *
 *   KGENOME_NAME_DIRECT   the argument IS a C string
 *   KGENOME_NAME_OBJECT   the argument points at an OBJECT, and the name is a
 *                     C string some pointer inside it points at
 *
 * AND NEVER WHICH FIELD. struct kprobe keeps its symbol_name at an offset
 * that is a fact about one kernel build - the layout moves with the version
 * and the configuration, and a kretprobe embeds the probe at a different
 * place - so a table naming the offset would be a table about one kernel,
 * and exactly the kind of source-code representation a rename or a rebuild
 * changes. The walk reads the object's words and asks which of them are
 * names; the layout never enters.
 *
 * Returns the kind, or 0 for a capability that carries no name. `*arg` is
 * the argument's index.
 */
#define KGENOME_NAME_DIRECT 1u
#define KGENOME_NAME_OBJECT 2u
unsigned kgenome_nucleo_name_arg(uint16_t cap, unsigned *arg);

/* The name's index, 1-based, or 0 - counted over the tables laid end to end, so the id says the target too and
 * kgenome_nucleo_name_of needs none. Carried instead of the string so a node is fixed width. */
uint16_t kgenome_nucleo_name_id(unsigned target, const char *sym);
/* The capability AND the id of a name from ONE lookup (kgenome_nucleo_cap_of_name and kgenome_nucleo_name_id are two searches of the same table): `*id` is the
 * name's id or 0, and the return is the capability or KGENOME_NUCLEO_NONE. `id` may be NULL. */
uint16_t kgenome_nucleo_name_lookup(unsigned target, const char *sym, uint16_t *id);

/* A named call refined by its first four arguments - see the .c. */
uint16_t kgenome_nucleo_cap_of_call(unsigned target, const char *name, const uint64_t *arg,
			      uint8_t *flags);


/* And back: the word for an id, or NULL. */
const char *kgenome_nucleo_name_of(uint16_t id);

#endif
