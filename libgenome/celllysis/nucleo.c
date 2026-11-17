/* See nucleo.h. The name half: what an imported name means, what a capability is called. */

#include "nucleo_private.h"

#include <string.h>

#include <kofcore.h>

/*
 * WHAT A NAME IS, in the same vocabulary, for the target it is read against.
 *
 * One table per target (nucleo_names_elf.c, _pe.c, _php.c, and one per other scripting language - see the targets in nucleo.h): the ELF and
 * the PE system interfaces are two APIs, and each script language has another. They were one table with the Windows names beside the POSIX ones "on purpose" - VirtualAlloc and mmap are the same
 * fact about a program - and that is still true of the WORDS: a rule is written over capabilities and is shared. What is not
 * shared is the spelling, and one table made every name answer for every target (a PE "unlink" is not an ELF one, and a PHP
 * "system" is neither).
 *
 * Longest-sensible match and no prefix guessing: "recv" and "recvfrom" are both rows rather than matched by a prefix, because
 * "recvmmsg" and "recvmsg" would fall out of a prefix test and so would anything a future libc adds. An ELF import may carry a
 * version suffix - "open64@@GLIBC_2.2.5" is the same function as "open64" - and an `@` ends the comparison.
 *
 * AN ID IS A POSITION IN THE TABLES LAID END TO END, 1-based, so it says the target as well and nothing needs the target to
 * turn it back into a name.
 */
static const struct kgenome_nucleo_names *const tables[] = {
	&kgenome_nucleo_names_elf, &kgenome_nucleo_names_pe, &kgenome_nucleo_names_php,
	&kgenome_nucleo_names_js,
	&kgenome_nucleo_names_py,
	&kgenome_nucleo_names_perl,
	&kgenome_nucleo_names_ruby,
	&kgenome_nucleo_names_lua,
	&kgenome_nucleo_names_tcl,
	&kgenome_nucleo_names_sh,
	&kgenome_nucleo_names_bat,
	&kgenome_nucleo_names_psh,
	&kgenome_nucleo_names_vbs,
	&kgenome_nucleo_names_dotnet,
	&kgenome_nucleo_names_java,
	&kgenome_nucleo_names_cfml
};

static const struct kgenome_nucleo_names *table_of(unsigned target, uint32_t *base, size_t *pos)
{
	size_t t;
	uint32_t at = 0;

	for (t = 0; t < sizeof tables / sizeof tables[0]; t++) {
		if (tables[t]->target == target) {
			*base = at;
			*pos = t;
			return tables[t];
		}
		at += tables[t]->n;
	}
	return NULL;
}

static int same_name(const char *a, const char *b, int fold)
{
	for (;;) {
		char x = *a, y = *b;

		if (fold) {
			x = (char)((unsigned char)x >= 'A' && (unsigned char)x <= 'Z' ? x + 32 : x);
			y = (char)((unsigned char)y >= 'A' && (unsigned char)y <= 'Z' ? y + 32 : y);
		}
		if (!x)
			return !y || y == '@';
		if (x != y)
			return 0;
		a++;
		b++;
	}
}

/*
 * THE ROW OF A NAME, found by its hash in the const index of nucleo_index.c and not by reading the rows in turn (measured, callgrind over 71 php files: the
 * scan was 204 M Ir of 4.1 G, ~500 rows for every identifier of every layer of every script). The index is generated from the tables (tools/gen_nucleo_index.py) and
 * holds no state at run time. The hash is FNV-1a over the name up to its NUL, folded to lower case for a `fold` table; a looked-up name stops at its NUL or at its `@` (a
 * version suffix), the two places same_name stops. The hash only picks which rows to read: the answer is same_name's, and equal names (a duplicate row) share a hash and
 * were placed in row order, so the FIRST row wins as it did in the scan. The generator refuses a table with an empty name, an "@" in a name or 65535 rows, so every
 * name of every table is reachable by hash (tests/lib/genome/nucleo_index.c asks every row of every table, in variants, against the scan written there from these rules).
 */
static uint32_t nidx_hash(const char *s, int fold)
{
	uint32_t h = KOF_HASH_INIT;

	for (; *s && *s != '@'; s++)
		h = kof_hash_step(h, fold ? kof_lower_byte((uint8_t)*s) : (uint8_t)*s);
	return h;
}

/* The row of `target`'s table that `sym` is, or NULL; `*id` is its position over all the tables. */
static const struct kgenome_nucleo_namerow *names_find(unsigned target, const char *sym, uint32_t *id)
{
	uint32_t base, j, m;
	size_t pos = 0;
	const struct kgenome_nucleo_names *t = table_of(target, &base, &pos);
	const struct kgenome_nucleo_index *ix = &kgenome_nucleo_index[pos];

	if (!sym || !*sym || !t)
		return NULL;
	m = ix->cap - 1u;
	for (j = nidx_hash(sym, t->fold) & m; ix->slot[j]; j = (j + 1u) & m) {
		uint32_t at = (uint32_t)ix->slot[j] - 1u;

		if (same_name(t->row[at].name, sym, t->fold)) {
			if (id)
				*id = base + at + 1u;
			return &t->row[at];
		}
	}
	return NULL;
}

/*
 * A NAMED CALL, REFINED BY THE ARGUMENTS IT WAS MADE WITH - the same job
 * kgenome_nucleo_cap_of_syscall does for a system call, for code that reached an API
 * by name or was observed calling one.
 *
 * VirtualAlloc and VirtualProtect become an executable allocation when the
 * protection asks for execute (PAGE_EXECUTE 0x10, _READ 0x20, _READWRITE 0x40,
 * _WRITECOPY 0x80), and W+X when it also asks for write: the Windows words for
 * what mmap and mprotect say with PROT_EXEC. Measured, the Metasploit stager
 * asks for 0x40.
 *
 * `arg` holds the first four arguments, which is what is carried; a call whose
 * protection is a later argument is left as it was named rather than guessed.
 */
uint16_t kgenome_nucleo_cap_of_call(unsigned target, const char *name, const uint64_t *arg,
			      uint8_t *flags)
{
	const struct kgenome_nucleo_namerow *row = names_find(target, name, NULL);
	uint16_t cap = row ? row->cap : KGENOME_NUCLEO_NONE;

	if (flags)
		*flags = 0;
	if (!arg || cap == KGENOME_NUCLEO_NONE)
		return cap;
	if (cap == KGENOME_NUCLEO_ALLOC) {
		uint64_t prot = 0;
		int have = 0;

		if (row->refine == KGENOME_NUCLEO_REFINE_PROT_ARG3) {
			prot = arg[3];
			have = 1;
		} else if (row->refine == KGENOME_NUCLEO_REFINE_PROT_ARG2) {
			prot = arg[2];
			have = 1;
		}
		if (have && (prot & 0xf0u)) {
			if (flags && (prot & 0xc0u))    /* ..._READWRITE, ..._WRITECOPY */
				*flags = KGENOME_NUCLEO_F_WX;
			return KGENOME_NUCLEO_ALLOC_EXEC;
		}
		return cap;
	}
	if (cap == KGENOME_NUCLEO_NET_OPEN && row->refine == KGENOME_NUCLEO_REFINE_SOCK)
		return kgenome_nucleo_sock_kind(arg, flags);
	return cap;
}

uint16_t kgenome_nucleo_cap_of_name(unsigned target, const char *sym)
{
	return kgenome_nucleo_name_lookup(target, sym, NULL);
}

/* A row with no capability (a fact-only row: an indirect entry, a release) answers KGENOME_NUCLEO_NONE with its id: a caller that
 * makes a node reads the capability (diag_scan.c, the PE route), and a name the vocabulary has no word for makes none. */
uint16_t kgenome_nucleo_name_lookup(unsigned target, const char *sym, uint16_t *id)
{
	uint32_t rid = 0;
	const struct kgenome_nucleo_namerow *row = names_find(target, sym, &rid);

	if (id)
		*id = row ? (uint16_t)rid : 0u;
	return row ? row->cap : KGENOME_NUCLEO_NONE;
}

/* ---- the row's shape (see nucleo.h, "THE ROW OF A CALL AND ITS SHAPE") ---- */

uint16_t kgenome_nucleo_row_of(unsigned target, const char *sym)
{
	uint32_t rid = 0;

	return names_find(target, sym, &rid) ? (uint16_t)rid : 0u;
}

uint16_t kgenome_nucleo_row_cap(uint16_t row)
{
	size_t t;

	if (!row)
		return KGENOME_NUCLEO_NONE;
	for (t = 0; t < sizeof tables / sizeof tables[0]; t++) {
		if (row <= tables[t]->n)
			return tables[t]->row[row - 1u].cap;
		row = (uint16_t)(row - tables[t]->n);
	}
	return KGENOME_NUCLEO_NONE;
}

/* The shape of the capability: the hand-written list (nucleo_capshape.c) is short and read in turn; index 0 is the empty shape. */
static const struct kgenome_nucleo_shape *cap_shape(uint16_t cap)
{
	uint32_t i;

	for (i = 0; i < kgenome_nucleo_capshape_n; i++)
		if (kgenome_nucleo_capshape_cap[i] == cap)
			return &kgenome_nucleo_shapes[kgenome_nucleo_capshape_shape[i]];
	return &kgenome_nucleo_shapes[0];
}

static const struct kgenome_nucleo_shape *row_shape(uint16_t row)
{
	if (!row || row > kgenome_nucleo_rows_n)
		return NULL;
	return &kgenome_nucleo_shapes[kgenome_nucleo_row_shape[row - 1u]];
}

static int shape_hands_on(const struct kgenome_nucleo_shape *s)
{
	return s->res == KGENOME_NUCLEO_RES_HANDLE || s->res == KGENOME_NUCLEO_RES_POINTER || s->res == KGENOME_NUCLEO_RES_CODEPTR;
}

uint8_t kgenome_nucleo_row_role(uint16_t row, unsigned i)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s && i < 8u ? s->role[i] : 0u;
}

int kgenome_nucleo_row_field(uint16_t row, unsigned i)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s && i < 8u && (s->field >> i) & 1u;
}

unsigned kgenome_nucleo_row_res(uint16_t row)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s ? s->res : KGENOME_NUCLEO_RES_STATUS;
}

int kgenome_nucleo_row_hands_on(uint16_t row)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s && shape_hands_on(s);
}

unsigned kgenome_nucleo_row_out(uint16_t row, unsigned k)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s && k < 2u ? s->out[k] : KGENOME_NUCLEO_ARG_NONE;
}

unsigned kgenome_nucleo_row_release(uint16_t row)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	return s ? s->release : KGENOME_NUCLEO_ARG_NONE;
}

unsigned kgenome_nucleo_entry_arg(uint16_t row, unsigned *how)
{
	const struct kgenome_nucleo_shape *s = row_shape(row);

	if (how)
		*how = s && s->entry != KGENOME_NUCLEO_ARG_NONE ? s->entry_how : 0u;
	return s ? s->entry : KGENOME_NUCLEO_ARG_NONE;
}

uint8_t kgenome_nucleo_cap_role(uint16_t cap, unsigned i)
{
	return i < 8u ? cap_shape(cap)->role[i] : 0u;
}

uint8_t kgenome_nucleo_call_role(uint16_t cap, uint16_t row, unsigned i)
{
	return row ? kgenome_nucleo_row_role(row, i) : kgenome_nucleo_cap_role(cap, i);
}

int kgenome_nucleo_call_hands_on(uint16_t cap, uint16_t row)
{
	return row ? kgenome_nucleo_row_hands_on(row) : shape_hands_on(cap_shape(cap));
}

int kgenome_nucleo_cap_named(uint16_t cap)
{
	size_t t;
	uint32_t i;

	if (cap == KGENOME_NUCLEO_NONE)
		return 0;
	for (t = 0; t < sizeof tables / sizeof tables[0]; t++)
		for (i = 0; i < tables[t]->n; i++)
			if (tables[t]->row[i].cap == cap || kgenome_nucleo_cap_generic(tables[t]->row[i].cap) == cap)
				return 1;
	return 0;
}

uint16_t kgenome_nucleo_name_id(unsigned target, const char *sym)
{
	uint16_t id;

	(void)kgenome_nucleo_name_lookup(target, sym, &id);
	return id;
}

const char *kgenome_nucleo_name_of(uint16_t id)
{
	size_t t;

	if (!id)
		return NULL;
	for (t = 0; t < sizeof tables / sizeof tables[0]; t++) {
		if (id <= tables[t]->n)
			return tables[t]->row[id - 1u].name;
		id = (uint16_t)(id - tables[t]->n);
	}
	return NULL;
}

/*
 * THE WORD THIS ONE IS A SPECIAL CASE OF, or KGENOME_NUCLEO_NONE.
 *
 * WHY A VOCABULARY NEEDS THIS AT ALL. Some capabilities are the same act
 * with a fact added:
 *
 *     net-recv, file-read   are mem-read with the descriptor identified
 *     net-send, file-write  are mem-write, likewise
 *     mem-alloc-exec        is mem-alloc with PROT_EXEC in its argument
 *
 * A rule names the level it MEANS. "A region was allocated writable and
 * executable" has to say mem-alloc-exec, because mem-alloc would match every
 * malloc on the machine. "Something filled it" has to say mem-read, because
 * the diagnose is true whether the bytes came off a socket or out of a file -
 * and MEASURED, naming the specific word instead is how rwx_exec stopped
 * matching the moment the engine learned to tell a socket read from a file
 * read. The rule had not changed and the program had not changed; only the
 * precision of the word had.
 *
 * SO THE MATCHER ASKS "IS THIS THAT, OR A KIND OF THAT", and the relation
 * lives here with the names rather than in the matcher, because it is a fact
 * about the vocabulary. One level is enough today; the walk is written as a
 * loop so a second does not need a second mechanism.
 *
 * IT IS NOT A GROUP. net-recv is in KGENOME_CG_NET and mem-read in KGENOME_CG_IO,
 * which is right - they answer different questions - so the encoding cannot
 * carry this and a table must.
 */
uint16_t kgenome_nucleo_cap_generic(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_NET_READ:
	case KGENOME_NUCLEO_READ:         return KGENOME_NUCLEO_MEM_READ;
	case KGENOME_NUCLEO_NET_WRITE:
	case KGENOME_NUCLEO_WRITE:        return KGENOME_NUCLEO_MEM_WRITE;
	case KGENOME_NUCLEO_ALLOC_EXEC:   return KGENOME_NUCLEO_ALLOC;
	default:                   return KGENOME_NUCLEO_NONE;
	}
}

/*
 * WHICH CASE OF A DESCRIPTOR CALL, from what made the descriptor: the "descriptor identified" half of the table above, as a
 * fact of the vocabulary. A route names the call (read(2), ReadFile) and not the object it is handed, so its word is the
 * generic one; the object is known only once the descriptor's producer is linked, and the scan asks this then
 * (caps_settle, diag_scan.c). Only calls whose result IS the object: a socket (socket, a raw socket, accept) and an opened
 * file. A memfd, a pipe and a dup'd number have no case word here (a memfd is not what a rule means by file-read, a pipe has
 * no word, dup2's answer is a number the shape does not hand on): they keep the generic word.
 */
uint16_t kgenome_nucleo_cap_on_handle(uint16_t cap, uint16_t made_by)
{
	int sock, file;

	if (cap != KGENOME_NUCLEO_MEM_READ && cap != KGENOME_NUCLEO_MEM_WRITE)
		return KGENOME_NUCLEO_NONE;
	sock = made_by == KGENOME_NUCLEO_NET_OPEN || made_by == KGENOME_NUCLEO_NET_RAW || made_by == KGENOME_NUCLEO_NET_ACCEPT;
	file = made_by == KGENOME_NUCLEO_FILE_OPEN;
	if (sock)
		return cap == KGENOME_NUCLEO_MEM_READ ? KGENOME_NUCLEO_NET_READ : KGENOME_NUCLEO_NET_WRITE;
	if (file)
		return cap == KGENOME_NUCLEO_MEM_READ ? KGENOME_NUCLEO_READ : KGENOME_NUCLEO_WRITE;
	return KGENOME_NUCLEO_NONE;
}

const char *kgenome_nucleo_cap_name(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_ALLOC:        return "mem-alloc";
	case KGENOME_NUCLEO_ALLOC_EXEC:   return "mem-alloc-exec";
	case KGENOME_NUCLEO_HEAP:         return "mem-alloc-heap";
	case KGENOME_NUCLEO_ACTION_READ:   return "mem-action-read";
	case KGENOME_NUCLEO_ACTION_WRITE:  return "mem-action-write";
	case KGENOME_NUCLEO_REG_OPEN:     return "reg-open";
	/* "exec-memory" and not "exec-register": the register is how the
	 * branch was spelled, the memory is what was entered. */
	case KGENOME_NUCLEO_EXEC_REG:     return "exec-memory";
	case KGENOME_NUCLEO_SELF_RESOLVE: return "lib-peb-walk";
	case KGENOME_NUCLEO_NAME_HASH:    return "lib-name-hash";
	/*
	 * "lib-call-indirect", AND IT USED TO BE "call-register".
	 *
	 * Two things were wrong with the old spelling. It was the only word
	 * in KGENOME_CG_LIB without the group's prefix - lib-api-resolve,
	 * lib-peb-walk, lib-name-hash - so a reader could not tell what
	 * family it belonged to. And it named the register, which is the way
	 * the instruction was WRITTEN, after the line directly above it had
	 * just refused to do that for exec-memory on the ground that the
	 * spelling is not the fact.
	 *
	 * What the fact is: a call whose target is not named at the call. The
	 * target was decided earlier, wherever the pointer was stored, and
	 * that is the whole difficulty - see the note on retpoline thunks in
	 * the table above.
	 */
	case KGENOME_NUCLEO_CALL_REG:     return "lib-call-indirect";
	case KGENOME_NUCLEO_CRYPTO:       return "crypto";
	case KGENOME_NUCLEO_CAPTURE:      return "input-capture";
	case KGENOME_NUCLEO_SVC_INSTALL:  return "service-install";
	case KGENOME_NUCLEO_MOD_LOAD:     return "kmodule-load";
	case KGENOME_NUCLEO_PIPE:         return "pipe-named-create";
	case KGENOME_NUCLEO_PIPE_OPEN:    return "pipe-create";
	case KGENOME_NUCLEO_FILE_DELETE:  return "file-delete";
	case KGENOME_NUCLEO_FILE_RENAME:  return "file-rename";
	case KGENOME_NUCLEO_PERM_SET:     return "file-perm-set";
	case KGENOME_NUCLEO_ANTI_DEBUG:   return "anti-debug";
	case KGENOME_NUCLEO_JAIL:         return "namespace-change";
	case KGENOME_NUCLEO_FD_REDIR:     return "fd-redirect";
	case KGENOME_NUCLEO_TIMESTOMP:    return "file-timestamp-set";
	case KGENOME_NUCLEO_PROC_LIST:    return "proc-enum";
	case KGENOME_NUCLEO_NET_READ:     return "net-recv";
	case KGENOME_NUCLEO_NET_WRITE:    return "net-send";
	case KGENOME_NUCLEO_FD_NONBLOCK:  return "fd-nonblock";
	case KGENOME_NUCLEO_NET_HDRINCL:  return "net-hdrincl";
	case KGENOME_NUCLEO_HTTP_OPEN:    return "http-open";
	case KGENOME_NUCLEO_HTTP_CONNECT: return "http-connect";
	case KGENOME_NUCLEO_HTTP_SEND:    return "http-send";
	case KGENOME_NUCLEO_HTTP_RECV:    return "http-recv";
	case KGENOME_NUCLEO_HTTP_FETCH:   return "http-fetch";
	case KGENOME_NUCLEO_NET_OPEN:     return "net-open";
	case KGENOME_NUCLEO_NET_CONNECT:  return "net-connect";
	case KGENOME_NUCLEO_NET_ACCEPT:   return "net-accept";
	case KGENOME_NUCLEO_NET_BIND:     return "net-bind";
	case KGENOME_NUCLEO_NET_LISTEN:   return "net-listen";
	case KGENOME_NUCLEO_MEM_READ:      return "mem-read";
	case KGENOME_NUCLEO_MEM_WRITE:     return "mem-write";
	case KGENOME_NUCLEO_READ:         return "file-read";
	case KGENOME_NUCLEO_WRITE:        return "file-write";
	case KGENOME_NUCLEO_FILE_OPEN:    return "file-open";
	case KGENOME_NUCLEO_MEMFD:        return "memfd-create";
	case KGENOME_NUCLEO_EXEC_IMAGE:   return "proc-start";
	case KGENOME_NUCLEO_SPAWN:        return "proc-fork";
	case KGENOME_NUCLEO_THREAD:       return "thread-create";
	case KGENOME_NUCLEO_NET_RAW:      return "net-raw";
	case KGENOME_NUCLEO_SLEEP:        return "sleep";
	case KGENOME_NUCLEO_PTRACE:       return "proc-open";
	case KGENOME_NUCLEO_PROC_MEM:     return "proc-mem-access";
	case KGENOME_NUCLEO_PROC_EXEC:    return "proc-control";
	case KGENOME_NUCLEO_RESOLVE:      return "lib-api-resolve";
	case KGENOME_NUCLEO_LIB_OPEN:     return "lib-load";
	case KGENOME_NUCLEO_DNS:          return "net-getaddr";
	case KGENOME_NUCLEO_REG_SET:      return "reg-set";
	case KGENOME_NUCLEO_CRED_SET:     return "cred-modify";
	case KGENOME_NUCLEO_HOOK:         return "kmodule-hook";
	case KGENOME_NUCLEO_KPROBE_REG:   return "kmodule-kprobe-register";
	case KGENOME_NUCLEO_KPROBE_UNREG: return "kmodule-kprobe-unregister";
	case KGENOME_NUCLEO_COPY_FROM_USER: return "kmodule-copy-from-user";
	case KGENOME_NUCLEO_COPY_TO_USER: return "kmodule-copy-to-user";
	case KGENOME_NUCLEO_KSYM_LOOKUP:  return "kmodule-ksym-lookup";
	case KGENOME_NUCLEO_SYMBOL_GET:   return "kmodule-symbol-get";
	case KGENOME_NUCLEO_CRED_PREPARE: return "cred-prepare";
	case KGENOME_NUCLEO_LIST_HIDE:    return "kmodule-list-edit";
	/* Named for the x86 instruction, which is the fault that took the
	 * word out of service - see the note in the import table. */
	case KGENOME_NUCLEO_PROT_OFF:     return "kmodule-write-protect-off";
	case KGENOME_NUCLEO_NET_ADDR:     return "net-addr";
	case KGENOME_NUCLEO_SELF_HIDE:    return "self-hide";
	case KGENOME_NUCLEO_BACKGROUND:   return "proc-background";
	case KGENOME_NUCLEO_DECODE:       return "data-decode";
	case KGENOME_NUCLEO_EVAL:         return "data-eval";
	case KGENOME_NUCLEO_CREATE:       return "data-create";
	case KGENOME_NUCLEO_DYNCALL:      return "data-call";
	case KGENOME_NUCLEO_DYNLOAD:      return "data-load";
	case KGENOME_NUCLEO_REQUEST:      return "input-request";
	default:                   return "?";
	}
}

/* See the note in nucleo.h: the capability's shape says which argument names the kernel symbol (name<k> / nameobj<k>). */
unsigned kgenome_nucleo_name_arg(uint16_t cap, unsigned *arg)
{
	const struct kgenome_nucleo_shape *s = cap_shape(cap);

	if (arg)
		*arg = s->name_kind ? s->name : 0u;
	return s->name_kind;
}

/*
 * THE ROW `nm` IS, for the two questions below that are asked with a name and no target. The ELF table first, then the PE table: the
 * routes that pass a name read one of those two (a syscall's label - kgenome_nucleo_sys_name, the kernel's own table - an ELF or a
 * PE import). A name both tables hold is one function of the same contract in both (socket, connect, closesocket).
 *
 * `nm` IS NOT A NAME THE FILE CHOSE: the label of a syscall NUMBER, or an IMPORT name the loader resolves (the one OS-defined
 * spelling: change it and the program no longer links). A symbol name from a program's own .symtab never reaches here - see
 * kgenome_diag_sym's sites, which come from undefined symbols only. Test: names_structural.
 */
static uint16_t row_of_any(const char *nm)
{
	uint16_t r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, nm);

	return r ? r : kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, nm);
}

/* See the note in nucleo.h: the row's answer when the name has one, the capability's otherwise. */
int kgenome_nucleo_hands_on(uint16_t cap, const char *nm)
{
	uint16_t r = nm ? row_of_any(nm) : 0u;

	return kgenome_nucleo_call_hands_on(cap, r);
}

/*
 * The names whose success value is zero: the rows of the ELF table whose result is res=status0 (KGENOME_SHAPE). It was a list of
 * names here, beside the table that names the same calls; "returns 0 on success" is a per-call fact in the manual page, and a rule
 * that inferred it from the capability would get `socket` and `bind` wrong in opposite directions. `name` has the provenance of
 * kgenome_nucleo_hands_on's `nm`.
 *
 * `execve` is deliberately not status0: on success it does not return at all, so there is no value to claim.
 */
int kgenome_nucleo_sys_zero_on_success(const char *name)
{
	uint16_t r = name ? kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, name) : 0u;

	return r && kgenome_nucleo_row_res(r) == KGENOME_NUCLEO_RES_STATUS0;
}
