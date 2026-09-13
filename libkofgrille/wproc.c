/*
 * wproc.c - the snapshot: what is running, and what is inside it.
 *
 * WHY THE PROCESS LIST COMES FROM TOOLHELP AND NOT FROM A HANDLE PER PID
 *
 * There are three ways to enumerate processes on Windows and they fail
 * differently, which is the only interesting thing about the choice.
 *
 * EnumProcesses gives a list of numbers and nothing else, so every field after
 * the pid costs an OpenProcess - including the parent, which means a caller
 * that only wants a process tree pays for four hundred handles and is refused
 * on the dozen that matter most. NtQuerySystemInformation gives everything in
 * one call and gives it out of a structure whose layout Windows does not
 * document, which is the same bet wcmdline.c takes and it is not worth taking
 * twice for a list that is not on any hot path.
 *
 * Toolhelp gives pid, parent, thread count and base name for every process on
 * the machine, WITHOUT OPENING ANYTHING. That last part is the whole argument:
 * the processes a snapshot most wants to describe are the protected ones, and
 * they refuse a handle to anybody. With toolhelp they are still in the list,
 * still named, still parented - and only the fields that genuinely need a
 * handle are missing, which is what KOFW_PF_REFUSED says.
 *
 *
 * EVERY FIELD THAT COSTS A SYSCALL IS BEHIND A BIT
 *
 * Not for elegance. A full walk of a workstation with the token and command
 * line asked for is four hundred OpenProcess, four hundred OpenProcessToken,
 * eight hundred GetTokenInformation and four hundred PEB reads, and the PEB
 * read alone needs PROCESS_VM_READ - a materially stronger right than
 * everything else here asks for, and one a hardened machine refuses far more
 * often. A caller drawing a process tree should not be paying that, and should
 * not be ASKING for that, because the right it asks for is visible to whatever
 * is watching it.
 *
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DO
 *
 * It does not read the process's own bookkeeping: not the PEB module list, not
 * the heap list, not any thread's TEB. Everything below comes from the memory
 * manager and the loader through documented calls, and the reason is in
 * wproc.h next to KOFW_USE_STACK: the party being looked for can edit those
 * structures, and a walk that depended on them would go quiet on exactly the
 * process it exists to describe. Reading them is a refinement that can only
 * ADD, and it is not here yet.
 *
 * It does not unmap an image back to file layout either. A loaded module is
 * not its file - sections are at SectionAlignment rather than FileAlignment,
 * relocations are applied and the import table is resolved - so comparing one
 * against the other, or handing one to a parser that expects a file, is work
 * with its own decisions to make. That belongs to whoever scans, and this
 * hands over bytes and says where they came from.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "wproc.h"
#include "wcmdline.h"
#include "wtext.h"

/*
 * HOW MUCH TEXT ONE RECORD GETS.
 *
 * A path is 32767 characters at the limit and 260 in practice, and a command
 * line is 32767 at the limit and a few hundred in practice. These are the
 * sizes at which the truncation flag stops firing on anything real, not the
 * sizes at which it becomes impossible - which is why the flag exists.
 */
#define PATH_CAP     1024u
#define CMDLINE_CAP  8192u

/*
 * REGIONS BIGGER THAN THIS ARE REPORTED AND NOT EXAMINED.
 *
 * 256MB, which is chosen against what actually appears in one: a .NET GC heap,
 * a database buffer pool and a VM's guest memory are all one committed region
 * of gigabytes, and the queries below cost one array entry per page. At 4KB
 * pages a 4GB region is a million entries, for an answer about memory whose
 * size alone says it is not a payload someone injected.
 */
#define MAX_REGION_DEFAULT (256ull * 1024ull * 1024ull)

/*
 * How many pages the working-set query asks about at once.
 *
 * The array is one entry per page and the query is answered in full, so this
 * is a memory bound and not a limit on what is examined: a region larger than
 * this is asked about in several passes, and the walk stops at the first
 * private page it finds because one is the whole answer.
 */
#define WS_BATCH 4096u

/* ------------------------------------------------------------------ names */

const char *kofw_integrity_name(uint8_t integ)
{
	switch (integ) {
	case KOFW_INTEG_UNTRUSTED: return "untrusted";
	case KOFW_INTEG_LOW:       return "low";
	case KOFW_INTEG_MEDIUM:    return "medium";
	case KOFW_INTEG_HIGH:      return "high";
	case KOFW_INTEG_SYSTEM:    return "system";
	default:                   return "?";
	}
}

const char *kofw_rgn_kind_name(uint8_t kind)
{
	switch (kind) {
	case KOFW_RGN_PRIVATE: return "private";
	case KOFW_RGN_MAPPED:  return "mapped";
	case KOFW_RGN_IMAGE:   return "image";
	default:               return "?";
	}
}

const char *kofw_rgn_use_name(uint8_t use)
{
	switch (use) {
	case KOFW_USE_IMAGE: return "image";
	case KOFW_USE_CODE:  return "code";
	case KOFW_USE_HEAP:  return "heap";
	case KOFW_USE_STACK: return "stack";
	case KOFW_USE_DATA:  return "data";
	default:             return "?";
	}
}

/* -------------------------------------------------------------- utilities */

static uint64_t ft64(const FILETIME *ft)
{
	return ((uint64_t)ft->dwHighDateTime << 32) | (uint64_t)ft->dwLowDateTime;
}

/*
 * A wide path into the caller's UTF-8 buffer, sanitised the way every other
 * string in this library is - see wtext.h for why control characters do not
 * survive a trip through something that will be printed.
 */
static void wide_to_buf(const wchar_t *w, char *dst, size_t cap, int *cut)
{
	size_t n = 0;

	dst[0] = '\0';
	if (!w)
		return;
	while (w[n])
		n++;
	kofw_utf16_to_utf8((const uint16_t *)w, n, dst, cap, cut);
}

/*
 * THE DEVICE-NAME TABLE, built once per opened process and never globally.
 *
 * The kernel names a mapped file \Device\HarddiskVolume3\Windows\..., and
 * kofwatchman already says what is wrong with that: a path from an event is
 * not a path a scanner can open. QueryDosDeviceW answers the other direction -
 * given "C:", what device is that - so the table is built by asking about
 * every drive letter that exists and matching prefixes against it.
 *
 * PER HANDLE RATHER THAN STATIC, because a static cache shared by two threads
 * scanning two processes is a data race for a table that costs twenty-six fast
 * calls to build. It is also not a cache that can go stale into a wrong answer
 * that way: a volume mounted during a walk is simply missing from that walk's
 * table, and a path that matches no device is passed through unchanged rather
 * than guessed at.
 */
struct dosmap {
	int      built;
	uint32_t n;
	struct {
		char     dev[96];
		size_t   devlen;
		char     drive[3];
	} e[26];
};

static void dosmap_build(struct dosmap *m)
{
	wchar_t letter[3] = { 0, L':', 0 };
	wchar_t target[512];
	int     i;

	m->built = 1;
	m->n = 0;
	for (i = 0; i < 26; i++) {
		size_t len;

		letter[0] = (wchar_t)(L'A' + i);
		if (!QueryDosDeviceW(letter, target,
				     (DWORD)(sizeof target / sizeof target[0])))
			continue;

		/* QueryDosDeviceW returns a double-NUL-terminated list and the
		 * first entry is the one that resolves. */
		wide_to_buf(target, m->e[m->n].dev, sizeof m->e[0].dev, NULL);
		len = strlen(m->e[m->n].dev);
		if (len == 0 || len >= sizeof m->e[0].dev - 1)
			continue;

		m->e[m->n].devlen = len;
		m->e[m->n].drive[0] = (char)('A' + i);
		m->e[m->n].drive[1] = ':';
		m->e[m->n].drive[2] = '\0';
		m->n++;
	}
}

/*
 * Rewrite a device path in place-ish: `in` is read, `out` is written.
 *
 * A path that matches no device is COPIED THROUGH UNCHANGED rather than
 * dropped or blanked. It is still true, it is still classifiable - kof_classify
 * handles device paths, which is what tests/unit/grille_host.c checks - and a
 * caller that tries to open it gets a clean failure. Inventing a drive letter
 * for it would be the only outcome worse than that.
 */
static void dosify(struct dosmap *m, const char *in, char *out, size_t cap)
{
	uint32_t i;

	if (!m->built)
		dosmap_build(m);

	for (i = 0; i < m->n; i++) {
		size_t dl = m->e[i].devlen;

		if (strncmp(in, m->e[i].dev, dl) == 0 && in[dl] == '\\') {
			snprintf(out, cap, "%s%s", m->e[i].drive, in + dl);
			return;
		}
	}
	snprintf(out, cap, "%s", in);
}

/* ----------------------------------------------------- per-process fields */

typedef BOOL (WINAPI *pfn_wow64_2)(HANDLE, USHORT *, USHORT *);

static pfn_wow64_2 resolve_wow64_2(void)
{
	static pfn_wow64_2 fn;
	static int tried;

	if (!tried) {
		HMODULE k = GetModuleHandleW(L"kernel32.dll");

		tried = 1;
		if (k)
			fn = (pfn_wow64_2)(void *)GetProcAddress(
				k, "IsWow64Process2");
	}
	return fn;
}

static uint8_t arch_of_machine(USHORT machine)
{
	switch (machine) {
	case IMAGE_FILE_MACHINE_I386:  return KOF_EARCH_X86;
	case IMAGE_FILE_MACHINE_AMD64: return KOF_EARCH_X86_64;
	case IMAGE_FILE_MACHINE_ARMNT: return KOF_EARCH_ARM;
	case IMAGE_FILE_MACHINE_ARM64: return KOF_EARCH_ARM64;
	default:                       return KOF_EARCH_UNKNOWN;
	}
}

/*
 * WHAT THE PROCESS IS BUILT FOR, and on an ARM64 machine that is four answers
 * rather than two.
 *
 * IsWow64Process2 reports the process's machine and the host's separately: an
 * UNKNOWN process machine means "native", whatever native happens to be here,
 * and anything else means the process is running under emulation and names
 * which architecture it really is. The older IsWow64Process can only say
 * "x86 under x64", which on this tree's own build host is the one combination
 * that never occurs.
 */
static void fill_arch(HANDLE h, struct kofw_proc *p)
{
	pfn_wow64_2 fn = resolve_wow64_2();
	BOOL        wow = FALSE;

	if (fn) {
		USHORT proc_m = 0, host_m = 0;

		if (fn(h, &proc_m, &host_m)) {
			if (proc_m == IMAGE_FILE_MACHINE_UNKNOWN) {
				p->arch = arch_of_machine(host_m);
			} else {
				p->arch = arch_of_machine(proc_m);
				p->flags |= KOFW_PF_WOW64;
			}
			return;
		}
	}

	if (IsWow64Process(h, &wow) && wow) {
		p->arch = KOF_EARCH_X86;
		p->flags |= KOFW_PF_WOW64;
	}
}

static uint8_t integrity_of_rid(DWORD rid)
{
	if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
		return KOFW_INTEG_SYSTEM;
	if (rid >= SECURITY_MANDATORY_HIGH_RID)
		return KOFW_INTEG_HIGH;
	if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
		return KOFW_INTEG_MEDIUM;
	if (rid >= SECURITY_MANDATORY_LOW_RID)
		return KOFW_INTEG_LOW;
	return KOFW_INTEG_UNTRUSTED;
}

static void fill_token(HANDLE h, struct kofw_proc *p)
{
	/*
	 * A union rather than a byte array, so the buffer is aligned for the
	 * structure written into it without a cast that -Wcast-align would be
	 * right to complain about. An integrity SID is S-1-16-xxxx: one
	 * sub-authority, twelve bytes, and 128 is room to spare.
	 */
	union {
		TOKEN_MANDATORY_LABEL tml;
		unsigned char         raw[128];
	} u;
	TOKEN_ELEVATION elev;
	HANDLE          tok = NULL;
	DWORD           got = 0;

	/* TOKEN_QUERY on a handle with QUERY_LIMITED_INFORMATION is enough for
	 * both of these, which is why nothing here asks for more. */
	if (!OpenProcessToken(h, TOKEN_QUERY, &tok))
		return;

	if (GetTokenInformation(tok, TokenIntegrityLevel, &u, (DWORD)sizeof u,
				&got) && u.tml.Label.Sid) {
		UCHAR *count = GetSidSubAuthorityCount(u.tml.Label.Sid);

		if (count && *count > 0) {
			DWORD *rid = GetSidSubAuthority(u.tml.Label.Sid,
							(DWORD)(*count - 1u));

			if (rid)
				p->integrity = integrity_of_rid(*rid);
		}
	}

	memset(&elev, 0, sizeof elev);
	if (GetTokenInformation(tok, TokenElevation, &elev, (DWORD)sizeof elev,
				&got) && elev.TokenIsElevated)
		p->flags |= KOFW_PF_ELEVATED;

	CloseHandle(tok);
}

/*
 * The full path, the creation time and the architecture - everything a handle
 * buys and nothing that needs a stronger right than
 * PROCESS_QUERY_LIMITED_INFORMATION.
 *
 * Returns the handle when it got one, so a caller that needs it again does not
 * open a second. NULL means refused, and the flag says so.
 */
static HANDLE fill_from_handle(struct kofw_proc *p, uint32_t want,
			       char *image, size_t image_cap)
{
	HANDLE   h;
	FILETIME create, exit_t, kern, user;
	wchar_t  wpath[PATH_CAP];
	DWORD    n = (DWORD)(sizeof wpath / sizeof wpath[0]);
	int      cut = 0;

	h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)p->pid);
	if (!h) {
		p->flags |= KOFW_PF_REFUSED | KOFW_PF_NO_PATH;
		return NULL;
	}

	if (GetProcessTimes(h, &create, &exit_t, &kern, &user))
		p->create_time = ft64(&create);

	if (QueryFullProcessImageNameW(h, 0, wpath, &n)) {
		wide_to_buf(wpath, image, image_cap, &cut);
		if (cut)
			p->flags |= KOFW_PF_TRUNCATED;
	} else {
		p->flags |= KOFW_PF_NO_PATH;
	}

	fill_arch(h, p);
	if (want & KOFW_PW_TOKEN)
		fill_token(h, p);

	return h;
}

/* ------------------------------------------------------------- the plist */

struct kofw_plist {
	HANDLE   snap;
	int      first;
	uint32_t want;
	uint32_t only_pid;
	uint32_t self;

	char     image[PATH_CAP];
	char     cmdline[CMDLINE_CAP];
};

struct kofw_plist *kofw_plist_open(const struct kofw_plist_option *opt, int *err)
{
	struct kofw_plist *l;
	HANDLE             snap;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		if (err)
			*err = KOFW_ERR_ACCESS;
		return NULL;
	}

	l = calloc(1, sizeof *l);
	if (!l) {
		CloseHandle(snap);
		if (err)
			*err = KOFW_ERR_MEM;
		return NULL;
	}

	l->snap = snap;
	l->first = 1;
	l->self = (uint32_t)GetCurrentProcessId();
	/* Zero is what a memset gives, so it has to mean the whole picture
	 * rather than the empty one - see wproc.h. */
	l->want = (opt && opt->want) ? opt->want : KOFW_PW_ALL;
	l->only_pid = opt ? opt->only_pid : 0;

	if (err)
		*err = 0;
	return l;
}

int kofw_plist_next(struct kofw_plist *l, struct kofw_proc *out)
{
	PROCESSENTRY32W pe;

	if (!l || !out)
		return 0;

	memset(&pe, 0, sizeof pe);
	pe.dwSize = (DWORD)sizeof pe;

	for (;;) {
		BOOL  ok;
		HANDLE h;
		int   cut = 0;

		ok = l->first ? Process32FirstW(l->snap, &pe)
			      : Process32NextW(l->snap, &pe);
		l->first = 0;
		if (!ok)
			return 0;

		if (l->only_pid && pe.th32ProcessID != l->only_pid)
			continue;

		memset(out, 0, sizeof *out);
		l->image[0] = '\0';
		l->cmdline[0] = '\0';

		out->pid = (uint32_t)pe.th32ProcessID;
		out->ppid = (uint32_t)pe.th32ParentProcessID;
		out->threads = (uint32_t)pe.cntThreads;
		if (out->pid == l->self)
			out->flags |= KOFW_PF_SELF;

		/* No handle needed, so it is answered for a protected process
		 * as readily as for any other. */
		{
			DWORD sid = 0;

			if (ProcessIdToSessionId((DWORD)out->pid, &sid))
				out->session_id = (uint32_t)sid;
		}

		/*
		 * The base name, which is what the snapshot itself carries. It
		 * is overwritten by the full path when one can be had, and it
		 * is what remains when one cannot - a name is not a location
		 * and KOFW_PF_NO_PATH says which of the two this is.
		 */
		wide_to_buf(pe.szExeFile, l->image, sizeof l->image, &cut);
		if (cut)
			out->flags |= KOFW_PF_TRUNCATED;

		h = NULL;
		if (l->want & KOFW_PW_PATH) {
			char full[PATH_CAP];

			full[0] = '\0';
			h = fill_from_handle(out, l->want, full, sizeof full);
			if (full[0])
				memcpy(l->image, full, sizeof full);
			else
				out->flags |= KOFW_PF_NO_PATH;
		} else {
			out->flags |= KOFW_PF_NO_PATH;
		}
		if (h)
			CloseHandle(h);

		if (l->want & KOFW_PW_CMDLINE) {
			int rc = kofw_cmdline_of(out->pid, l->cmdline,
						 sizeof l->cmdline);

			if (rc == KOFW_CMDLINE_FAIL)
				out->flags |= KOFW_PF_CMDLINE_LOST;
			else if (rc == KOFW_CMDLINE_CUT)
				out->flags |= KOFW_PF_TRUNCATED;
		}

		out->loc = kof_classify(l->image, &out->attack);
		out->image = l->image;
		out->cmdline = l->cmdline;
		return 1;
	}
}

void kofw_plist_close(struct kofw_plist *l)
{
	if (!l)
		return;
	if (l->snap && l->snap != INVALID_HANDLE_VALUE)
		CloseHandle(l->snap);
	free(l);
}

/* -------------------------------------------------------------- the pmem */

struct kofw_pmem {
	HANDLE   h;
	uint32_t want;
	uint64_t max_region;
	DWORD    page;

	struct kofw_proc proc;
	char     image[PATH_CAP];
	char     cmdline[CMDLINE_CAP];

	/* the module walk */
	HMODULE *mods;
	uint32_t n_mods;
	uint32_t i_mod;
	char     mod_path[PATH_CAP];

	/* the region walk */
	uint64_t addr;
	int      done;
	char     rgn_path[PATH_CAP];
	struct dosmap dos;

	/*
	 * WHERE THE LAST GUARD RUN ENDED, which is the whole of the stack test.
	 *
	 * The walk goes upward through the address space, and Windows puts a
	 * stack's guard page immediately BELOW the committed part of the stack
	 * inside the same allocation - so by the time a candidate is reached,
	 * the evidence has already gone past. One pair of numbers carried
	 * forward is all it takes to still have it. See wproc.h for what this
	 * test can and cannot do.
	 */
	uint64_t guard_end;
	uint64_t guard_alloc;

	/* The PE check is per ALLOCATION, and one allocation is several runs,
	 * so the answer is remembered rather than re-read for each of them. */
	uint64_t pe_alloc;
	int      pe_seen;

	PSAPI_WORKING_SET_EX_INFORMATION *ws;
};

const struct kofw_proc *kofw_pmem_proc(const struct kofw_pmem *m)
{
	static const struct kofw_proc empty = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, "", "" };

	return m ? &m->proc : &empty;
}

struct kofw_pmem *kofw_pmem_open(uint32_t pid, uint64_t create_time,
				 const struct kofw_pmem_option *opt, int *err)
{
	struct kofw_pmem *m;
	SYSTEM_INFO       si;
	FILETIME          create, exit_t, kern, user;
	wchar_t           wpath[PATH_CAP];
	DWORD             n = (DWORD)(sizeof wpath / sizeof wpath[0]);
	int               cut = 0;

	if (pid == 0) {
		if (err)
			*err = KOFW_ERR_ARG;
		return NULL;
	}

	m = calloc(1, sizeof *m);
	if (!m) {
		if (err)
			*err = KOFW_ERR_MEM;
		return NULL;
	}

	/*
	 * QUERY_INFORMATION rather than the limited form, and it is asked for
	 * because of one call: QueryWorkingSetEx, which is what answers whether
	 * an image page has gone private. VM_READ is what everything else here
	 * needs. Both together are refused outright for a protected process,
	 * however elevated the caller is, and that is reported rather than
	 * worked around.
	 */
	m->h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
			   (DWORD)pid);
	if (!m->h) {
		free(m);
		if (err)
			*err = KOFW_ERR_ACCESS;
		return NULL;
	}

	m->want = (opt && opt->want) ? opt->want : KOFW_MW_DEFAULT;
	m->max_region = (opt && opt->max_region) ? opt->max_region
						 : MAX_REGION_DEFAULT;

	GetSystemInfo(&si);
	m->page = si.dwPageSize ? si.dwPageSize : 4096u;

	m->proc.pid = pid;
	m->proc.image = m->image;
	m->proc.cmdline = m->cmdline;
	if (pid == (uint32_t)GetCurrentProcessId())
		m->proc.flags |= KOFW_PF_SELF;

	if (GetProcessTimes(m->h, &create, &exit_t, &kern, &user))
		m->proc.create_time = ft64(&create);

	/*
	 * THE PID-REUSE CHECK, and it is the reason this function takes a
	 * second argument at all.
	 *
	 * A pid observed a second ago may belong to something else now, and
	 * everything this handle can do - read its memory, list its modules -
	 * would be done to that something else without complaint. Refusing
	 * here is the only place the mistake is still cheap.
	 */
	if (create_time && m->proc.create_time &&
	    create_time != m->proc.create_time) {
		CloseHandle(m->h);
		free(m);
		if (err)
			*err = KOFW_ERR_GONE;
		return NULL;
	}

	if (QueryFullProcessImageNameW(m->h, 0, wpath, &n)) {
		wide_to_buf(wpath, m->image, sizeof m->image, &cut);
		if (cut)
			m->proc.flags |= KOFW_PF_TRUNCATED;
	} else {
		m->proc.flags |= KOFW_PF_NO_PATH;
	}

	fill_arch(m->h, &m->proc);
	fill_token(m->h, &m->proc);
	m->proc.loc = kof_classify(m->image, &m->proc.attack);

	{
		DWORD sid = 0;

		if (ProcessIdToSessionId((DWORD)pid, &sid))
			m->proc.session_id = (uint32_t)sid;
	}

	if (err)
		*err = 0;
	return m;
}

/* ------------------------------------------------------------- the modules */

/*
 * LIST_MODULES_ALL, so a 32-bit process seen from a 64-bit walker reports its
 * modules rather than nothing. The call is asked twice on purpose: once to
 * learn the size, once to fill it, because a process loads modules while this
 * runs and a fixed array would silently report a prefix of the list.
 */
static int mods_load(struct kofw_pmem *m)
{
	DWORD need = 0, have;

	if (m->mods)
		return 1;

	if (!EnumProcessModulesEx(m->h, NULL, 0, &need, LIST_MODULES_ALL) &&
	    need == 0)
		return 0;
	if (need == 0)
		return 0;

	/* Room for what arrived plus a little, since the list can grow between
	 * the two calls; a truncated answer is detected below either way. */
	have = need + (DWORD)(16u * sizeof(HMODULE));
	m->mods = malloc(have);
	if (!m->mods)
		return 0;

	if (!EnumProcessModulesEx(m->h, m->mods, have, &need,
				  LIST_MODULES_ALL)) {
		free(m->mods);
		m->mods = NULL;
		return 0;
	}
	if (need > have)
		need = have;
	m->n_mods = (uint32_t)(need / sizeof(HMODULE));
	return 1;
}

int kofw_pmem_next_module(struct kofw_pmem *m, struct kofw_module *out)
{
	MODULEINFO mi;
	wchar_t    wpath[PATH_CAP];
	int        cut = 0;

	if (!m || !out)
		return 0;
	if (!mods_load(m))
		return 0;
	if (m->i_mod >= m->n_mods)
		return 0;

	memset(out, 0, sizeof *out);
	m->mod_path[0] = '\0';

	memset(&mi, 0, sizeof mi);
	if (GetModuleInformation(m->h, m->mods[m->i_mod], &mi, (DWORD)sizeof mi)) {
		out->base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
		out->size = (uint64_t)mi.SizeOfImage;
		out->entry = (uint64_t)(uintptr_t)mi.EntryPoint;
	} else {
		out->base = (uint64_t)(uintptr_t)m->mods[m->i_mod];
	}

	if (GetModuleFileNameExW(m->h, m->mods[m->i_mod], wpath,
				 (DWORD)(sizeof wpath / sizeof wpath[0]))) {
		wide_to_buf(wpath, m->mod_path, sizeof m->mod_path, &cut);
		/*
		 * A MAPPING KEEPS ITS FILE ALIVE, so a path that resolves to
		 * nothing is a file that was deleted or renamed AFTER the
		 * load. That is what a dropper does to its own payload, and it
		 * is worth one attribute query per module to notice.
		 */
		if (m->mod_path[0] &&
		    GetFileAttributesW(wpath) == INVALID_FILE_ATTRIBUTES)
			out->flags |= KOFW_MDF_NO_FILE;
	}
	if (!m->mod_path[0])
		out->flags |= KOFW_MDF_UNNAMED;

	/* The loader lists the process's own image first, and it is the one
	 * module whose absence from disk means something different. */
	if (m->i_mod == 0)
		out->flags |= KOFW_MDF_MAIN;

	out->loc = kof_classify(m->mod_path, &out->attack);
	out->path = m->mod_path;
	m->i_mod++;
	return 1;
}

/* ------------------------------------------------------------- the regions */

static int prot_exec(DWORD p)
{
	DWORD base = p & 0xffu;

	return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
	       base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static int prot_write(DWORD p)
{
	DWORD base = p & 0xffu;

	return base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
	       base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static int prot_rwx(DWORD p)
{
	DWORD base = p & 0xffu;

	return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

/*
 * IS THERE A PE LAID OUT BY HAND AT THIS ALLOCATION.
 *
 * Read the two bytes at the base, then e_lfanew, then the signature it points
 * at - each one checked before the next is believed, which is the same
 * discipline wcmdline.c applies to the PEB and for the same reason: a wrong
 * answer here does not look wrong, it looks like a finding.
 *
 * A short read is not an error. Anything that refuses is simply not a PE as
 * far as this is concerned, because what this is asked is whether a header IS
 * there and not whether one might be.
 */
static int alloc_has_pe(struct kofw_pmem *m, uint64_t alloc_base)
{
	unsigned char head[0x40];
	unsigned char sig[4];
	SIZE_T        rd = 0;
	uint32_t      lfanew;

	if (m->pe_seen && m->pe_alloc == alloc_base)
		return 1;
	if (m->pe_alloc == alloc_base)
		return 0;

	m->pe_alloc = alloc_base;
	m->pe_seen = 0;

	if (!ReadProcessMemory(m->h, (void *)(uintptr_t)alloc_base, head,
			       sizeof head, &rd) || rd != sizeof head)
		return 0;
	if (head[0] != 'M' || head[1] != 'Z')
		return 0;

	lfanew = (uint32_t)head[0x3c] | ((uint32_t)head[0x3d] << 8) |
		 ((uint32_t)head[0x3e] << 16) | ((uint32_t)head[0x3f] << 24);
	/* A PE header sits within the first page or two of its image. A value
	 * outside that is a coincidence in somebody's data, not an offset. */
	if (lfanew < 0x40u || lfanew > 0x1000u)
		return 0;

	if (!ReadProcessMemory(m->h, (void *)(uintptr_t)(alloc_base + lfanew),
			       sig, sizeof sig, &rd) || rd != sizeof sig)
		return 0;
	if (sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0)
		return 0;

	m->pe_seen = 1;
	return 1;
}

/*
 * HAS ANY RESIDENT PAGE OF THIS IMAGE REGION STOPPED BEING SHARED.
 *
 * Image pages are shared with every process that mapped the same file, so one
 * that is private is one somebody WROTE - the kernel's own record of a
 * copy-on-write, and the only in-box signal that survives a hook restoring the
 * original page protection afterwards.
 *
 * It stops at the first one, because one is the whole answer, and it says
 * nothing about pages that are not resident: an unshared page trimmed out of
 * the working set is invisible here. That makes this a floor and never a count,
 * which is what wproc.h tells a caller.
 */
static int region_has_private_page(struct kofw_pmem *m, uint64_t base,
				   uint64_t size)
{
	uint64_t off;

	if (!m->ws) {
		m->ws = malloc(WS_BATCH * sizeof *m->ws);
		if (!m->ws)
			return 0;
	}

	for (off = 0; off < size; off += (uint64_t)WS_BATCH * m->page) {
		uint64_t left = size - off;
		uint32_t want = WS_BATCH;
		uint32_t i;

		if (left / m->page < want)
			want = (uint32_t)(left / m->page);
		if (want == 0)
			break;

		for (i = 0; i < want; i++) {
			memset(&m->ws[i], 0, sizeof m->ws[i]);
			m->ws[i].VirtualAddress =
				(void *)(uintptr_t)(base + off +
						    (uint64_t)i * m->page);
		}

		if (!QueryWorkingSetEx(m->h, m->ws,
				       (DWORD)(want * sizeof *m->ws)))
			return 0;

		for (i = 0; i < want; i++)
			if (m->ws[i].VirtualAttributes.Valid &&
			    !m->ws[i].VirtualAttributes.Shared)
				return 1;
	}
	return 0;
}

/* The file behind a mapped run, as something a scanner could open. */
static void region_path(struct kofw_pmem *m, uint64_t base)
{
	wchar_t wdev[PATH_CAP];
	char    dev[PATH_CAP];

	m->rgn_path[0] = '\0';
	if (!GetMappedFileNameW(m->h, (void *)(uintptr_t)base, wdev,
				(DWORD)(sizeof wdev / sizeof wdev[0])))
		return;

	wide_to_buf(wdev, dev, sizeof dev, NULL);
	if (dev[0])
		dosify(&m->dos, dev, m->rgn_path, sizeof m->rgn_path);
}

int kofw_pmem_next_region(struct kofw_pmem *m, struct kofw_region *out)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!m || !out || m->done)
		return 0;

	for (;;) {
		uint64_t base, size, alloc;
		int      exec, guard;

		memset(&mbi, 0, sizeof mbi);
		if (VirtualQueryEx(m->h, (void *)(uintptr_t)m->addr, &mbi,
				   sizeof mbi) != sizeof mbi) {
			m->done = 1;
			return 0;
		}

		base = (uint64_t)(uintptr_t)mbi.BaseAddress;
		size = (uint64_t)mbi.RegionSize;
		alloc = (uint64_t)(uintptr_t)mbi.AllocationBase;

		/*
		 * A run that does not advance ends the walk rather than
		 * spinning on it. VirtualQueryEx returning a zero-length
		 * region, or one at or below where the probe already was, is
		 * not something to reason about - it is a walk that has
		 * stopped making progress, and the only safe reading of that
		 * is that there is nothing more to see.
		 */
		if (size == 0 || base + size <= m->addr) {
			m->done = 1;
			return 0;
		}
		m->addr = base + size;

		guard = (mbi.State == MEM_COMMIT) &&
			(mbi.Protect & PAGE_GUARD) != 0;
		if (guard) {
			m->guard_end = base + size;
			m->guard_alloc = alloc;
		}

		if (mbi.State != MEM_COMMIT)
			continue;

		memset(out, 0, sizeof *out);
		out->base = base;
		out->size = size;
		out->alloc_base = alloc;
		out->protect = (uint32_t)mbi.Protect;
		out->alloc_protect = (uint32_t)mbi.AllocationProtect;

		switch (mbi.Type) {
		case MEM_IMAGE:  out->kind = KOFW_RGN_IMAGE;   break;
		case MEM_MAPPED: out->kind = KOFW_RGN_MAPPED;  break;
		default:         out->kind = KOFW_RGN_PRIVATE; break;
		}

		exec = prot_exec(mbi.Protect);
		if (exec)
			out->flags |= KOFW_RGF_EXEC;
		if (prot_write(mbi.Protect))
			out->flags |= KOFW_RGF_WRITE;
		if (exec && prot_rwx(mbi.Protect))
			out->flags |= KOFW_RGF_RWX;
		if (guard)
			out->flags |= KOFW_RGF_GUARD;

		if ((m->want & KOFW_MW_EXEC_ONLY) && !exec)
			continue;

		/*
		 * The path first, because two of the decisions below are about
		 * whether there is one - and a guard page is not read from,
		 * which is a refusal rather than an answer.
		 */
		m->rgn_path[0] = '\0';
		if ((m->want & KOFW_MW_PATHS) && out->kind != KOFW_RGN_PRIVATE)
			region_path(m, base);
		out->path = m->rgn_path;
		out->loc = kof_classify(m->rgn_path, NULL);

		if (size > m->max_region)
			out->flags |= KOFW_RGF_UNEXAMINED;

		/*
		 * IS THERE A FILE BEHIND THIS, which three of the flags below
		 * turn on and which is NOT the same question as "did the name
		 * query return something".
		 *
		 * An IMAGE region always has a file - that is what makes it an
		 * image - and a PRIVATE region never has one. Only MAPPED is
		 * genuinely in doubt, because a section can be backed by the
		 * page file and then has no name to give.
		 *
		 * The last clause is the one that matters: with the name not
		 * asked for, this answers BACKED rather than unbacked. Reading
		 * an empty string as "nothing behind it" was wrong in the way
		 * that matters most here - it made every executable region of
		 * every loaded module report as unbacked code the moment a
		 * caller turned KOFW_MW_PATHS off, which is a finding on every
		 * process on the machine. A check that was not performed must
		 * never come back as the interesting answer.
		 */
		{
			int backed;

			if (out->kind == KOFW_RGN_IMAGE)
				backed = 1;
			else if (out->kind == KOFW_RGN_PRIVATE)
				backed = 0;
			else
				backed = !(m->want & KOFW_MW_PATHS) ||
					 m->rgn_path[0] != '\0';

			if (exec && !backed)
				out->flags |= KOFW_RGF_UNBACKED;
			if (exec && backed && out->kind == KOFW_RGN_MAPPED)
				out->flags |= KOFW_RGF_DATA_EXEC;

			/*
			 * A PE HEADER ONLY COUNTS WHERE NO FILE ACCOUNTS FOR
			 * IT, and that clause was missing.
			 *
			 * Without it this fired on every .mui and every
			 * resource-only DLL that anything had mapped as data -
			 * measured, seven of them in one powershell.exe - and
			 * each was correct and none was the point. A PE file
			 * mapped as data has a PE header because it IS a PE
			 * file; the flag exists to say a module was laid out
			 * by hand in memory nobody can point at a file for.
			 */
			if (!backed && !guard &&
			    !(out->flags & KOFW_RGF_UNEXAMINED) &&
			    alloc && alloc_has_pe(m, alloc))
				out->flags |= KOFW_RGF_PE;
		}

		if (out->kind == KOFW_RGN_IMAGE && exec &&
		    (m->want & KOFW_MW_DIRTY) &&
		    !(out->flags & KOFW_RGF_UNEXAMINED) &&
		    region_has_private_page(m, base, size))
			out->flags |= KOFW_RGF_DIRTY_IMAGE;

		/*
		 * WHAT IT IS FOR. Four of the six come straight from what has
		 * already been established; the split between the last two is
		 * the guard run carried forward - see wproc.h for exactly how
		 * much that test is worth.
		 */
		if (out->kind == KOFW_RGN_IMAGE)
			out->use = KOFW_USE_IMAGE;
		else if (exec)
			out->use = KOFW_USE_CODE;
		else if (out->kind == KOFW_RGN_PRIVATE &&
			 prot_write(mbi.Protect) && !guard)
			out->use = (m->guard_alloc == alloc &&
				    m->guard_end == base) ? KOFW_USE_STACK
							  : KOFW_USE_HEAP;
		else
			out->use = KOFW_USE_DATA;

		if (out->use == KOFW_USE_HEAP && !(m->want & KOFW_MW_HEAP))
			continue;

		return 1;
	}
}

/* ---------------------------------------------------------------- reading */

size_t kofw_pmem_read(struct kofw_pmem *m, uint64_t addr, void *buf, size_t n)
{
	unsigned char *p = buf;
	size_t         got = 0;

	if (!m || !buf || n == 0)
		return 0;

	/*
	 * PAGE AT A TIME, STOPPING AT THE FIRST REFUSAL.
	 *
	 * ReadProcessMemory is all-or-nothing over the range it is given: one
	 * unreadable page in the middle fails the whole call and reports
	 * nothing about the pages either side. Every thread stack has a guard
	 * page in it, so that is not an unusual shape, and a caller that asked
	 * for a region and got zero would conclude the process refused it.
	 *
	 * So the range is walked in page steps and what came back is returned.
	 * The first page is attempted whole first, because for the overwhelming
	 * majority of reads the range is readable and one call is the right
	 * cost.
	 */
	{
		SIZE_T rd = 0;

		if (ReadProcessMemory(m->h, (void *)(uintptr_t)addr, p, n, &rd))
			return (size_t)rd;
	}

	while (got < n) {
		uint64_t at = addr + got;
		size_t   step = m->page - (size_t)(at % m->page);
		SIZE_T   rd = 0;

		if (step > n - got)
			step = n - got;

		if (!ReadProcessMemory(m->h, (void *)(uintptr_t)at, p + got,
				       step, &rd) || rd == 0)
			break;
		got += (size_t)rd;
	}
	return got;
}

void kofw_pmem_close(struct kofw_pmem *m)
{
	if (!m)
		return;
	if (m->h)
		CloseHandle(m->h);
	free(m->mods);
	free(m->ws);
	free(m);
}

/* --------------------------------------------------------------- printing */

static void size_text(uint64_t n, char *buf, size_t cap)
{
	if (n >= (1ull << 30))
		snprintf(buf, cap, "%lluG", (unsigned long long)(n >> 30));
	else if (n >= (1ull << 20))
		snprintf(buf, cap, "%lluM", (unsigned long long)(n >> 20));
	else if (n >= (1ull << 10))
		snprintf(buf, cap, "%lluK", (unsigned long long)(n >> 10));
	else
		snprintf(buf, cap, "%llu", (unsigned long long)n);
}

size_t kofw_region_describe(const struct kofw_region *r, char *buf, size_t cap)
{
	static const struct {
		uint32_t bit;
		const char *word;
	} words[] = {
		{ KOFW_RGF_RWX,         "rwx" },
		{ KOFW_RGF_UNBACKED,    "unbacked" },
		{ KOFW_RGF_PE,          "pe" },
		{ KOFW_RGF_DIRTY_IMAGE, "dirty" },
		{ KOFW_RGF_DATA_EXEC,   "data-exec" },
		{ KOFW_RGF_GUARD,       "guard" },
		{ KOFW_RGF_UNEXAMINED,  "unexamined" }
	};
	char   sz[16];
	char   prot[4];
	size_t used = 0;
	size_t i;
	int    wrote;

	if (!buf || cap == 0)
		return 0;
	buf[0] = '\0';
	if (!r)
		return 0;

	size_text(r->size, sz, sizeof sz);
	prot[0] = (r->protect & 0xffu) == PAGE_NOACCESS ? '-' : 'r';
	prot[1] = (r->flags & KOFW_RGF_WRITE) ? 'w' : '-';
	prot[2] = (r->flags & KOFW_RGF_EXEC) ? 'x' : '-';
	prot[3] = '\0';

	wrote = snprintf(buf, cap, "0x%016llx %6s %s %s/%s",
			 (unsigned long long)r->base, sz, prot,
			 kofw_rgn_kind_name(r->kind),
			 kofw_rgn_use_name(r->use));
	if (wrote < 0)
		return 0;
	used = (size_t)wrote;
	if (used >= cap)
		return cap - 1u;

	for (i = 0; i < sizeof words / sizeof words[0]; i++) {
		if (!(r->flags & words[i].bit))
			continue;
		wrote = snprintf(buf + used, cap - used, " %s", words[i].word);
		if (wrote < 0)
			return used;
		used += (size_t)wrote;
		if (used >= cap)
			return cap - 1u;
	}

	if (r->path && r->path[0]) {
		wrote = snprintf(buf + used, cap - used, " %s", r->path);
		if (wrote < 0)
			return used;
		used += (size_t)wrote;
		if (used >= cap)
			return cap - 1u;
	}
	return used;
}
