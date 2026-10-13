/*
 * kofmontrace_tracer.c - the tracer: one collector per platform behind one set of calls. Split from kofmontrace.c; the text is unchanged.
 */

/* _GNU_SOURCE before any include - see kofmontrace.c. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "kofmontrace_int.h"

/*
 * THE FILES --watch NAMED, or NULL for "whatever this host will give".
 *
 * A file list, not a directory list, because the two are different marks and
 * only the inode one reports a write - see kofa_fan_option.files. Static
 * rather than threaded through every caller: there is one tracer per run and
 * the list is read once, at open.
 */
const char *kmt_watch[32];
unsigned    kmt_n_watch;

int kmt_tracer_open(struct tracer *t, unsigned providers, uint32_t ring)
{
	int err = 0;

	memset(t, 0, sizeof *t);
#ifdef _WIN32
	{
		struct kofw_mon_option opt;

		memset(&opt, 0, sizeof opt);
		opt.providers = providers;
		opt.ring_capacity = ring;
		opt.trace_self = 1;   /* our own CreateProcess raises the most
				       * important event in the run */
		/*
		 * A DISCOVERY RUN SEES THE STREAM AS IT IS, so the duplicate
		 * collapser is off here and nowhere else.
		 *
		 * This tool exists to answer "what does the machine actually
		 * emit and what does it cost" - the same reason it defaults to
		 * every provider. A reduction would answer a different
		 * question, and it would hide the very measurement that
		 * justifies the reduction: eight identical CreateKey records
		 * from one nslookup is a fact somebody had to be able to see
		 * before anyone could argue for collapsing it.
		 */
		opt.dedup_off = 1;
		t->mon = kofw_mon_open(&opt, &err);
		if (!t->mon) {
			fprintf(stderr, "kofmontrace: %s\n",
				kofw_err_name(err));
			return 0;
		}
	}
#else
	{
		struct kofa_mon_option mo;
		struct kofa_fan_option *fop = &mo.fan;

		(void)providers; (void)ring;
		memset(&mo, 0, sizeof mo);
		/* Our own events are the only ones carrying a pid in a
		 * degraded session, and the group test below is what scopes -
		 * so the self-filter must not drop them first. */
		fop->trace_self = 1;
		/*
		 * WHAT --watch NAMED. The list is NULL-terminated and the
		 * array has a spare slot for that, so a full list is still a
		 * valid one. Naming anything also stops the collector from
		 * reaching for the whole-filesystem mark, which is a different
		 * question and a privilege the operator may not have.
		 */
		if (kmt_n_watch) {
			kmt_watch[kmt_n_watch] = NULL;
			fop->files = kmt_watch;
		}
		/*
		 * BOTH HALVES, which is what makes a Linux trace comparable
		 * to the Windows one: files from fanotify AND execs and exits
		 * from the process connector. This used to open the file
		 * collector alone, so `kofmontrace` on Linux showed no process
		 * starts at all while the same tool on Windows showed seven
		 * providers.
		 */
		t->mon_l = kofa_mon_open(&mo, &err);
		if (!t->mon_l) {
			fprintf(stderr, "kofmontrace: %s\n",
				kofa_err_name(err));
			return 0;
		}
		t->api = kofa_mon_api(t->mon_l);
		t->api->print_extra(t->api->self, stderr);

		/*
		 * WHAT THIS HOST CAN ACTUALLY DELIVER, worked out here so the
		 * REFUSED line below can say the rest out loud.
		 *
		 * fanotify watches FILES. It has nothing to say about a
		 * connection, a name lookup or a thread, and there is no
		 * registry or AMSI to have an opinion about - so six of the
		 * ten providers this tool offers can never arrive on Linux.
		 * The banner used to announce all ten anyway, which is the
		 * exact failure the note beside it warns about: a trace that
		 * shows no network activity, truthfully, to somebody who
		 * asked for network activity and was told they had it.
		 *
		 * FILE_WRITE AND IMAGE ARE PRIVILEGE-DEPENDENT. The full mask
		 * carries FAN_CLOSE_WRITE and FAN_OPEN_EXEC; the unprivileged
		 * fallback carries neither, so a degraded session reports
		 * creates, deletes and renames and nothing else. See the mask
		 * pair in afan.c.
		 */
		t->asked = providers;
		t->granted = providers & TRACER_SUB_FILE;
		if (kofa_fan_mode(kofa_mon_fan(t->mon_l)) != KOFA_FAN_DEGRADED)
			t->granted |= providers & (TRACER_SUB_FILE_WRITE |
						   TRACER_SUB_IMAGE);
		/*
		 * NOTHING TO SCOPE BY, SAID OUT LOUD.
		 *
		 * Unprivileged, every record about another process arrives
		 * with KOF_F_PID in `miss` - so the group test below has
		 * nothing to test and would refuse the entire trace, which
		 * looks exactly like a program that did nothing. Showing
		 * everything and saying so is the only honest answer: the
		 * lines are real, the attribution is not, and a reader told
		 * that can still use them.
		 */
		if (kofa_fan_mode(kofa_mon_fan(t->mon_l)) == KOFA_FAN_DEGRADED) {
			t->unscoped = 1;
			fputs("kofmontrace: UNSCOPED: this session cannot "
			      "attribute events, so every record below is "
			      "shown and NONE is known to belong to the "
			      "traced program - run as root to scope it\n",
			      stderr);
		}
	}
#endif
	return 1;
}

/*
 * Start it, STOPPED, so that "the subject is known" happens strictly before
 * "the subject can do anything". Windows creates it suspended; POSIX raises
 * SIGSTOP on itself after setpgid and before exec.
 */
int kmt_tracer_start(struct tracer *t, char **argv, const char *cmdline)
{
#ifdef _WIN32
	memset(&t->si, 0, sizeof t->si);
	t->si.cb = sizeof t->si;
	memset(&t->pi, 0, sizeof t->pi);
	snprintf(t->cmd, sizeof t->cmd, "%s", cmdline);
	if (!CreateProcessA(NULL, t->cmd, NULL, NULL, FALSE,
			    CREATE_SUSPENDED, NULL, NULL, &t->si, &t->pi)) {
		fprintf(stderr, "kofmontrace: cannot run '%s' (error %lu)\n",
			argv[0], (unsigned long)GetLastError());
		return 0;
	}
	t->root_pid = t->pi.dwProcessId;
	return 1;
#else
	(void)cmdline;
	t->kid = fork();
	if (t->kid < 0) {
		perror("kofmontrace: fork");
		return 0;
	}
	if (t->kid == 0) {
		setpgid(0, 0);
		raise(SIGSTOP);
		execvp(argv[0], argv);
		fprintf(stderr, "kofmontrace: cannot run %s: %s\n",
			argv[0], strerror(errno));
		_exit(127);
	}
	/* Set on both sides: whichever runs first, the group is right before
	 * the child can produce an event. */
	setpgid(t->kid, t->kid);
	t->group = t->kid;
	t->root_pid = (uint32_t)t->kid;
	t->running = 1;

	/*
	 * WAIT FOR IT TO ACTUALLY BE STOPPED, and this is not belt and braces.
	 *
	 * A SIGCONT delivered before the child reaches raise(SIGSTOP) is not
	 * queued and not remembered - it is simply gone, and the child then
	 * stops and never starts again. The tracer sits out its whole timeout
	 * watching a process that never ran, and the trace is empty for a
	 * reason nothing in it mentions. WUNTRACED returns when the child has
	 * stopped, which is the only point at which SIGCONT is certain to be
	 * seen.
	 */
	{
		int st;

		if (waitpid(t->kid, &st, WUNTRACED) == t->kid &&
		    !WIFSTOPPED(st)) {
			/* It exited before it ever stopped: exec failed, or
			 * the program is gone. Nothing to trace and nothing
			 * to resume. */
			t->running = 0;
			fprintf(stderr, "kofmontrace: %s did not start\n",
				argv[0]);
			return 0;
		}
	}
	return 1;
#endif
}

/* Scope the collector to it. Windows is told; POSIX already is, by the group. */
int kmt_tracer_track(struct tracer *t, const char *leaf)
{
#ifdef _WIN32
	return kofw_mon_track(t->mon, t->root_pid, leaf) == 0;
#else
	(void)t; (void)leaf;
	return 1;
#endif
}

/*
 * Contain the lifetime, BEFORE it runs - a child created before the container
 * exists is outside it forever. Non-zero when contained.
 */
int kmt_tracer_contain(struct tracer *t)
{
#ifdef _WIN32
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;

	t->job = CreateJobObjectW(NULL, NULL);
	if (t->job) {
		memset(&eli, 0, sizeof eli);
		eli.BasicLimitInformation.LimitFlags =
			JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(t->job,
					     JobObjectExtendedLimitInformation,
					     &eli, sizeof eli) ||
		    !AssignProcessToJobObject(t->job, t->pi.hProcess)) {
			CloseHandle(t->job);
			t->job = NULL;
		}
	}
	return t->job != NULL;
#else
	/* The group was created at fork and every descendant inherits it, so
	 * there is nothing to assign and nothing that can be created outside
	 * it - which is the one respect in which this is stronger than the
	 * job object it replaces. */
	(void)t;
	return 1;
#endif
}

void kmt_tracer_resume(struct tracer *t)
{
#ifdef _WIN32
	ResumeThread(t->pi.hThread);
#else
	kill(t->kid, SIGCONT);
#endif
}

/* The next record, already neutral and already scoped. */
#ifndef _WIN32
#define TRACER_SEEN (sizeof ((struct tracer *)0)->seen / \
		     sizeof ((struct tracer *)0)->seen[0])

/* Was this pid in the traced group? 1 yes, 0 no, -1 never resolved. */
static int seen_get(const struct tracer *t, uint32_t pid)
{
	size_t i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	size_t n;

	for (n = 0; n < 8; n++, i = (i + 1) % TRACER_SEEN) {
		if (!t->seen[i].known)
			return -1;
		if (t->seen[i].pid == pid)
			return t->seen[i].in;
	}
	return -1;
}

static void seen_put(struct tracer *t, uint32_t pid, int in)
{
	size_t i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	size_t n;

	for (n = 0; n < 8; n++, i = (i + 1) % TRACER_SEEN) {
		if (!t->seen[i].known || t->seen[i].pid == pid) {
			t->seen[i].pid = pid;
			t->seen[i].known = 1;
			t->seen[i].in = (uint8_t)(in ? 1 : 0);
			return;
		}
	}
	/* Every probe taken: overwrite the first. See the note on the table. */
	i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	t->seen[i].pid = pid;
	t->seen[i].known = 1;
	t->seen[i].in = (uint8_t)(in ? 1 : 0);
}
#endif

int kmt_tracer_next(struct tracer *t, struct kof_evt *out, uint32_t wait_ms,
		       int all)
{
#ifdef _WIN32
	(void)all;
	if (!kofw_mon_next(t->mon, &t->raw, wait_ms))
		return 0;
	kofw_evt_to_kof(&t->raw, out);
	return 1;
#else
	for (;;) {
		if (!kof_mon_next(t->api, out, wait_ms))
			return 0;
		if (all || t->unscoped)
			return 1;
		if (out->miss & KOF_F_PID) {
			t->out_of_scope++;
			continue;
		}
		{
			pid_t g = getpgid((pid_t)out->pid);
			int known;

			if (g >= 0) {
				/* The kernel still knows. Answer, and
				 * remember for after it exits. */
				seen_put(t, out->pid, g == t->group);
				if (g == t->group)
					return 1;
				t->out_of_scope++;
				continue;
			}
			/*
			 * IT HAS EXITED. Answer from what was learned while it
			 * lived, and when nothing was - a process that wrote
			 * one file and was gone before the drain - SHOW IT.
			 *
			 * That is the deliberate choice: a trace that drops
			 * what it cannot prove drops the dropper, and the
			 * whole run is then clean for the one reason nobody
			 * would suspect. Counted separately and reported at
			 * the end, so nothing here is mistaken for attributed.
			 */
			known = seen_get(t, out->pid);
			if (known == 1)
				return 1;
			if (known == 0) {
				t->out_of_scope++;
				continue;
			}
			t->unattributed++;
			out->miss |= KOF_F_PID;
			return 1;
		}
	}
#endif
}

/*
 * The image name for the pid of the record kmt_tracer_next last returned. It reads
 * the RAW record rather than the neutral one because the Windows lookup is
 * keyed on (pid, create_time) and create_time is a collector field - a pid on
 * its own names whoever holds it now, which after a reuse is the wrong
 * process. Linux has no such map and returns the empty string, which
 * kof_evt_render already treats as "not known".
 */
const char *kmt_tracer_name_of(struct tracer *t)
{
#ifdef _WIN32
	return kofw_mon_name_of(t->mon, t->raw.pid,
				t->raw.type == KOF_EVT_PROC_START ||
				t->raw.type == KOF_EVT_PROC_STOP
					? t->raw.create_time : 0);
#else
	(void)t;
	return "";
#endif
}

int kmt_tracer_alive(struct tracer *t)
{
#ifdef _WIN32
	return kofw_mon_tracked_alive(t->mon) != 0;
#else
	int st;

	if (!t->running)
		return 0;
	if (waitpid(t->kid, &st, WNOHANG) == t->kid)
		t->running = 0;
	return t->running;
#endif
}

void kmt_tracer_health(struct tracer *t, struct kof_evt_health *nh)
{
#ifdef _WIN32
	kofw_mon_health_neutral(t->mon, nh);
#else
	t->api->health(t->api->self, nh);
#endif
}

void kmt_tracer_extra(struct tracer *t, FILE *out)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	kofw_health_print_extra(out, &h);
#else
	t->api->print_extra(t->api->self, out);
#endif
}

/*
 * WHAT THE COLLECTOR WAS ASKED FOR AND WHAT IT GOT. Windows can refuse a
 * provider one at a time; the Linux collector is one subscription that either
 * opened or did not, and kmt_tracer_open has already failed if it did not - so
 * asked and enabled are equal and the "REFUSED" report never fires.
 */
void kmt_tracer_subs(struct tracer *t, uint32_t *asked, uint32_t *enabled)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	*asked = h.sub_asked;
	*enabled = h.sub_enabled;
#else
	*asked = t->asked;
	*enabled = t->granted;
#endif
}

const char *kmt_tracer_sub_name(uint32_t bit)
{
#ifdef _WIN32
	return kofw_sub_name(bit);
#else
	switch (bit) {
	case TRACER_SUB_PROCESS:    return "process";
	case TRACER_SUB_IMAGE:      return "image";
	case TRACER_SUB_FILE:       return "file";
	case TRACER_SUB_FILE_WRITE: return "file-write";
	case TRACER_SUB_FILE_OPEN:  return "file-open";
	case TRACER_SUB_NET:        return "net";
	case TRACER_SUB_REGISTRY:   return "registry";
	case TRACER_SUB_AMSI:       return "amsi";
	case TRACER_SUB_DNS:        return "dns";
	case TRACER_SUB_THREAD:     return "thread";
	default:                    return "?";
	}
#endif
}

/*
 * The output filter. Windows applies it inside the collector, which is where
 * dropping belongs when the collector is the thing producing the volume.
 * fanotify has no such knob - the mask is set at open and there is nothing
 * per-event to tune - so the flags that matter there are carried on the tracer
 * and applied by kmt_tracer_next.
 */
void kmt_tracer_filter(struct tracer *t, uint32_t root_pid, int no_scope,
			  int show_all_img, int show_raw, int amsi_anywhere)
{
#ifdef _WIN32
	struct kofw_filter f;

	memset(&f, 0, sizeof f);
	/*
	 * NO SCOPE AT ALL, when asked.
	 *
	 * Scoping to a tree is what makes a trace readable, and it has one
	 * failure that is not a bug and cannot be fixed from inside:
	 * parentage. A payload that migrates is running in a process that is
	 * nobody's descendant, and everything it does from there - including
	 * every process it goes on to create - is attributed outside the tree
	 * and dropped. The trace shows a clean subtree and says nothing about
	 * the thing that walked out of it.
	 *
	 * There is no clever repair for that: no event says "this process is
	 * now running somebody else's code". So the honest option is to turn
	 * the scope off and take the noise, which on a quiet test machine is a
	 * fair trade.
	 */
	f.root_pid = no_scope ? 0u : root_pid;
	if (!show_all_img)
		f.drop_loc = 1u << KOF_LOC_SYSTEM;
	if (!show_raw)
		f.types = ~(uint32_t)(1u << KOF_EVT_RAW);
	if (amsi_anywhere)
		f.scope_exempt_prov = 1u << KOFW_PROV_AMSI;
	kofw_mon_filter(t->mon, &f);
#else
	(void)t; (void)root_pid; (void)no_scope;
	(void)show_all_img; (void)show_raw; (void)amsi_anywhere;
#endif
}

/*
 * THE SUBJECT AS A PATH THAT CAN BE OPENED. Both hosts resolve a bare name
 * against PATH before running it, so the report has to resolve it the same
 * way or every digest in it is "could not be read". Non-zero when `out` holds
 * a path.
 */
int kmt_tracer_resolve(const char *name, char *out, size_t cap)
{
#ifdef _WIN32
	/*
	 * SearchPath returns TWO different lengths and only one of them means
	 * it wrote something: the characters PUT IN the buffer on success, and
	 * the characters the buffer would have NEEDED - the NUL among them -
	 * when it was too small. The second writes nothing. Reading non-zero
	 * as success left `out` holding whatever it held before and the report
	 * named a subject it had never opened, which is the failure this whole
	 * function exists to prevent.
	 */
	DWORD n = SearchPathA(NULL, name, ".exe", (DWORD)cap, out, NULL);

	return n != 0 && (size_t)n < cap;
#else
	const char *path, *p, *e;
	size_t nlen = strlen(name);

	if (strchr(name, '/')) {   /* already a path: execvp does not search */
		if (nlen >= cap)
			return 0;
		memcpy(out, name, nlen + 1);
		return access(out, X_OK) == 0;
	}
	/*
	 * The search this has to match is execvp's, which falls back to
	 * confstr when PATH is unset - so the fallback is the same one, not a
	 * guess at /bin:/usr/bin.
	 */
	path = getenv("PATH");
	if (!path || !*path) {
		static char def[1024];
		size_t need = confstr(_CS_PATH, def, sizeof def);

		/*
		 * confstr reports the size it NEEDED, not the size it wrote,
		 * and a value longer than the buffer is truncated while still
		 * returning non-zero. A truncated PATH is missing its last
		 * directory, and the whole point here is to search the same
		 * places the exec will - so a search that cannot be the same
		 * one is refused rather than done differently.
		 */
		if (need == 0 || need > sizeof def)
			return 0;
		path = def;
	}
	for (p = path; *p; p = (*e ? e + 1 : e)) {
		size_t dlen;

		e = strchr(p, ':');
		if (!e)
			e = p + strlen(p);
		dlen = (size_t)(e - p);
		if (dlen == 0) {   /* an empty field means "." */
			p = ".";
			dlen = 1;
		}
		if (dlen + 1 + nlen >= cap)
			continue;
		memcpy(out, p, dlen);
		out[dlen] = '/';
		memcpy(out + dlen + 1, name, nlen + 1);
		if (access(out, X_OK) == 0)
			return 1;
	}
	return 0;
#endif
}

/*
 * HOW MANY RECORDS WERE SHOWN WITHOUT BEING ATTRIBUTED - see kmt_tracer_next.
 * Zero on Windows, which tracks processes and therefore always knows.
 */
void kmt_tracer_report_unattributed(struct tracer *t, FILE *out)
{
#ifdef _WIN32
	(void)t; (void)out;
#else
	if (!t->unattributed)
		return;
	fprintf(out, "   %llu event(s) shown but NOT attributed: the process "
		"that caused them had already exited\n"
		"   and was never seen alive, so it could not be placed in or "
		"out of the traced group.\n",
		(unsigned long long)t->unattributed);
#endif
}

/* How many records the scope refused - the one number that says whether a
 * quiet trace was quiet or merely narrow. */
uint64_t kmt_tracer_filtered_scope(struct tracer *t)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	return h.filtered_scope;
#else
	return t->out_of_scope;
#endif
}

/* Two Windows-only readouts. Both have no Linux counterpart and say so by
 * being empty rather than by being printed wrong. */
int kmt_tracer_describe(struct tracer *t, char *buf, size_t cap)
{
#ifdef _WIN32
	return kofw_mon_describe(t->mon, buf, cap) != 0;
#else
	(void)t; (void)buf; (void)cap;
	return 0;
#endif
}

const char *kmt_tracer_tracked_nth(struct tracer *t, uint32_t k,
				      uint32_t *pid)
{
#ifdef _WIN32
	return kofw_mon_tracked_nth(t->mon, k, pid);
#else
	(void)t; (void)k; (void)pid;
	return NULL;
#endif
}

/* End the run. The container is what makes this one call rather than a hunt. */
void kmt_tracer_stop(struct tracer *t)
{
#ifdef _WIN32
	if (t->job) {
		TerminateJobObject(t->job, 1);
		CloseHandle(t->job);
		t->job = NULL;
	}
#else
	kill(-t->group, SIGKILL);
	if (t->running) {
		int st;

		(void)waitpid(t->kid, &st, 0);
		t->running = 0;
	}
#endif
}

void kmt_tracer_close(struct tracer *t)
{
#ifdef _WIN32
	if (t->pi.hThread)  CloseHandle(t->pi.hThread);
	if (t->pi.hProcess) CloseHandle(t->pi.hProcess);
	kofw_mon_close(t->mon);
#else
	kof_mon_close(t->api);
#endif
}
