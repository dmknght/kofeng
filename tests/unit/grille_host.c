/*
 * grille_host - the half of libkofgrille that has no Windows in it.
 *
 * WHY THIS FILE EXISTS AT ALL.
 *
 * kofgrille.h, wevt_ring.h and wtext.h each say, in so many words, that a
 * particular piece was kept free of the Windows API *so that it could be
 * tested* - the ring because it is the one place a record crosses a thread,
 * the conversions because they are the only arithmetic in the decode, the
 * classifier because a rule written against a path is what an attacker
 * respells to evade. Three claims, and until this file none of them were
 * checked by anything.
 *
 * Nothing here touches ETW, so it builds and runs on the Linux CI. That is the
 * whole point: the ETW layer cannot be tested off Windows, so everything that
 * CAN be has to be, or the untested part is the entire library rather than the
 * thin edge that talks to the provider.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../../libkofgrille/kofgrille.h"
#include "../../libkofgrille/wevt_ring.h"
#include "../../libkofgrille/wfilter.h"
#include "../../libkofgrille/wtext.h"
#include "../../libkofeng/kofevt/kofevt.h"
#include "../../libkofeng/kofevt/kofevtfmt.h"
#include "../../libkofeng/kofevt/kofevtlog.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

static void eq_str(const char *what, const char *got, const char *want)
{
	if (strcmp(got, want)) {
		printf("  FAIL %s: got \"%s\", wanted \"%s\"\n", what, got,
		       want);
		failures++;
	}
}

static void eq_u64(const char *what, uint64_t got, uint64_t want)
{
	if (got != want) {
		printf("  FAIL %s: got %llu, wanted %llu\n", what,
		       (unsigned long long)got, (unsigned long long)want);
		failures++;
	}
}

/* ---- the record's own layout ------------------------------------------- */

/*
 * The ring is an array of these and the text arena is sized from the constant,
 * so a field added above text[] without moving the constant makes every string
 * in every record start at the wrong offset - and a path read from the wrong
 * offset still looks like a path.
 */
static void t_layout(void)
{
	if (sizeof(struct kofw_evt) != KOFW_REC_SIZE)
		fail("layout", "struct kofw_evt is not KOFW_REC_SIZE bytes");
	if ((size_t)((const char *)&((struct kofw_evt *)0)->text -
		     (const char *)0) != KOFW_REC_HEAD)
		fail("layout", "KOFW_REC_HEAD is not where text[] starts");
}

/* ---- every type has a name ---------------------------------------------- */

/*
 * A verb added to the enum without a name prints as "?", and "?" in a trace is
 * indistinguishable from a decode that went wrong. The renderer's switch has
 * the same problem one layer up, but this catches the common half of it - and
 * it catches it the moment somebody adds a verb, which is when they still
 * remember what it was for.
 */
static void t_type_names(void)
{
	uint16_t i;

	for (i = 1; i < KOF_EVT_TYPE_COUNT; i++) {
		const char *n = kof_evt_verb_name(i);

		if (!n || !*n || !strcmp(n, "?")) {
			printf("  FAIL type name: verb %u has no name\n",
			       (unsigned)i);
			failures++;
		}
	}
	/* Out of range still has to answer something, so a record written by a
	 * build that knew one more verb still prints. */
	if (strcmp(kof_evt_verb_name(KOF_EVT_TYPE_COUNT + 50u), "?"))
		fail("type name", "an unknown verb did not come back as ?");

	for (i = 1; i < KOFW_PROV_COUNT; i++) {
		if (!strcmp(kofw_provider_name((uint8_t)i), "?")) {
			printf("  FAIL provider name: %u has no name\n",
			       (unsigned)i);
			failures++;
		}
	}
}

/* ---- UTF-16 ------------------------------------------------------------- */

static void t_utf16(void)
{
	char buf[64];
	int  cut = 1;
	size_t n;

	{
		static const uint16_t ascii[] = { 'a', 'b', 'c', 0 };
		n = kofw_utf16_to_utf8(ascii, 4, buf, sizeof buf, &cut);
		eq_str("utf16 ascii", buf, "abc");
		eq_u64("utf16 ascii len", n, 3);
		if (cut)
			fail("utf16 ascii", "reported cut and was not");
	}

	/* A surrogate pair is ONE codepoint of four bytes, not two of three.
	 * Getting this wrong emits CESU-8, which is not UTF-8 and which every
	 * consumer downstream then carries. U+1F600. */
	{
		static const uint16_t pair[] = { 0xd83d, 0xde00, 0 };
		n = kofw_utf16_to_utf8(pair, 3, buf, sizeof buf, &cut);
		eq_u64("utf16 surrogate len", n, 4);
		eq_str("utf16 surrogate", buf, "\xf0\x9f\x98\x80");
	}

	/* A LONE half is not a reason to lose the rest of a path. */
	{
		static const uint16_t lone[] = { 0xd83d, 'x', 0 };
		n = kofw_utf16_to_utf8(lone, 3, buf, sizeof buf, &cut);
		eq_str("utf16 lone high", buf, "\xef\xbf\xbdx");
		eq_u64("utf16 lone high len", n, 4);
	}
	{
		static const uint16_t lone[] = { 0xdc00, 'y', 0 };
		(void)kofw_utf16_to_utf8(lone, 3, buf, sizeof buf, &cut);
		eq_str("utf16 lone low", buf, "\xef\xbf\xbdy");
	}

	/*
	 * A TERMINAL ESCAPE INSIDE A FILE NAME.
	 *
	 * The name is chosen by whoever created the file and it is printed to a
	 * terminal, so an ESC that survives here is a report that lies about
	 * what it says. Same reason the engine sanitises an archive entry name.
	 */
	{
		static const uint16_t esc[] = { 'a', 0x1b, '[', '2', 'J', 0 };
		(void)kofw_utf16_to_utf8(esc, 6, buf, sizeof buf, &cut);
		eq_str("utf16 escape", buf, "a.[2J");
	}

	/*
	 * A BUFFER THAT RUNS OUT MID-CODEPOINT.
	 *
	 * The cut has to land on a codepoint boundary and it has to be
	 * reported: half a UTF-8 sequence is not a string, and a path that was
	 * truncated silently is exactly what a later rule matches against and
	 * is wrong about.
	 */
	{
		static const uint16_t wide[] = { 0x4e00, 0x4e00, 0x4e00, 0 };
		char small[5];   /* room for one 3-byte codepoint and a NUL */

		cut = 0;
		n = kofw_utf16_to_utf8(wide, 4, small, sizeof small, &cut);
		eq_u64("utf16 cut len", n, 3);
		if (!cut)
			fail("utf16 cut", "was cut and did not say so");
		if (small[n] != '\0')
			fail("utf16 cut", "not terminated");
	}

	/* A zero-capacity buffer must write nothing at all rather than a NUL. */
	{
		static const uint16_t any[] = { 'a', 0 };
		char none[1];
		none[0] = (char)0x7f;
		n = kofw_utf16_to_utf8(any, 2, none, 0, &cut);
		eq_u64("utf16 zero cap", n, 0);
		if (none[0] != (char)0x7f)
			fail("utf16 zero cap", "wrote into a zero-size buffer");
	}
}

static void t_ansi(void)
{
	char buf[32];
	int  cut = 0;

	{
		static const uint8_t s[] = { 'c', ':', '\\', 'a', 0 };
		(void)kofw_ansi_to_text(s, sizeof s, buf, sizeof buf, &cut);
		eq_str("ansi plain", buf, "c:\\a");
	}
	/* No codepage is declared, so a high byte is marked unknown rather than
	 * guessed at or passed through as invalid UTF-8. */
	{
		static const uint8_t s[] = { 'a', 0xe9, 'b', 0 };
		(void)kofw_ansi_to_text(s, sizeof s, buf, sizeof buf, &cut);
		eq_str("ansi high byte", buf, "a?b");
	}
	{
		static const uint8_t s[] = { 'a', 0x1b, 'b', 0 };
		(void)kofw_ansi_to_text(s, sizeof s, buf, sizeof buf, &cut);
		eq_str("ansi escape", buf, "a.b");
	}
	{
		static const uint8_t s[] = { 'a', 'b', 'c', 'd' };
		char small[3];

		cut = 0;
		(void)kofw_ansi_to_text(s, sizeof s, small, sizeof small, &cut);
		eq_str("ansi cut", small, "ab");
		if (!cut)
			fail("ansi cut", "was cut and did not say so");
	}
}

/* ---- a buffer is not a C string ----------------------------------------- */

/*
 * WHAT BLOCKED AMSI CONTENT, half of it, tested where it can be tested.
 *
 * A submitted script block is a length-delimited BUFFER. Read with the string
 * conversion it ends at the first NUL - and a UTF-16 buffer read as bytes has
 * a NUL at index 1, so the whole submission comes back as one character.
 */
static void t_bytes(void)
{
	char buf[64];
	int  cut = 0;
	size_t n;

	{
		static const uint8_t utf16le[] = {
			'e', 0, 'c', 0, 'h', 0, 'o', 0
		};

		/* The string version stops dead at the first high byte. */
		n = kofw_ansi_to_text(utf16le, sizeof utf16le, buf,
				      sizeof buf, &cut);
		eq_u64("ansi stops at NUL", n, 1);

		/* The buffer version does not. */
		n = kofw_bytes_to_text(utf16le, sizeof utf16le, buf,
				       sizeof buf, &cut);
		eq_u64("bytes keeps going", n, sizeof utf16le);
		eq_str("bytes readable", buf, "e.c.h.o.");
	}

	/* Read as what it is, it is just text. */
	{
		static const uint16_t script[] = {
			'e', 'c', 'h', 'o', ' ', 'h', 'i'
		};
		n = kofw_utf16_to_utf8(script, 7, buf, sizeof buf, &cut);
		eq_str("utf16 script", buf, "echo hi");
		eq_u64("utf16 script len", n, 7);
	}

	/* A buffer that does not fit is cut and says so. */
	{
		static const uint8_t big[32] = { 0 };
		char small[5];

		cut = 0;
		n = kofw_bytes_to_text(big, sizeof big, small, sizeof small,
				       &cut);
		eq_u64("bytes cut len", n, 4);
		if (!cut)
			fail("bytes", "was cut and did not say so");
	}
}

/* ---- path classification ------------------------------------------------ */

static void loc_is(const char *path, uint8_t want)
{
	uint8_t got = kof_classify_path(path);

	if (got != want) {
		printf("  FAIL classify \"%s\": got %s, wanted %s\n", path,
		       kof_loc_name(got), kof_loc_name(want));
		failures++;
	}
}

static void t_classify(void)
{
	/*
	 * TEMP BEFORE USER, which is the whole correctness of the function.
	 *
	 * The per-user temp directory is INSIDE a user profile, so a \Users\
	 * check that ran first would swallow it and every dropper's first write
	 * would be filed as ordinary user activity.
	 */
	loc_is("C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe", KOF_LOC_TEMP);
	loc_is("C:\\Windows\\Temp\\a.exe", KOF_LOC_TEMP);
	loc_is("C:\\Users\\bob\\Desktop\\a.exe", KOF_LOC_USER);

	/* ETW delivers device paths, not drive letters. If this stopped
	 * matching, every module load would classify as `other` and the
	 * system-module filter would suppress nothing. */
	loc_is("\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll",
	       KOF_LOC_SYSTEM);
	loc_is("\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Temp\\x",
	       KOF_LOC_TEMP);

	/* The 8.3 spellings of the same places - the branch that exists so a
	 * short path is not silently classified as something else. */
	loc_is("C:\\DOCUME~1\\bob\\LOCALS~1\\Temp\\a.exe", KOF_LOC_TEMP);
	loc_is("C:\\PROGRA~1\\thing\\a.dll", KOF_LOC_PROGRAMS);

	/* The two extra system directories an ARM64 machine has. */
	loc_is("C:\\Windows\\SyChpe32\\kernel32.dll", KOF_LOC_SYSTEM);
	loc_is("C:\\Windows\\SysArm32\\kernel32.dll", KOF_LOC_SYSTEM);
	loc_is("C:\\Windows\\SysWOW64\\kernel32.dll", KOF_LOC_SYSTEM);

	/* Case is not a way to spell a different location. */
	loc_is("c:\\windows\\system32\\ntdll.dll", KOF_LOC_SYSTEM);
	loc_is("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", KOF_LOC_SYSTEM);

	loc_is("D:\\stuff\\a.exe", KOF_LOC_OTHER);

	/*
	 * WINDOWS FOLDS CASE, LINUX DOES NOT, and one matcher cannot do both -
	 * so the table says per row and this is what checks it.
	 *
	 * Folding everything would have been the easy bug: /etc/PASSWD is a
	 * different file from /etc/passwd, and reporting T1136.001 against it
	 * is a finding about a file nobody touched.
	 */
	loc_is("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", KOF_LOC_SYSTEM);
	loc_is("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\"
	       "CURRENTVERSION\\RUN", KOF_LOC_AUTOSTART);
	loc_is("/etc/passwd", KOF_LOC_CREDENTIAL);
	loc_is("/etc/PASSWD", KOF_LOC_OTHER);
	loc_is("/ETC/ld.so.preload", KOF_LOC_OTHER);

	/* ---- the technique tag, which rides the same single pass -------- */
	{
		uint16_t att = 0xffff;

		if (kof_classify("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
				  "\\Windows\\CurrentVersion\\Run", &att)
		    != KOF_LOC_AUTOSTART || att != KOF_ATT_RUN_KEY)
			fail("attack", "a Run value is not T1547.001");

		if (kof_classify("/etc/ld.so.preload", &att)
		    != KOF_LOC_PRELOAD || att != KOF_ATT_LD_PRELOAD)
			fail("attack", "ld.so.preload is not T1574.006");

		if (kof_classify("C:\\Windows\\System32\\drivers\\etc\\"
				  "hosts", &att) != KOF_LOC_HOSTS ||
		    att != KOF_ATT_HOSTS)
			fail("attack", "the hosts file is not T1562.001");

		if (kof_classify("\\REGISTRY\\MACHINE\\SYSTEM\\"
				  "CurrentControlSet\\Services\\evil", &att)
		    != KOF_LOC_SERVICE || att != KOF_ATT_SERVICE)
			fail("attack", "a service key is not T1543.003");

		/* Temp is not a technique. A location worth knowing and a
		 * technique are different claims, and conflating them would
		 * tag every ordinary download. */
		if (kof_classify("C:\\Users\\b\\AppData\\Local\\Temp\\a",
				  &att) != KOF_LOC_TEMP ||
		    att != KOF_ATT_NONE)
			fail("attack", "temp carries a technique tag");

		/*
		 * THE METASPLOIT PERSISTENCE SET, one assertion per module.
		 *
		 * A coverage claim is worth what somebody checked, so each of
		 * these is a path one of those modules writes. Four of them
		 * matched nothing when this list was first walked, which is
		 * why the four techniques exist.
		 */
		if (kof_classify("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
				  "\\Windows NT\\CurrentVersion\\Image File "
				  "Execution Options\\sethc.exe", &att)
		    == KOF_LOC_UNKNOWN || att != KOF_ATT_IFEO)
			fail("attack", "accessibility_features_debugger");

		if (kof_classify("C:\\Windows\\System32\\sethc.exe", &att)
		    != KOF_LOC_AUTOSTART || att != KOF_ATT_ACCESSIBILITY)
			fail("attack", "sethc replacement not a technique");

		if (kof_classify("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
				  "\\Windows NT\\CurrentVersion\\Accessibility"
				  "\\ATs\\evil", &att) != KOF_LOC_AUTOSTART ||
		    att != KOF_ATT_ACCESSIBILITY)
			fail("attack", "assistive_technology");

		if (kof_classify("C:\\ProgramData\\Microsoft\\Network"
				  "\\Downloader\\qmgr.db", &att)
		    != KOF_LOC_AUTOSTART || att != KOF_ATT_BITS_JOB)
			fail("attack", "bits");

		if (kof_classify("C:\\Users\\b\\Documents\\WindowsPowerShell"
				  "\\Microsoft.PowerShell_profile.ps1", &att)
		    != KOF_LOC_SHELL_INIT || att != KOF_ATT_PS_PROFILE)
			fail("attack", "powershell_profile");

		if (kof_classify("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
				  "\\Active Setup\\Installed Components\\{g}"
				  "\\StubPath", &att) != KOF_LOC_AUTOSTART ||
		    att != KOF_ATT_ACTIVE_SETUP)
			fail("attack", "registry_active_setup");

		if (kof_classify("\\REGISTRY\\MACHINE\\SYSTEM\\"
				  "CurrentControlSet\\Services\\evil", &att)
		    != KOF_LOC_SERVICE || att != KOF_ATT_SERVICE)
			fail("attack", "service / service_for_user");

		if (kof_classify("C:\\Windows\\System32\\Tasks\\evil", &att)
		    != KOF_LOC_SCHEDULE || att != KOF_ATT_SCHED_TASK)
			fail("attack", "service_for_user schedule");

		if (kof_classify("C:\\Users\\b\\AppData\\Roaming\\Microsoft"
				  "\\Windows\\Start Menu\\Programs\\Startup"
				  "\\e.lnk", &att) != KOF_LOC_AUTOSTART ||
		    att != KOF_ATT_STARTUP_DIR)
			fail("attack", "startup_folder");

		/* Every technique in the list has both an id and a name. */
		{
			uint16_t i;
			for (i = 1; i < KOF_ATT_COUNT; i++) {
				if (!*kof_attack_id(i) ||
				    !*kof_attack_name(i)) {
					printf("  FAIL attack %u: no id or "
					       "name\n", (unsigned)i);
					failures++;
				}
			}
		}
	}

	/* "nothing to classify" is not the same answer as "classified, and it
	 * is nowhere interesting" - drop_loc is tested against this. */
	loc_is("", KOF_LOC_UNKNOWN);
	loc_is(NULL, KOF_LOC_UNKNOWN);
}

/* ---- the ring ----------------------------------------------------------- */

static struct kofw_evt *push(struct kofw_ring *r, uint64_t seq)
{
	struct kofw_evt *s = kofw_ring_claim(r);

	if (!s)
		return NULL;
	s->seq = seq;
	(void)kofw_ring_commit(r);
	return s;
}

static void t_ring(void)
{
	struct kofw_ring r;
	struct kofw_evt  e;
	uint64_t i, taken = 0, gaps = 0, prev = 0;

	if (kofw_ring_init(&r, 256) != 0) {
		fail("ring", "would not initialise");
		return;
	}

	/*
	 * A DROP MUST LEAVE A HOLE IN seq, and this is the test that says so.
	 *
	 * seq used to be taken from ring.produced, which only advances on a
	 * successful commit - so every seq a consumer saw was contiguous no
	 * matter how much had been thrown away, and kofw_health.seq_gaps could
	 * not be non-zero. The producer now stamps an ARRIVAL counter, and a
	 * refused record is exactly the number that goes missing.
	 */
	for (i = 0; i < 300; i++)
		(void)push(&r, i);           /* 256 slots: 44 must be refused */

	eq_u64("ring dropped", r.dropped, 44);
	eq_u64("ring produced", r.produced, 256);
	eq_u64("ring high water", r.high_water, 256);

	/*
	 * One taken to free a slot, then one more arrival - so the hole falls
	 * INSIDE the stream. A gap only at the very end is not something a
	 * consumer reading in order can ever observe, and testing only that
	 * would have passed against the old, broken numbering too.
	 */
	if (!kofw_ring_take(&r, &e))
		fail("ring", "empty after 256 commits");
	prev  = e.seq;
	taken = 1;

	if (!push(&r, 300))
		fail("ring", "refused a record after a slot was freed");

	while (kofw_ring_take(&r, &e)) {
		if (e.seq > prev + 1)
			gaps += e.seq - prev - 1;
		prev = e.seq;
		taken++;
	}
	eq_u64("ring taken", taken, 257);
	eq_u64("ring seq gaps", gaps, 44);

	/* Empty is empty, and a take on it must not hand back a stale slot. */
	if (kofw_ring_take(&r, &e))
		fail("ring", "took from an empty ring");

	/* It wraps: the ring is reusable after being drained, which is the case
	 * a mask-versus-modulo mistake gets wrong only on the second lap. */
	for (i = 0; i < 300; i++) {
		if (!push(&r, 1000 + i))
			fail("ring", "refused after being drained");
		if (!kofw_ring_take(&r, &e))
			fail("ring", "nothing to take after a commit");
		eq_u64("ring wrap seq", e.seq, 1000 + i);
	}

	kofw_ring_free(&r);
}

/* ---- the subtree filter ------------------------------------------------- */

static void mk(struct kofw_evt *e, uint16_t type, uint32_t pid, uint32_t ppid)
{
	memset(e, 0, sizeof *e);
	e->type       = type;
	e->pid        = pid;
	e->ppid       = ppid;
	e->raiser_pid = ppid;
	e->off_image   = KOF_TEXT_NONE;
	e->off_object  = KOF_TEXT_NONE;
	/* All THREE, because 0 is a legal offset: a record that left this at
	 * zero would report the object string as the command line, which is
	 * exactly what this test caught the first time it ran. */
	e->off_cmdline = KOF_TEXT_NONE;
}

static void set_obj(struct kofw_evt *e, const char *path)
{
	size_t n = strlen(path);

	memcpy(e->text, path, n + 1);
	e->off_object = 0;
	e->text_len   = (uint16_t)(n + 1);
}

static void t_scope(void)
{
	struct kofw_ptab   t;
	struct kofw_filter f;
	struct kofw_evt    e;

	kofw_ptab_init(&t);
	memset(&f, 0, sizeof f);
	f.root_pid = 100;

	/* The root is seeded by hand, before it can run - the ordering
	 * kofmontrace depends on. */
	{
		struct kofw_pent *p = kofw_ptab_add(&t, 100, 0, "root.exe", 0);
		if (!p)
			fail("scope", "could not seed the root");
		p->tracked = 1;
		t.n_alive_tracked++;
	}

	/* A child of the root is kin. */
	mk(&e, KOF_EVT_PROC_START, 200, 100);
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a child of the root");

	/* A GRANDCHILD is kin too - the set has to grow transitively or a
	 * dropper that shells out twice disappears. */
	mk(&e, KOF_EVT_PROC_START, 300, 200);
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a grandchild");

	/* An unrelated process is not. */
	mk(&e, KOF_EVT_PROC_START, 400, 999);
	if (kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "admitted an unrelated process");

	/* A file event from inside the tree is kept, one from outside is not. */
	mk(&e, KOF_EVT_FILE_NEW, 300, 0);
	set_obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\drop.exe");
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a file event from the tree");
	if (e.obj_loc != KOF_LOC_TEMP)
		fail("scope", "did not classify the object path");

	mk(&e, KOF_EVT_FILE_NEW, 400, 0);
	set_obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\other.exe");
	if (kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "admitted a file event from outside the tree");

	/*
	 * drop_loc IS TESTED AGAINST THE OBJECT, NEVER THE SUBJECT.
	 *
	 * A caller hiding the modules every process loads must not thereby hide
	 * the ProcessStart of every program that lives in System32 - which is
	 * most of them.
	 */
	f.drop_loc = 1u << KOF_LOC_SYSTEM;

	mk(&e, KOF_EVT_IMAGE_LOAD, 300, 0);
	set_obj(&e, "C:\\Windows\\System32\\ntdll.dll");
	if (kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "kept a system module load under drop_loc");

	mk(&e, KOF_EVT_IMAGE_LOAD, 300, 0);
	set_obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.dll");
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "dropped a module load from temp");

	mk(&e, KOF_EVT_PROC_START, 500, 300);
	set_obj(&e, "");
	e.off_object = KOF_TEXT_NONE;
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "drop_loc suppressed a process start");
	f.drop_loc = 0;

	/* Liveness: the tree is finished when every tracked pid has stopped,
	 * which is what a trace waits for. */
	eq_u64("scope alive", t.n_alive_tracked, 4);
	mk(&e, KOF_EVT_PROC_STOP, 500, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	mk(&e, KOF_EVT_PROC_STOP, 300, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	eq_u64("scope alive after two stops", t.n_alive_tracked, 2);

	/* A repeated stop for the same pid must not underflow the count. */
	mk(&e, KOF_EVT_PROC_STOP, 300, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	eq_u64("scope alive after a repeat stop", t.n_alive_tracked, 2);

	/* A zeroed filter means everything, which is the answer a caller who
	 * forgot a field should get: less filtering, never more. */
	{
		struct kofw_filter none;
		memset(&none, 0, sizeof none);
		mk(&e, KOF_EVT_FILE_NEW, 4242, 0);
		if (!kofw_filter_apply(&t, &none, &e, NULL))
			fail("scope", "a zeroed filter refused something");
	}
}

/* ---- FileKey -> path ---------------------------------------------------- */

/*
 * WHAT [unknown] [miss 0x40] ON EVERY POWERSHELL WRITE WAS.
 *
 * FileIo Write carries FileObject and FileKey - kernel pointers - and no
 * filename. FILENAME emits separate records mapping one to a path, and until
 * they were kept, a write was a byte count against an address nobody could
 * resolve.
 */
static void t_ftab(void)
{
	struct kofw_ftab t;
	struct kofw_evt  e;

	kofw_ftab_init(&t);

	/* A name record teaches the table. */
	mk(&e, KOF_EVT_RAW, 100u, 0u);
	e.addr = 0xffffab0012340000ull;
	set_obj(&e, "C:\\Users\\b\\AppData\\Local\\Temp\\p.ps1");
	kofw_ftab_add(&t, e.addr, kofw_evt_object(&e));

	/* A write carrying only the key gets the path, and stops being
	 * partial - which is what a reader saw as [miss 0x40]. */
	mk(&e, KOF_EVT_FILE_WRITE, 100u, 0u);
	e.addr = 0xffffab0012340000ull;
	e.miss  = KOF_F_OBJECT;
	e.flags = KOF_EF_PARTIAL;
	if (!kofw_ftab_resolve(&t, &e))
		fail("ftab", "did not resolve a known key");
	eq_str("ftab path", kofw_evt_object(&e),
	       "C:\\Users\\b\\AppData\\Local\\Temp\\p.ps1");
	eq_u64("ftab miss cleared", e.miss, 0);
	if (e.flags & KOF_EF_PARTIAL)
		fail("ftab", "still flagged partial after resolving");

	/* An unknown key changes nothing and is counted. */
	mk(&e, KOF_EVT_FILE_WRITE, 100u, 0u);
	e.addr = 0xdeadbeefull;
	if (kofw_ftab_resolve(&t, &e))
		fail("ftab", "resolved a key it was never told about");
	eq_u64("ftab unresolved", t.unresolved, 1);

	/* A record that already has a path keeps it: a name record must not
	 * overwrite itself with a lookup of itself. */
	mk(&e, KOF_EVT_RAW, 100u, 0u);
	e.addr = 0xffffab0012340000ull;
	set_obj(&e, "keep me");
	if (kofw_ftab_resolve(&t, &e))
		fail("ftab", "overwrote a path that was already there");
	eq_str("ftab kept", kofw_evt_object(&e), "keep me");

	/* A zero key is not a key. */
	kofw_ftab_add(&t, 0, "nowhere");
	mk(&e, KOF_EVT_FILE_WRITE, 100u, 0u);
	e.addr = 0;
	if (kofw_ftab_resolve(&t, &e))
		fail("ftab", "resolved a zero key");
}

/* ---- pid reuse ---------------------------------------------------------- */

/*
 * A pid is reused, sometimes within seconds, so the pair (pid, create_time) is
 * what names a process. A table that answers on the number alone confidently
 * returns the wrong program's name for the wrong process.
 */
static void t_pid_reuse(void)
{
	struct kofw_ptab t;

	kofw_ptab_init(&t);
	(void)kofw_ptab_add(&t, 1234, 111, "first.exe", 1);

	if (!kofw_ptab_of(&t, 1234, 111))
		fail("reuse", "lost the process it was just told about");
	if (kofw_ptab_of(&t, 1234, 222))
		fail("reuse", "answered for a different create_time");
	/* 0 means the caller has no discriminator and the pid has to do. */
	if (!kofw_ptab_of(&t, 1234, 0))
		fail("reuse", "refused a lookup with no discriminator");
}

/* ---- the recorded trace ------------------------------------------------- */

/*
 * THE POINT OF THE FORMAT, TESTED ON THE PLATFORM THAT CANNOT COLLECT.
 *
 * A trace is written and read back here on a host with no ETW at all - which
 * is the whole claim wtrace.h makes, and the reason a rule engine over events
 * will be testable when there is one.
 */
static void t_trace(void)
{
	const char *path = "grille_host_trace.tmp";
	struct kofevt_log_w *w;
	struct kofevt_log_r *r;
	const struct kofevt_log_hdr *h;
	struct kofevt_log_info li;
	struct kofw_evt e;
	const char *why = "";
	uint64_t n;
	unsigned i, got = 0;

	memset(&li, 0, sizeof li);
	li.rec_size  = (uint32_t)sizeof(struct kofw_evt);
	li.head_size = (uint16_t)KOFW_REC_HEAD;
	li.len_off   = (uint16_t)offsetof(struct kofw_evt, text_len);
	li.rec_kind = KOFEVT_REC_KOFW;
	li.build    = 20260908u;
	li.platform = KOF_PLAT_WINDOWS;
	li.arch     = KOF_EARCH_X86_64;
	li.root_pid = 4321u;
	w = kofevt_log_create(path, &li);
	if (!w) {
		fail("trace", "could not create");
		return;
	}
	for (i = 0; i < 100; i++) {
		mk(&e, KOF_EVT_FILE_NEW, 1000u + i, 7u);
		e.seq   = i;
		e.stamp = 1000000ull + i;
		set_obj(&e, "C:\\Users\\b\\AppData\\Local\\Temp\\a.exe");
		if (kofevt_log_write(w, &e))
			fail("trace", "write failed");
	}
	n = kofevt_log_close(w);
	eq_u64("trace written", n, 100);

	/*
	 * THE PADDING IS ACTUALLY GONE, measured rather than assumed.
	 *
	 * Fixed 512-byte records put 100 events in 51 264 bytes and most of it
	 * was the zeros between one path and the next. Variable records cost
	 * the head plus exactly the text each event had.
	 */
	{
		FILE *f = fopen(path, "rb");
		long  sz = 0;
		long  want = (long)sizeof(struct kofevt_log_hdr) +
			     100L * ((long)KOFW_REC_HEAD + (long)e.text_len);

		if (f) {
			fseek(f, 0, SEEK_END);
			sz = ftell(f);
			fclose(f);
		}
		eq_u64("trace file size", (uint64_t)sz, (uint64_t)want);
		if (sz >= (long)sizeof(struct kofevt_log_hdr) + 100L * 512L)
			fail("trace", "still writing fixed-size records");
	}

	r = kofevt_log_open(path, (uint32_t)sizeof(struct kofw_evt),
			    KOFEVT_REC_KOFW, &why);
	if (!r) {
		printf("  FAIL trace open: %s\n", why);
		failures++;
		remove(path);
		return;
	}
	h = kofevt_log_header(r);
	eq_u64("trace rec_size", h->rec_size, sizeof(struct kofw_evt));
	eq_u64("trace root_pid", h->root_pid, 4321u);
	eq_u64("trace build", h->build, 20260908u);
	/* The most important thing in the header after the record's identity:
	 * which machine wrote it. A reader opening this on another platform
	 * has no other way to know. */
	eq_u64("trace platform", h->platform, KOF_PLAT_WINDOWS);
	eq_u64("trace arch", h->arch, KOF_EARCH_X86_64);
	/* Written by seeking back at close - zero here would mean the writer
	 * was killed, which is a different thing from an empty trace. */
	eq_u64("trace n_records", h->n_records, 100);

	while (kofevt_log_read(r, &e)) {
		eq_u64("trace seq", e.seq, got);
		eq_u64("trace pid", e.pid, 1000u + got);
		eq_str("trace object", kofw_evt_object(&e),
		       "C:\\Users\\b\\AppData\\Local\\Temp\\a.exe");
		got++;
	}
	eq_u64("trace read back", got, 100);

	/*
	 * WHAT A VIEWER NEEDS: jump to a record without having read the ones
	 * before it, and without the file being in memory.
	 */
	eq_u64("trace count", kofevt_log_count(r), 100);

	if (!kofevt_log_seek(r, 42))
		fail("trace", "could not seek to a record");
	if (!kofevt_log_read(r, &e))
		fail("trace", "nothing at the record seeked to");
	eq_u64("trace seek seq", e.seq, 42);
	eq_u64("trace seek pid", e.pid, 1000u + 42u);

	/* The last one, and one past it. */
	if (!kofevt_log_seek(r, 99) || !kofevt_log_read(r, &e))
		fail("trace", "could not reach the last record");
	eq_u64("trace last seq", e.seq, 99);
	if (kofevt_log_seek(r, 100))
		fail("trace", "seeked past the end");

	/*
	 * A RECORD MUST NOT INHERIT THE PREVIOUS ONE'S TEXT.
	 *
	 * The one way a variable-length format hands back something that looks
	 * like a complete path and is two records spliced together: seek back
	 * to a short record after reading a long one and check the tail is
	 * clear.
	 */
	if (kofevt_log_seek(r, 0) && kofevt_log_read(r, &e)) {
		size_t k;
		for (k = e.text_len; k < sizeof e.text; k++) {
			if (e.text[k] != 0) {
				fail("trace", "text left over from another record");
				break;
			}
		}
	}

	kofevt_log_free(r);

	/* A file that is not a trace is refused, not read. */
	{
		FILE *f = fopen(path, "wb");
		if (f) {
			fputs("not a trace at all, quite definitely", f);
			fclose(f);
		}
		if (kofevt_log_open(path, (uint32_t)sizeof(struct kofw_evt),
				    KOFEVT_REC_KOFW, &why))
			fail("trace", "opened something that is not a log");
	}

	/*
	 * THE CHECK THE FORMAT EXISTS FOR: a record size that is not ours is
	 * refused rather than read from the wrong offsets.
	 */
	{
		struct kofevt_log_hdr bad;
		FILE *f;

		memset(&bad, 0, sizeof bad);
		bad.magic    = KOFEVT_LOG_MAGIC;
		bad.version  = KOFEVT_LOG_VERSION;
		bad.hdr_size = (uint16_t)sizeof bad;
		bad.rec_size = (uint32_t)sizeof(struct kofw_evt) + 8u;
		bad.head_size = (uint16_t)KOFW_REC_HEAD;
		bad.len_off = (uint16_t)offsetof(struct kofw_evt, text_len);
		f = fopen(path, "wb");
		if (f) {
			fwrite(&bad, sizeof bad, 1, f);
			fclose(f);
		}
		bad.rec_kind = KOFEVT_REC_KOFW;
		if (kofevt_log_open(path, (uint32_t)sizeof(struct kofw_evt),
				    KOFEVT_REC_KOFW, &why))
			fail("trace", "read a log whose record size differs");
	}

	/*
	 * SIZE IS NOT IDENTITY. A record of the right size from a different
	 * collector decodes at the right offsets and means something else, and
	 * nothing downstream can notice - so the kind is checked too.
	 */
	{
		struct kofevt_log_hdr other;
		FILE *f;

		memset(&other, 0, sizeof other);
		other.magic    = KOFEVT_LOG_MAGIC;
		other.version  = KOFEVT_LOG_VERSION;
		other.hdr_size = (uint16_t)sizeof other;
		other.rec_size = (uint32_t)sizeof(struct kofw_evt);
		other.head_size = (uint16_t)KOFW_REC_HEAD;
		other.len_off = (uint16_t)offsetof(struct kofw_evt, text_len);
		other.rec_kind = KOFEVT_REC_KOF;   /* the neutral record */
		f = fopen(path, "wb");
		if (f) {
			fwrite(&other, sizeof other, 1, f);
			fclose(f);
		}
		if (kofevt_log_open(path, (uint32_t)sizeof(struct kofw_evt),
				    KOFEVT_REC_KOFW, &why))
			fail("trace", "read another collector's record as ours");
		/* ...but a reader that only reports what a file claims may
		 * open it, which is what KOFEVT_REC_NONE is for. */
		{
			struct kofevt_log_r *any =
				kofevt_log_open(path, 0, KOFEVT_REC_NONE, &why);
			if (!any)
				fail("trace", "REC_NONE refused a valid log");
			else
				kofevt_log_free(any);
		}
	}

	remove(path);
}

/* ---- collector record -> neutral record --------------------------------- */

/*
 * THE CONVERSION IS WHERE THE TWO VOCABULARIES MEET, so it is the one place a
 * mismatch between them turns into a wrong answer rather than a compile error.
 *
 * Checked field by field on purpose. A memcpy-shaped test would pass while
 * actor_pid held a tid, because both are uint32 and both are plausible.
 */
static void t_convert(void)
{
	struct kofw_evt in;
	struct kof_evt  out;

	mk(&in, KOF_EVT_FILE_NEW, 4242u, 7u);
	in.stamp       = 123456789ull;
	in.seq         = 99u;
	in.create_time = 555u;
	in.tid         = 31u;
	in.session_id  = 2u;
	in.exit_code   = 0u;
	in.addr        = 0x7ff600001000ull;
	in.addr_size   = 4096u;
	in.net_daddr   = 0x08080808u;
	in.net_dport   = 0x5000u;      /* 80, network order */
	in.net_size    = 1500u;
	in.raw_id      = 30u;
	in.attack      = KOF_ATT_RUN_KEY;
	in.obj_loc     = KOF_LOC_AUTOSTART;
	set_obj(&in, "C:\\Windows\\Temp\\a.exe");

	kofw_evt_to_kof(&in, &out);

	eq_u64("conv stamp", out.stamp, 123456789ull);
	eq_u64("conv seq", out.seq, 99u);
	eq_u64("conv create_time", out.create_time, 555u);
	eq_u64("conv pid", out.pid, 4242u);
	eq_u64("conv ppid", out.ppid, 7u);
	/* raiser_pid becomes actor_pid - the rename IS the point, so a test
	 * that only compared sizes would not notice it going to the wrong
	 * field. */
	eq_u64("conv actor_pid", out.actor_pid, in.raiser_pid);
	eq_u64("conv tid", out.tid, 31u);
	eq_u64("conv session", out.session_id, 2u);
	eq_u64("conv addr", out.addr, 0x7ff600001000ull);
	eq_u64("conv addr_size", out.addr_size, 4096u);
	eq_u64("conv daddr", out.net_daddr, 0x08080808u);
	eq_u64("conv dport", out.net_dport, 0x5000u);
	eq_u64("conv size", out.net_size, 1500u);
	eq_u64("conv verb", out.verb, KOF_EVT_FILE_NEW);
	eq_u64("conv raw_id", out.raw_id, 30u);
	eq_u64("conv attack", out.attack, KOF_ATT_RUN_KEY);
	eq_u64("conv loc", out.loc, KOF_LOC_AUTOSTART);
	eq_u64("conv os", out.os, KOF_OS_WINDOWS);
	eq_str("conv object", kof_evt_object(&out), "C:\\Windows\\Temp\\a.exe");
	eq_str("conv image", kof_evt_image(&out), "");
	eq_str("conv cmdline", kof_evt_cmdline(&out), "");

	/*
	 * THE ARENA IS SMALLER IN THE NEUTRAL RECORD - its header carries two
	 * more fields - so text that fit in one may not fit in the other. It
	 * has to be cut AND flagged: a path shortened without saying so is what
	 * a later rule matches and is wrong about.
	 */
	{
		size_t i;

		/*
		 * A FULL ARENA MUST SURVIVE WHOLE.
		 *
		 * The two records' headers grow independently, so which arena
		 * is larger is not obvious and was guessed wrongly here once -
		 * the neutral one is larger today, and a static assert in
		 * wtext.c is what keeps it that way. This checks the
		 * consequence: nothing is cut and nothing is flagged.
		 */
		mk(&in, KOF_EVT_FILE_NEW, 1u, 1u);
		in.off_object = 0;
		for (i = 0; i + 1 < sizeof in.text; i++)
			in.text[i] = 'x';
		in.text[sizeof in.text - 1] = '\0';
		in.text_len = (uint16_t)sizeof in.text;

		kofw_evt_to_kof(&in, &out);
		eq_u64("conv full arena", out.text_len, sizeof in.text);
		if (out.flags & KOF_EF_TRUNCATED)
			fail("convert", "flagged a truncation that did not happen");
		if (strlen(kof_evt_object(&out)) != sizeof in.text - 1u)
			fail("convert", "lost bytes from a full arena");
	}

	/* An offset that fell outside what was copied becomes absent - the
	 * bytes it pointed at are not there to be read. */
	{
		mk(&in, KOF_EVT_PROC_START, 1u, 1u);
		in.text_len   = 4u;
		in.off_image  = 0u;
		in.off_object = 400u;      /* past text_len */
		kofw_evt_to_kof(&in, &out);
		eq_u64("conv stale offset", out.off_object, KOF_TEXT_NONE);
	}
}

/* ---- the browsing API --------------------------------------------------- */

/*
 * The NEUTRAL record's own helpers. `mk`/`set_obj` above build a kofw_evt -
 * the collector's transport - and the browsing API takes a kof_evt. Two
 * helpers rather than one taking a void*, because the whole point of the two
 * records being different types is that a mix-up is a compile error.
 */
static void mk_kof(struct kof_evt *e, uint16_t verb, uint32_t pid)
{
	memset(e, 0, sizeof *e);
	e->verb        = verb;
	e->pid         = pid;
	e->off_image   = KOF_TEXT_NONE;
	e->off_object  = KOF_TEXT_NONE;
	e->off_cmdline = KOF_TEXT_NONE;
}

static void set_obj_kof(struct kof_evt *e, const char *path)
{
	size_t n = strlen(path);

	memcpy(e->text, path, n + 1);
	e->off_object = 0;
	e->text_len   = (uint16_t)(n + 1);
}

/* The image and the command line, appended after whatever is already in the
 * arena - a process start carries both, and the second must land where the
 * first left off or the two rows overlap. */
static void put_kof(struct kof_evt *e, uint16_t *off, const char *s)
{
	size_t n = strlen(s);

	*off = e->text_len;
	memcpy(e->text + e->text_len, s, n + 1);
	e->text_len = (uint16_t)(e->text_len + n + 1);
}

static void set_img_kof(struct kof_evt *e, const char *s)
{ put_kof(e, &e->off_image, s); }

static void set_cmd_kof(struct kof_evt *e, const char *s)
{ put_kof(e, &e->off_cmdline, s); }

/*
 * CONTENT, not a path - so content_len is set and the bytes may be anything.
 *
 * A producer of a content event has to set that length; a path-shaped setter
 * leaves it zero and the content then reads as empty, which is exactly what
 * this test caught the first time it ran against raw bytes.
 */
static void set_content_kof(struct kof_evt *e, const void *bytes, size_t n)
{
	memcpy(e->text, bytes, n);
	e->text[n]       = '\0';
	e->off_object    = 0;
	e->content_len   = (uint16_t)n;
	e->text_len      = (uint16_t)(n + 1);
}

/*
 * WHAT A UI ASKS OF A RECORD, tested without a UI.
 *
 * A label for a list row, the fields for a properties panel, and where one
 * event's bytes live in the file so a hex pane can be pointed at them. All of
 * it is pure record reading, so it is checkable here rather than by looking at
 * a screen - which is the only way it stays correct.
 */
/*
 * THE ROWS AND THE BYTES AGREE, which is the whole claim the viewer's event
 * panel makes: a colour on a row and the same colour on a run of the dump say
 * they are the same thing.
 *
 * Three properties, each of which was broken at least once:
 *
 *  - every extent lies INSIDE the record. The text rows are computed as
 *    offsetof(text) + off_object, and an absent offset is 0xFFFF - which wraps
 *    a uint16 straight back into the head and lights a field the row is not
 *    about.
 *
 *  - extents do not OVERLAP. The viewer takes the first row covering a byte, so
 *    an overlap does not show as a clash - it shows as one row silently eating
 *    the front of another, which is exactly how the old "peer" row (four bytes
 *    of address plus two, over a struct that puts the port twelve bytes later)
 *    ate half of net_saddr.
 *
 *  - rows come out in LAYOUT order, so the panel reads down in step with the
 *    dump beside it, and the flag rows - which name no bytes - come last.
 *
 * Run over every shape of record the collector produces, because each of them
 * turns on a different set of rows and the bugs above were all in rows only
 * some verbs have.
 */
static void check_extents(const struct kof_evt *e, const char *what)
{
	unsigned n = kof_evt_n_fields(e), a;
	uint16_t po = 0, pl = 0;

	for (a = 0; a < n; a++) {
		uint16_t ao = 0, al = 0;
		unsigned b;

		if (!kof_evt_field_extent(e, a, &ao, &al)) {
			fail(what, "no extent for a row n_fields promised");
			return;
		}
		if (al && (size_t)ao + al > sizeof *e)
			fail(what, "an extent runs past the record");
		if (al && pl == 0 && a > 0)
			fail(what, "a field row after a flag row");
		if (al && pl && ao < po)
			fail(what, "rows are not in layout order");
		for (b = 0; b < a; b++) {
			uint16_t bo = 0, bl = 0;

			kof_evt_field_extent(e, b, &bo, &bl);
			if (!al || !bl)
				continue;
			if (ao < bo + bl && bo < ao + al)
				fail(what, "two rows claim the same bytes");
		}
		po = ao;
		pl = al;
	}
}

static void t_browse(void)
{
	struct kof_evt e;
	char lab[KOF_EVT_LABEL_MAX];
	char nm[32], vl[256];
	unsigned i, n;
	int saw_verb = 0, saw_obj = 0, saw_tech = 0, saw_port = 0;

	mk_kof(&e, KOF_EVT_REG_SET_VALUE, 4242u);
	e.ppid = 7u;
	e.actor_pid = 99u;
	e.session_id = 2u;
	set_obj_kof(&e, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows"
		    "\\CurrentVersion\\Run\\evil");
	e.loc = kof_classify(kof_evt_object(&e), &e.attack);
	e.os = KOF_OS_WINDOWS;

	/*
	 * The label leads with the index, because that is what a reader refers
	 * to and it is what sorts, and it carries nothing but the index, the
	 * verb and the process.
	 *
	 * IT IS THE WHOLE LABEL, checked with strcmp rather than a prefix. It
	 * used to append the leaf of the path, which is the field a column is
	 * worst at showing - it is the part that does not fit, so it is the
	 * part that gets cut, and a column of half-cut names has to be read
	 * twice. A prefix test would not have noticed it coming back.
	 *
	 * No "//" either: that is the engine's nesting, and an event is not
	 * inside anything.
	 */
	kof_evt_label(&e, 42u, lab, sizeof lab);
	if (strcmp(lab, "42 RegSet pid=4242"))
		printf("  FAIL label: got \"%s\"\n", lab), failures++;

	n = kof_evt_n_fields(&e);
	if (n < 6)
		fail("fields", "too few fields for a registry write");
	for (i = 0; i < n; i++) {
		if (!kof_evt_field(&e, i, nm, sizeof nm, vl, sizeof vl)) {
			fail("fields", "n_fields promised more than it yields");
			break;
		}
		if (!strcmp(nm, "verb") && !strcmp(vl, "RegSet")) saw_verb = 1;
		if (!strcmp(nm, "object")) saw_obj = 1;
		/* The technique belongs on a PROPERTIES panel and nowhere on an
		 * event line - see the note in kofevt.h. */
		if (!strcmp(nm, "technique") &&
		    strstr(vl, "T1547.001")) saw_tech = 1;
		if (!strcmp(nm, "peer")) saw_port = 1;
	}
	if (!saw_verb) fail("fields", "no verb row");
	if (!saw_obj)  fail("fields", "no object row");
	if (!saw_tech) fail("fields", "no technique row on a Run key write");
	/* A registry write has no peer, and a row reading 0.0.0.0:0 would be
	 * worse than no row - a reader cannot tell it from a real zero. */
	if (saw_port)  fail("fields", "a registry write reported a peer");

	/*
	 * THE ROWS AND THE BYTES AGREE, which is the whole claim the viewer's
	 * event panel makes: a colour on a row and the same colour on a run of
	 * the dump say they are the same thing.
	 *
	 * Three properties, each of which was broken at least once:
	 *
	 *  - every extent lies INSIDE the record. The text rows are computed
	 *    as offsetof(text) + off_object, and an absent offset is 0xFFFF -
	 *    which wraps a uint16 straight back into the head and lights a
	 *    field the row is not about.
	 *
	 *  - extents do not OVERLAP. evt_row_of takes the first row covering a
	 *    byte, so an overlap does not show as a clash, it shows as one row
	 *    silently eating the front of another - which is exactly how the
	 *    old "peer" row (four bytes of address plus two, over a struct that
	 *    puts the port twelve bytes later) ate half of net_saddr.
	 *
	 *  - rows come out in LAYOUT order, so the panel reads down in step
	 *    with the dump beside it.
	 */
	check_extents(&e, "regset");

	/*
	 * The same, over the shapes that turn on the rows the registry write
	 * does not have: the network pair, the flag rows, and a process start
	 * carrying every text field at once.
	 */
	{
		struct kof_evt x;

		mk_kof(&x, KOF_EVT_NET_SEND, 300u);
		x.net_daddr = 0x0100007fu;
		x.net_dport = 0xbb01u;          /* 443, network order */
		x.net_size = 4096u;
		x.os = KOF_OS_WINDOWS;
		check_extents(&x, "netsend");

		mk_kof(&x, KOF_EVT_PROC_START, 400u);
		x.ppid = 4u;
		set_img_kof(&x, "C:\\Windows\\System32\\cmd.exe");
		set_cmd_kof(&x, "cmd.exe /c whoami");
		x.os = KOF_OS_WINDOWS;
		check_extents(&x, "procstart");

		/* Every flag at once: they are the rows with no extent, and
		 * they must all sort behind every row that has one. */
		x.flags |= (uint32_t)(KOF_EF_TRUNCATED | KOF_EF_PARTIAL |
				      KOF_EF_UNBACKED | KOF_EF_LATE_LOAD |
				      KOF_EF_CMDLINE_RACED);
		check_extents(&x, "procstart+flags");
	}

	/*
	 * PUTTING A CUT SUBMISSION BACK TOGETHER, and refusing to when a chunk
	 * was lost.
	 *
	 * The collector emits KOF_EVT_CONT records behind a content event whose
	 * payload did not fit. What matters here is not the concatenation - it
	 * is the refusal: joining across a dropped chunk produces a buffer that
	 * reads as one script and is two halves of two, and nothing downstream
	 * could tell that from a fact.
	 */
	{
		struct kof_evt parent, c1, c2;
		struct kof_evt_join j;
		char buf[64];

		mk_kof(&parent, KOF_EVT_AMSI_SCAN, 900u);
		parent.seq = 10u;
		parent.off_object = 0;
		memcpy(parent.text, "AAAA", 4);
		parent.content_len = 4u;
		parent.text_len = 5u;
		parent.flags |= KOF_EF_TRUNCATED;

		mk_kof(&c1, KOF_EVT_CONT, 900u);
		c1.seq = 11u;
		c1.off_object = 0;
		memcpy(c1.text, "BBB", 3);
		c1.content_len = 3u;
		c1.text_len = 4u;

		c2 = c1;
		c2.seq = 12u;
		memcpy(c2.text, "CC", 2);
		c2.content_len = 2u;

		if (!kof_evt_join_start(&j, &parent, buf, sizeof buf))
			fail("join", "a content event refused to start a join");
		/* The parent said it was cut and nothing has finished it. */
		if (kof_evt_join_whole(&j, &parent))
			fail("join", "a truncated parent alone reported whole");
		if (!kof_evt_join_add(&j, &c1) || !kof_evt_join_add(&j, &c2))
			fail("join", "a contiguous chunk was refused");
		if (j.len != 9u || memcmp(buf, "AAAABBBCC", 9))
			fail("join", "the chunks did not reassemble");
		if (!kof_evt_join_whole(&j, &parent))
			fail("join", "a complete chain reported short");

		/* A HOLE. c2 arrives without c1, so its bytes belong somewhere
		 * unknown in the middle - the join must stop, not append. */
		kof_evt_join_start(&j, &parent, buf, sizeof buf);
		if (kof_evt_join_add(&j, &c2))
			fail("join", "a chunk after a gap was appended");
		if (!j.holed)
			fail("join", "a gap was not reported");
		if (j.len != 4u)
			fail("join", "a refused chunk still changed the buffer");
		if (kof_evt_join_whole(&j, &parent))
			fail("join", "a holed join reported whole");
		/* And it stays refused: a later contiguous-looking chunk does
		 * not repair a hole that is already in the middle. */
		if (kof_evt_join_add(&j, &c1))
			fail("join", "a holed join accepted a later chunk");

		/* A chunk is not a parent - starting on one would treat somebody
		 * else's tail as a new head. */
		if (kof_evt_join_start(&j, &c1, buf, sizeof buf))
			fail("join", "a continuation started a join");

		/* A buffer too small is a prefix, and says so rather than
		 * overrunning. */
		{
			char small[6];

			kof_evt_join_start(&j, &parent, small, sizeof small);
			kof_evt_join_add(&j, &c1);
			if (!j.full)
				fail("join", "a full buffer was not reported");
			if (j.len > sizeof small)
				fail("join", "the join wrote past the buffer");
			if (kof_evt_join_whole(&j, &parent))
				fail("join", "a full join reported whole");
		}
	}

	/* A registry write is not content. */
	if (kof_evt_content(&e, NULL, NULL))
		fail("content", "a registry write reported content");

	/*
	 * AN AMSI SUBMISSION IS content, and a mangled binary is reported as
	 * one - because a screen of '?' would otherwise read as a junk payload
	 * rather than as bytes this record cannot carry.
	 */
	{
		struct kof_evt a;
		const char *t = NULL;
		size_t tn = 0;

		static const char script[] =
			"Write-Host 'hello there, this is a script'";
		/* A PE header, verbatim - which the record now carries because
		 * the collector stopped sanitising what goes to a scanner. */
		static const unsigned char pe[] = {
			'M','Z',0x90,0x00,0x03,0x00,0x00,0x00,
			0x04,0x00,0x00,0x00,0xff,0xff,0x00,0x00
		};
		/* UTF-16 'echo' - a NUL at index 1, which is why a string
		 * would have reported one character. */
		static const unsigned char u16[] = {
			'e',0,'c',0,'h',0,'o',0,' ',0,'h',0,'i',0,0,0
		};

		mk_kof(&a, KOF_EVT_AMSI_SCAN, 7u);
		set_content_kof(&a, script, sizeof script - 1u);
		if (!kof_evt_content(&a, &t, &tn))
			fail("content", "an AMSI event reported no content");
		eq_u64("content len", tn, sizeof script - 1u);
		if (kof_evt_content_looks_binary(&a))
			fail("content", "called a script binary");

		mk_kof(&a, KOF_EVT_AMSI_SCAN, 7u);
		set_content_kof(&a, pe, sizeof pe);
		if (!kof_evt_content_looks_binary(&a))
			fail("content", "did not notice an MZ");

		/* THE ONE A STRING GOT WRONG: bytes past a NUL survive, and
		 * the length is the buffer's rather than up to the NUL. */
		mk_kof(&a, KOF_EVT_AMSI_SCAN, 7u);
		set_content_kof(&a, u16, sizeof u16);
		if (!kof_evt_content(&a, &t, &tn))
			fail("content", "no content for a UTF-16 buffer");
		eq_u64("content len past NUL", tn, sizeof u16);
		if (t[2] != 'c')
			fail("content", "lost the bytes after the first NUL");
	}

	/* One past the end yields nothing rather than an empty row. */
	if (kof_evt_field(&e, n, nm, sizeof nm, vl, sizeof vl))
		fail("fields", "yielded a field past the end");
}

/* ---- where an event's bytes are ---------------------------------------- */

static void t_extent(void)
{
	const char *path = "grille_host_extent.tmp";
	struct kofevt_log_info li;
	struct kofevt_log_w *w;
	struct kofevt_log_r *r;
	const char *why = "";
	struct kof_evt e;
	uint64_t off_a = 0, off_b = 0;
	uint32_t len_a = 0, len_b = 0;

	memset(&li, 0, sizeof li);
	li.rec_size  = (uint32_t)sizeof(struct kof_evt);
	li.head_size = (uint16_t)KOF_EVT_HEAD;
	li.len_off   = (uint16_t)offsetof(struct kof_evt, text_len);
	li.rec_kind  = KOFEVT_REC_KOF;
	w = kofevt_log_create(path, &li);
	if (!w) {
		fail("extent", "could not create");
		return;
	}
	/* Two records with DIFFERENT text lengths, which is the case a length
	 * taken from sizeof the struct gets wrong. */
	mk_kof(&e, KOF_EVT_FILE_NEW, 1u);
	set_obj_kof(&e, "/a");
	kofevt_log_write(w, &e);
	mk_kof(&e, KOF_EVT_FILE_NEW, 2u);
	set_obj_kof(&e, "/a/much/longer/path/than/the/first/one");
	kofevt_log_write(w, &e);
	(void)kofevt_log_close(w);

	r = kofevt_log_open(path, (uint32_t)sizeof(struct kof_evt),
			    KOFEVT_REC_KOF, &why);
	if (!r) {
		printf("  FAIL extent open: %s\n", why);
		failures++;
		remove(path);
		return;
	}
	if (!kofevt_log_extent(r, 0, &off_a, &len_a))
		fail("extent", "no extent for record 0");
	if (!kofevt_log_extent(r, 1, &off_b, &len_b))
		fail("extent", "no extent for record 1");

	eq_u64("extent 0 off", off_a, sizeof(struct kofevt_log_hdr));
	eq_u64("extent 0 len", len_a, KOF_EVT_HEAD + 3u);   /* "/a" + NUL */
	eq_u64("extent 1 off", off_b, off_a + len_a);
	/* ON-DISK length, not sizeof: the second record is longer, and a pane
	 * sized from the struct would show the next record's opening bytes. */
	if (len_b <= len_a)
		fail("extent", "the longer record did not measure longer");
	if (len_b == sizeof(struct kof_evt))
		fail("extent", "reported sizeof instead of the on-disk length");

	/* Asking must not disturb a walk: read after an extent query and the
	 * record that comes back is the one seeked to. */
	if (kofevt_log_extent(r, 1, &off_b, &len_b) &&
	    kofevt_log_read(r, &e))
		eq_u64("extent leaves position", e.pid, 2u);
	else
		fail("extent", "could not read after asking");

	kofevt_log_free(r);
	remove(path);
}

int main(void)
{
	printf("grille_host: the ETW-free half of libkofgrille\n");
	t_layout();
	t_type_names();
	t_utf16();
	t_ansi();
	t_bytes();
	t_classify();
	t_ring();
	t_scope();
	t_ftab();
	t_pid_reuse();
	t_convert();
	t_trace();
	t_browse();
	t_extent();

	if (failures) {
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok\n");
	return 0;
}
