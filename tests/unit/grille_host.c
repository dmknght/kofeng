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

#include <stdio.h>
#include <string.h>

#include "../../libkofgrille/kofgrille.h"
#include "../../libkofgrille/wevt_ring.h"
#include "../../libkofgrille/wfilter.h"
#include "../../libkofgrille/wtext.h"

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
	if (sizeof(struct kofw_evt) != KOFW_EVT_SIZE)
		fail("layout", "struct kofw_evt is not KOFW_EVT_SIZE bytes");
	if ((size_t)((const char *)&((struct kofw_evt *)0)->text -
		     (const char *)0) != KOFW_EVT_HEAD)
		fail("layout", "KOFW_EVT_HEAD is not where text[] starts");
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

	for (i = 1; i < KOFW_EVT_TYPE_COUNT; i++) {
		const char *n = kofw_evt_type_name(i);

		if (!n || !*n || !strcmp(n, "?")) {
			printf("  FAIL type name: verb %u has no name\n",
			       (unsigned)i);
			failures++;
		}
	}
	/* Out of range still has to answer something, so a record written by a
	 * build that knew one more verb still prints. */
	if (strcmp(kofw_evt_type_name(KOFW_EVT_TYPE_COUNT + 50u), "?"))
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

/* ---- path classification ------------------------------------------------ */

static void loc_is(const char *path, uint8_t want)
{
	uint8_t got = kofw_classify_path(path);

	if (got != want) {
		printf("  FAIL classify \"%s\": got %s, wanted %s\n", path,
		       kofw_loc_name(got), kofw_loc_name(want));
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
	loc_is("C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe", KOFW_LOC_TEMP);
	loc_is("C:\\Windows\\Temp\\a.exe", KOFW_LOC_TEMP);
	loc_is("C:\\Users\\bob\\Desktop\\a.exe", KOFW_LOC_USER);

	/* ETW delivers device paths, not drive letters. If this stopped
	 * matching, every module load would classify as `other` and the
	 * system-module filter would suppress nothing. */
	loc_is("\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll",
	       KOFW_LOC_SYSTEM);
	loc_is("\\Device\\HarddiskVolume3\\Users\\bob\\AppData\\Local\\Temp\\x",
	       KOFW_LOC_TEMP);

	/* The 8.3 spellings of the same places - the branch that exists so a
	 * short path is not silently classified as something else. */
	loc_is("C:\\DOCUME~1\\bob\\LOCALS~1\\Temp\\a.exe", KOFW_LOC_TEMP);
	loc_is("C:\\PROGRA~1\\thing\\a.dll", KOFW_LOC_PROGRAMS);

	/* The two extra system directories an ARM64 machine has. */
	loc_is("C:\\Windows\\SyChpe32\\kernel32.dll", KOFW_LOC_SYSTEM);
	loc_is("C:\\Windows\\SysArm32\\kernel32.dll", KOFW_LOC_SYSTEM);
	loc_is("C:\\Windows\\SysWOW64\\kernel32.dll", KOFW_LOC_SYSTEM);

	/* Case is not a way to spell a different location. */
	loc_is("c:\\windows\\system32\\ntdll.dll", KOFW_LOC_SYSTEM);
	loc_is("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", KOFW_LOC_SYSTEM);

	loc_is("D:\\stuff\\a.exe", KOFW_LOC_OTHER);

	/*
	 * WINDOWS FOLDS CASE, LINUX DOES NOT, and one matcher cannot do both -
	 * so the table says per row and this is what checks it.
	 *
	 * Folding everything would have been the easy bug: /etc/PASSWD is a
	 * different file from /etc/passwd, and reporting T1136.001 against it
	 * is a finding about a file nobody touched.
	 */
	loc_is("C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", KOFW_LOC_SYSTEM);
	loc_is("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\"
	       "CURRENTVERSION\\RUN", KOFW_LOC_AUTOSTART);
	loc_is("/etc/passwd", KOFW_LOC_CREDENTIAL);
	loc_is("/etc/PASSWD", KOFW_LOC_OTHER);
	loc_is("/ETC/ld.so.preload", KOFW_LOC_OTHER);

	/* ---- the technique tag, which rides the same single pass -------- */
	{
		uint16_t att = 0xffff;

		if (kofw_classify("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft"
				  "\\Windows\\CurrentVersion\\Run", &att)
		    != KOFW_LOC_AUTOSTART || att != KOFW_ATT_RUN_KEY)
			fail("attack", "a Run value is not T1547.001");

		if (kofw_classify("/etc/ld.so.preload", &att)
		    != KOFW_LOC_PRELOAD || att != KOFW_ATT_LD_PRELOAD)
			fail("attack", "ld.so.preload is not T1574.006");

		if (kofw_classify("C:\\Windows\\System32\\drivers\\etc\\"
				  "hosts", &att) != KOFW_LOC_HOSTS ||
		    att != KOFW_ATT_HOSTS)
			fail("attack", "the hosts file is not T1562.001");

		if (kofw_classify("\\REGISTRY\\MACHINE\\SYSTEM\\"
				  "CurrentControlSet\\Services\\evil", &att)
		    != KOFW_LOC_SERVICE || att != KOFW_ATT_SERVICE)
			fail("attack", "a service key is not T1543.003");

		/* Temp is not a technique. A location worth knowing and a
		 * technique are different claims, and conflating them would
		 * tag every ordinary download. */
		if (kofw_classify("C:\\Users\\b\\AppData\\Local\\Temp\\a",
				  &att) != KOFW_LOC_TEMP ||
		    att != KOFW_ATT_NONE)
			fail("attack", "temp carries a technique tag");

		/* Every technique in the list has both an id and a name. */
		{
			uint16_t i;
			for (i = 1; i < KOFW_ATT_COUNT; i++) {
				if (!*kofw_attack_id(i) ||
				    !*kofw_attack_name(i)) {
					printf("  FAIL attack %u: no id or "
					       "name\n", (unsigned)i);
					failures++;
				}
			}
		}
	}

	/* "nothing to classify" is not the same answer as "classified, and it
	 * is nowhere interesting" - drop_loc is tested against this. */
	loc_is("", KOFW_LOC_UNKNOWN);
	loc_is(NULL, KOFW_LOC_UNKNOWN);
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
	e->off_image  = KOFW_TEXT_NONE;
	e->off_object = KOFW_TEXT_NONE;
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
	 * kofwintrace depends on. */
	{
		struct kofw_pent *p = kofw_ptab_add(&t, 100, 0, "root.exe", 0);
		if (!p)
			fail("scope", "could not seed the root");
		p->tracked = 1;
		t.n_alive_tracked++;
	}

	/* A child of the root is kin. */
	mk(&e, KOFW_EVT_PROC_START, 200, 100);
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a child of the root");

	/* A GRANDCHILD is kin too - the set has to grow transitively or a
	 * dropper that shells out twice disappears. */
	mk(&e, KOFW_EVT_PROC_START, 300, 200);
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a grandchild");

	/* An unrelated process is not. */
	mk(&e, KOFW_EVT_PROC_START, 400, 999);
	if (kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "admitted an unrelated process");

	/* A file event from inside the tree is kept, one from outside is not. */
	mk(&e, KOFW_EVT_FILE_NEW, 300, 0);
	set_obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\drop.exe");
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "refused a file event from the tree");
	if (e.obj_loc != KOFW_LOC_TEMP)
		fail("scope", "did not classify the object path");

	mk(&e, KOFW_EVT_FILE_NEW, 400, 0);
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
	f.drop_loc = 1u << KOFW_LOC_SYSTEM;

	mk(&e, KOFW_EVT_IMAGE_LOAD, 300, 0);
	set_obj(&e, "C:\\Windows\\System32\\ntdll.dll");
	if (kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "kept a system module load under drop_loc");

	mk(&e, KOFW_EVT_IMAGE_LOAD, 300, 0);
	set_obj(&e, "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.dll");
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "dropped a module load from temp");

	mk(&e, KOFW_EVT_PROC_START, 500, 300);
	set_obj(&e, "");
	e.off_object = KOFW_TEXT_NONE;
	if (!kofw_filter_apply(&t, &f, &e, NULL))
		fail("scope", "drop_loc suppressed a process start");
	f.drop_loc = 0;

	/* Liveness: the tree is finished when every tracked pid has stopped,
	 * which is what a trace waits for. */
	eq_u64("scope alive", t.n_alive_tracked, 4);
	mk(&e, KOFW_EVT_PROC_STOP, 500, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	mk(&e, KOFW_EVT_PROC_STOP, 300, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	eq_u64("scope alive after two stops", t.n_alive_tracked, 2);

	/* A repeated stop for the same pid must not underflow the count. */
	mk(&e, KOFW_EVT_PROC_STOP, 300, 0);
	(void)kofw_filter_apply(&t, &f, &e, NULL);
	eq_u64("scope alive after a repeat stop", t.n_alive_tracked, 2);

	/* A zeroed filter means everything, which is the answer a caller who
	 * forgot a field should get: less filtering, never more. */
	{
		struct kofw_filter none;
		memset(&none, 0, sizeof none);
		mk(&e, KOFW_EVT_FILE_NEW, 4242, 0);
		if (!kofw_filter_apply(&t, &none, &e, NULL))
			fail("scope", "a zeroed filter refused something");
	}
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

int main(void)
{
	printf("grille_host: the ETW-free half of libkofgrille\n");
	t_layout();
	t_type_names();
	t_utf16();
	t_ansi();
	t_classify();
	t_ring();
	t_scope();
	t_pid_reuse();

	if (failures) {
		printf("%d failure(s)\n", failures);
		return 1;
	}
	printf("ok\n");
	return 0;
}
