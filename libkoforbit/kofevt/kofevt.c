/*
 * kofevt.c - the tables that turn a path and a verb into meaning.
 *
 * NO OS HEADER HERE AND NONE MAY BE ADDED. Everything in this file is string
 * work and switch statements, which is exactly why it is here rather than in a
 * collector: it is the half that a Linux CI can run against a Windows log, and
 * the half where the bugs are.
 *
 * It moved out of libkofgrille for the reason the header gives - the enums are
 * defined once or they rot - and the tables came with them, because a
 * classification split across two libraries is two classifications.
 */

/*
 * BEFORE ANY INCLUDE, because a feature-test macro that arrives after the
 * first header does nothing.
 *
 * clock_gettime is POSIX and is hidden by a strict -std=c11, which this tree
 * builds with. Declared here rather than relying on the build to pass
 * -D_GNU_SOURCE: this file is compiled by the Makefile, by the host test rule
 * and by hand, and the one that fails is always the one nobody set a flag for.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stddef.h>
#include <string.h>

#include "kofevt.h"

static int has_ci(const char *hay, const char *needle, int fold)
{
	size_t i, j;

	for (i = 0; hay[i]; i++) {
		for (j = 0; needle[j]; j++) {
			char a = hay[i + j], b = needle[j];

			if (fold) {
				if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
				if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
			}
			if (a != b)
				break;
		}
		if (!needle[j])
			return 1;
	}
	return 0;
}

/*
 * THE TABLE, AND WHY ITS ORDER IS ITS CORRECTNESS.
 *
 * One pass, first match wins, MOST SPECIFIC FIRST. That is not a style
 * preference, it is the only ordering that is right, and the reason is one
 * example: the per-user temp directory lives INSIDE a user profile, so a
 * \Users\ row that ran before \AppData\Local\Temp\ would swallow it and every
 * dropper's first write would be filed as ordinary user activity. Every row
 * below is placed by that rule and nothing may be appended without checking it.
 *
 * BOTH PLATFORMS IN ONE TABLE, because a path is unambiguous about which one it
 * is - a backslash row cannot match a Linux path and a /etc row cannot match a
 * Windows one - and two tables would be two places to forget a row.
 *
 * The technique is the ATT&CK id this path IS. Where a row has one, an event
 * that WRITES to it is a finding on its own with no chain and no window behind
 * it: T1547.001 is a value under Run, T1053.005 is a file under System32\Tasks.
 * Where a row has KOF_ATT_NONE the location is still worth knowing and is not
 * itself a finding.
 */
static const struct {
	const char *needle;
	uint8_t     loc;
	uint16_t    att;
	/*
	 * 1 for a Windows path, 0 for a Linux one. Not derived from the
	 * separator, even though every row happens to agree with it: a derived
	 * rule is one somebody has to re-derive when they add a row, and this
	 * is the field that decides whether /etc/PASSWD is a finding.
	 */
	uint8_t     fold;
} LOCS[] = {
	/*
	 * A PIPE BEFORE ANYTHING ELSE, because \Device\NamedPipe\ is not
	 * under any of the directories below and a row that matched it later
	 * would never be reached anyway - but putting it first says that a
	 * pipe is not a file in a place, it is a different kind of object.
	 */
	{ "\\Device\\NamedPipe\\", KOF_LOC_PIPE, KOF_ATT_PIPE_IMPERSONATE, 1 },
	{ "\\pipe\\", KOF_LOC_PIPE, KOF_ATT_PIPE_IMPERSONATE, 1 },

	/* ---- temp, FIRST, for the reason above ---------------------------- */
	{ "\\AppData\\Local\\Temp\\", KOF_LOC_TEMP, KOF_ATT_NONE, 1 },
	{ "\\Windows\\Temp\\", KOF_LOC_TEMP, KOF_ATT_NONE, 1 },
	{ "\\APPDAT~1\\LOCAL~1\\Temp\\", KOF_LOC_TEMP, KOF_ATT_NONE, 1 },
	{ "\\LOCALS~1\\Temp\\", KOF_LOC_TEMP, KOF_ATT_NONE, 1 },
	{ "/tmp/", KOF_LOC_TEMP, KOF_ATT_NONE, 0 },
	{ "/var/tmp/", KOF_LOC_TEMP, KOF_ATT_NONE, 0 },
	{ "/dev/shm/", KOF_LOC_TEMP, KOF_ATT_NONE, 0 },

	/* ---- the matrix rows, before the generic locations they sit inside - */

	/* Registry autoruns. RunOnce and the Wow6432Node mirror are separate
	 * spellings of the same key and each needs its own row: a needle is a
	 * substring, not a pattern. */
	{ "\\CurrentVersion\\Run", KOF_LOC_AUTOSTART, KOF_ATT_RUN_KEY, 1 },
	{ "\\CurrentVersion\\RunOnce", KOF_LOC_AUTOSTART, KOF_ATT_RUN_KEY, 1 },
	{ "\\Start Menu\\Programs\\Startup\\",
	  KOF_LOC_AUTOSTART,  KOF_ATT_STARTUP_DIR, 1 },
	{ "/.config/autostart/", KOF_LOC_AUTOSTART, KOF_ATT_STARTUP_DIR, 0 },
	/* The system-wide one, which starts for every user who logs in and is
	 * not under any home directory the row above would reach. */
	{ "/etc/xdg/autostart/", KOF_LOC_AUTOSTART, KOF_ATT_STARTUP_DIR, 0 },

	{ "\\Winlogon\\Shell", KOF_LOC_AUTOSTART, KOF_ATT_WINLOGON, 1 },

	/*
	 * ACCESSIBILITY, and it is two rows because the technique has two
	 * halves. Registering an "assistive technology" is a registry write;
	 * the sticky-keys variant instead replaces a binary that the logon
	 * screen already runs, which is a file write into System32 and is why
	 * the second row has to sit above the generic System32 row below.
	 */
	{ "\\CurrentVersion\\Accessibility\\ATs\\",
	  KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY, 1 },
	{ "\\System32\\sethc.exe", KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY, 1 },
	{ "\\System32\\utilman.exe", KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY, 1 },
	{ "\\System32\\osk.exe", KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY, 1 },
	{ "\\System32\\Magnify.exe", KOF_LOC_AUTOSTART, KOF_ATT_ACCESSIBILITY, 1 },

	/* StubPath under a component GUID runs once per user at logon. */
	{ "\\Active Setup\\Installed Components\\",
	  KOF_LOC_AUTOSTART, KOF_ATT_ACTIVE_SETUP, 1 },

	/*
	 * A BITS JOB LEAVES NO REGISTRY KEY, which is the point of it. The job
	 * queue is a file, and writing it is the only thing this collector can
	 * see - the job is created over COM, and COM calls are not events.
	 */
	{ "\\Microsoft\\Network\\Downloader\\",
	  KOF_LOC_AUTOSTART, KOF_ATT_BITS_JOB, 1 },

	/* Both profile locations: Windows PowerShell and PowerShell 7. */
	{ "\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
	  KOF_LOC_SHELL_INIT, KOF_ATT_PS_PROFILE, 1 },
	{ "\\WindowsPowerShell\\profile.ps1",
	  KOF_LOC_SHELL_INIT, KOF_ATT_PS_PROFILE, 1 },
	{ "\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
	  KOF_LOC_SHELL_INIT, KOF_ATT_PS_PROFILE, 1 },
	{ "\\Winlogon\\Userinit", KOF_LOC_AUTOSTART, KOF_ATT_WINLOGON, 1 },

	{ "\\AppInit_DLLs", KOF_LOC_PRELOAD, KOF_ATT_APPINIT, 1 },
	{ "\\Image File Execution Options\\",
	  KOF_LOC_SERVICE,    KOF_ATT_IFEO, 1 },
	{ "\\CurrentControlSet\\Services\\",
	  KOF_LOC_SERVICE,    KOF_ATT_SERVICE, 1 },
	{ "\\System32\\Tasks\\", KOF_LOC_SCHEDULE, KOF_ATT_SCHED_TASK, 1 },
	{ "\\Schedule\\TaskCache\\", KOF_LOC_SCHEDULE, KOF_ATT_SCHED_TASK, 1 },

	/* Linux persistence. */
	{ "/etc/ld.so.preload", KOF_LOC_PRELOAD, KOF_ATT_LD_PRELOAD, 0 },
	/*
	 * AND THE DIRECTORY BESIDE IT. A .conf dropped in ld.so.conf.d adds a
	 * directory to the search path, so the next binary that starts picks
	 * up an attacker's copy of a library it asked for by name - the same
	 * technique the preload file is, reached by moving the library instead
	 * of naming it.
	 */
	{ "/etc/ld.so.conf.d/", KOF_LOC_PRELOAD, KOF_ATT_LD_PRELOAD, 0 },
	{ "/etc/cron", KOF_LOC_SCHEDULE, KOF_ATT_CRON, 0 },
	{ "/var/spool/cron", KOF_LOC_SCHEDULE, KOF_ATT_CRON, 0 },
	{ "/etc/systemd/system/", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD, 0 },
	{ "/lib/systemd/system/", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD, 0 },
	{ "/.config/systemd/user/", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD, 0 },
	/*
	 * THE OTHER TWO UNIT DIRECTORIES, and both are places a unit is put by
	 * somebody who does not want it found in the obvious one.
	 *
	 * /etc/systemd/user is the system-wide USER unit directory - the
	 * per-user one above is covered, this one was not - and /run/systemd
	 * holds TRANSIENT units, which systemd-run writes and which vanish on
	 * reboot. A unit that leaves no file after a restart is a unit nobody
	 * finds by looking at the disk afterwards.
	 */
	{ "/etc/systemd/user/", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD, 0 },
	{ "/run/systemd/system/", KOF_LOC_SERVICE, KOF_ATT_SYSTEMD, 0 },
	{ "/etc/rc.local", KOF_LOC_SHELL_INIT, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/init.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	/*
	 * THE RUNLEVEL DIRECTORIES, SPELLED OUT. A needle is a substring and
	 * not a pattern - see the note on the table - so there is no way to
	 * write /etc/rc?.d in one row, and a row per runlevel is what the
	 * table's own rule costs here. /etc/rc.d/ is the Red Hat spelling and
	 * rcS.d the Debian single-user one.
	 */
	{ "/etc/rc.d/",  KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rcS.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc0.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc1.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc2.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc3.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc4.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc5.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/etc/rc6.d/", KOF_LOC_SERVICE, KOF_ATT_RC_SCRIPT, 0 },
	{ "/.bashrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.bash_profile", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.bash_logout", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.profile", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/etc/profile", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	/*
	 * THE SYSTEM-WIDE bashrc, which is not the one above: the needle there
	 * is "/.bashrc" and /etc/bash.bashrc does not contain it. It was
	 * filed as OTHER, which is how a write to the file every interactive
	 * shell on the machine sources read as nothing in particular.
	 */
	{ "/etc/bash.bashrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	/*
	 * AND ZSH, which was missing entirely. A .zshrc under /home matched
	 * the generic /home/ row and came out as ordinary user activity -
	 * exactly the failure the note at the top of this table warns about,
	 * on the default login shell of macOS and of a good many Linux
	 * desktops.
	 */
	{ "/.zshrc", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.zshenv", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.zprofile", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.zlogin", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/etc/zsh/", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	/* Run for every interactive login, and writable scripts rather than
	 * static text on every distribution that ships it. */
	{ "/etc/update-motd.d/", KOF_LOC_SHELL_INIT, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/.ssh/authorized_keys", KOF_LOC_SSH, KOF_ATT_SSH_KEY, 0 },
	/*
	 * THE TWO SSH FILES THAT RUN COMMANDS, which authorized_keys is not.
	 * sshd executes ~/.ssh/rc, or /etc/ssh/sshrc when that is absent, on
	 * every successful login - so it is persistence that survives the key
	 * being rotated and leaves the key file untouched.
	 */
	{ "/.ssh/rc", KOF_LOC_SSH, KOF_ATT_SHELL_PROFILE, 0 },
	{ "/etc/ssh/sshrc", KOF_LOC_SSH, KOF_ATT_SHELL_PROFILE, 0 },

	/* Identity and privilege. */
	{ "/etc/passwd", KOF_LOC_CREDENTIAL, KOF_ATT_ACCOUNT_FILE, 0 },
	{ "/etc/shadow", KOF_LOC_CREDENTIAL, KOF_ATT_ACCOUNT_FILE, 0 },
	{ "/etc/sudoers", KOF_LOC_CREDENTIAL, KOF_ATT_SUDOERS, 0 },
	{ "\\config\\SAM", KOF_LOC_CREDENTIAL, KOF_ATT_CRED_STORE, 1 },
	{ "\\config\\SECURITY", KOF_LOC_CREDENTIAL, KOF_ATT_CRED_STORE, 1 },
	{ "\\config\\SYSTEM", KOF_LOC_CREDENTIAL, KOF_ATT_CRED_STORE, 1 },

	/* Defence evasion. */
	{ "\\drivers\\etc\\hosts", KOF_LOC_HOSTS, KOF_ATT_HOSTS, 1 },
	{ "/etc/hosts", KOF_LOC_HOSTS, KOF_ATT_HOSTS, 0 },

	{ "/lib/modules/", KOF_LOC_KERNEL_MOD, KOF_ATT_KERNEL_MOD, 0 },
	{ "\\System32\\drivers\\", KOF_LOC_KERNEL_MOD, KOF_ATT_KERNEL_MOD, 1 },

	{ "\\inetpub\\wwwroot\\", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL, 1 },
	{ "/var/www/", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL, 0 },
	/* The other document roots that ship by default: nginx's own, and the
	 * two under /srv that Arch and SUSE use. A webshell is a webshell
	 * wherever the server was told to look. */
	{ "/usr/share/nginx/html/", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL, 0 },
	{ "/srv/http/", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL, 0 },
	{ "/srv/www/", KOF_LOC_WEB_ROOT, KOF_ATT_WEB_SHELL, 0 },

	/* ---- the generic locations, LAST ---------------------------------- */
	{ "\\Windows\\System32\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "\\Windows\\SysWOW64\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	/* The two extra system directories an ARM64 machine has: SyChpe32
	 * holds the compiled-hybrid x86 binaries and SysArm32 the ARM32 ones.
	 * Leaving them out made every x86 process on such a host look like it
	 * was loading unknown modules. */
	{ "\\Windows\\SyChpe32\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "\\Windows\\SysArm32\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "\\Windows\\WinSxS\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "\\Windows\\assembly\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "\\Windows\\Microsoft.NET\\", KOF_LOC_SYSTEM, KOF_ATT_NONE, 1 },
	{ "/usr/lib/", KOF_LOC_SYSTEM, KOF_ATT_NONE, 0 },
	{ "/usr/lib64/", KOF_LOC_SYSTEM, KOF_ATT_NONE, 0 },
	{ "/lib/", KOF_LOC_SYSTEM, KOF_ATT_NONE, 0 },
	{ "/lib64/", KOF_LOC_SYSTEM, KOF_ATT_NONE, 0 },

	{ "\\Program Files\\", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 1 },
	{ "\\Program Files (x86)\\", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 1 },
	{ "\\PROGRA~1\\", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 1 },
	{ "\\PROGRA~2\\", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 1 },
	{ "/usr/bin/", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 0 },
	{ "/usr/sbin/", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 0 },
	/* Where anything not from a package manager is installed, and where a
	 * dropped binary meant to look installed goes. It fell through to
	 * OTHER, so a new executable there said less than one in /usr/bin. */
	{ "/usr/local/bin/", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 0 },
	{ "/usr/local/sbin/", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 0 },
	{ "/opt/", KOF_LOC_PROGRAMS, KOF_ATT_NONE, 0 },

	{ "\\Users\\", KOF_LOC_USER, KOF_ATT_NONE, 1 },
	{ "/home/", KOF_LOC_USER, KOF_ATT_NONE, 0 },
	{ "/root/", KOF_LOC_USER, KOF_ATT_NONE, 0 },
};

uint8_t kof_classify(const char *path, uint16_t *att)
{
	size_t i;

	if (att)
		*att = KOF_ATT_NONE;
	if (!path || !*path)
		return KOF_LOC_UNKNOWN;

	for (i = 0; i < sizeof LOCS / sizeof LOCS[0]; i++) {
		if (has_ci(path, LOCS[i].needle, LOCS[i].fold)) {
			if (att)
				*att = LOCS[i].att;
			return LOCS[i].loc;
		}
	}
	return KOF_LOC_OTHER;
}

uint8_t kof_classify_path(const char *path)
{
	return kof_classify(path, NULL);
}

const char *kof_loc_name(uint8_t loc)
{
	switch (loc) {
	case KOF_LOC_SYSTEM:     return "system";
	case KOF_LOC_PROGRAMS:   return "programs";
	case KOF_LOC_TEMP:       return "temp";
	case KOF_LOC_USER:       return "user";
	case KOF_LOC_AUTOSTART:  return "autostart";
	case KOF_LOC_SERVICE:    return "service";
	case KOF_LOC_SCHEDULE:   return "schedule";
	case KOF_LOC_SHELL_INIT: return "shellinit";
	case KOF_LOC_PRELOAD:    return "preload";
	case KOF_LOC_SSH:        return "ssh";
	case KOF_LOC_CREDENTIAL: return "credential";
	case KOF_LOC_KERNEL_MOD: return "kmod";
	case KOF_LOC_WEB_ROOT:   return "webroot";
	case KOF_LOC_HOSTS:      return "hosts";
	case KOF_LOC_PIPE:       return "pipe";
	case KOF_LOC_OTHER:      return "other";
	default:                 return "unknown";
	}
}

const char *kof_attack_id(uint16_t att)
{
	switch (att) {
#define KOF_ATT_X_ID(name, tech, word) case name: return tech;
	KOF_ATTACK_LIST(KOF_ATT_X_ID)
#undef KOF_ATT_X_ID
	default: return "";
	}
}

const char *kof_attack_name(uint16_t att)
{
	switch (att) {
#define KOF_ATT_X_NAME(name, tech, word) case name: return word;
	KOF_ATTACK_LIST(KOF_ATT_X_NAME)
#undef KOF_ATT_X_NAME
	default: return "";
	}
}

const char *kof_evt_source_name(uint8_t src)
{
	switch (src) {
	case KOF_SRC_PROCESS:  return "process";
	case KOF_SRC_FILE:     return "file";
	case KOF_SRC_NET:      return "net";
	case KOF_SRC_REGISTRY: return "registry";
	case KOF_SRC_AMSI:     return "amsi";
	case KOF_SRC_DNS:      return "dns";
	default:               return "?";
	}
}

const char *kof_evt_verb_name(uint16_t verb)
{
	switch (verb) {
	case KOF_EVT_PROC_START:    return "ProcStart";
	case KOF_EVT_PROC_STOP:     return "ProcStop";
	case KOF_EVT_IMAGE_LOAD:    return "ImageLoad";
	case KOF_EVT_IMAGE_UNLOAD:  return "ImgUnload";
	case KOF_EVT_FILE_NEW:      return "FileNew";
	case KOF_EVT_FILE_DELETE:   return "FileDel";
	case KOF_EVT_FILE_RENAME:   return "FileRen";
	case KOF_EVT_FILE_WRITE:    return "FileWrite";
	case KOF_EVT_FILE_ATTRIB:   return "FileAttrib";
	case KOF_EVT_REG_CREATE:    return "RegNew";
	case KOF_EVT_REG_SET_VALUE: return "RegSet";
	case KOF_EVT_REG_DELETE:    return "RegDel";
	case KOF_EVT_NET_CONNECT:   return "NetConn";
	case KOF_EVT_NET_SEND:      return "NetSend";
	case KOF_EVT_NET_RECV:      return "NetRecv";
	case KOF_EVT_NET_DISCONNECT: return "NetClose";
	case KOF_EVT_THREAD_START:  return "ThreadNew";
	case KOF_EVT_THREAD_STOP:   return "ThreadEnd";
	case KOF_EVT_AMSI_SCAN:     return "AmsiScan";
	case KOF_EVT_PROC_ATTACH:   return "ProcAttach";
	case KOF_EVT_PROC_PRIVILEGE: return "ProcPriv";
	case KOF_EVT_PROC_SESSION:  return "ProcSession";
	case KOF_EVT_PROC_RENAME:   return "ProcRename";
	case KOF_EVT_PROC_CRASH:    return "ProcCrash";
	case KOF_EVT_CONT:          return "Cont";
	case KOF_EVT_DNS_QUERY:     return "DnsQuery";
	case KOF_EVT_PROC_INFO:     return "ProcInfo";
	/* Capitalised like every other name in this table. These two were the
	 * only lower-case ones, which showed wherever verbs sit in a column
	 * beside each other - and it also put them last in any name ordering,
	 * because lower case sorts after upper. */
	case KOF_EVT_RAW:           return "Raw";
	default:                    return "?";
	}
}

/* ---- reading a record back --------------------------------------------- */

static const char *at(const struct kof_evt *e, uint16_t off)
{
	if (!e || off == KOF_TEXT_NONE || off >= sizeof e->text)
		return "";
	return e->text + off;
}

const char *kof_evt_image(const struct kof_evt *e)   { return at(e, e ? e->off_image   : KOF_TEXT_NONE); }
const char *kof_evt_object(const struct kof_evt *e)  { return at(e, e ? e->off_object  : KOF_TEXT_NONE); }
const char *kof_evt_cmdline(const struct kof_evt *e) { return at(e, e ? e->off_cmdline : KOF_TEXT_NONE); }

uint16_t kof_evt_text_put(struct kof_evt *e, const char *s)
{
	size_t n;

	if (!e || !s || !*s)
		return KOF_TEXT_NONE;
	n = strlen(s) + 1u;
	if ((size_t)e->text_len + n > sizeof e->text) {
		e->flags |= KOF_EF_TRUNCATED;
		return KOF_TEXT_NONE;
	}
	memcpy(e->text + e->text_len, s, n);
	{
		uint16_t off = e->text_len;

		e->text_len = (uint16_t)(e->text_len + n);
		return off;
	}
}

/* ---- the per-verb payload ----------------------------------------------- */

enum kof_evt_kind kof_evt_kind_of(uint16_t verb)
{
	switch (verb) {
	case KOF_EVT_PROC_START:
	case KOF_EVT_PROC_STOP:
	/*
	 * AND THE FIVE THAT ARE ALSO ABOUT A PROCESS. They carry the same
	 * payload - a create time, a session, an exit code where there is one -
	 * and a kind that said otherwise would hand kof_evt_as_proc a NULL for
	 * a record plainly about a process.
	 */
	case KOF_EVT_PROC_ATTACH:
	case KOF_EVT_PROC_PRIVILEGE:
	case KOF_EVT_PROC_SESSION:
	case KOF_EVT_PROC_RENAME:
	case KOF_EVT_PROC_CRASH:
		return KOF_EK_PROC;

	/*
	 * An image load names a base and a size; a thread names its entry
	 * point. Different questions, same two numbers, and the answer to
	 * "where in memory" is the one thing both of them are about.
	 */
	case KOF_EVT_IMAGE_LOAD:
	case KOF_EVT_IMAGE_UNLOAD:
	case KOF_EVT_THREAD_START:
	case KOF_EVT_THREAD_STOP:
		return KOF_EK_MEM;

	/*
	 * AN UNTYPED EVENT IS READ AS AN ADDRESS, because that is the one
	 * numeric thing the collector takes from a shape it does not
	 * recognise.
	 *
	 * It used to say "and because thread events arrive here today" - they
	 * no longer do. Kernel-Process ids 3 and 4 are established and typed,
	 * so a thread start is a THREAD_START and gets the MEM payload by
	 * being one rather than by defaulting into it.
	 *
	 * THE COST IS STATED RATHER THAN HIDDEN: an untyped event that also
	 * had ports or a size loses them, because there is no way to carry two
	 * shapes for something whose shape is unknown. The fix is not a bigger
	 * payload, it is naming the id in type_of() so the event stops being
	 * raw - and that is now what has happened to the network provider's
	 * whole table, IPv6 and UDP included. What is left untyped there
	 * (accept, retransmit, the copy step) carries no peer this drops, or
	 * carries one under a verb that does not exist yet.
	 */
	case KOF_EVT_RAW:
		return KOF_EK_MEM;

	case KOF_EVT_NET_CONNECT:
	case KOF_EVT_NET_DISCONNECT:
	case KOF_EVT_NET_SEND:
	case KOF_EVT_NET_RECV:
	/*
	 * A lookup belongs here because what it carries IS an address - the
	 * one that came back. The name it asked about is in the object arena,
	 * where every verb's strings live.
	 */
	case KOF_EVT_DNS_QUERY:
		return KOF_EK_NET;

	case KOF_EVT_FILE_NEW:
	case KOF_EVT_FILE_DELETE:
	case KOF_EVT_FILE_RENAME:
	case KOF_EVT_FILE_WRITE:
	case KOF_EVT_FILE_ATTRIB:
		return KOF_EK_FILE;

	/*
	 * THE REGISTRY, WHICH USED TO BE IN THE LIST BELOW.
	 *
	 * It was there because a registry event carried a path and nothing
	 * else, and that was the gap rather than the design: the one Windows
	 * persistence event the collector sees said WHERE something was written
	 * and never WHAT. With the value's type, its full size and its
	 * disposition there is a payload to own, and the bytes themselves sit
	 * at off_data in the arena.
	 */
	case KOF_EVT_REG_CREATE:
	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:
		return KOF_EK_REG;

	/*
	 * AMSI, continuations and raw events carry no payload of their own -
	 * what they are about is the object path or the content, which lives
	 * in the arena where every verb's strings live.
	 *
	 * The default lands here too, and must: a verb from a NEWER build is
	 * one this one cannot name, so its payload is bytes of unknown shape.
	 * Returning a kind for it would be guessing at a layout, which is the
	 * one thing a union must never do.
	 */
	default:
		return KOF_EK_NONE;
	}
}

#define AS(name, kind, member, type)                                          \
	const type *kof_evt_as_##name(const struct kof_evt *e)                \
	{                                                                     \
		if (!e || kof_evt_kind_of(e->verb) != (kind))                 \
			return NULL;                                          \
		return &e->u.member;                                          \
	}                                                                     \
	type *kof_evt_set_##name(struct kof_evt *e)                           \
	{                                                                     \
		if (!e || kof_evt_kind_of(e->verb) != (kind))                 \
			return NULL;                                          \
		return &e->u.member;                                          \
	}

AS(proc, KOF_EK_PROC, proc, struct kof_evt_proc)
AS(mem,  KOF_EK_MEM,  mem,  struct kof_evt_mem)
AS(net,  KOF_EK_NET,  net,  struct kof_evt_net)
AS(file, KOF_EK_FILE, file, struct kof_evt_file)
AS(reg,  KOF_EK_REG,  reg,  struct kof_evt_reg)

#undef AS

/* ---- putting a record back together ------------------------------------ */

/*
 * The bytes a record carries, without going through kofevtfmt - this file is
 * the record's own, and a join must not need the presentation half linked in
 * to work. The two agree because there is only one rule: content_len says how
 * many, and it is never strlen.
 */
static const char *content_of(const struct kof_evt *e, size_t *n)
{
	if (!e || !e->content_len) {
		*n = 0;
		return NULL;
	}
	if (e->off_object == KOF_TEXT_NONE ||
	    e->off_object >= sizeof e->text) {
		*n = 0;
		return NULL;
	}
	*n = e->content_len;
	if (*n > sizeof e->text - e->off_object)
		*n = sizeof e->text - e->off_object;
	return e->text + e->off_object;
}

int kof_evt_join_start(struct kof_evt_join *j, const struct kof_evt *parent,
		       void *buf, size_t cap)
{
	const char *p;
	size_t n = 0;

	if (!j)
		return 0;
	memset(j, 0, sizeof *j);
	j->buf = buf;
	j->cap = cap;
	j->idle = 1;
	if (!parent || !buf || !cap)
		return 0;

	/*
	 * A CONTINUATION IS NOT A PARENT. Starting a join on one would treat
	 * the tail of somebody else's submission as the head of a new one -
	 * which is exactly the shape of mistake this API exists to prevent, so
	 * it is refused here rather than left to each caller's loop.
	 */
	if (parent->verb == KOF_EVT_CONT)
		return 0;

	p = content_of(parent, &n);
	if (!p && parent->verb != KOF_EVT_AMSI_SCAN)
		return 0;   /* not a content event: nothing to gather */

	j->idle = 0;
	j->seq = parent->seq;
	if (n > cap) {
		n = cap;
		j->full = 1;
	}
	if (n && p)
		memcpy(j->buf, p, n);
	j->len = n;
	return 1;
}

int kof_evt_join_add(struct kof_evt_join *j, const struct kof_evt *chunk)
{
	const char *p;
	size_t n = 0, room;

	if (!j || j->idle || !chunk)
		return 0;
	if (chunk->verb != KOF_EVT_CONT)
		return 0;
	if (j->holed || j->full)
		return 0;

	/*
	 * ONE PAST THE LAST, and nothing else will do.
	 *
	 * seq is the arrival counter, stamped before anything can refuse a
	 * record, so a gap in it is a record that was dropped rather than one
	 * that was filtered. A chunk on the far side of a gap is bytes from
	 * somewhere in the middle of the submission, and there is no way to
	 * know how far in - so joining it produces a buffer that is missing an
	 * unknown amount from its middle while reading as continuous. Stop
	 * instead, and say so.
	 */
	if (chunk->seq != j->seq + 1u) {
		j->holed = 1;
		return 0;
	}

	p = content_of(chunk, &n);
	j->seq = chunk->seq;
	if (!p || !n)
		return 1;   /* an empty chunk is contiguous and adds nothing */

	room = j->cap - j->len;
	if (n > room) {
		n = room;
		j->full = 1;
	}
	if (n)
		memcpy(j->buf + j->len, p, n);
	j->len += n;
	return n > 0;
}

int kof_evt_join_whole(const struct kof_evt_join *j,
		       const struct kof_evt *parent)
{
	if (!j || j->idle || j->holed || j->full)
		return 0;
	/*
	 * The parent said it was cut. Something has to have finished it, and
	 * the only thing that can is a continuation - so a join that gathered
	 * nothing beyond the parent's own bytes is still short, however
	 * contiguous it was.
	 */
	if (parent && (parent->flags & KOF_EF_TRUNCATED) &&
	    j->seq == parent->seq)
		return 0;
	return 1;
}

/* ---- which machine this is --------------------------------------------- */

const char *kof_evt_platform_name(uint8_t plat)
{
	switch (plat) {
	case KOF_PLAT_WINDOWS: return "windows";
	case KOF_PLAT_LINUX:   return "linux";
	case KOF_PLAT_MACOS:   return "macos";
	default:               return "unknown";
	}
}

const char *kof_evt_arch_name(uint8_t arch)
{
	switch (arch) {
	case KOF_EARCH_X86:    return "x86";
	case KOF_EARCH_X86_64: return "x86_64";
	case KOF_EARCH_ARM:    return "arm";
	case KOF_EARCH_ARM64:  return "arm64";
	default:               return "unknown";
	}
}

/*
 * Answered by the preprocessor rather than by each collector, so the two
 * cannot spell the same machine differently - which is the only way a header
 * field like this goes wrong.
 */
uint8_t kof_evt_platform_self(void)
{
#if defined(_WIN32)
	return KOF_PLAT_WINDOWS;
#elif defined(__linux__)
	return KOF_PLAT_LINUX;
#elif defined(__APPLE__)
	return KOF_PLAT_MACOS;
#else
	return KOF_PLAT_UNKNOWN;
#endif
}

uint8_t kof_evt_arch_self(void)
{
#if defined(__x86_64__) || defined(_M_X64)
	return KOF_EARCH_X86_64;
#elif defined(__i386__) || defined(_M_IX86)
	return KOF_EARCH_X86;
#elif defined(__aarch64__) || defined(_M_ARM64)
	return KOF_EARCH_ARM64;
#elif defined(__arm__) || defined(_M_ARM)
	return KOF_EARCH_ARM;
#else
	return KOF_EARCH_UNKNOWN;
#endif
}

/* ---- time and paths ------------------------------------------------- */

double kof_evt_secs_since(uint64_t t0, uint64_t t)
{
	int64_t d = (int64_t)(t - t0);

	return d < 0 ? 0.0 : (double)d / (double)KOF_TICKS_PER_SEC;
}

const char *kof_path_leaf(const char *path)
{
	const char *last = path;

	for (; *path; path++) {
		if (*path == '\\' || *path == '/')
			last = path + 1;
	}
	return last;
}

/*
 * The clock, and the only per-platform code in this directory.
 *
 * Both branches produce 100ns units since 1601, because that is what an
 * event's stamp is on the platform that has one - and a consumer comparing the
 * two must not have to know which it is holding.
 */
#ifdef _WIN32
#include <windows.h>
uint64_t kof_evt_now(void)
{
	FILETIME       ft;
	ULARGE_INTEGER u;

	GetSystemTimeAsFileTime(&ft);
	u.LowPart  = ft.dwLowDateTime;
	u.HighPart = ft.dwHighDateTime;
	return u.QuadPart;
}
#else
#include <time.h>
/* Unix epoch to 1601, in 100ns units. */
#define KOF_EPOCH_DELTA 116444736000000000ull
uint64_t kof_evt_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return KOF_EPOCH_DELTA + (uint64_t)ts.tv_sec * 10000000ull +
	       (uint64_t)ts.tv_nsec / 100ull;
}
#endif

void kof_evt_banner(FILE *out, const char *tool, uint32_t build,
		    const char *collects)
{
	fprintf(out, "%s (kofevt) build %lu\n", tool ? tool : "?",
		(unsigned long)build);
	if (build == 0u)
		fputs("  built without a build stamp - cannot tell you which "
		      "build this is\n", out);
	if (collects && *collects)
		fprintf(out, "  collects: %s\n", collects);
}

void kof_evt_health_print(FILE *out, const struct kof_evt_health *h,
			  double secs)
{
	uint32_t missing, b;

	if (!out || !h)
		return;

	fprintf(out, "-- %6.1fs  kept %llu (%.1f/s)  dropped %llu  "
		     "high-water %llu  upstream lost %llu  undecoded %llu\n",
		secs, (unsigned long long)h->produced,
		secs > 0.0 ? (double)h->produced / secs : 0.0,
		(unsigned long long)h->dropped,
		(unsigned long long)h->high_water,
		(unsigned long long)h->upstream_lost,
		(unsigned long long)h->undecoded);

	/*
	 * INCOMPLETE IS SAID, not left to be inferred from a number.
	 *
	 * A reader about to conclude "the sample did nothing" has to be told
	 * which kind of run they are holding.
	 */
	if (h->dropped || h->upstream_lost || h->seq_gaps)
		fprintf(out, "   INCOMPLETE: dropped %llu, seq gaps %llu, "
			     "upstream lost %llu\n",
			(unsigned long long)h->dropped,
			(unsigned long long)h->seq_gaps,
			(unsigned long long)h->upstream_lost);

	missing = h->sub_asked & ~h->sub_enabled;
	if (missing) {
		fputs("   INCOMPLETE: subscription(s) never started:", out);
		for (b = 1u; b; b <<= 1)
			if (missing & b)
				fprintf(out, " 0x%x", (unsigned)b);
		fputs("\n", out);
	}
}

/* ---- addresses ---------------------------------------------------------- */

/*
 * THE IPv4-MAPPED PREFIX, ::ffff:0:0/96, and it is the whole of why these
 * four functions are short.
 *
 * One representation in the record means the record cannot be ambiguous about
 * which family it holds, and it means a v4 address is never confused with an
 * unset one - :: is a legal address, so "the first four bytes and zeroes
 * elsewhere" could not have told those apart.
 */
static const uint8_t V4_PREFIX[12] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

int kof_evt_ip_is_unset(const uint8_t addr[16])
{
	unsigned i;

	if (!addr)
		return 1;
	for (i = 0; i < 16u; i++)
		if (addr[i])
			return 0;
	return 1;
}

int kof_evt_ip_is_v6(const uint8_t addr[16])
{
	if (!addr || kof_evt_ip_is_unset(addr))
		return 0;
	return memcmp(addr, V4_PREFIX, sizeof V4_PREFIX) != 0;
}

void kof_evt_ip_set_v4(uint8_t addr[16], uint32_t be_v4)
{
	if (!addr)
		return;
	memcpy(addr, V4_PREFIX, sizeof V4_PREFIX);
	memcpy(addr + 12, &be_v4, 4);
}

const char *kof_evt_ip_str(const uint8_t addr[16], char *out, size_t cap)
{
	unsigned i, best = 0, best_len = 0, run = 0, run_at = 0;
	uint16_t g[8];
	size_t   at = 0;

	if (!out || !cap)
		return "";
	out[0] = '\0';

	if (kof_evt_ip_is_unset(addr))
		return out;

	if (!kof_evt_ip_is_v6(addr)) {
		/* A dotted quad, because that is what somebody pastes into a
		 * search box. Printing ::ffff:1.2.3.4 would be equally correct
		 * and would match nothing anybody looks for. */
		snprintf(out, cap, "%u.%u.%u.%u", addr[12], addr[13],
			 addr[14], addr[15]);
		return out;
	}

	for (i = 0; i < 8u; i++)
		g[i] = (uint16_t)(((uint16_t)addr[2u * i] << 8) |
				   (uint16_t)addr[2u * i + 1u]);

	/*
	 * THE LONGEST RUN OF ZERO GROUPS, COLLAPSED ONCE, and only when it is
	 * at least two groups long - RFC 5952. A canonical form exists so that
	 * two tools produce the same text for the same address; without it a
	 * report and a trace line can disagree about the same C2 and a search
	 * for one misses the other.
	 */
	for (i = 0; i < 8u; i++) {
		if (g[i] == 0) {
			if (!run++)
				run_at = i;
			if (run > best_len) {
				best_len = run;
				best     = run_at;
			}
		} else {
			run = 0;
		}
	}
	if (best_len < 2u)
		best_len = 0;

	/*
	 * "::" IS WRITTEN WHOLE, AND A SEPARATOR FLAG DECIDES THE REST.
	 *
	 * The first version tried to treat each colon of the pair as a
	 * neighbouring group's separator, and got ::1 wrong - it printed ":1",
	 * because a run at the START has no group in front of it to have
	 * written the first colon. The failure is the kind this whole file is
	 * careful about: ":1" is not a plausible-looking address, but it is
	 * also not an obviously broken one, and the report and the trace line
	 * would have agreed with each other about it.
	 *
	 * So the pair is emitted as one token and `first` says whether the next
	 * group needs a colon in front of it. The four shapes that have to
	 * work are ::1, 2001:db8::1, 1:: and an address with no run at all.
	 */
	{
		int first = 1;

		i = 0;
		while (i < 8u) {
			int n;

			if (best_len && i == best) {
				if (at + 2u >= cap)
					break;
				out[at++] = ':';
				out[at++] = ':';
				i    += best_len;
				first = 1;
				continue;
			}
			n = snprintf(out + at, cap - at, "%s%x",
				     first ? "" : ":", (unsigned)g[i]);
			if (n < 0 || (size_t)n >= cap - at)
				break;
			at   += (size_t)n;
			first = 0;
			i++;
		}
	}
	out[at < cap ? at : cap - 1u] = '\0';
	return out;
}
