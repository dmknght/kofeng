/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kofpath.h - where a host keeps what it must keep between runs.
 *
 * IT IS IN ORBIT BECAUSE IT IS POLICY. koffridge.h says a verdict cache is a
 * host's policy - how long an answer stays good, what identity means here,
 * where it lives - and the engine must never decide any of it. This answers
 * the last of those, once, so two tools cannot put their state in two places
 * and so neither has to know what a Linux cache directory is called.
 *
 *
 * NOT FROM THE ENVIRONMENT, AND THAT IS THE WHOLE POINT.
 *
 * The obvious implementation reads $XDG_CACHE_HOME, or $HOME, or
 * %LOCALAPPDATA%. Measured on this machine, inside an ordinary desktop
 * session:
 *
 *     getenv("HOME")            /home/dmknght
 *     getenv("XDG_CACHE_HOME")  /home/dmknght/.var/app/com.visualstudio.code/cache
 *     getpwuid_r(geteuid())     /home/dmknght
 *
 * XDG_CACHE_HOME points inside a FLATPAK SANDBOX, because the terminal this
 * ran in was started by one. Nothing is wrong with that environment - it is
 * telling the truth about the process that set it - but a scanner that
 * believed it would write its verdict cache into an application's sandbox,
 * where that application can rewrite it. And a verdict cache is a file whose
 * writer decides what the scanner calls clean.
 *
 * So the user's directory comes from the PASSWORD DATABASE, which a process
 * cannot set for its children, and the effective uid is what is looked up -
 * not the real one, because a setuid tool must keep the state of who it is
 * running AS.
 *
 *
 * RESOLVING IS NOT ENOUGH; IT IS ALSO CHECKED.
 *
 * A path is only safe if nobody else can write it, and the two facts that
 * decide that are the owner and the mode. Both are checked after the directory
 * is opened, on the handle, so the answer is about the directory that will be
 * used rather than about a name that may have been replaced since.
 *
 * A directory that fails is not repaired and not used: the caller is told, and
 * a caller told this must carry on WITHOUT persistence rather than write into
 * a place somebody else can edit. That is the difference between a scan that
 * is slower and a scan that can be told what to ignore.
 */

#ifndef KOFORBIT_KOFPATH_H
#define KOFORBIT_KOFPATH_H

#include <stddef.h>

/* What the state is for. They differ in lifetime and in where a system puts
 * them: a cache may be deleted at any time by anybody and the program must
 * still work; state may not. */
enum kof_path_kind {
	/* Verdict caches and anything else that is an optimisation. Linux:
	 * <home>/.cache/kofeng, or /var/cache/kofeng as root. */
	KOF_PATH_CACHE = 0,

	/* Things whose loss changes behaviour. Linux: <home>/.local/state/kofeng,
	 * or /var/lib/kofeng as root. */
	KOF_PATH_STATE = 1
};

/* Why a directory could not be used. Returned so a caller can print it; it is
 * always a literal and never NULL. */
enum {
	KOF_PATH_OK = 0,
	KOF_PATH_NO_HOME,      /* the password database had no directory */
	KOF_PATH_TOO_LONG,
	KOF_PATH_MKDIR,        /* it does not exist and could not be made */
	KOF_PATH_NOT_DIR,
	KOF_PATH_FOREIGN,      /* somebody else owns it */
	KOF_PATH_WIDE_OPEN,    /* group or world may write it */
	KOF_PATH_UNSUPPORTED
};

const char *kof_path_why(int rc);

/*
 * Resolve the directory for `kind`, create it if it is missing, check that it
 * is ours and private, and write it to `out` WITHOUT a trailing separator.
 *
 * Returns KOF_PATH_OK, or one of the codes above - and on anything but OK the
 * buffer holds the path it was going to use, so a message can name it.
 */
int kof_path_dir(int kind, char *out, size_t cap);

/*
 * The same, with `leaf` appended: the full path of one file.
 *
 * `leaf` is a bare name. A leaf containing a separator is refused rather than
 * joined, because the only thing that could produce one is a caller building a
 * path out of something it was given, and this is the last place that can
 * still say no.
 */
int kof_path_file(int kind, const char *leaf, char *out, size_t cap);

#endif /* KOFORBIT_KOFPATH_H */
