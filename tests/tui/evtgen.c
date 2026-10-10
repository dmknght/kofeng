/* evtgen.c - writes a small synthetic event log (.ktr) for the viewer's event
 * panel tests.  Not part of the build; compiled on demand by mkfixtures.py:
 *   cc -I<repo>/libkoforbit/evt evtgen.c kofevt.c kofevtlog.c kofevtfmt.c -o evtgen
 * usage: evtgen out.ktr [count]                                              */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "kofevt.h"
#include "kofevtlog.h"

int main(int argc, char **argv)
{
	struct kofevt_log_info li;
	struct kofevt_log_w *w;
	int n = argc > 2 ? atoi(argv[2]) : 40, i;
	static const unsigned verbs[] = {
		KOF_EVT_PROC_START, KOF_EVT_PROC_STOP, KOF_EVT_IMAGE_LOAD,
		KOF_EVT_FILE_NEW, KOF_EVT_FILE_DELETE, KOF_EVT_FILE_RENAME,
		KOF_EVT_NET_CONNECT, KOF_EVT_NET_SEND, KOF_EVT_NET_RECV,
		KOF_EVT_NET_DISCONNECT };

	if (argc < 2)
		return 2;
	memset(&li, 0, sizeof li);
	li.rec_size = (uint32_t)sizeof(struct kof_evt);
	li.head_size = (uint16_t)KOF_EVT_HEAD;
	li.len_off = (uint16_t)offsetof(struct kof_evt, text_len);
	li.rec_kind = KOFEVT_REC_KOF;
	li.build = 1;
	li.src_major = 1;
	li.started = kof_evt_now();
	w = kofevt_log_create(argv[1], &li);
	if (!w)
		return 1;
	for (i = 0; i < n; i++) {
		struct kof_evt e;
		unsigned vb = verbs[i % (sizeof verbs / sizeof verbs[0])];
		char path[96];

		memset(&e, 0, sizeof e);
		e.stamp = kof_evt_now() + (uint64_t)i * 10000000ull;
		e.seq = (uint64_t)i + 1u;
		e.pid = 1000u + (unsigned)(i % 7);
		e.ppid = 1u;
		e.actor_pid = e.pid;
		e.tid = e.pid + 1u;
		e.verb = (uint16_t)vb;
		e.off_image = e.off_object = e.off_cmdline = KOF_TEXT_NONE;
		e.off_data = KOF_TEXT_NONE;
		switch (vb) {
		case KOF_EVT_PROC_START: {
			struct kof_evt_proc *p = kof_evt_set_proc(&e);

			if (p)
				p->create_time = e.stamp;
			snprintf(path, sizeof path, "/usr/bin/tool%d", i);
			e.off_image = kof_evt_text_put(&e, path);
			e.off_cmdline = kof_evt_text_put(&e,
				"tool --flag value --long-option=1 \"quoted arg\"");
			break;
		}
		case KOF_EVT_PROC_STOP:
			kof_evt_set_proc(&e);
			e.off_image = kof_evt_text_put(&e, "/usr/bin/tool");
			break;
		case KOF_EVT_IMAGE_LOAD: {
			struct kof_evt_mem *m = kof_evt_set_mem(&e);

			if (m) { m->addr = 0x7f0000000000ull + (uint64_t)i * 4096; m->addr_size = 8192; }
			snprintf(path, sizeof path, "/lib/x86_64-linux-gnu/lib%d.so", i);
			e.off_object = kof_evt_text_put(&e, path);
			break;
		}
		case KOF_EVT_FILE_NEW:
		case KOF_EVT_FILE_DELETE:
		case KOF_EVT_FILE_RENAME:
			kof_evt_set_file(&e);
			snprintf(path, sizeof path, "/tmp/dropped_%d.bin", i);
			e.off_object = kof_evt_text_put(&e, path);
			break;
		default: {
			struct kof_evt_net *nt = kof_evt_set_net(&e);

			if (nt) {
				memset(nt->daddr, 0, 16); nt->daddr[10] = nt->daddr[11] = 0xff;
				nt->daddr[12] = 10; nt->daddr[15] = (uint8_t)(i + 1);
				nt->dport = 0x5000;      /* 80, network order */
				nt->size = 128u * (unsigned)i;
			}
			break;
		}
		}
		if (kofevt_log_write(w, &e))
			return 1;
	}
	kofevt_log_close(w);
	return 0;
}
