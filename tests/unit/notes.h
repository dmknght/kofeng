/*
 * notes.h - what a test module said it found, as the engine lets a host see it.
 *
 * A module does not name the object (the diseases do), so a test that needs to know
 * "this module matched here" reads the one thing a module may say without deciding
 * anything: a note (kof_debug), delivered through kscan_on_debug. The test modules of
 * tests/sigs write one note where they used to report, and spell it
 * "<Family>#<variant>" - the words the old finding carried, so a test keeps asking for
 * the family or the variant it always asked for. Notes of any other kind (an unpacker's
 * "UPX.PE.version") have no '#' and are not these.
 *
 * Notes arrive while an object is scanned and the object's callback runs after, so the
 * pending list is what the object said: take it in the callback.
 */

#ifndef KOFENG_TESTS_NOTES_H
#define KOFENG_TESTS_NOTES_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"

#define NOTES_MAX 16u

struct note_list {
	uint32_t n;                      /* notes kept, at most NOTES_MAX         */
	uint32_t lost;                   /* notes seen past NOTES_MAX             */
	char     name[NOTES_MAX][96];
	uint64_t value[NOTES_MAX];
};

static _Thread_local struct note_list notes_pending;

/*
 * The kof_on_debug a test registers with kscan_on_debug. `user` is a struct note_list the
 * test owns, or NULL for the executing thread's own list (notes_pending): a scanner that
 * scans on several threads (kscan_path_mt) delivers a module's note and the callback of
 * the object it made on the same thread, so the thread's list is the object's.
 */
static inline void notes_on(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct note_list *p = user ? user : &notes_pending;

	(void)fact;
	if (!p || !what || !strchr(what, '#'))
		return;
	if (p->n >= NOTES_MAX) {
		p->lost++;
		return;
	}
	snprintf(p->name[p->n], sizeof p->name[0], "%s", what);
	p->value[p->n] = value;
	p->n++;
}

/* The object's notes: moved out of the pending list, which is left empty. */
static inline void notes_take(struct note_list *pending, struct note_list *out)
{
	*out = *pending;
	memset(pending, 0, sizeof *pending);
}

/* Whether the notes hold one whose name contains `word`. */
static inline int notes_has(const struct note_list *p, const char *word)
{
	uint32_t i;

	for (i = 0; p && i < p->n; i++)
		if (strstr(p->name[i], word))
			return 1;
	return 0;
}

/*
 * THE SHORT FORM, for a test with one list of its own per translation unit: register a
 * scanner with notes_watch, and take what the module just said in the callback with
 * notes_here. notes_clear drops what is pending before a new scan begins.
 */

static inline void notes_watch(kof_scanner *sc)
{
	if (sc)
		kscan_on_debug(sc, notes_on, NULL);
}

/* A scanner made and watched in one step, for the thread that will scan with it. */
static inline kof_scanner *notes_scanner(kof_engine *e)
{
	kof_scanner *sc = e ? kscan_new(e) : NULL;

	notes_watch(sc);
	return sc;
}

static inline void notes_here(struct note_list *out)
{
	notes_take(&notes_pending, out);
}

static inline void notes_clear(void)
{
	memset(&notes_pending, 0, sizeof notes_pending);
}

#endif /* KOFENG_TESTS_NOTES_H */
