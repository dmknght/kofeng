#define _GNU_SOURCE

/* kv_ftext.c - the text field's state and rules, without a terminal. See kv_ftext.h. */

#include <string.h>

#include "kv_ftext.h"

void kv_ft_init(struct kv_ftext *f, int id, size_t cap, int (*accept)(int), kv_ft_fn check, kv_ft_fn commit, void *user,
		enum kv_ft_mode mode, int bracket, char *err, size_t err_cap)
{
	memset(f, 0, sizeof *f);
	f->id = id;
	f->cap = cap < sizeof f->buf ? cap : sizeof f->buf;
	f->accept = accept;
	f->check = check;
	f->commit = commit;
	f->user = user;
	f->mode = mode;
	f->bracket = bracket;
	f->err = err;
	f->err_cap = err_cap;
}

static void say(struct kv_ftext *f, const char *line)
{
	if (f->err && f->err_cap) {
		strncpy(f->err, line, f->err_cap - 1u);
		f->err[f->err_cap - 1u] = 0;
	}
}

void kv_ft_set(struct kv_ftext *f, const char *text)
{
	size_t n = strlen(text);

	if (n + 1u > f->cap)
		n = f->cap - 1u;
	memcpy(f->buf, text, n);
	f->buf[n] = 0;
	f->off = 0;
	f->open = 1;
	say(f, "");
}

int kv_ft_accepts(const struct kv_ftext *f, int k)
{
	return k >= 0x20 && k < 0x7f && strlen(f->buf) + 2u < f->cap && (!f->accept || f->accept(k));
}

int kv_ft_validate(struct kv_ftext *f)
{
	char line[128] = "";

	if (!f->check || f->check(f->user, f->buf, line, sizeof line))
		return 1;
	say(f, line);
	return 0;
}

int kv_ft_commit(struct kv_ftext *f)
{
	char line[128] = "";

	if (!f->open)
		return 1;
	if (!kv_ft_validate(f))
		return 0;
	if (f->mode == KV_FT_LIVE) {
		if (f->commit && !f->commit(f->user, f->buf, line, sizeof line)) {
			say(f, line);
			return 0;
		}
		f->open = 0;
	}
	say(f, "");
	return 1;
}

void kv_ft_cancel(struct kv_ftext *f)
{
	f->open = 0;
	say(f, "");
}

int kv_ft_hit(const struct kv_ftext *f, int y, int x)
{
	return y == f->y && x >= f->x0 && x <= f->x1;
}
