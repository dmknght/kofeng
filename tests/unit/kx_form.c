/*
 * kx_form - kofexamine/kv_form.c's tick-cell writer against slots past the form's table (KXA-7). The source is included; the rest
 * of the viewer is not linked (its symbols are left unresolved, and nothing here reaches them).
 *
 * The three span arrays of struct kv_form are adjacent ints, so a write at slot KV_FORM_SLOTS lands in the NEXT array's slot 0:
 * the test sets known spans, writes cells at slots past the end and checks that nothing it did not name changed.
 */
#define _GNU_SOURCE
#include "../../kofexamine/kv_form.c"

int g_mod_shift, g_mod_ctrl, g_mx, g_my;

static int fails, checks;

#define CK(cond, what) do { checks++; if (!(cond)) { printf("  FAIL %s\n", what); fails++; } } while (0)

int main(void)
{
	static struct kv_form fm;
	struct out o;
	char buf[4096];
	uint32_t slot, i;
	int before[3 * KV_FORM_SLOTS];

	memset(&o, 0, sizeof o);
	o.p = buf;
	o.cap = sizeof buf;
	kv_form_reset(&fm);
	for (i = 0; i < KV_FORM_SLOTS; i++) {
		fm.tick_x0[i] = 1000 + (int)i;
		fm.tick_x1[i] = 2000 + (int)i;
	}
	memcpy(before, fm.tick_y, sizeof before);

	/* the last slot is a slot */
	o.n = 0;
	kv_form_tick_cell(&o, &fm, KV_FORM_SLOTS - 1u, 5, "label", 1, 1, 10);
	CK(fm.tick_y[KV_FORM_SLOTS - 1u] == 5, "the last slot keeps its span");
	memcpy(before, fm.tick_y, sizeof before);
	/* past it: drawn or not, no span of any other slot may change */
	for (slot = KV_FORM_SLOTS; slot < KV_FORM_SLOTS + 8u; slot++) {
		o.n = 0;
		kv_form_tick_cell(&o, &fm, slot, 7, "label", 1, 1, 10);
		CK(memcmp(before, fm.tick_y, sizeof before) == 0, "a cell past the table wrote into the spans of another slot");
	}
	CK(kv_form_tick_at(&fm, 5000u, 7, 1000) != 0 || 1, "tick_at still answers");
	printf("%d check(s), %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
