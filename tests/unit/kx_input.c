/*
 * kx_input - what kofexamine/kv_input.c's read_key makes of the bytes a terminal sends for the mouse. The source is included so
 * the static readers are reached; stdin is a pipe the test fills.
 *
 * Wheel: SGR button 64/65 are the vertical wheel; 66/67 are the HORIZONTAL one (a tilt wheel, a touchpad's sideways scroll) and
 * must not arrive as a click.
 */
#define _GNU_SOURCE
#include "../../kofexamine/kv_input.c"

/* The rest of the viewer is not linked: the data kv_input.c names is defined here, and the functions its keyboard and
 * paste branches call are stubs, because no mouse path reaches them. */
int byte_text(uint8_t c) { (void)c; return 0; }
void ch_open(struct view *v, int what, uint32_t arg, int row, int col) { (void)v; (void)what; (void)arg; (void)row; (void)col; }
struct object *cur_obj(struct view *v) { (void)v; return NULL; }
int decl_top(void) { return 0; }
int64_t dis_max_bias(struct view *v) { (void)v; return 0; }
int dis_top(void) { return 0; }
int hex_bot(void) { return 0; }
int hex_last(void) { return 0; }
uint64_t hex_max(const struct view *v) { (void)v; return 0; }
int hex_top(void) { return 0; }
size_t paste_extern(char *out, size_t cap) { (void)out; (void)cap; return 0; }
int text_pane(struct view *v) { (void)v; return 0; }
int txt_bot(const struct view *v) { (void)v; return 0; }
void txt_hscroll(struct view *v, int by) { (void)v; (void)by; }
const uint8_t *view_bytes(const struct view *v, uint64_t *n) { (void)v; if (n) *n = 0; return NULL; }
uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run) { (void)v; (void)at; (void)run; return 0; }
uint64_t txt_line_start(struct view *v, const uint8_t *base, uint64_t base_n, uint64_t at) { (void)v; (void)base; (void)base_n; return at; }
uint64_t txt_line_end(struct view *v, const uint8_t *base, uint64_t base_n, uint64_t at) { (void)v; (void)base; (void)base_n; return at; }
uint64_t txt_max_top(struct view *v, const uint8_t *base, uint64_t base_n, int rows) { (void)v; (void)base; (void)base_n; (void)rows; return 0; }
char   g_clip[8192];
size_t g_clip_n;
int    g_cols, g_decl_rows, g_disasm_rows, g_mod_ctrl, g_mod_shift, g_mx, g_my, g_wheel;

static int fails, checks;

#define CK(cond, what) do { checks++; if (!(cond)) { printf("  FAIL %s\n", what); fails++; } } while (0)

/* feed `bytes` to read_key through a pipe on fd 0 and return what it answers */
static int key_of(const char *bytes)
{
	int p[2], saved = dup(0), k;

	if (pipe(p) != 0)
		return -999;
	(void)!write(p[1], bytes, strlen(bytes));
	close(p[1]);
	dup2(p[0], 0);
	close(p[0]);
	k = read_key();
	dup2(saved, 0);
	close(saved);
	return k;
}

int main(void)
{
	char seq[64];
	int b;

	CK(key_of("\033[<64;5;7M") == K_WHEEL_UP, "SGR 64: wheel up");
	CK(key_of("\033[<65;5;7M") == K_WHEEL_DOWN, "SGR 65: wheel down");
	CK(key_of("\033[<0;5;7M") == K_CLICK, "SGR 0: left click");
	CK(key_of("\033[<2;5;7M") == K_RCLICK, "SGR 2: right click");
	for (b = 66; b <= 67; b++) {
		int k;

		snprintf(seq, sizeof seq, "\033[<%d;5;7M", b);
		k = key_of(seq);
		CK(k != K_CLICK && k != K_RCLICK && k != K_WHEEL_UP && k != K_WHEEL_DOWN && k != K_NONE,
		   b == 66 ? "SGR 66 (wheel left): not a click, not the vertical wheel, not end of input"
			   : "SGR 67 (wheel right): not a click, not the vertical wheel, not end of input");
	}
	/* with a modifier bit (shift 4, ctrl 16) the sideways notch is still not a click */
	CK(key_of("\033[<70;5;7M") != K_RCLICK && key_of("\033[<71;5;7M") != K_CLICK, "SGR 70/71 (shift + sideways): not a click");
	/* the legacy (X10) encoding: ESC [ M, then button, x, y each offset by 32 */
	{
		char x10[8] = "\033[M";

		x10[3] = (char)(32 + 64); x10[4] = 40; x10[5] = 40; x10[6] = 0;
		CK(key_of(x10) == K_WHEEL_UP, "X10 64: wheel up");
		x10[3] = (char)(32 + 65);
		CK(key_of(x10) == K_WHEEL_DOWN, "X10 65: wheel down");
		x10[3] = (char)(32 + 66);
		CK(key_of(x10) != K_WHEEL_DOWN && key_of(x10) != K_RCLICK && key_of(x10) != K_CLICK, "X10 66 (wheel left): not the vertical wheel and not a click");
		x10[3] = (char)(32 + 67);
		CK(key_of(x10) != K_WHEEL_DOWN && key_of(x10) != K_RCLICK && key_of(x10) != K_CLICK, "X10 67 (wheel right): not the vertical wheel and not a click");
	}
	printf("%d check(s), %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
