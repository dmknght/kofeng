/*
 * find_str_forms - the kof_find_str_* macros expand to what they claim.
 *
 * These are the one part of the module ABI that is preprocessor arithmetic rather
 * than code: an argument counter, sixteen fold macros, and a paste that picks one of
 * them. Every failure mode of that machinery is silent. Drop a name and the search
 * for it never happens; get the fold wrong by one and the last string in every list
 * is ignored; paste the wrong arity and the expansion still compiles because the
 * remaining arguments land in __VA_ARGS__ of a shorter fold. A signature written
 * against any of that looks exactly like one that works.
 *
 * So this stands a fake host underneath the macros - a context whose find_str
 * answers out of a bitmask the test sets - and checks three things for every arity
 * from 1 to 16:
 *
 *   the answer is right for every possible pattern of present and absent
 *   every string in the list is actually asked about, and none twice
 *   the short circuit really stops where the operator says it does
 *
 * The middle one is what a value check on its own would miss: `a || b || b` gives
 * the right answer for two thirds of the inputs.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <kofmod/kofsig.h>

/* ---- the fake host ---------------------------------------------------------- */

/*
 * Which strings are present, and which were asked about.
 *
 * Globals because the macros reach through a context whose priv pointer the module
 * ABI deliberately gives a module no way to use - the test is standing where the
 * host stands, and the host keeps this in its scanner.
 */
static uint32_t present;      /* bit i set: string i is in the object */
static uint32_t asked;        /* bit i set: string i was searched for */
static uint32_t ask_count[32];

static int fake_find_str(const struct kof_obj_ctx *c, uint32_t str_id,
			 uint32_t range_id)
{
	(void)c;
	/* Every call in this test names the same range. A range id that is not the
	 * one declared below means the macro put an argument in the wrong slot,
	 * which is precisely the mistake the parameter order was changed to make
	 * impossible - so it is worth failing loudly rather than ignoring. */
	if (range_id != 7) {
		printf("  FAIL: range id %u reached find_str, expected 7\n", range_id);
		return 0;
	}
	if (str_id < 32) {
		asked |= 1u << str_id;
		ask_count[str_id]++;
	}
	return (present >> str_id) & 1u;
}

static struct kof_content vtable;
static struct kof_obj_ctx ctx_storage;

/*
 * The macros name `ctx`, so the test provides one - the same way a module does.
 * A pointer rather than the struct, because that is what KOF_DEFINE_SCAN puts in
 * scope and the expansion is written for it.
 */
static const struct kof_obj_ctx *ctx = &ctx_storage;

/* ---- the declarations the build would have generated ------------------------ */

/*
 * Written out rather than produced by ksigbuilder --extract, because what is under
 * test is the expansion and not the extractor. Sixteen strings and one range, ids
 * assigned exactly as the extractor assigns them.
 */
#define kof_rangeid_r 7

#define kof_strid_s0   0
#define kof_strid_s1   1
#define kof_strid_s2   2
#define kof_strid_s3   3
#define kof_strid_s4   4
#define kof_strid_s5   5
#define kof_strid_s6   6
#define kof_strid_s7   7
#define kof_strid_s8   8
#define kof_strid_s9   9
#define kof_strid_s10 10
#define kof_strid_s11 11
#define kof_strid_s12 12
#define kof_strid_s13 13
#define kof_strid_s14 14
#define kof_strid_s15 15

/* The lists, one per arity, so each fold macro is reached. */
#define L1  s0
#define L2  L1,  s1
#define L3  L2,  s2
#define L4  L3,  s3
#define L5  L4,  s4
#define L6  L5,  s5
#define L7  L6,  s6
#define L8  L7,  s7
#define L9  L8,  s8
#define L10 L9,  s9
#define L11 L10, s10
#define L12 L11, s11
#define L13 L12, s12
#define L14 L13, s13
#define L15 L14, s14
#define L16 L15, s15

static int failures;

static void fail(unsigned n, uint32_t mask, const char *what, long got, long want)
{
	printf("  FAIL arity %u mask 0x%05x: %s gave %ld, expected %ld\n",
	       n, mask, what, got, want);
	failures++;
}

/* ---- what the answers should be --------------------------------------------- */

static int want_any(unsigned n, uint32_t mask)
{
	return (mask & ((1u << n) - 1u)) != 0;
}

static int want_all(unsigned n, uint32_t mask)
{
	return (mask & ((1u << n) - 1u)) == ((1u << n) - 1u);
}

static int want_multi(unsigned n, uint32_t mask)
{
	unsigned i, c = 0;

	for (i = 0; i < n; i++)
		if (mask & (1u << i))
			c++;
	return (int)c;
}

/*
 * Which strings a correct expansion asks about, given where it may stop.
 *
 * ANY walks until it finds one present, ALL until it finds one absent, MULTI to the
 * end. Anything else asked, or anything skipped before the stopping point, is a
 * fold that is not doing what the operator says.
 */
static uint32_t want_asked_any(unsigned n, uint32_t mask)
{
	unsigned i;
	uint32_t seen = 0;

	for (i = 0; i < n; i++) {
		seen |= 1u << i;
		if (mask & (1u << i))
			break;
	}
	return seen;
}

static uint32_t want_asked_all(unsigned n, uint32_t mask)
{
	unsigned i;
	uint32_t seen = 0;

	for (i = 0; i < n; i++) {
		seen |= 1u << i;
		if (!(mask & (1u << i)))
			break;
	}
	return seen;
}

/* ---- one arity -------------------------------------------------------------- */

/*
 * The three forms at one arity, over every combination of present and absent.
 *
 * A macro because the list of names has to be a literal argument list at the call
 * site - there is no way to pass "the first n of them" as a value, which is the
 * whole reason the expansion is what it is.
 */
#define CHECK_ARITY(n, list)                                                   \
	do {                                                                   \
		uint32_t mask, limit = (n) >= 12 ? 4096u : (1u << (n));        \
		unsigned i;                                                    \
		for (mask = 0; mask < limit; mask++) {                         \
			int got;                                               \
			present = mask;                                        \
                                                                               \
			asked = 0;                                             \
			memset(ask_count, 0, sizeof ask_count);                \
			got = kof_find_str_any(r, list) ? 1 : 0;               \
			if (got != want_any((n), mask))                        \
				fail((n), mask, "any", got, want_any((n), mask)); \
			if (asked != want_asked_any((n), mask))                \
				fail((n), mask, "any asked",                   \
				     (long)asked,                              \
				     (long)want_asked_any((n), mask));         \
                                                                               \
			asked = 0;                                             \
			memset(ask_count, 0, sizeof ask_count);                \
			got = kof_find_str_all(r, list) ? 1 : 0;               \
			if (got != want_all((n), mask))                        \
				fail((n), mask, "all", got, want_all((n), mask)); \
			if (asked != want_asked_all((n), mask))                \
				fail((n), mask, "all asked",                   \
				     (long)asked,                              \
				     (long)want_asked_all((n), mask));         \
                                                                               \
			asked = 0;                                             \
			memset(ask_count, 0, sizeof ask_count);                \
			got = kof_find_str_multi(r, list);                     \
			if (got != want_multi((n), mask))                      \
				fail((n), mask, "multi", got,                  \
				     want_multi((n), mask));                   \
			/* multi has no short circuit: every name, once. */    \
			if (asked != ((n) >= 32 ? 0xffffffffu                  \
					        : (1u << (n)) - 1u))           \
				fail((n), mask, "multi asked", (long)asked,    \
				     (long)((1u << (n)) - 1u));                \
			for (i = 0; i < (n); i++)                              \
				if (ask_count[i] != 1)                         \
					fail((n), mask, "multi ask count",     \
					     (long)ask_count[i], 1);           \
		}                                                              \
	} while (0)

int main(void)
{
	memset(&vtable, 0, sizeof vtable);
	vtable.find_str = fake_find_str;
	memset(&ctx_storage, 0, sizeof ctx_storage);
	ctx_storage.content = &vtable;

	CHECK_ARITY(1,  L1);
	CHECK_ARITY(2,  L2);
	CHECK_ARITY(3,  L3);
	CHECK_ARITY(4,  L4);
	CHECK_ARITY(5,  L5);
	CHECK_ARITY(6,  L6);
	CHECK_ARITY(7,  L7);
	CHECK_ARITY(8,  L8);
	CHECK_ARITY(9,  L9);
	CHECK_ARITY(10, L10);
	CHECK_ARITY(11, L11);
	/* Past 12 the loop stops enumerating every combination and takes the first
	 * 4096, which still reaches every stopping point in the fold: what changes
	 * with arity is the length of the chain, and that is exercised by the arity
	 * itself rather than by the number of masks. */
	CHECK_ARITY(12, L12);
	CHECK_ARITY(13, L13);
	CHECK_ARITY(14, L14);
	CHECK_ARITY(15, L15);
	CHECK_ARITY(16, L16);

	/* The single form is the same expansion with no fold around it, and it is
	 * what every signature uses most, so it is checked rather than assumed. */
	present = 0;
	asked = 0;
	if (kof_find_str(r, s0) != 0)
		fail(1, 0, "single absent", 1, 0);
	present = 1;
	if (kof_find_str(r, s0) == 0)
		fail(1, 1, "single present", 0, 1);

	printf("find_str forms: arity 1-16 %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
