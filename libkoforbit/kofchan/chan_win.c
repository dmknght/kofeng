/*
 * wchan.c - see wchan.h.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#include "kofchan.h"
#include "kofevtlog.h"

#define CHAN_CAP_MIN 1024u
#define CHAN_CAP_MAX (1u << 20)

struct kof_chan_pub {
	HANDLE h_data, h_cur, h_wake;
	/* The private namespace these live in, and the boundary that gates it.
	 * Both are held for the publisher's lifetime: closing the namespace
	 * takes the objects' names with it. */
	HANDLE h_ns, bd;
	struct kof_chan_hdr    *hdr;
	unsigned char           *rec;
	struct kof_chan_cursor *cur;
	uint32_t capacity, rec_size;
};

struct kof_chan_sub {
	HANDLE h_data, h_cur, h_wake;
	HANDLE h_ns, bd;
	const struct kof_chan_hdr *hdr;
	const unsigned char        *rec;
	struct kof_chan_cursor    *cur;

	/*
	 * The same mapping as `hdr`, kept non-const for UnmapViewOfFile.
	 *
	 * The pointer everything READS through is const, because the data
	 * section is read-only and the type should say so. Unmapping needs a
	 * writable pointer, and casting the const away at the two teardown
	 * sites is how -Wcast-qual stops catching the casts that matter. One
	 * field, set once, used twice.
	 */
	void *hdr_raw;
};

/*
 * THE CHANNEL LIVES IN A PRIVATE NAMESPACE BOUND TO Administrators.
 *
 * WHAT WAS WRONG WITH A NAME. The objects were called Local\kofwatchtower.*
 * and the publisher defended the name by refusing to attach to one that
 * already existed - which is a real defence and only covers one direction.
 * The SUBSCRIBER had none: it opened by name and checked magic, version and
 * layout, and nothing asked WHO CREATED IT. Anything that made those three
 * names before the sensor started became the sensor, as far as the client was
 * concerned - free to report a quiet machine, or to name files the client
 * would then open and scan.
 *
 * A private namespace makes that unrepresentable rather than detectable. The
 * boundary descriptor carries a SID, and a process whose token does not hold
 * it cannot create the namespace OR open it - so an unprivileged process
 * cannot squat a name it cannot reach. Measured on this host, unelevated:
 *
 *     boundary SID = Administrators   CreatePrivateNamespaceW -> err 5
 *     no boundary SID                 CreatePrivateNamespaceW -> succeeds
 *
 * The control is the second line: without the SID the same call works, so the
 * refusal is the boundary doing its job and not something else in the way.
 *
 * Local\ ALSO HAD TO GO for the deployment this is for - a sensor running as a
 * service is in session 0 and a client is not, so a session-local name is one
 * neither can share. A private namespace is not session-scoped.
 *
 * NO FALLBACK TO Local\ IF THIS FAILS. A downgrade path is a weakness an
 * attacker can force: make the namespace unavailable and the channel reappears
 * under a name anyone can squat. It fails and says why instead.
 */
static const wchar_t KOF_CHAN_NS[] = L"kofeng";

#ifndef PRIVATE_NAMESPACE_FLAG_DESTROY
#define PRIVATE_NAMESPACE_FLAG_DESTROY 0x00000001
#endif

/*
 * WHO MAY TOUCH THE OBJECTS, written out rather than inherited.
 *
 * Every object was created with SECURITY_ATTRIBUTES of NULL, which means the
 * default DACL of whatever token happened to create it. That is not a decision,
 * it is the absence of one, and it made the access rules depend on how the
 * publisher was started.
 *
 * SYSTEM and the built-in Administrators, and nobody else. `P` makes the DACL
 * protected so nothing is inherited into it.
 *
 * NO MANDATORY LABEL, deliberately. A label would stop a low-integrity process
 * writing the cursor - but a process that is not elevated carries Administrators
 * as DENY-ONLY, so the DACL above already refuses it, and a label that changes
 * nothing is a line that has to be explained every time somebody reads it.
 */
static const wchar_t KOF_CHAN_SDDL[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/*
 * The boundary descriptor, bound to the built-in Administrators alias.
 *
 * Both ends of this channel are privileged by design - the sensor is a service
 * and the decider is elevated, see the three-tier note in kofchan.h - so the
 * alias is exactly the set that should be able to reach it, and an ordinary
 * user token cannot.
 */
static HANDLE chan_boundary(void)
{
	SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
	PSID admins = NULL;
	HANDLE bd;

	bd = CreateBoundaryDescriptorW(KOF_CHAN_NS, 0);
	if (!bd)
		return NULL;
	if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
				      DOMAIN_ALIAS_RID_ADMINS,
				      0, 0, 0, 0, 0, 0, &admins)) {
		DeleteBoundaryDescriptor(bd);
		return NULL;
	}
	if (!AddSIDToBoundaryDescriptor(&bd, admins)) {
		FreeSid(admins);
		DeleteBoundaryDescriptor(bd);
		return NULL;
	}
	FreeSid(admins);
	return bd;
}

/*
 * The three object names, derived from one base so a caller names the channel
 * once, and qualified by the private namespace above.
 */
static int chan_names(const char *base, wchar_t *d, wchar_t *c, wchar_t *w,
		      size_t cap)
{
	static const wchar_t pre[] = L"kofeng\\";
	const char *b = (base && *base) ? base : KOF_CHAN_NAME;
	wchar_t stem[192];
	size_t i = 0, o = 0;

	for (; pre[i] && o + 1 < sizeof stem / sizeof stem[0]; i++)
		stem[o++] = pre[i];
	for (i = 0; b[i] && o + 1 < sizeof stem / sizeof stem[0]; i++)
		stem[o++] = (wchar_t)(unsigned char)b[i];
	stem[o] = 0;

	if (o + 8 >= cap)
		return 0;
	{
		static const wchar_t sd[] = L".data";
		static const wchar_t sc[] = L".cur";
		static const wchar_t sw[] = L".wake";
		size_t k;

		for (k = 0; k <= o; k++)
			d[k] = c[k] = w[k] = stem[k];
		for (k = 0; sd[k]; k++) d[o + k] = sd[k];
		d[o + k] = 0;
		for (k = 0; sc[k]; k++) c[o + k] = sc[k];
		c[o + k] = 0;
		for (k = 0; sw[k]; k++) w[o + k] = sw[k];
		w[o + k] = 0;
	}
	return 1;
}

/* The DACL above, as a SECURITY_ATTRIBUTES the create calls can take. */
static int chan_sd(SECURITY_ATTRIBUTES *sa, PSECURITY_DESCRIPTOR *sd)
{
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		    KOF_CHAN_SDDL, SDDL_REVISION_1, sd, NULL))
		return 0;
	sa->nLength = (DWORD)sizeof *sa;
	sa->lpSecurityDescriptor = *sd;
	sa->bInheritHandle = FALSE;
	return 1;
}

/*
 * IS THIS OBJECT OWNED BY SOMETHING PRIVILEGED.
 *
 * Defence in depth behind the namespace, and it answers the question the
 * subscriber never used to ask: not "does this look like a channel" - magic and
 * version answer that and an impostor can write both - but "who made it".
 *
 * An unprivileged process cannot create an object owned by SYSTEM or by the
 * Administrators alias, so an owner drawn from that set is a fact about the
 * publisher's privilege that the publisher cannot fake downward.
 *
 * Kept even though the namespace already gates creation, because the two fail
 * in different ways: the namespace is configuration and this is a property of
 * the object in hand.
 */
static int chan_owner_ok(HANDLE h)
{
	SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
	PSECURITY_DESCRIPTOR sd = NULL;
	PSID owner = NULL, sys = NULL, adm = NULL;
	int ok = 0;

	if (GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
			    &owner, NULL, NULL, NULL, &sd) != ERROR_SUCCESS)
		return 0;
	if (!owner)
		goto done;

	if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
				     0, 0, 0, 0, 0, 0, 0, &sys) &&
	    EqualSid(owner, sys))
		ok = 1;
	if (!ok &&
	    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
				     DOMAIN_ALIAS_RID_ADMINS,
				     0, 0, 0, 0, 0, 0, &adm) &&
	    EqualSid(owner, adm))
		ok = 1;

done:
	if (sys)
		FreeSid(sys);
	if (adm)
		FreeSid(adm);
	if (sd)
		LocalFree(sd);
	return ok;
}

static uint32_t round_pow2(uint32_t v)
{
	uint32_t p = CHAN_CAP_MIN;

	while (p < v && p < CHAN_CAP_MAX)
		p <<= 1;
	return p;
}

/* ---------------------------------------------------------------- publish */

/*
 * NOT A GROUP NAME ON THIS HOST. Who may open a mapping here is an ACL on the
 * object, set at creation; there is no chown to make after the fact and a unix
 * group is not the vocabulary. Refused rather than silently ignored, so a
 * caller that asked to widen the channel learns it did not happen.
 */
int kof_chan_publish_grant(struct kof_chan_pub *p, const char *group)
{
	(void)p; (void)group;
	errno = ENOSYS;
	return -1;
}

int kof_chan_publish_grant_console(struct kof_chan_pub *p, char *who,
				   size_t who_cap)
{
	(void)p;
	if (who && who_cap)
		who[0] = '\0';
	errno = ENOSYS;
	return -1;
}

struct kof_chan_pub *kof_chan_publish_open(const char *name,
					     uint32_t capacity)
{
	wchar_t nd[256], nc[256], nw[256];
	struct kof_chan_pub *p;
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	uint64_t bytes;
	uint32_t cap = round_pow2(capacity ? capacity : 8192u);

	if (!chan_names(name, nd, nc, nw, 256))
		return NULL;

	p = calloc(1, sizeof *p);
	if (!p)
		return NULL;
	p->capacity = cap;
	p->rec_size = (uint32_t)sizeof(struct kof_evt);
	bytes = sizeof(struct kof_chan_hdr) +
		(uint64_t)cap * p->rec_size;

	/*
	 * THE NAMESPACE FIRST: nothing below can be created until it exists,
	 * and a failure here is the one worth naming - it means this process
	 * is not privileged enough to publish, which is a configuration
	 * mistake rather than a missing sensor.
	 */
	p->bd = chan_boundary();
	if (!p->bd)
		goto fail;
	if (!chan_sd(&sa, &sd))
		goto fail;
	p->h_ns = CreatePrivateNamespaceW(&sa, p->bd, KOF_CHAN_NS);
	if (!p->h_ns) {
		/*
		 * Already there: another publisher owns this channel, or
		 * something is holding the namespace. Opening it would be
		 * attaching to a ring this process does not own - refused for
		 * the same reason an existing section is.
		 */
		goto fail;
	}

	p->h_data = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
				       PAGE_READWRITE,
				       (DWORD)(bytes >> 32),
				       (DWORD)(bytes & 0xffffffffu), nd);
	/*
	 * REFUSED IF IT ALREADY EXISTS, rather than attached.
	 *
	 * Two publishers on one ring interleave into it and the records that
	 * come out belong to neither. It is also the shape of a squatting
	 * attack: something that created the section first would otherwise
	 * have the sensor write every event into a mapping it controls.
	 */
	if (!p->h_data || GetLastError() == ERROR_ALREADY_EXISTS)
		goto fail;

	p->h_cur = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
				      PAGE_READWRITE, 0,
				      (DWORD)sizeof(struct kof_chan_cursor),
				      nc);
	if (!p->h_cur || GetLastError() == ERROR_ALREADY_EXISTS)
		goto fail;

	/*
	 * THE SAME SQUAT CHECK THE TWO SECTIONS GET, which this did not have.
	 * The defence covered two of the three objects, so a name the sections
	 * refused could still be pre-made here - and the wake handle is the one
	 * a subscriber blocks on.
	 */
	p->h_wake = CreateEventW(&sa, FALSE, FALSE, nw);
	if (!p->h_wake || GetLastError() == ERROR_ALREADY_EXISTS)
		goto fail;

	p->hdr = MapViewOfFile(p->h_data, FILE_MAP_WRITE, 0, 0, 0);
	p->cur = MapViewOfFile(p->h_cur, FILE_MAP_WRITE, 0, 0, 0);
	if (!p->hdr || !p->cur)
		goto fail;

	p->rec = (unsigned char *)p->hdr + sizeof *p->hdr;

	memset(p->hdr, 0, sizeof *p->hdr);
	p->hdr->rec_size  = p->rec_size;
	p->hdr->head_size = (uint32_t)KOF_EVT_HEAD;
	p->hdr->len_off   = (uint32_t)offsetof(struct kof_evt, text_len);
	p->hdr->rec_kind  = KOFEVT_REC_KOF;
	p->hdr->capacity  = cap;
	p->hdr->pid       = GetCurrentProcessId();
	p->hdr->version   = KOF_CHAN_VERSION;
	/*
	 * The magic LAST, and with a release, so a subscriber that sees it sees
	 * every field above it. Written first, a subscriber could attach to a
	 * header whose capacity was still zero and index a ring of no slots.
	 */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic,
			      KOF_CHAN_MAGIC, memory_order_release);
	/*
	 * The descriptor was COPIED INTO each object when it was created, so
	 * the objects keep their DACL after this. Freeing it here rather than
	 * holding it for the publisher's life keeps the lifetime where the use
	 * is - and the fail path below frees it for the same reason.
	 */
	LocalFree(sd);
	return p;

fail:
	if (sd) LocalFree(sd);
	if (p->hdr) UnmapViewOfFile(p->hdr);
	if (p->cur) UnmapViewOfFile(p->cur);
	if (p->h_wake) CloseHandle(p->h_wake);
	if (p->h_cur)  CloseHandle(p->h_cur);
	if (p->h_data) CloseHandle(p->h_data);
	/*
	 * DESTROYED, not merely closed - and only ever one this process
	 * CREATED, because h_ns is NULL when the create failed. A sensor that
	 * stopped and left the namespace behind would leave its names taken,
	 * and the next publisher's squat check would correctly read that as an
	 * attack.
	 */
	if (p->h_ns) ClosePrivateNamespace(p->h_ns,
					   PRIVATE_NAMESPACE_FLAG_DESTROY);
	if (p->bd)   DeleteBoundaryDescriptor(p->bd);
	free(p);
	return NULL;
}

int kof_chan_publish(struct kof_chan_pub *p, const struct kof_evt *e)
{
	uint32_t h, t, depth;

	if (!p || !e)
		return -1;

	h = p->hdr->head;
	/*
	 * THE TAIL IS NOT TRUSTED.
	 *
	 * It is written by the subscriber, which is the lower-privilege half
	 * and may be compromised or merely wrong. An out-of-range value would
	 * otherwise make this overwrite live slots or compute a depth that
	 * wraps - so it is clamped to a ring's worth and nothing else is
	 * assumed about it. A bogus tail costs that subscriber its own events.
	 */
	t = atomic_load_explicit((_Atomic uint32_t *)&p->cur->tail,
				 memory_order_acquire);
	depth = h - t;
	if (depth > p->capacity)
		depth = p->capacity;

	if (depth >= p->capacity) {
		p->hdr->dropped++;
		return 1;
	}

	memcpy(p->rec + (uint64_t)(h & (p->capacity - 1u)) * p->rec_size,
	       e, p->rec_size);
	p->hdr->produced++;

	/* RELEASE: publishes the record above, so a subscriber that acquires
	 * this head sees a complete one rather than a half-written one. */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->head, h + 1u,
			      memory_order_release);

	/* Woken on the empty-to-nonempty edge only, so a burst costs one
	 * syscall rather than one per record. A missed edge costs latency, not
	 * a stall: the subscriber caps every wait. */
	if (depth == 0)
		SetEvent(p->h_wake);
	return 0;
}

void kof_chan_publish_close(struct kof_chan_pub *p)
{
	if (!p)
		return;
	/* Zero the magic first: a subscriber attaching during teardown must
	 * not find a header that describes a mapping about to go away. */
	if (p->hdr)
		atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic, 0u,
				      memory_order_release);
	if (p->hdr) UnmapViewOfFile(p->hdr);
	if (p->cur) UnmapViewOfFile(p->cur);
	if (p->h_wake) CloseHandle(p->h_wake);
	if (p->h_cur)  CloseHandle(p->h_cur);
	if (p->h_data) CloseHandle(p->h_data);
	/*
	 * DESTROYED, not merely closed - and only ever one this process
	 * CREATED, because h_ns is NULL when the create failed. A sensor that
	 * stopped and left the namespace behind would leave its names taken,
	 * and the next publisher's squat check would correctly read that as an
	 * attack.
	 */
	if (p->h_ns) ClosePrivateNamespace(p->h_ns,
					   PRIVATE_NAMESPACE_FLAG_DESTROY);
	if (p->bd)   DeleteBoundaryDescriptor(p->bd);
	free(p);
}

/* -------------------------------------------------------------- subscribe */

struct kof_chan_sub *kof_chan_sub_open(const char *name, const char **why,
				       int *reason)
{
	wchar_t nd[256], nc[256], nw[256];
	struct kof_chan_sub *s;

	if (why)
		*why = "";
	if (reason)
		*reason = KOF_CHAN_WHY_BROKEN;
	if (!chan_names(name, nd, nc, nw, 256)) {
		if (why) *why = "the channel name is too long";
		return NULL;
	}

	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;

	/*
	 * FILE_MAP_READ on the data, FILE_MAP_WRITE on the cursor, and that
	 * asymmetry is the point - see wchan.h. A subscriber cannot write a
	 * record because it does not hold the access to, not because it has
	 * been asked not to.
	 */
	/*
	 * THE NAMESPACE BEFORE THE OBJECTS. A token that does not hold the
	 * boundary SID cannot open it, so this is where an unprivileged
	 * subscriber is turned away - by the operating system, before any name
	 * in this process has been resolved.
	 */
	s->bd = chan_boundary();
	if (!s->bd) {
		if (why) *why = "cannot build the channel's boundary";
		goto fail;
	}
	s->h_ns = OpenPrivateNamespaceW(s->bd, KOF_CHAN_NS);
	if (!s->h_ns) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			if (why) *why = "this account may not reach the "
					"sensor's channel";
			if (reason) *reason = KOF_CHAN_WHY_DENIED;
		} else {
			if (why) *why = "no sensor is publishing";
			if (reason) *reason = KOF_CHAN_WHY_ABSENT;
		}
		goto fail;
	}

	s->h_data = OpenFileMappingW(FILE_MAP_READ, FALSE, nd);
	if (!s->h_data) {
		/* ERROR_ACCESS_DENIED means the mapping is there and this
		 * token may not open it - a different problem from there
		 * being no sensor, and a different thing to tell somebody. */
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			if (why) *why = "a sensor is publishing but this "
					"account may not read its channel";
			if (reason) *reason = KOF_CHAN_WHY_DENIED;
		} else {
			if (why) *why = "no sensor is publishing";
			if (reason) *reason = KOF_CHAN_WHY_ABSENT;
		}
		goto fail;
	}
	s->h_cur = OpenFileMappingW(FILE_MAP_WRITE, FALSE, nc);
	if (!s->h_cur) {
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			if (why) *why = "a sensor is publishing but this "
					"account may not write its cursor";
			if (reason) *reason = KOF_CHAN_WHY_DENIED;
		} else {
			if (why) *why = "the cursor is not there";
		}
		goto fail;
	}
	/*
	 * WHO MADE THIS, ASKED BEFORE ANY OF IT IS BELIEVED.
	 *
	 * Checked on BOTH sections. The data section is what records are read
	 * from and the cursor is what this process writes; an impostor holding
	 * either one is a different attack, and owning only one of them must
	 * not pass. Done before the mapping is looked at, so a header written
	 * by something unprivileged is never parsed at all.
	 */
	if (!chan_owner_ok(s->h_data) || !chan_owner_ok(s->h_cur)) {
		if (why) *why = "the channel is not owned by a privileged "
				"account - refusing to trust it";
		if (reason) *reason = KOF_CHAN_WHY_DENIED;
		goto fail;
	}

	s->h_wake = OpenEventW(SYNCHRONIZE, FALSE, nw);

	s->hdr_raw = MapViewOfFile(s->h_data, FILE_MAP_READ, 0, 0, 0);
	s->hdr     = s->hdr_raw;
	s->cur = MapViewOfFile(s->h_cur, FILE_MAP_WRITE, 0, 0, 0);
	if (!s->hdr || !s->cur) {
		if (why) *why = "cannot map the channel";
		goto fail;
	}

	if (atomic_load_explicit((_Atomic uint32_t *)s->hdr_raw,
				 memory_order_acquire) != KOF_CHAN_MAGIC) {
		if (why) *why = "not a kofgrille channel";
		goto fail;
	}
	if (s->hdr->version != KOF_CHAN_VERSION) {
		if (why) *why = "a channel version this build does not know";
		goto fail;
	}
	/*
	 * The check the header exists for. A record of a different size decodes
	 * every field from the wrong offset; one of a different KIND decodes at
	 * the right offsets and means something else. Both are refused.
	 */
	if (s->hdr->rec_size != (uint32_t)sizeof(struct kof_evt)) {
		if (why) *why = "the sensor's record is a different size";
		goto fail;
	}
	if (s->hdr->rec_kind != KOFEVT_REC_KOF) {
		if (why) *why = "the sensor publishes a different record";
		goto fail;
	}
	if (s->hdr->capacity == 0u ||
	    (s->hdr->capacity & (s->hdr->capacity - 1u)) != 0u) {
		if (why) *why = "the channel capacity is not a power of two";
		goto fail;
	}

	s->rec = (const unsigned char *)s->hdr + sizeof *s->hdr;
	return s;

fail:
	if (s->hdr_raw) UnmapViewOfFile(s->hdr_raw);
	if (s->cur) UnmapViewOfFile(s->cur);
	if (s->h_wake) CloseHandle(s->h_wake);
	if (s->h_cur)  CloseHandle(s->h_cur);
	if (s->h_data) CloseHandle(s->h_data);
	/* CLOSED, never destroyed: a subscriber did not create this
	 * namespace and must not take it away from the sensor. */
	if (s->h_ns) ClosePrivateNamespace(s->h_ns, 0);
	if (s->bd)   DeleteBoundaryDescriptor(s->bd);
	free(s);
	return NULL;
}

const struct kof_chan_hdr *kof_chan_sub_header(const struct kof_chan_sub *s)
{
	return s ? s->hdr : NULL;
}

int kof_chan_next(struct kof_chan_sub *s, struct kof_evt *out,
		   uint32_t wait_ms)
{
	uint32_t left = wait_ms;

	if (!s || !out)
		return 0;

	for (;;) {
		uint32_t t = s->cur->tail;
		uint32_t h = atomic_load_explicit(
			(_Atomic uint32_t *)((unsigned char *)s->hdr_raw +
				offsetof(struct kof_chan_hdr, head)),
			memory_order_acquire);

		if (h != t) {
			/*
			 * A PUBLISHER THAT LAPPED US.
			 *
			 * If more than a ring's worth arrived since the last
			 * read, the oldest slots have been overwritten and
			 * reading from `tail` would hand back a record that is
			 * half old and half new. Skip forward to the oldest
			 * slot that is still intact: the loss already happened
			 * and is counted in the header - what must not happen
			 * is reporting a spliced record as an event.
			 */
			if (h - t > s->hdr->capacity)
				t = h - s->hdr->capacity;

			memcpy(out, s->rec + (uint64_t)(t & (s->hdr->capacity -
							     1u)) *
					     s->hdr->rec_size,
			       sizeof *out);

			/* RELEASE, so the publisher cannot begin overwriting
			 * the slot until the copy above has happened. */
			atomic_store_explicit(
				(_Atomic uint32_t *)&s->cur->tail, t + 1u,
				memory_order_release);
			return 1;
		}

		if (left == 0)
			return 0;
		{
			DWORD slice = left < 50u ? left : 50u;

			/* Capped: the publisher signals only on the
			 * empty-to-nonempty edge and decides that from a tail
			 * it may have read a moment stale, so a missed wakeup
			 * must cost latency and not a hang. */
			if (s->h_wake)
				(void)WaitForSingleObject(s->h_wake, slice);
			else
				Sleep(slice);
			left -= slice;
		}
	}
}

void kof_chan_sub_close(struct kof_chan_sub *s)
{
	if (!s)
		return;
	if (s->hdr_raw) UnmapViewOfFile(s->hdr_raw);
	if (s->cur) UnmapViewOfFile(s->cur);
	if (s->h_wake) CloseHandle(s->h_wake);
	if (s->h_cur)  CloseHandle(s->h_cur);
	if (s->h_data) CloseHandle(s->h_data);
	/* CLOSED, never destroyed: a subscriber did not create this
	 * namespace and must not take it away from the sensor. */
	if (s->h_ns) ClosePrivateNamespace(s->h_ns, 0);
	if (s->bd)   DeleteBoundaryDescriptor(s->bd);
	free(s);
}
