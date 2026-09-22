/* See apagemap.h. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "apagemap.h"

#define PM_PRESENT (1ULL << 63)
#define PM_SWAPPED (1ULL << 62)

int kofa_pm_open(uint32_t pid, int *err)
{
	char path[64];
	int fd;

	snprintf(path, sizeof path, "/proc/%u/pagemap", (unsigned)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0)
		return fd;

	if (err)
		*err = (errno == ENOENT) ? KOFA_ERR_UNSUPPORTED
					 : KOFA_ERR_DENIED;
	return -1;
}

int kofa_pm_scan(int pmfd, uint64_t base, uint64_t size,
		 uint64_t *scratch, size_t scratch_ents,
		 struct kofa_run *out, int max_runs,
		 struct kofa_pm_result *res)
{
	uint64_t npages, done = 0;
	uint64_t run_start = 0, run_pages = 0;

	if (!res || !scratch || scratch_ents < 64 || !out || max_runs < 1)
		return KOFA_ERR_OS;

	memset(res, 0, sizeof *res);

	if (pmfd < 0)
		return KOFA_ERR_UNSUPPORTED;

	/* A region is always page aligned; a size that is not is a maps line
	 * this library did not produce. */
	if ((base & (KOFA_PAGE_SIZE - 1)) || !size)
		return KOFA_ERR_OS;

	npages = (size + KOFA_PAGE_SIZE - 1) >> KOFA_PAGE_SHIFT;

	while (done < npages) {
		uint64_t want = npages - done;
		ssize_t got;
		uint64_t i, have;

		if (want > scratch_ents)
			want = scratch_ents;

		/*
		 * The offset is the page frame number times eight. It exceeds
		 * 32 bits on any 64-bit address, which is why off_t is what
		 * pread takes and why this is built with _FILE_OFFSET_BITS=64
		 * - a truncated offset here reads ANOTHER region's map and
		 * reports confident, wrong runs.
		 */
		got = pread(pmfd, scratch, (size_t)want * 8,
			    (off_t)(((base >> KOFA_PAGE_SHIFT) + done) * 8));
		if (got <= 0) {
			/*
			 * A short or failed read mid-region: the mapping went
			 * away, or the kernel refused past some point. What was
			 * learned so far is still true, so close the open run
			 * and report success with what there is - the caller
			 * gets fewer runs, never wrong ones.
			 */
			break;
		}

		have = (uint64_t)got / 8;
		if (!have)
			break;

		for (i = 0; i < have; i++) {
			uint64_t ent = scratch[i];

			if (ent & PM_PRESENT) {
				res->resident += KOFA_PAGE_SIZE;
				if (run_pages == 0)
					run_start = base +
						((done + i) << KOFA_PAGE_SHIFT);
				run_pages++;
				continue;
			}

			if (ent & PM_SWAPPED)
				res->swapped += KOFA_PAGE_SIZE;

			/* Not present: close whatever run was open. */
			if (run_pages) {
				/*
				 * A FULL ARRAY STOPS RECORDING AND DOES NOT
				 * STOP COUNTING, and that is not a detail.
				 *
				 * `resident` is what a caller sizes its work
				 * from - it is kofa_region.rss. Returning
				 * early here would report the resident bytes
				 * of the first `max_runs` runs as if they were
				 * the region's, so a fragmented 512 MB mapping
				 * would come back claiming to hold a few
				 * hundred kilobytes. The runs are a prefix and
				 * say so through `more`; the count is always
				 * the whole region.
				 */
				if (res->runs < max_runs) {
					out[res->runs].addr = run_start;
					out[res->runs].len =
						run_pages << KOFA_PAGE_SHIFT;
					res->runs++;
				} else {
					res->more = 1;
				}
				run_pages = 0;
			}
		}

		done += have;
	}

	/*
	 * The tail. A run that reached the end of the region is still a run,
	 * and forgetting it here is the bug that loses the LAST run of every
	 * fully resident mapping - which is most of them, and which a test
	 * over a sparse region would never show.
	 */
	if (run_pages) {
		if (res->runs >= max_runs) {
			res->more = 1;
		} else {
			out[res->runs].addr = run_start;
			out[res->runs].len = run_pages << KOFA_PAGE_SHIFT;
			res->runs++;
		}
	}

	/* A run may extend past the region when size is not page aligned;
	 * clamp so a caller never reads outside what it asked about. */
	if (res->runs > 0) {
		struct kofa_run *last = &out[res->runs - 1];

		if (last->addr + last->len > base + size)
			last->len = base + size - last->addr;
	}

	return KOFA_OK;
}
