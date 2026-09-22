/*
 * wfid.c - what Windows says about a file, as an identity the cache can key on.
 *
 * The Windows half of kof_fid_of, whose Linux half is libkoforbit/antarc/afid.c. One
 * name, two files, one compiled per host - the same arrangement kof_walk_open
 * has and for the same reason: the caller is the same scanner on both, and it
 * should not be reading an #ifdef to find out where it is.
 *
 * NOTHING HERE READS A BYTE OF THE FILE. The handle is opened for metadata
 * only, which is what lets this identify a file the caller has no right to the
 * contents of. What makes an identity trustworthy is that something is
 * watching for writes - see the note at the top of fidset.h.
 */

#include <string.h>
#include <windows.h>

#include "wfid.h"

/*
 * FILETIME IS 100-NANOSECOND TICKS SINCE 1601 and the field is documented in
 * nanoseconds, so it is multiplied out. The epoch stays Windows's and that is
 * deliberate: this number is hashed and compared against itself, never against
 * a Linux one, and shifting it to 1970 would spend an arithmetic step to make
 * two incomparable numbers look comparable.
 */
static uint64_t ft_ns(const FILETIME *ft)
{
	uint64_t t = ((uint64_t)ft->dwHighDateTime << 32) |
		     (uint64_t)ft->dwLowDateTime;

	return t * 100ull;
}

int kof_fid_of(const char *path, struct kof_fid *out)
{
	BY_HANDLE_FILE_INFORMATION bi;
	FILE_ID_INFO fid;
	HANDLE h;
	int ok;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!path || !path[0])
		return 0;

	/*
	 * FILE_READ_ATTRIBUTES AND NOTHING ELSE - metadata, not content. The
	 * share mode allows delete because a file somebody else is in the
	 * middle of replacing must not have its identification blocked, and
	 * must certainly not have its REPLACEMENT blocked by this.
	 *
	 * FILE_FLAG_OPEN_REPARSE_POINT IS THE lstat OF THIS CALL. afid.c uses
	 * lstat so that a symlink is its own file with its own identity, and
	 * says why: two links to one target would otherwise share a key, so
	 * calling one clean would speak for the other - and a link is exactly
	 * what an attacker repoints afterwards. Without this flag Windows
	 * silently follows the symlink or junction and hands back the target's
	 * identity, which is that bug with a different spelling.
	 *
	 * FILE_FLAG_BACKUP_SEMANTICS is what lets the open succeed on a
	 * directory at all - which matters because a directory must be
	 * RECOGNISED and refused below, not left to fail as an open error that
	 * a caller cannot tell from a missing file.
	 */
	h = CreateFileA(path, FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			NULL);
	if (h == INVALID_HANDLE_VALUE)
		return 0;

	if (!GetFileInformationByHandle(h, &bi)) {
		CloseHandle(h);
		return 0;
	}
	/*
	 * ONLY A REGULAR FILE HAS CONTENT TO CACHE - the S_ISREG of this call.
	 * A directory has no bytes to scan, and a reparse point identified as
	 * itself has none either: what it names is another file with its own
	 * identity and its own entry.
	 */
	if (bi.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_REPARSE_POINT)) {
		CloseHandle(h);
		return 0;
	}

	/*
	 * THE 128-BIT FILE ID WHERE THERE IS ONE, and the 64-bit index where
	 * there is not.
	 *
	 * nFileIndex is 64 bits and ReFS outgrew it - its file ids do not fit,
	 * and what comes back in the old fields on such a volume is not a
	 * durable identity. FileIdInfo is the modern answer and carries the
	 * 128-bit reference this struct was sized for, plus a 64-bit volume
	 * serial instead of a 32-bit one.
	 *
	 * The fallback is not dead code: FileIdInfo is refused on some volumes
	 * - older filesystems, some network redirectors - and there the 64-bit
	 * index is the best answer available and a correct one for NTFS.
	 */
	ok = GetFileInformationByHandleEx(h, FileIdInfo, &fid, sizeof fid) != 0;
	CloseHandle(h);

	if (ok) {
		memcpy(out->volume, &fid.VolumeSerialNumber,
		       sizeof fid.VolumeSerialNumber);
		memcpy(out->node, &fid.FileId, sizeof fid.FileId);
	} else {
		uint64_t vol = bi.dwVolumeSerialNumber;
		uint64_t idx = ((uint64_t)bi.nFileIndexHigh << 32) |
			       bi.nFileIndexLow;

		memcpy(out->volume, &vol, sizeof vol);
		memcpy(out->node, &idx, sizeof idx);
	}

	out->size = ((uint64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
	/*
	 * CreationTime is the analogue of ctime here, and it is the weaker of
	 * the two: SetFileTime can move it, where POSIX ctime cannot be set
	 * through the normal interface. It is asked for anyway for the reason
	 * afid.c gives about ctime - it is one more thing that has to be put
	 * back, and it costs nothing to ask.
	 */
	out->born = ft_ns(&bi.ftCreationTime);
	out->written = ft_ns(&bi.ftLastWriteTime);
	return 1;
}
