/*
 * dbloader_int.h - what the units of the pack loader share (dbloader.c, dbpackcheck.c,
 * dbloader_packs.c). Private to databases/.
 */

#ifndef KOFENG_DBLOADER_INT_H
#define KOFENG_DBLOADER_INT_H

#include "dbloader.h"
#include "pack/hexprog.h"
#include "../detectors/pattern/kofmultimatch.h"
#include "../detectors/pattern/kofpix.h"
#include "../detectors/linkage/kofdiag.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"

/* How pack_check gets the CRC: the caller checked it, the mapping is read, or a descriptor is (>= 0). */
#define KOF_CRC_DONE      (-2)
#define KOF_CRC_FROM_MAP  (-1)
int kof_db_pack_valid(const void *map, uint64_t len, const char *path);
/* The same, the checksum read from the descriptor with pread rather than from the mapping. */
int kof_db_pack_valid_fd(const void *map, uint64_t len, int fd, const char *path);
/* The CRC of [from, to) of a file against `want`, read in pieces (a short read fails it). */
int kof_db_crc_holds(int fd, uint64_t from, uint64_t to, uint32_t want);
/* The same for a pack with an index trailer, of which only [0, map_len) is mapped, and whose
 * checksum of that part the caller has already checked (see pack_check). */
int kof_db_pack_valid_old(const void *map, uint64_t map_len, uint64_t file_len, const char *path);
int kof_db_map_pack(struct kof_db_pack *mp, const char *path);
void kof_db_unmap_pack(struct kof_db_pack *mp);
int kof_db_arena_open(struct kof_engine *e, size_t want);
void kof_db_load_diagnoses(struct kof_engine *e, const char *dir);
void kof_db_refuse_retired(struct kof_engine *e, const char *dir);
void kof_db_load_diseases(struct kof_engine *e, const char *dir);
/* Mark the modules the loaded diagnoses name as their readers, and free the scratch. */
void kof_db_mark_diag_readers(struct kof_engine *e);
const char **kof_db_collect_packs(const char *dir, uint32_t *out_n);

#endif /* KOFENG_DBLOADER_INT_H */
