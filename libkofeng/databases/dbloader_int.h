/*
 * dbloader_int.h - what the units of the pack loader share (dbloader.c, dbpackcheck.c,
 * dbloader_packs.c). Private to databases/.
 */

#ifndef KOFENG_DBLOADER_INT_H
#define KOFENG_DBLOADER_INT_H

#include "dbloader.h"
#include "pack/hexprog.h"
#include "../detectors/pattern/kofmultimatch.h"
#include "../detectors/linkage/kofdiag.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../kofcore/kofplatform.h"

int kof_db_pack_valid(const void *map, uint64_t len, const char *path);
int kof_db_map_pack(struct kof_db_pack *mp, const char *path);
void kof_db_unmap_pack(struct kof_db_pack *mp);
int kof_db_arena_open(struct kof_engine *e, size_t want);
void kof_db_load_diagnoses(struct kof_engine *e, const char *dir);
void kof_db_load_syndromes(struct kof_engine *e, const char *dir);
void kof_db_load_diseases(struct kof_engine *e, const char *dir);
const char **kof_db_collect_packs(const char *dir, uint32_t *out_n);

#endif /* KOFENG_DBLOADER_INT_H */
