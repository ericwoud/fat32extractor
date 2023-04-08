
/*
 * Fat32 library extract a file from fat32 image. Can use long filenames.
 *
 * Copyright (C) 2023      Eric Woudstra
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License v2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <lib/fat32.h>

#include <stdbool.h>
#include <string.h>

#ifdef BUILD4ATF

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <platform_def.h>
#include <drivers/io/io_driver.h>
#include <lib/utils.h>

#define atfstatic static // Don't use the stack
#define toupper(c)  ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
#define tolower(c)  ((c) + 0x20 * (((c) >= 'A') && ((c) <= 'Z')))

static uint32_t * const fat32_buffer = (uint32_t *)FAT32BUFFER;

static int strcasecmp(const char *s1, const char *s2) {
  const unsigned char *us1 = (const unsigned char *)s1;
  const unsigned char *us2 = (const unsigned char *)s2;
  while (tolower(*us1) == tolower(*us2)) {
    if (*us1++ == '\0') return 0;
    us2++;
  }
  return tolower(*us1) - tolower(*us2);
}

#else // BUILD4LINUX

#include <stdlib.h>
#include <unistd.h>

#define atfstatic // Use the stack
#define IO_SEEK_SET 1
#define ERROR printf
#define NOTICE printf
#define WARN printf
#define INFO printf
#define VERBOSE printf

static uint32_t *fat32_buffer = NULL;

static int io_seek(uintptr_t handle, int mode, signed long long offset) {
  if (mode != IO_SEEK_SET) return -1;
  int res = lseek(handle, offset, SEEK_SET);
  if (res < 0) return res;
  return 0;
}

static int io_read(uintptr_t handle, uintptr_t buffer, size_t length,
                   size_t *length_read) {
  *length_read = 0;
  int res = read(handle, (void *) buffer, length);
  if (res < 0) return res;
  *length_read = res;
  return 0;
}

static void zeromem(void * buffer, size_t length) {
  memset(buffer, 0, length);
}

static void strlcpy(char * dst, const char * src, size_t dsize) {
  strncpy(dst, src, dsize);
  dst[dsize] = '\0'; // make sure it is nul terminated
  return;
}

#endif

static struct BPB fat32_bs = {0};

static int min3(const int s1,const int s2,const int s3) {
  int min = s1;
  if (min > s2) min = s2;
  if (min > s3) min = s3;
  return min;
}

static bool csum_direntry(const DIR * entry, const uint8_t csum) {
  const uint8_t *name = entry->S.DIR_Name;
  uint8_t sum = 0;
  for (int len = 11; len != 0; len--) {
    sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *name++;
  }
  return (sum == csum);
}

static bool is_file_direntry(const DIR * entry) {
  return ((entry->S.DIR_Attr & ATTR_DIRECTORY) == 0);
}

static bool is_long_direntry(const DIR * entry) {
  return ((entry->L.LDIR_Attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME);
}

static bool is_free_direntry(const DIR * entry) {
  return (entry->S.DIR_Name[0] == FREE_DIR_ENTRY);
}

static bool is_last_direntry(const DIR * entry) {
  return (entry->S.DIR_Name[0] == LAST_DIR_ENTRY);
}

static bool is_volumeId_direntry(const DIR * entry) {
  return ((entry->S.DIR_Attr & ATTR_VOLUME_ID) != 0);
}

static uint32_t first_cluster_direntry(const DIR * entry) {
  return ((entry->S.DIR_FstClusHI<<0x10) | entry->S.DIR_FstClusLO);
}

static void fill_long_name(const DIR * entry, char* dest, uint8_t* csum) {
  if (entry->L.LDIR_Ord & LAST_LONG_ENTRY) { // Shows up first
    zeromem(dest, FAT32_MAX_LONG_NAME_LENGTH);
    *csum = entry->L.LDIR_Chksum;
  }
  else if (*csum != entry->L.LDIR_Chksum) return;
  int i, j = ((entry->L.LDIR_Ord & (LAST_LONG_ENTRY - 1)) - 1) * 13;
  for (i = 0; i < 10 && j < (FAT32_MAX_LONG_NAME_LENGTH-1); i += 2)
    dest[j++] = entry->L.LDIR_Name1[i];
  for (i = 0; i < 12 && j < (FAT32_MAX_LONG_NAME_LENGTH-1); i += 2)
    dest[j++] = entry->L.LDIR_Name2[i];
  for (i = 0; i <  4 && j < (FAT32_MAX_LONG_NAME_LENGTH-1); i += 2)
    dest[j++] = entry->L.LDIR_Name3[i];
}

static void fill_short_name(DIR * entry, char * dest) {
  int j = 0;
  bool appenddot = is_file_direntry(entry) && (entry->S.DIR_Name[8] != ' ');
  for (int i = 0; i < 11; i++) {
    if (entry->S.DIR_Name[i] == '\0') break;
    if ((i == 8) && appenddot)       dest[j++] = '.';
    if (entry->S.DIR_Name[i] != ' ') dest[j++] = entry->S.DIR_Name[i];
  }
  dest[j] = '\0';
}

static uint64_t first_bytes(const uint32_t cluster) {
  uint64_t sector = fat32_bs.BPB_RsvdSecCnt +
                    fat32_bs.BPB_NumFATs*fat32_bs.BPB_FATSz32 +
                    fat32_bs.BPB_SecPerClus*(cluster-2);
  return  (sector * fat32_bs.BPB_BytesPerSec);
}

static uint32_t read_fat(const int handle, const uint32_t cluster) {
  size_t len;
  if (cluster >= fat32_bs.BPB_FATSz32*fat32_bs.BPB_BytesPerSec/sizeof(uint32_t))
      return BAD_CLUSTER;
  if (fat32_buffer[cluster]) return fat32_buffer[cluster];
  uint64_t skipsect = fat32_bs.BPB_RsvdSecCnt*fat32_bs.BPB_BytesPerSec;
  uint64_t clussect = ( sizeof(uint32_t)*cluster ) &
                      ( ~(fat32_bs.BPB_BytesPerSec-1) );
  if (io_seek(handle, IO_SEEK_SET, skipsect + clussect) < 0) return BAD_CLUSTER;
  io_read(handle, (uintptr_t)&fat32_buffer[clussect/sizeof(uint32_t)],
                             fat32_bs.BPB_BytesPerSec, &len);
  if (len != fat32_bs.BPB_BytesPerSec) return BAD_CLUSTER;
  return fat32_buffer[cluster];
}

static bool handle_entry(DIR * entry, char *lname, uint8_t *csum) {
  if (entry == NULL) goto handle_entry_abort;
  if (is_free_direntry(entry)) goto handle_entry_abort;
  if (is_long_direntry(entry)) {
    fill_long_name(entry, lname, csum);
    return false;
  } // After this: Short Dir Entry
  if (is_volumeId_direntry(entry)) goto handle_entry_abort;
  if ((lname[0] == '\0') || (!csum_direntry(entry, *csum))) {
    fill_short_name(entry, lname);
  }
  if (strcmp(lname,".") == 0) goto handle_entry_abort;
  if (strcmp(lname,"..") == 0) goto handle_entry_abort;
  return true; // handling entry needs to continue
 handle_entry_abort:
  lname[0] = '\0';
  return false;
}

static bool find_entry(const int handle, uint32_t cluster, char *name,
                       DIR * entry) {
  uint8_t csum;
  atfstatic DIR entry_array[FAT32_MAX_SECTOR_SIZE/sizeof(DIR)];
  atfstatic char lname[FAT32_MAX_LONG_NAME_LENGTH];
  lname[0] = '\0';
  while (cluster < BAD_CLUSTER) {
    if (io_seek(handle, IO_SEEK_SET, first_bytes(cluster)) < 0) return false;
    for (int i = 0; i < fat32_bs.BPB_SecPerClus; i++) {
      size_t len;
      io_read(handle, (uintptr_t)entry_array, fat32_bs.BPB_BytesPerSec, &len);
      if (len != fat32_bs.BPB_BytesPerSec) return false;
      for (int j = 0; j < fat32_bs.BPB_BytesPerSec/sizeof(DIR); j++) {
        if (is_last_direntry(&entry_array[j])) return false;
        if (!handle_entry(&entry_array[j], lname, &csum)) continue;
        if (strcasecmp(name, lname) != 0) continue;
        memcpy(entry, &entry_array[j], sizeof(DIR));
        return true;
      }
    }
    cluster = read_fat(handle, cluster);
  }
  return false;
}

int fat32_open_file(const int handle, char *filename, DIR * entry) {
  uint32_t cluster = fat32_bs.BPB_RootClus;
  atfstatic char namebuffer[FAT32_MAX_LONG_NAME_LENGTH];
  strlcpy(namebuffer, filename, FAT32_MAX_LONG_NAME_LENGTH);
  char *name = namebuffer;
  char *token;
  while ((token = strtok_r(name, "/", &name))) {
    bool success = find_entry(handle, cluster, token, entry);
    if (!success) break;
    cluster = first_cluster_direntry(entry);
    if (name != NULL) { if (name[0] == '\0') name = NULL; } // linux compatible
    if (name == NULL) {
      if (is_file_direntry(entry)) return 0;
      else break;
    }
    if (is_file_direntry(entry)) break; // continue if directory found
  }
  zeromem(entry, sizeof(DIR));
  return -1;
}

size_t fat32_file_size(const DIR * entry) {
  return entry->S.DIR_FileSize;
}

size_t fat32_read_file(const int handle, const DIR * entry, char *buffer,
                       size_t size) {
  size_t len;
  size_t count = 0;
  size_t filesize = fat32_file_size(entry);
  uint32_t cluster = first_cluster_direntry(entry);
  while (cluster < BAD_CLUSTER) {
    size_t min = min3(size, filesize,
                      fat32_bs.BPB_BytesPerSec*fat32_bs.BPB_SecPerClus);
    if (io_seek(handle, IO_SEEK_SET, first_bytes(cluster)) < 0) break;
    io_read(handle, (uintptr_t)buffer, min, &len);
    buffer += len; count += len; size -= len; filesize -= len;
    if (len != min) break;
    if ((size == 0) || (filesize == 0)) break; // sizes should never become < 0
    cluster = read_fat(handle, cluster);
  }
  VERBOSE("fat32_read_file: size read = %ld\n", count);
  return count;
}

int fat32_init(const int handle) {
  size_t len;
  if (fat32_bs.BS_Sig != 0xAA55) {
    if (io_seek(handle, IO_SEEK_SET, 0) < 0) return -1;
    io_read(handle, (uintptr_t)&fat32_bs, sizeof(BPB), &len);
    if (len != sizeof(BPB)) return -1;
    VERBOSE("fat32_init: Name: %s\n", fat32_bs.BS_OEMName);
    VERBOSE("fat32_init: Bytes per Sector: %d\n", fat32_bs.BPB_BytesPerSec);
    VERBOSE("fat32_init: Sectors per Cluster: %d\n", fat32_bs.BPB_SecPerClus);
    VERBOSE("fat32_init: Number of FATs = %d\n", fat32_bs.BPB_NumFATs);
    VERBOSE("fat32_init: Number of Clusters: %ld\n",
             fat32_bs.BPB_FATSz32*fat32_bs.BPB_BytesPerSec/sizeof(uint32_t));
  }
  if (fat32_bs.BS_Sig != 0xAA55) {
    ERROR("FAT32: readBS: Boot Sector Signature Mismatch 0x%x != 0xAA55)\n",
             fat32_bs.BS_Sig);
    return -1;
  }
#ifdef BUILD4ATF
  zeromem(fat32_buffer, fat32_bs.BPB_FATSz32 * fat32_bs.BPB_BytesPerSec);
#else // BUILD4LINUX
  if (fat32_buffer == NULL) {
    fat32_buffer = (uint32_t*)calloc(fat32_bs.BPB_FATSz32 ,
                                     fat32_bs.BPB_BytesPerSec);
  }
#endif
  return 0;
}

void fat32_free() {
  zeromem(&fat32_bs, sizeof(BPB));
#ifdef BUILD4ATF
#else // BUILD4LINUX
  if (fat32_buffer) {
    free(fat32_buffer);
    fat32_buffer = NULL;
  }
#endif
}

#ifdef BUILD4ATF
// fat32_list_entries() uses too much stack for ATF
#else // BUILD4LINUX
// Start list with cluster 0 and name ""
void fat32_list_entries(const int handle, uint32_t cluster, char *name) {
  DIR entry_array[FAT32_MAX_SECTOR_SIZE/sizeof(DIR)];
  char lname[FAT32_MAX_LONG_NAME_LENGTH] = {0};
  uint8_t csum = 0;
  if (cluster == 0) cluster = fat32_bs.BPB_RootClus;
  while (cluster < BAD_CLUSTER) {
    if (io_seek(handle, IO_SEEK_SET, first_bytes(cluster)) < 0) return;
    for (int i = 0; i < fat32_bs.BPB_SecPerClus; i++) {
      size_t len;
      io_read(handle, (uintptr_t)entry_array, fat32_bs.BPB_BytesPerSec, &len);
      if (len != fat32_bs.BPB_BytesPerSec) return;
      for (int j = 0; j < fat32_bs.BPB_BytesPerSec/sizeof(DIR); j++) {
        if (is_last_direntry(&entry_array[j])) return;
        if (!handle_entry(&entry_array[j], lname, &csum)) continue;
        if (is_file_direntry(&entry_array[j])) {
          VERBOSE("FAT32: find_entry: %s/%s\n", name, lname);
          continue;
        } // is Directory, go recursive
        char path[FAT32_MAX_LONG_NAME_LENGTH+2];
        snprintf(path, sizeof(path), "%s/%s", name, lname);
        fat32_list_entries(handle, first_cluster_direntry(&entry_array[j]),
                           path);
      }
    }
    cluster = read_fat(handle, cluster);
  }
}
#endif
