
/*
 * Fat32extractor, extract a file from fat32 image. Can use long filenames.
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

#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <lib/fat32.h>

static void write_buffer(const char * name, const char *buf, const size_t size) {
  FILE *pFile;
  pFile = fopen(name,"wb");
  if (pFile) {
    fwrite(buf, size, 1, pFile);
    fclose(pFile);
  }
  return;
}

int main(int argc, char** argv) {
  DIR entry;
  int out=0;
  if (argc <= 1) exit(0);
  dup2(STDOUT_FILENO, out);           // store stdout
  dup2(STDERR_FILENO, STDOUT_FILENO); // redirect printf to stderr
  int backend_handle = open(argv[1], O_RDWR);
  if (backend_handle == -1) exit(0);
  if (fat32_init(backend_handle)) exit(0);
  if (argc == 2) fat32_list_entries(backend_handle, 0, "");
  else if (fat32_open_file(backend_handle, argv[2], &entry) == 0) {
    char * filebuffer = malloc(32*1024*1024);
    int count = fat32_read_file(backend_handle, &entry, filebuffer, malloc_usable_size(filebuffer));
    if (argc > 3) write_buffer(argv[3], filebuffer, count);
    else write(out, filebuffer, count);
    free(filebuffer);
  }
  exit(0);
}

