#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <leveldb/c.h>

#include "helpers.h"
#include "config.h"

int main(void) {
  leveldb_t *db;
  leveldb_options_t *opts = leveldb_options_create();
  leveldb_readoptions_t *r_opts = leveldb_readoptions_create();
  leveldb_iterator_t *iter;
  char *errstr = NULL;

  db = leveldb_open(opts, DB, &errstr);
  if (errstr != NULL) {
    puts(errstr);
    return -1;
  }

  iter = leveldb_create_iterator(db, r_opts);
  leveldb_iter_seek_to_first(iter);
  if (leveldb_iter_valid(iter)) printf("%7s %3s\n", "PID", "CNT");
  for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
    size_t klen, vlen;
    const char *key = to_cstr(leveldb_iter_key(iter, &klen), klen);
    const char *val = to_cstr(leveldb_iter_value(iter, &vlen), vlen);
    printf("%7s %3s\n", key, val);
  }

  return 0;
}
