#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include <leveldb/c.h>
#include <nvml.h>

#include "helpers.h"
#include "config.h"

struct pid_da {
  pid_t *items;
  size_t count;
  size_t capacity;
};

#define DA_INIT_CAP 16

#define da_append(da, item)                                                    \
  do {                                                                         \
    if ((da)->count >= (da)->capacity) {                                       \
      (da)->capacity = (da)->capacity == 0 ? DA_INIT_CAP : (da)->capacity * 2; \
      (da)->items = realloc((da)->items, (da)->capacity*sizeof(*(da)->items)); \
    }                                                                          \
    (da)->items[(da)->count++] = (item);                                       \
  } while (0)

#define da_remove(da, item)                   \
  do {                                        \
    size_t i;                                 \
    for (i = 0; i < (da)->count; i++) {       \
      if ((da)->items[i] == item) {           \
        size_t j;                             \
        for (j = i; j < (da)->count - 1; j++) \
          (da)->items[j] = (da)->items[j+1];  \
        (da)->count--;                        \
        break;                                \
      }                                       \
    }                                         \
  } while (0)

#define da_free(da) free((da).items)

int compare_pids(const void *p1, const void *p2) {
  return *(const pid_t *)p1 - *(const pid_t *)p2;
}

struct pid_da get_idle_pids(void) {
  nvmlReturn_t res;
  unsigned int devcnt, i, j;
  struct pid_da pids = { 0 };

  if ((res = nvmlDeviceGetCount_v2(&devcnt)) != NVML_SUCCESS) goto nvml_err;

  for (i = 0; i < devcnt; i++) {
    nvmlDevice_t dev;
    unsigned int cnt = 0;

    if ((res = nvmlDeviceGetHandleByIndex_v2(i, &dev)) != NVML_SUCCESS) goto nvml_err;

    res = nvmlDeviceGetComputeRunningProcesses_v3(dev, &cnt, NULL);
    if (res == NVML_SUCCESS) continue;
    else if (res == NVML_ERROR_INSUFFICIENT_SIZE) {
      nvmlProcessInfo_t *infos = calloc(cnt, sizeof(nvmlProcessInfo_t));

      if ((res = nvmlDeviceGetComputeRunningProcesses_v3(dev, &cnt, infos)) != NVML_SUCCESS) goto nvml_err;
      for (j = 0; j < cnt; j++) da_append(&pids, (pid_t)infos[j].pid);
      free(infos);
    } else goto nvml_err;
  }

  // separate loops in case one PID is on two GPUs
  for (i = 0; i < devcnt; i++) {
    nvmlDevice_t dev;
    unsigned int cnt = 0;

    if ((res = nvmlDeviceGetHandleByIndex_v2(i, &dev)) != NVML_SUCCESS) goto nvml_err;

    res = nvmlDeviceGetProcessUtilization(dev, NULL, &cnt, 0);
    if (res == NVML_SUCCESS) continue;
    else if (res == NVML_ERROR_INSUFFICIENT_SIZE) {
      nvmlProcessUtilizationSample_t *utils = calloc(cnt, sizeof(nvmlProcessUtilizationSample_t));

      if ((res = nvmlDeviceGetProcessUtilization(dev, utils, &cnt, 0)) != NVML_SUCCESS) {
        if (res == NVML_ERROR_NOT_FOUND) continue;
        else goto nvml_err;
      }

      for (j = 0; j < cnt; j++) da_remove(&pids, (pid_t)utils[j].pid);
      free(utils);
    } else goto nvml_err;
  }

  qsort(pids.items, pids.count, sizeof(pid_t), compare_pids);

  return pids;

nvml_err:
  printf("NVML error: %s\n", nvmlErrorString(res));
  if ((res = nvmlShutdown()) != NVML_SUCCESS)
    printf("failed to shutdown NVML: %s\n", nvmlErrorString(res));
  exit(-1);
}

int update_and_kill(struct pid_da *pids) {
  leveldb_t *db;
  leveldb_options_t *opts;
  leveldb_iterator_t *iter;
  leveldb_readoptions_t *r_opts = leveldb_readoptions_create();
  leveldb_writeoptions_t *w_opts = leveldb_writeoptions_create();
  char *errstr = NULL;
  size_t i;

  opts = leveldb_options_create();
  leveldb_options_set_create_if_missing(opts, true);

  db = leveldb_open(opts, DB, &errstr);
  if (errstr != NULL) {
    puts(errstr);
    return -1;
  }

  for (i = 0; i < pids->count; i++) {
    char *val, key[8]; // log10(2 ** 22) = 6.6
    size_t vallen;

    snprintf(key, 8, "%d", pids->items[i]);

    val = leveldb_get(db, r_opts, key, strlen(key), &vallen, &errstr);
    if (errstr != NULL) goto leveldb_err;
    if (val == NULL) {
      leveldb_put(db, w_opts, key, strlen(key), "1", strlen("1"), &errstr);
      if (errstr != NULL) goto leveldb_err;
    }
    free(val);
  }

  iter = leveldb_create_iterator(db, r_opts);

  for (leveldb_iter_seek_to_first(iter); leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
    size_t keylen, vallen;
    char *key = to_cstr(leveldb_iter_key(iter, &keylen), keylen);
    char *val = to_cstr(leveldb_iter_value(iter, &vallen), keylen);
    pid_t pid = (pid_t)atoi(key);

    if (bsearch(&pid, pids->items, pids->count, sizeof(pid_t), compare_pids) != NULL) {
      uint8_t cnt = (uint8_t)atoi(val);
      if (cnt >= KILL_COUNT) {
        printf("killing %d\n", pid);
        kill(pid, SIGTERM);
        leveldb_delete(db, w_opts, key, keylen, &errstr);
        if (errstr != NULL) goto leveldb_err;
      } else {
        cnt++;
        char new_val[4];
        snprintf(new_val, sizeof(new_val), "%d", cnt);
        leveldb_put(db, w_opts, key, keylen, new_val, strlen(new_val), &errstr);
        if (errstr != NULL) goto leveldb_err;
      }
    } else {
      leveldb_delete(db, w_opts, key, keylen, &errstr);
      if (errstr != NULL) goto leveldb_err;
    }

    free(key);
    free(val);
  }

  leveldb_iter_destroy(iter);

  leveldb_close(db);
  leveldb_options_destroy(opts);
  leveldb_readoptions_destroy(r_opts);
  leveldb_writeoptions_destroy(w_opts);

  return 0;

leveldb_err:
  printf("leveldb error: %s\n", errstr);
  leveldb_close(db);
  leveldb_options_destroy(opts);
  leveldb_readoptions_destroy(r_opts);
  leveldb_writeoptions_destroy(w_opts);
  return -1;
}


int main(void) {
  nvmlReturn_t nvmlRC;
  struct pid_da pids;

  if ((nvmlRC = nvmlInit_v2()) != NVML_SUCCESS) {
    printf("failed to initialize NVML: %s\n", nvmlErrorString(nvmlRC));
    return -1;
  }

  pids = get_idle_pids();

  return update_and_kill(&pids);
}

