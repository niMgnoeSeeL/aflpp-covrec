//
// This is an example on how to use afl_custom_post_run
// It executes custom code each time after AFL++ executes the target
//
// cc -O3 -fPIC -shared -g -o custom_post_run.so -I../../include
// custom_post_run.c cd ../.. afl-cc -o test-instr test-instr.c
// AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/examples/custom_post_run.so \
//   afl-fuzz -i in -o out -- ./test-instr -f /tmp/foo
//

#include "afl-fuzz.h"
#include "common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "set.h"

typedef struct record {
  // stats
  long long unsigned int time_ms;
  long long unsigned int execs;
  u32                    n_seeds;
  // total
  long unsigned int      n_covered_total;
  long unsigned int      n_sglt_clusts_total;
  long unsigned int      n_singletons_total;
  // reset
  long unsigned int      n_covered_reset;
  long unsigned int      n_sglt_clusts_reset;
  long unsigned int      n_singletons_reset;

  // for ground truth computation
  SimpleSet             *covered;
  long long unsigned int n_found_new;
  bool                   check_new;

  // was it recorded because there was a change in the singleton set?
  bool is_update;

  struct record *prev;
  struct record *next;
} record_t;

typedef struct setofset {
  SimpleSet       *set;
  struct setofset *next;
} setofset_t;

typedef struct covmanager {
  u32         n_execs;
  SimpleSet  *covered_prev;
  setofset_t *sglt_clusts;
  u32         n_sglt_clusts;
  SimpleSet  *singletons;
} covmanager_t;

typedef struct my_mutator {
  afl_state_t *afl;

  covmanager_t *covman_total;
  covmanager_t *covman_reset;
  u32           n_prev_seeds;

  record_t *records;
  u32       records_len;
  u64       last_record_add_time;

  bool force_save;
  bool reset_after_tmin;
  u32  tmin;
  u64  last_record_write_time;

} my_mutator_t;

inline u64 get_cur_time(void) {
  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

covmanager_t *covmanager_init(void) {
  covmanager_t *covman = (covmanager_t *)malloc(sizeof(covmanager_t));
  covman->n_execs = 0;
  covman->covered_prev = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(covman->covered_prev);
  covman->sglt_clusts = NULL;
  covman->n_sglt_clusts = 0;
  covman->singletons = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(covman->singletons);
  return covman;
}

void reset_covmanager(covmanager_t *covman) {
  // Note. we do not reset n_execs
  set_clear(covman->covered_prev);
  setofset_t *cur = covman->sglt_clusts;
  while (cur) {
    set_destroy(cur->set);
    setofset_t *tmp = cur;
    cur = cur->next;
    free(tmp);
  }
  covman->sglt_clusts = NULL;
  covman->n_sglt_clusts = 0;
  set_clear(covman->singletons);
}

void destroy_covmanager(covmanager_t *covman) {
  set_destroy(covman->covered_prev);
  setofset_t *cur = covman->sglt_clusts;
  while (cur) {
    set_destroy(cur->set);
    setofset_t *tmp = cur;
    cur = cur->next;
    free(tmp);
  }
  set_destroy(covman->singletons);
  free(covman);
}

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  data->afl = afl;

  data->covman_total = covmanager_init();
  data->covman_reset = covmanager_init();
  data->n_prev_seeds = afl->queued_items;
  
  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->reset_after_tmin = true;
  data->tmin = 0;
  data->last_record_write_time = get_cur_time();

  // check if the records file exists; if so, remove it
  char *filename = alloc_printf("%s/records.csv", afl->out_dir);
  if (access(filename, F_OK) == 0) {
    if (remove(filename) == 0) {
      printf("Removed the existing records file\n");
    } else {
      perror("Error removing the existing records file");
    }
  }

  return data;
}

void reset_entire_data(my_mutator_t *data) {
  destroy_covmanager(data->covman_total);
  destroy_covmanager(data->covman_reset);
  data->covman_total = covmanager_init();
  data->covman_reset = covmanager_init();

  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->last_record_write_time = get_cur_time();
}

const char *idx_to_str(u32 idx) {
  static char buf[32];
  snprintf(buf, sizeof(buf), "%u", idx);
  return buf;
}

bool update_covmanager(
  covmanager_t *covman, char *key, SimpleSet *new_sglt_clust
) {
  bool add_new_record = false;
  if (set_contains(covman->covered_prev, key) == SET_FALSE) {
    add_new_record = true;
    set_add(covman->covered_prev, key);
    set_add(covman->singletons, key);
    set_add(new_sglt_clust, key);
  } else {
    // if the key was in singletons, remove it from singletons and
    // sglt_clusts
    if (set_contains(covman->singletons, key) == SET_TRUE) {
      add_new_record = true;
      set_remove(covman->singletons, key);
      // iterate over the sglt_clusts and remove the key from the sets
      setofset_t *cur = covman->sglt_clusts;
      while (cur) {
        if (set_contains(cur->set, key) == SET_TRUE) {
          set_remove(cur->set, key);
          if (set_length(cur->set) == 0) {
            setofset_t *tmp = cur;
            cur = cur->next;
            if (tmp == covman->sglt_clusts) {
              covman->sglt_clusts = cur;
            } else {
              setofset_t *prev = covman->sglt_clusts;
              while (prev->next != tmp) {
                prev = prev->next;
              }
              prev->next = cur;
            }
            set_destroy(tmp->set);
            free(tmp);
            covman->n_sglt_clusts--;
          }
          break;
        } else {
          cur = cur->next;
          // if cur is NULL, something is wrong
          if (!cur) {
            FATAL("Error: key %s is in singletons but not in sglt_clusts",
                  key);
          }
        }
      }
    }
  }
  return add_new_record;
}

void update_singleton_clusters(covmanager_t *covman, SimpleSet *new_sglt_clust) {
  // if there is new singleton cluster, add it to sglt_clusts
  if (set_length(new_sglt_clust) > 0) {
    setofset_t *new_sglt_clust_node = (setofset_t *)malloc(sizeof(setofset_t));
    new_sglt_clust_node->set = new_sglt_clust;
    new_sglt_clust_node->next = covman->sglt_clusts;
    covman->sglt_clusts = new_sglt_clust_node;
    covman->n_sglt_clusts++;
  } else {
    set_destroy(new_sglt_clust);
    free(new_sglt_clust);
  }
}

void afl_custom_post_run(my_mutator_t *data) {
  // printf("|C%d", data->afl->record_sampling);
  if (data->reset_after_tmin &&
      get_cur_time() - data->afl->start_time > data->tmin) {
    reset_entire_data(data);
    data->reset_after_tmin = false;
  }

  if (!data->afl->record_sampling) { return; }
  // printf("|R%d", data->afl->record_sampling);
  data->afl->record_sampling = false;
  data->covman_total->n_execs++;
  data->covman_reset->n_execs = data->covman_total->n_execs;

  u32  i;
  bool add_new_record = false;

  // check whether the number of seeds has changed
  if (data->n_prev_seeds != data->afl->queued_items) {
    data->n_prev_seeds = data->afl->queued_items;
    add_new_record = true;
    reset_covmanager(data->covman_reset);
  }

  SimpleSet *new_sglt_clust_total = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust_total);
  SimpleSet *new_sglt_clust_reset = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust_reset);

  // flag up the check_new for all records. this recording for the missing mass
  // analysis only done until the number of executions is doubled.
  record_t *cur = data->records;
  while (cur && cur->execs * 2 >= data->covman_total->n_execs) {
    cur->check_new = true;
    cur = cur->prev;
  }

  record_t *stop_record = cur;
  for (i = 0; i < data->afl->fsrv.map_size; i++) {
    // if the trace bit is nonzero, then this has been covered in this run
    if (data->afl->fsrv.trace_bits[i]) {
      const char *key = idx_to_str(i);
      // iterate over the records and update n_found_new
      record_t *cur = data->records;
      while (cur) {
        if (cur == stop_record) { break; }
        // if covered_curr has unseen keys in cur->covered, +1 to n_found_new
        if (cur->check_new && set_contains(cur->covered, key) == SET_FALSE) {
          cur->n_found_new++;
          cur->check_new = false;
        }
        cur = cur->prev;
      }

      // update covmanager:
      // if the key was not in covered_prev, add it as a new singleton
      // if the key was in singletons, remove it from singletons
      add_new_record = update_covmanager(
        data->covman_total, key, new_sglt_clust_total) || add_new_record;
      add_new_record = update_covmanager(
        data->covman_reset, key, new_sglt_clust_reset) || add_new_record;
    }
  }
  // if there is new singleton cluster, add it to sglt_clusts
  update_singleton_clusters(data->covman_total, new_sglt_clust_total);
  update_singleton_clusters(data->covman_reset, new_sglt_clust_reset);

  // if the singleton status has changed, add a new record
  // otherwise, if it has been 10 minutes since the last record or the
  // force_save is true, add a new record
  u64 time_so_far = get_cur_time() - data->afl->start_time;
  u64 threshold = 60000;
  if (time_so_far > 600000) {  // 10 minutes
    threshold = 600000;        // 10 minutes
  }
  if (time_so_far > 3600000) {  // 1 hour
    threshold = 3600000;         // 1 hour
  }
  if (time_so_far > 21600000) {  // 6 hours
    threshold = 10800000;        // 3 hours
  }
  if (time_so_far > 43200000) {  // 12 hours
    threshold = 21600000;        // 6 hours
  }
  if (add_new_record || data->force_save ||
      get_cur_time() - data->last_record_add_time > threshold) {
    record_t *new_record = (record_t *)malloc(sizeof(record_t));
    new_record->time_ms = get_cur_time() - data->afl->start_time;
    if (!data->reset_after_tmin) { new_record->time_ms -= data->tmin; }
    new_record->execs = data->covman_total->n_execs;
    new_record->n_seeds = data->afl->queued_items;
    
    new_record->n_covered_total = set_length(data->covman_total->covered_prev);
    new_record->n_sglt_clusts_total = data->covman_total->n_sglt_clusts;
    new_record->n_singletons_total = set_length(data->covman_total->singletons);
    
    new_record->n_covered_reset = set_length(data->covman_reset->covered_prev);
    new_record->n_sglt_clusts_reset = data->covman_reset->n_sglt_clusts;
    new_record->n_singletons_reset = set_length(data->covman_reset->singletons);
    
    SimpleSet *covered_so_far = (SimpleSet *)malloc(sizeof(SimpleSet));
    set_init(covered_so_far);
    for (uint64_t i = 0; i < data->covman_total->covered_prev->number_nodes; ++i) {
      if (data->covman_total->covered_prev->nodes[i] != NULL) {
        set_add(covered_so_far, data->covman_total->covered_prev->nodes[i]->_key);
      }
    }
    new_record->covered = covered_so_far;
    
    new_record->n_found_new = 0;
    new_record->is_update = add_new_record;
    new_record->prev = data->records;
    new_record->next = NULL;

    if (data->records) { data->records->next = new_record; }
    data->records = new_record;
    data->records_len++;
    data->last_record_add_time = get_cur_time();
  }

  // update the record every 1 seconds
  threshold = 1000;
  if (time_so_far > 60000) {  // 1 minute
    threshold = 10000;        // 10 seconds
  }
  if (time_so_far > 600000) {  // 10 minutes
    threshold = 60000;         // 1 minute
  }
  if (time_so_far > 3600000) {  // 1 hour
    threshold = 300000;         // 5 minutes
  }
  if (time_so_far > 21600000) {  // 6 hours
    threshold = 600000;         // 10 minutes
  }
  if (time_so_far > 43200000) {  // 12 hours
    threshold = 1800000;        // 30 minutes
  }
  if (get_cur_time() - data->last_record_write_time > threshold) {
    update_record(data); 
  }

  return;
}

void update_record(my_mutator_t *data) {
  // filename: afl->out_dir/records.csv
  char *filename = alloc_printf("%s/records.csv", data->afl->out_dir);
  FILE *f = fopen(filename, "w");
  if (!f) {
    perror("fopen");
    return;
  }
  fprintf(f,
          "time, #execs, #seeds, "
          "#covered, #singletons, #sglt_clusts, "
          "#coveredR, #singletonsR, #sglt_clustsR, "
          "#foundnew, done, update?\n");
  record_t *cur = data->records;
  // find the first record
  while (cur && cur->prev) {
    cur = cur->prev;
  }
  while (cur) {
    fprintf(f, "%llu, %llu, %u, "
            "%lu, %lu, %lu, "
            "%lu, %lu, %lu, "
            "%llu, %s, %s\n", 
            cur->time_ms, cur->execs, cur->n_seeds,
            cur->n_covered_total, cur->n_singletons_total, cur->n_sglt_clusts_total,
            cur->n_covered_reset, cur->n_singletons_reset, cur->n_sglt_clusts_reset,
            cur->n_found_new, cur->execs * 2 < data->covman_total->n_execs ? "true" : "false",
            cur->is_update ? "true" : "false");
    cur = cur->next;
  }
  fclose(f);
  data->last_record_write_time = get_cur_time();
  ck_free(filename);
}

// write the records to a file
void afl_custom_end_job(my_mutator_t *data) {
  // record the last status
  data->force_save = true;
  afl_custom_post_run(data);

  // update the record
  update_record(data);
  return;
}

void afl_custom_deinit(my_mutator_t *data) {
  record_t *cur = data->records;
  while (cur) {
    record_t *tmp = cur;
    cur = cur->next;
    set_destroy(tmp->covered);
    free(tmp);
  }
  destroy_covmanager(data->covman_total);
  destroy_covmanager(data->covman_reset);
  free(data->covman_total);
  free(data->covman_reset);

  free(data);
}