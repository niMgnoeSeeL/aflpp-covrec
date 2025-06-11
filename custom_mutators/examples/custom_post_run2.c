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
  long unsigned int      n_covered;
  long unsigned int      n_sglt_clusts;
  long unsigned int      n_singletons;

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

typedef struct my_mutator {
  afl_state_t *afl;

  u32         n_execs;
  SimpleSet  *covered_prev;
  setofset_t *sglt_clusts;
  u32         n_sglt_clusts;
  SimpleSet  *singletons;
  u64         last_record_add_time;

  record_t *records;
  u32       records_len;

  bool force_save;
  bool reset_after_tmin;
  u32  tmin;
  u64  last_record_write_time;

  // Neil's data
  bool initialize_after_start;  // true;
  u32  incidence_n_exec;        // e.g., 100;
  u32  curr_n_exec;             // e.g., 0;
  u32  map_size;  // to check whether the coverage vector size is consistent
  u32  map_size_byte;            // to assign the size of the coverage vector
  u32  max_memory_byte;          // e.g., 1,048,576=1mb;
  u8  *coverage_vector;          // cumulative coverage vector
  u8  *coverage_matrix;          // coverage vector record
  u32  coverage_matrix_byteidx;  // index for the coverage matrix
  u32  num_matrix;               // number of coverage matrix
} my_mutator_t;

inline u64 get_cur_time(void) {
  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  data->afl = afl;
  data->n_execs = 0;
  data->covered_prev = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(data->covered_prev);
  data->sglt_clusts = NULL;
  data->n_sglt_clusts = 0;
  data->singletons = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(data->singletons);
  // data->trace_bits_prev = ck_alloc(afl->fsrv.map_size);
  // memset(data->trace_bits_prev, 0, afl->fsrv.map_size);
  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->reset_after_tmin = true;
  data->tmin = 0;
  data->last_record_write_time = get_cur_time();

  // check if the records file exists; if so, remove it
  char *filename = (char *)alloc_printf("%s/records.csv", afl->out_dir);
  if (access(filename, F_OK) == 0) {
    if (remove(filename) == 0) {
      printf("Removed the existing records file\n");
    } else {
      perror("Error removing the existing records file");
    }
  }

  // Neil's data
  data->initialize_after_start = true;
  return data;
}

void reset_data(my_mutator_t *data) {
  data->n_execs = 0;
  set_clear(data->covered_prev);
  setofset_t *cur = data->sglt_clusts;
  while (cur) {
    set_destroy(cur->set);
    setofset_t *tmp = cur;
    cur = cur->next;
    free(tmp);
  }
  data->sglt_clusts = NULL;
  data->n_sglt_clusts = 0;
  set_clear(data->singletons);
  record_t *cur_record = data->records;
  while (cur_record) {
    set_destroy(cur_record->covered);
    record_t *tmp = cur_record;
    cur_record = cur_record->next;
    free(tmp);
  }
  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->last_record_write_time = get_cur_time();

  // Neil's data
  data->curr_n_exec = 0;
  memset(data->coverage_vector, 0, data->map_size_byte);
  memset(data->coverage_matrix, 0, data->max_memory_byte);
  data->coverage_matrix_byteidx = 0;
  data->num_matrix = 0;
}

const char *idx_to_str(u32 idx) {
  static char buf[32];
  snprintf(buf, sizeof(buf), "%u", idx);
  return buf;
}

void afl_custom_post_run(my_mutator_t *data) {
  if (data->initialize_after_start) {
    data->incidence_n_exec = 10;
    data->curr_n_exec = 0;
    data->map_size = data->afl->fsrv.map_size;
    data->map_size_byte = (data->map_size + 7) / 8;
    data->max_memory_byte = 1048576;  // 1kb
    data->coverage_vector = (u8 *)malloc(data->map_size_byte);
    data->coverage_matrix = (u8 *)malloc(data->max_memory_byte);
    data->coverage_matrix_byteidx = 0;
    data->num_matrix = 0;
    data->initialize_after_start = false;
  }
  if (data->reset_after_tmin &&
      get_cur_time() - data->afl->start_time > data->tmin) {
    reset_data(data);
    data->reset_after_tmin = false;
  }

  if (!data->afl->record_sampling) { return; }
  data->afl->record_sampling = false;
  data->n_execs++;

  u32  i;
  bool add_new_record = false;

  SimpleSet *new_sglt_clust = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust);

  // flag up the check_new for all records. this recording for the missing mass
  // analysis only done until the number of executions is doubled.
  record_t *cur = data->records;
  while (cur && cur->execs * 2 >= data->n_execs) {
    cur->check_new = true;
    cur = cur->prev;
  }

  record_t *stop_record = cur;
  for (i = 0; i < data->afl->fsrv.map_size; i++) {
    // if the trace bit is nonzero, then this has been covered in this run
    if (data->afl->fsrv.trace_bits[i]) {
      // Neil's data:: update the coverage vector
      int byte_idx = i / 8;
      int bit_offset = i % 8;
      data->coverage_vector[byte_idx] |= (1 << bit_offset);

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
      // if the key is not in covered_prev, add it to singletons and sglt_clusts
      if (set_contains(data->covered_prev, key) == SET_FALSE) {
        add_new_record = true;
        set_add(data->covered_prev, key);
        set_add(data->singletons, key);
        set_add(new_sglt_clust, key);
      } else {
        // if the key was in singletons, remove it from singletons and
        // sglt_clusts
        if (set_contains(data->singletons, key) == SET_TRUE) {
          add_new_record = true;
          set_remove(data->singletons, key);
          // iterate over the sglt_clusts and remove the key from the sets
          setofset_t *cur = data->sglt_clusts;
          while (cur) {
            if (set_contains(cur->set, key) == SET_TRUE) {
              set_remove(cur->set, key);
              if (set_length(cur->set) == 0) {
                setofset_t *tmp = cur;
                cur = cur->next;
                if (tmp == data->sglt_clusts) {
                  data->sglt_clusts = cur;
                } else {
                  setofset_t *prev = data->sglt_clusts;
                  while (prev->next != tmp) {
                    prev = prev->next;
                  }
                  prev->next = cur;
                }
                set_destroy(tmp->set);
                free(tmp);
                data->n_sglt_clusts--;
              }
              break;
            } else {
              cur = cur->next;
              // if cur is NULL, something is wrong
              if (!cur) {
                // FATAL("Error: key %s is in singletons but not in sglt_clusts",
                //       key);
                printf("Warning: key %s is in singletons but not in "
                  "sglt_clusts\n",
                  key);
              }
            }
          }
        }
      }
    }
  }

  // Neil's data:: increase the current number of executions
  //               if it reaches the incidence number, store the coverage vector
  //               to the coverage matrix and reset the coverage vector
  //               if the coverage matrix capacity is reached, write the matrix
  //               to a file
  data->curr_n_exec++;
  if (data->curr_n_exec >= data->incidence_n_exec) {
    printf("DEBUG:: Coverage matrix filled up %d% (%d/%d)\n",
           data->coverage_matrix_byteidx * 100 / data->max_memory_byte,
           data->coverage_matrix_byteidx, data->max_memory_byte);
    // check the map size consistency
    if (data->map_size != data->afl->fsrv.map_size) {
      FATAL(
          "Error: map size inconsistency; (map_size) %u != %u "
          "(afl->fsrv.map_size)",
          data->map_size, data->afl->fsrv.map_size);
    }
    for (i = 0; i < data->map_size_byte; i++) {
      data->coverage_matrix[data->coverage_matrix_byteidx + i] =
          data->coverage_vector[i];
    }
    data->coverage_matrix_byteidx += data->map_size_byte;
    data->curr_n_exec = 0;
    memset(data->coverage_vector, 0, data->map_size_byte);
    if (data->coverage_matrix_byteidx + data->map_size_byte >
        data->max_memory_byte) {
      if (!data->reset_after_tmin) {
        char *filename = alloc_printf("%s/covmat_%u_%u.bin", data->afl->out_dir,
                                      data->map_size, data->num_matrix);
        FILE *f = fopen(filename, "wb");
        if (!f) {
          perror("fopen");
          return;
        }
        fwrite(data->coverage_matrix, sizeof(u8), data->max_memory_byte, f);
        fclose(f);
        ck_free(filename);
      }
      data->coverage_matrix_byteidx = 0;
      data->num_matrix++;
      memset(data->coverage_matrix, 0, data->max_memory_byte);
    }
  }
  // if there is new singleton cluster, add it to sglt_clusts
  if (set_length(new_sglt_clust) > 0) {
    setofset_t *new_sglt_clust_node = (setofset_t *)malloc(sizeof(setofset_t));
    new_sglt_clust_node->set = new_sglt_clust;
    new_sglt_clust_node->next = data->sglt_clusts;
    data->sglt_clusts = new_sglt_clust_node;
    data->n_sglt_clusts++;
  } else {
    set_destroy(new_sglt_clust);
    free(new_sglt_clust);
  }
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
    new_record->execs = data->n_execs;
    new_record->n_covered = set_length(data->covered_prev);
    new_record->n_sglt_clusts = data->n_sglt_clusts;
    new_record->n_singletons = set_length(data->singletons);
    SimpleSet *covered_so_far = (SimpleSet *)malloc(sizeof(SimpleSet));
    set_init(covered_so_far);
    for (uint64_t i = 0; i < data->covered_prev->number_nodes; ++i) {
      if (data->covered_prev->nodes[i] != NULL) {
        set_add(covered_so_far, data->covered_prev->nodes[i]->_key);
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
          "time, #execs, #covered, #singletons, #sglt_clusts, #foundnew, done, "
          "update?\n");
  record_t *cur = data->records;
  // find the first record
  while (cur && cur->prev) {
    cur = cur->prev;
  }
  while (cur) {
    fprintf(f, "%llu, %llu, %lu, %lu, %lu, %llu, %s, %s\n", cur->time_ms,
            cur->execs, cur->n_covered, cur->n_singletons, cur->n_sglt_clusts,
            cur->n_found_new, cur->execs * 2 < data->n_execs ? "true" : "false",
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

  // For Neil's data
  if (data->coverage_matrix_byteidx > 0) {
    char *filename = alloc_printf("%s/covmat_%u_%u.bin", data->afl->out_dir,
                                  data->map_size, data->num_matrix);
    FILE *f = fopen(filename, "wb");
    if (!f) {
      perror("fopen");
      return;
    }
    fwrite(data->coverage_matrix, sizeof(u8), data->coverage_matrix_byteidx, f);
    fclose(f);
    ck_free(filename);
  }
  return;
}

void afl_custom_deinit(my_mutator_t *data) {
  afl_custom_end_job(data);
  set_destroy(data->covered_prev);
  set_destroy(data->singletons);
  // ck_free(data->trace_bits_prev);
  record_t *cur = data->records;
  while (cur) {
    record_t *tmp = cur;
    cur = cur->next;
    set_destroy(tmp->covered);
    free(tmp);
  }
  setofset_t *cur_set = data->sglt_clusts;
  while (cur_set) {
    set_destroy(cur_set->set);
    setofset_t *tmp = cur_set;
    cur_set = cur_set->next;
    free(tmp);
  }

  free(data);
}