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
#include <math.h>
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
  // mean local estimator
  double                 n_ml_sglt;
  double                 n_ml_sglt_clusts;
  u32                    n_items;
  double                 remain_weight;
  double                 lesti_min;
  double                 lesti_mean;
  double                 lesti_max;
  u32                    lesti_min_id;
  u32                    lesti_max_id;

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

// queue_entry is defined in afl-fuzz.h
typedef struct queue_entry queue_entry_t;

typedef struct item2manager {
  u32           *id_list;
  covmanager_t  **covman_list;
  u32 n_items;
} item2manager_t;

typedef struct my_mutator {
  afl_state_t *afl;

  // blackbox estimator
  covmanager_t *covman_total;
  // reset estimator
  covmanager_t *covman_reset;
  u32           n_prev_seeds;
  // mean local estimator
  item2manager_t         *item2man;

  record_t *records;
  u32       records_len;
  u64       last_record_add_time;

  bool force_save;
  bool reset_after_tmin;
  u32  tmin;
  u64  last_record_write_time;

} my_mutator_t;

typedef struct ml_stat {
  double esti;
  double remain_weight;
  double lesti_min;
  double lesti_mean;
  double lesti_max;
  u32 lesti_min_id;
  u32 lesti_max_id;
} ml_stat_t;

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

u32 compute_record_memory(record_t *record) {
  u32 size = 0;
  size += sizeof(record_t);
  size += set_memory(record->covered);
  return size;
}

u32 compute_covmanager_memory(covmanager_t *covman) {
  u32 size = 0;
  size += sizeof(covmanager_t);      // The covmanager struct itself

  // The 'covered_prev' set
  size += set_memory(covman->covered_prev);

  // Each setofset_t node plus its SimpleSet
  setofset_t *cur = covman->sglt_clusts;
  while (cur) {
      size += sizeof(setofset_t);    // the list node itself
      size += set_memory(cur->set);  // the SimpleSet
      cur = cur->next;
  }

  // The 'singletons' set
  size += set_memory(covman->singletons);

  return size;
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

// iterate over the queue and find the queue_entry_t with the given id
queue_entry_t *get_queue_entry(afl_state_t *afl, u32 id) {
  queue_entry_t *q = afl->queue_buf[id];
  // assert q->id == id
  if (q->id != id) {
    FATAL("Error: queue_entry_t id does not match the given id");
  }
  return q;
}

covmanager_t *get_covmanager(item2manager_t *item2man, u32 id) {
  // check if item
  for (u32 i = 0; i < item2man->n_items; ++i) {
    if (item2man->id_list[i] == id) {
      return item2man->covman_list[i];
    }
  }
  return NULL;
}

void add_item2manager(item2manager_t *item2man, u32 id) {
  item2man->id_list = (u32 *)realloc(item2man->id_list, (item2man->n_items + 1) * sizeof(u32));
  if (item2man->covman_list == NULL) {
    item2man->covman_list = (covmanager_t **)malloc(sizeof(covmanager_t *));
  } else {
    item2man->covman_list = (covmanager_t **)realloc(
      item2man->covman_list, (item2man->n_items + 1) * sizeof(covmanager_t *)
    );
  }
  item2man->id_list[item2man->n_items] = id;
  item2man->covman_list[item2man->n_items] = covmanager_init();
  item2man->n_items++;
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

  data->item2man = (item2manager_t *)malloc(sizeof(item2manager_t));
  data->item2man->n_items = 0;
  data->item2man->id_list = NULL;
  data->item2man->covman_list = NULL;
  
  data->records = NULL;
  data->records_len = 0;
  data->force_save = false;
  data->last_record_add_time = get_cur_time();
  data->reset_after_tmin = true;
  data->tmin = 0;
  data->last_record_write_time = get_cur_time();

  // check if the records file exists; if so, remove it
  char *filename = (char *) alloc_printf("%s/records.csv", afl->out_dir);
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
  data->n_prev_seeds = data->afl->queued_items;

  for (u32 i = 0; i < data->item2man->n_items; ++i) {
    destroy_covmanager(data->item2man->covman_list[i]);
  }
  data->item2man->n_items = 0;
  data->item2man->id_list = NULL;
  data->item2man->covman_list = NULL;

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
  covmanager_t *covman, const char *key, SimpleSet *new_sglt_clust
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
            // FATAL("Error: key %s is in singletons but not in sglt_clusts",
            //       key);
            printf("Warning: key %s is in singletons but not in sglt_clusts\n",
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

void compute_alias_weights(double *alias_probability, u32 *alias_table, u32 N, double *weight) {
  // check if alias_probability and alias_table are valid
  if (alias_probability == NULL || alias_table == NULL) {
    // return equal weights
    for (u32 i = 0; i < N; i++) {
      weight[i] = 1.0 / N;
    }
    return;
  }
  // sometimes alias_probability has weird values
  double *_alias_probability = (double *)malloc(N * sizeof(double));
  for (u32 i = 0; i < N; i++) {
    if (alias_probability[i] < 0.0 || alias_probability[i] > 1.0) {
      _alias_probability[i] = 0.0;
    } else {
      _alias_probability[i] = alias_probability[i];
    }
  }
  // sometimes alias_table has weird values
  u32 *_alias_table = (u32 *)malloc(N * sizeof(u32));
  for (u32 i = 0; i < N; i++) {
    if (alias_table[i] < 0 || alias_table[i] >= N) {
      _alias_table[i] = 0;
    } else {
      _alias_table[i] = alias_table[i];
    }
  }
  // Initialize weight array to 0
  for (u32 i = 0; i < N; i++) {
      weight[i] = 0.0;
  }
  // Compute the probability for each item
  for (u32 i = 0; i < N; i++) {
    // Direct probability contribution
    weight[i] += _alias_probability[i] / N;

    // Indirect probability contribution
    if (_alias_table[i] < N) { // Ensure _alias_table[i] is a valid index
      weight[_alias_table[i]] += (1.0 - _alias_probability[i]) / N;
    }
  }
  // Verify that the sum of weights is approximately 1
  double sum = 0.0;
  for (u32 i = 0; i < N; i++) {
    sum += weight[i];
  }
  // assert(fabs(sum - 1.0) < 1e-6);
  if (fabs(sum - 1.0) >= 0.2) {
    // for debugging purpose
    // print the _alias_probability
    for (u32 i = 0; i < N; i++) {
      printf("SMDEBUG::compute_alias_weights::_alias_probability[%d] = %f\n", i, _alias_probability[i]);
    }
    // print the _alias_table
    for (u32 i = 0; i < N; i++) {
      printf("SMDEBUG::compute_alias_weights::_alias_table[%d] = %d\n", i, _alias_table[i]);
    }
    // print the weights
    for (u32 i = 0; i < N; i++) {
      printf("SMDEBUG::compute_alias_weights::weight[%d] = %f\n", i, weight[i]);
    }
    // print the sum
    printf("SMDEBUG::compute_alias_weights::sum = %f\n", sum);
    FATAL("Error: sum of weights is not 1.0");
  }
}


double compute_local_estimator(covmanager_t *covman, bool is_cluster) {
  double estimate = 0.0;
  if (covman->n_execs == 0) { estimate = 1.0; }
  else if (covman->n_sglt_clusts == 0) {
    estimate = 1.0 / ((double)covman->n_execs + 2.0);
  } else {
    if (is_cluster)
      estimate = (double)covman->n_sglt_clusts / (double)covman->n_execs;
    else
      estimate = (double)set_length(covman->singletons) / (double)covman->n_execs;
  }
  return estimate;
}

ml_stat_t *compute_mean_local_estimator(my_mutator_t *data, double *weight, 
                                    bool is_cluster) {
  item2manager_t *item2man = data->item2man;
  double mean_local_estimator = 0;
  double lesti_max = 0.0, lesti_mean = 0.0, lesti_min = 1.0;
  u32 lesti_max_id = 0, lesti_min_id = 0;
  double remain_weight = 1.0;
  for (u32 i = 0; i < item2man->n_items; ++i) {
    u32 id = item2man->id_list[i];
    covmanager_t *covman = get_covmanager(item2man, id);
    double local_estimator = compute_local_estimator(covman, is_cluster);
    mean_local_estimator += weight[id] * local_estimator;
    
    // stats
    if (is_cluster) {
      if (local_estimator > lesti_max) {
        lesti_max = local_estimator;
        lesti_max_id = id;
      }
      if (local_estimator < lesti_min) {
        lesti_min = local_estimator;
        lesti_min_id = id;
      }
      lesti_mean += local_estimator;
    }
    remain_weight -= weight[id];
  }
  if (is_cluster)
    lesti_mean /= item2man->n_items;

  // for seeds that are not items, we assume the local estimator is 0.5
  // same as the case where there is no singletons.
  mean_local_estimator += remain_weight * 0.5;

  ml_stat_t *ml_stat = (ml_stat_t *)malloc(sizeof(ml_stat_t));
  ml_stat->esti = mean_local_estimator;
  if (is_cluster) {
    ml_stat->remain_weight = remain_weight;
    ml_stat->lesti_min = lesti_min;
    ml_stat->lesti_mean = lesti_mean;
    ml_stat->lesti_max = lesti_max;
    ml_stat->lesti_min_id = lesti_min_id;
    ml_stat->lesti_max_id = lesti_max_id;
  }

  return ml_stat;
}

void update_record(my_mutator_t *data, double *weight, bool is_end);

void afl_custom_post_run(my_mutator_t *data) {
  // time check for debugging
  u64 debug_time_start = get_cur_time();
  u64 debug_time_prev = get_cur_time();
  if (data->reset_after_tmin &&
      get_cur_time() - data->afl->start_time > data->tmin) {
    reset_entire_data(data);
    data->reset_after_tmin = false;
  }

  if (!data->afl->record_sampling) { return; }
  data->afl->record_sampling = false;
  data->covman_total->n_execs++;
  data->covman_reset->n_execs = data->covman_total->n_execs;

  u32  i;
  bool is_update = false;

  // check whether the number of seeds has changed
  if (data->n_prev_seeds != data->afl->queued_items) {
    data->n_prev_seeds = data->afl->queued_items;
    is_update = true;
    reset_covmanager(data->covman_reset);
  }

  // find the covemanager for the current item
  queue_entry_t *queue_cur = data->afl->queue_cur;
  // check if the mother is NULL, then mid = queue_cur->id
  // otherwise, mid = queue_cur->mother->id
  u32 mid = queue_cur->id;
  if (queue_cur->mother) {
    mid = queue_cur->mother->id;
  }
  covmanager_t *covman_curr = get_covmanager(data->item2man, mid);
  if (!covman_curr) {
    add_item2manager(data->item2man, mid);
    covman_curr = get_covmanager(data->item2man, mid);
  }
  covman_curr->n_execs++;

  SimpleSet *new_sglt_clust_total = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust_total);
  SimpleSet *new_sglt_clust_reset = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust_reset);
  SimpleSet *new_sglt_clust_curr = (SimpleSet *)malloc(sizeof(SimpleSet));
  set_init(new_sglt_clust_curr);

  // flag up the check_new for all records. this recording for the missing mass
  // analysis only done until the number of executions is doubled.
  record_t *cur = data->records;
  while (cur && cur->execs * 2 >= data->covman_total->n_execs) {
    cur->check_new = true;
    cur = cur->prev;
  }

  debug_time_prev = get_cur_time();
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
      is_update = update_covmanager(
        data->covman_total, key, new_sglt_clust_total) || is_update;
      is_update = update_covmanager(
        data->covman_reset, key, new_sglt_clust_reset) || is_update;
      is_update = update_covmanager(
        covman_curr, key, new_sglt_clust_curr) || is_update;
    }
  }
  // if there is new singleton cluster, add it to sglt_clusts
  update_singleton_clusters(data->covman_total, new_sglt_clust_total);
  update_singleton_clusters(data->covman_reset, new_sglt_clust_reset);
  update_singleton_clusters(covman_curr, new_sglt_clust_curr);
  u64 debug_time_BitIter = get_cur_time() - debug_time_prev;

  debug_time_prev = get_cur_time();
  
  // only add record if time_so_far > previous record time * 1.05
  u64 time_so_far = get_cur_time() - data->afl->start_time;
  bool add_new_record = (!data->records) || (time_so_far * 100 >= data->records->time_ms * 105);

  u32 N = data->afl->queued_items;
  double *weight = (double *)malloc(N * sizeof(double));
  compute_alias_weights(data->afl->alias_probability, data->afl->alias_table, N, weight);
  if (add_new_record || data->force_save) {
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

    new_record->n_ml_sglt = compute_mean_local_estimator(data, weight, false)->esti;
    // scale it to the number of executions to compare with others
    // (e.g., # singletons)
    new_record->n_ml_sglt *= new_record->execs;

    ml_stat_t *ml_stat = compute_mean_local_estimator(data, weight, true);
    new_record->n_ml_sglt_clusts = ml_stat->esti;
    // scale it to the number of executions to compare with others
    // (e.g., # singletons)
    new_record->n_ml_sglt_clusts *= new_record->execs;
    new_record->remain_weight = ml_stat->remain_weight;
    new_record->lesti_min = ml_stat->lesti_min;
    new_record->lesti_mean = ml_stat->lesti_mean;
    new_record->lesti_max = ml_stat->lesti_max;
    new_record->lesti_min_id = ml_stat->lesti_min_id;
    new_record->lesti_max_id = ml_stat->lesti_max_id;

    new_record->n_items = data->item2man->n_items;
    
    SimpleSet *covered_so_far = (SimpleSet *)malloc(sizeof(SimpleSet));
    set_init(covered_so_far);
    for (uint64_t i = 0; i < data->covman_total->covered_prev->number_nodes; ++i) {
      if (data->covman_total->covered_prev->nodes[i] != NULL) {
        set_add(covered_so_far, data->covman_total->covered_prev->nodes[i]->_key);
      }
    }
    new_record->covered = covered_so_far;
    
    new_record->n_found_new = 0;
    // new_record->is_update = add_new_record;
    new_record->prev = data->records;
    new_record->next = NULL;

    if (data->records) { data->records->next = new_record; }
    data->records = new_record;
    data->records_len++;
    data->last_record_add_time = get_cur_time();
  }
  u64 debug_time_AddRecord = get_cur_time() - debug_time_prev;

  // update the record every 1 seconds
  int threshold = 1000;
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
  debug_time_prev = get_cur_time();
  if (get_cur_time() - data->last_record_write_time > threshold) {
    update_record(data, weight, false);
  }
  u64 debug_time_WriteRecord = get_cur_time() - debug_time_prev;

  free(weight);
  u64 debug_time_total = get_cur_time() - debug_time_start;
  // u32 total_memory = 0;
  // total_memory += compute_covmanager_memory(data->covman_total);
  // total_memory += compute_covmanager_memory(data->covman_reset);
  // for (u32 i = 0; i < data->item2man->n_items; ++i) {
  //   total_memory += compute_covmanager_memory(data->item2man->covman_list[i]);
  // }
  // total_memory += compute_record_memory(data->records);
  // float mgb = (float)total_memory / 1024 / 1024 / 1024;
  // printf("SMDEBUG::afl_custom_post_run::BitIter = %llus, AddRecord = %llus, WriteRecord = %llus, Total = %llus, len_records = %u, total_memory = %fGB\n",
  //        debug_time_BitIter / 1000, debug_time_AddRecord / 1000, debug_time_WriteRecord / 1000, debug_time_total / 1000, data->records_len, mgb);
  return;
}

void update_record(my_mutator_t *data, double *weight, bool is_end) {
  // filename: afl->out_dir/records.csv
  char *filename = (char *) alloc_printf("%s/records.csv", data->afl->out_dir);
  FILE *f;
  // check if the file exists
  if (access(filename, F_OK) == 0) {
    // if the file exists, open it and append the records
    f = fopen(filename, "a");
  } else {
    // if the file does not exist, create it and write the header
    f = fopen(filename, "w");
    if (!f) {
      perror("fopen");
      return;
    }
    fprintf(f,
            "time, #execs, #seeds, #items, "
            "#covered, #singletons, #sglt_clusts, "
            "#coveredR, #singletonsR, #sglt_clustsR, "
            "ML_sglt, ML_sglt_clusts, "
            "remainW, lesti_mean, lesti_min, lesti_min_id, lesti_max, lesti_max_id, "
            "#foundnew, done\n");
  }
  record_t *cur = data->records;
  // find the first record
  while (cur && cur->prev) {
    cur = cur->prev;
  }
  while (cur) {
    // check if the record is done
    if (cur->execs * 2 >= data->covman_total->n_execs) {
      break;
    }
    fprintf(f, "%llu, %llu, %u, %u, "
            "%lu, %lu, %lu, "
            "%lu, %lu, %lu, "
            "%f, %f, "
            "%f, %f, %f, %u, %f, %u, "
            "%llu, %s\n", 
            cur->time_ms, cur->execs, cur->n_seeds, cur->n_items,
            cur->n_covered_total, cur->n_singletons_total, cur->n_sglt_clusts_total,
            cur->n_covered_reset, cur->n_singletons_reset, cur->n_sglt_clusts_reset,
            cur->n_ml_sglt, cur->n_ml_sglt_clusts,
            cur->remain_weight, cur->lesti_mean, cur->lesti_min, cur->lesti_min_id,
            cur->lesti_max, cur->lesti_max_id,
            cur->n_found_new, cur->execs * 2 < data->covman_total->n_execs ? "true" : "false");
            // cur->is_update ? "true" : "false");
    cur = cur->next;
    // remove the record
    if (cur) {
      free(cur->prev->covered);
      free(cur->prev);
    }
    cur->prev = NULL;
    data->records_len--;
  }
  fclose(f);

  // write not done records to a file if it is the end
  if (is_end) {
    char *filename_not_done = (char *) alloc_printf("%s/records_not_done.csv", data->afl->out_dir);
    FILE *f_not_done = fopen(filename_not_done, "w");
    if (!f_not_done) {
      perror("fopen");
      return;
    }
    fprintf(f_not_done,
            "time, #execs, #seeds, #items, "
            "#covered, #singletons, #sglt_clusts, "
            "#coveredR, #singletonsR, #sglt_clustsR, "
            "ML_sglt, ML_sglt_clusts, "
            "remainW, lesti_mean, lesti_min, lesti_min_id, lesti_max, lesti_max_id, "
            "#foundnew, done, update?\n");
    while (cur) {
      fprintf(f_not_done, "%llu, %llu, %u, %u, "
              "%lu, %lu, %lu, "
              "%lu, %lu, %lu, "
              "%f, %f, "
              "%f, %f, %f, %u, %f, %u, "
              "%llu, %s, %s\n", 
              cur->time_ms, cur->execs, cur->n_seeds, cur->n_items,
              cur->n_covered_total, cur->n_singletons_total, cur->n_sglt_clusts_total,
              cur->n_covered_reset, cur->n_singletons_reset, cur->n_sglt_clusts_reset,
              cur->n_ml_sglt, cur->n_ml_sglt_clusts,
              cur->remain_weight, cur->lesti_mean, cur->lesti_min, cur->lesti_min_id,
              cur->lesti_max, cur->lesti_max_id,
              cur->n_found_new, cur->execs * 2 < data->covman_total->n_execs ? "true" : "false",
              cur->is_update ? "true" : "false");
      cur = cur->next;
    }
    fclose(f_not_done);
  }

  ck_free(filename);

  // // record the covmanagers for each item under the directory local_records
  // char *dir = (char *) alloc_printf("%s/local_records", data->afl->out_dir);
  // if (access(dir, F_OK) != 0) {
  //   if (mkdir(dir, 0777) != 0) {
  //     perror("mkdir");
  //     return;
  //   }
  // }
  // // keep appending the records to the file
  // for (u32 i = 0; i < data->item2man->n_items; ++i) {
  //   u32 id = data->item2man->id_list[i];
  //   covmanager_t *covman = data->item2man->covman_list[i];
  //   // double weight = get_queue_entry(data->afl, id)->weight;
  //   char *filename = (char *) alloc_printf("%s/records_%06u.csv", dir, id);
  //   FILE *f;
  //   // check if the file exists
  //   if (access(filename, F_OK) == 0) {
  //     f = fopen(filename, "a");
  //   } else {
  //     f = fopen(filename, "w");
  //     fprintf(f, "time, #total_execs, weight, #execs, #covered, #singletons, #sglt_clusts\n");
  //   }
  //   if (!f) {
  //     // raise an error
  //     exit(1);
  //   }
  //   fprintf(f, "%llu, %u, %f, %u, %lu, %lu, %u\n",
  //           get_cur_time() - data->afl->start_time, data->covman_total->n_execs,
  //           weight[id], covman->n_execs,
  //           set_length(covman->covered_prev), set_length(covman->singletons),
  //           covman->n_sglt_clusts);
  //   fclose(f);
  //   ck_free(filename);
  // }

  data->last_record_write_time = get_cur_time();
}

// write the records to a file
void afl_custom_end_job(my_mutator_t *data) {
  // record the last status
  data->force_save = true;
  afl_custom_post_run(data);
  // update the record
  u32 N = data->afl->queued_items;
  double *weight = (double *)malloc(N * sizeof(double));
  compute_alias_weights(data->afl->alias_probability, data->afl->alias_table, N, weight);
  update_record(data, weight, true);
  free(weight);
  return;
}

void afl_custom_deinit(my_mutator_t *data) {
  afl_custom_end_job(data);
  record_t *cur = data->records;
  while (cur) {
    record_t *tmp = cur;
    cur = cur->next;
    set_destroy(tmp->covered);
    free(tmp);
  }
  destroy_covmanager(data->covman_total);
  fflush(stdout);
  destroy_covmanager(data->covman_reset);
  fflush(stdout);
  for (u32 i = 0; i < data->item2man->n_items; ++i) {
    destroy_covmanager(data->item2man->covman_list[i]);
  }
  free(data->item2man->id_list);
  free(data->item2man->covman_list);
  free(data->item2man);
  free(data);
}