#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef NDEBUG

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include "jiffyjson.h"
#include "region_allocator.h"
#include "ujson4c/src/ujdecode.h"
#ifdef NEED_YAJL
#include <yajl/yajl_tree.h>
#endif

static size_t get_file_size(int fd) {
    struct stat st;
    int r = fstat(fd, &st);
    assert(r == 0);
    return st.st_size;
}

static const char *read_file(size_t *size, const char *fname) {
    FILE *f = fopen(fname, "r");
    assert(f);
    size_t file_size = get_file_size(fileno(f));
    assert(file_size);
    char *data = (char *)malloc(file_size);
    assert(data);
    int r = fread(data, 1, file_size, f);
    assert(r == (int)file_size);

    *size = file_size;
    return data;
}

static uint32_t get_timespec_diff_mcs(const struct timespec *b, const struct timespec *e) {
    return (e->tv_sec - b->tv_sec) * 1000000 + (e->tv_nsec - b->tv_nsec) / 1000;
}

#define TIMER_START() \
    struct timespec ts_start_; \
    clock_gettime(CLOCK_MONOTONIC, &ts_start_)

#define TIMER_STOP(size_, etalon_time_mcs_, name_) ({ \
    struct timespec ts_finish_; \
    clock_gettime(CLOCK_MONOTONIC, &ts_finish_); \
    uint32_t elapsed_mcs_ = get_timespec_diff_mcs(&ts_start_, &ts_finish_); \
    double speed_mb_sec_ = ((double)size_) / (double)elapsed_mcs_; \
    double etalon_mul_coef_ = etalon_time_mcs_ ? ((double)elapsed_mcs_ / etalon_time_mcs_) : 1; \
    printf("'%s' took %umcs, speed is %.1fMb/sec = %.1f * etalon\n", \
        name_, elapsed_mcs_, speed_mb_sec_, etalon_mul_coef_); \
    elapsed_mcs_; \
})

static uint32_t test_strdup(const char *data, size_t size) {
    TIMER_START();
        const char *s = strdup(data);
    uint32_t elapsed_mcs = TIMER_STOP(size, 0, "strdup");
    printf("just for antioptimization: s[0] = %c\n", s[0]);
    free((void *)s);
    return elapsed_mcs;
}

static void test_ujson4c(const char *data, size_t size) {
    void *state;
    UJObject obj = UJDecode(data, size, NULL, &state);
    assert(obj);
}

#ifdef NEED_YAJL
static void test_yajl(const char *data, size_t size) {
    char *data_copy = strndup(data, size);
    char errbuf[1024];
    yajl_val node = yajl_tree_parse(data_copy, errbuf, sizeof(errbuf));
    (void)node;
    free(data_copy);
}
#endif

static void test_jiffyjson(const char *data, size_t size) {
    struct jiffy_parser *parser = jiffy_parser_create();
    jiffy_parser_set_input(parser, data, size);
    struct jiffy_json_value *val = jiffy_parser_parse(parser);
    if (!val) {
        printf("%s\n", jiffy_parser_get_error(parser));
        abort();
    }
}

extern void test_rapidjson(const char *data, size_t data_size);

int main(int argc, char *argv[]) {
    size_t size;
    const char *data = read_file(&size, argv[1]);

    bool perf_mode = argc == 3;
    if (perf_mode) {
        for (int i = 0; i < atoi(argv[2]); ++i)
            test_jiffyjson(data, size);
        return 0;
    }

    uint32_t etalon_time_mcs = test_strdup(data, size);

    {
        TIMER_START();
            test_jiffyjson(data, size);
        TIMER_STOP(size, etalon_time_mcs, "jiffyjson");
    }

    {
        TIMER_START();
            test_rapidjson(data, size);
        TIMER_STOP(size, etalon_time_mcs, "rapidjson");
    }

    {
        TIMER_START();
            test_ujson4c(data, size);
        TIMER_STOP(size, etalon_time_mcs, "ujson4c");
    }

#ifdef NEED_YAJL
    {
        TIMER_START();
            test_yajl(data, size);
        TIMER_STOP(size, etalon_time_mcs, "yajl");
    }
#endif

    return 0;
}
