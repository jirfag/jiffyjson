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
#include <sys/time.h>

#include "jiffyjson.h"
#include "region_allocator.h"

#include "ujson4c/src/ujdecode.h"
#include "google_benchmark/include/benchmark/benchmark_api.h"


size_t size;
const char *data;


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

static void test_ujson4c(benchmark::State& state) {
    while (state.KeepRunning()) {
        void *state;
        UJObject obj = UJDecode(data, size, NULL, &state);
        assert(obj);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * size);
}
BENCHMARK(test_ujson4c);

extern "C" {
    extern void *yajl_tree_parse (const char *input, char *error_buffer, size_t error_buffer_size);
}

static void test_yajl(benchmark::State& state) {
    while (state.KeepRunning()) {
        char *data_copy = strndup(data, size);
        char errbuf[1024];
        void *node = yajl_tree_parse(data_copy, errbuf, sizeof(errbuf));
        (void)node;
        free(data_copy);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * size);
}
BENCHMARK(test_yajl);

static void test_jiffyjson(benchmark::State& state) {
    while (state.KeepRunning()) {
        struct jiffy_parser *parser = jiffy_parser_create();
        jiffy_parser_set_input(parser, data, size);
        struct jiffy_json_value *val = jiffy_parser_parse(parser);
        if (!val) {
            printf("%s\n", jiffy_parser_get_error(parser));
            abort();
        }
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * size);
}
BENCHMARK(test_jiffyjson);

extern "C" {
extern void test_rapidjson(const char *data, size_t data_size);
};

static void test_rapid_wr(benchmark::State& state) {
    while (state.KeepRunning()) {
        test_rapidjson(data, size);
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * size);
}
BENCHMARK(test_rapid_wr);

int main(int argc, char *argv[]) {
    data = read_file(&size, argv[1]);

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
