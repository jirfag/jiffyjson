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

static void test_jiffyjson(const char *data, size_t size) {
    struct jiffy_parser *parser = jiffy_parser_create();
    jiffy_parser_set_input(parser, data, size);
    struct jiffy_json_value *val = jiffy_parser_parse(parser);
    if (!val) {
        printf("%s\n", jiffy_parser_get_error(parser));
        abort();
    }
}


int main(int argc, char *argv[]) {
    size_t size;
    const char *data = read_file(&size, argv[1]);

    const int n = 10000;
    for(int i=0; i<n; i++)
        test_jiffyjson(data, size);

    return 0;
}
