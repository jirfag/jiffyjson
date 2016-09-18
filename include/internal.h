#pragma once
#include <stdbool.h>

#include "jvector.h"
#include "immutable_jvector.h"
#include "jiffyjson.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PACKED __attribute__((packed))
struct json_string {
    char *data;
    uint32_t size;
} PACKED;

enum json_value_type {
    JVT_ARRAY,
    JVT_OBJECT,
    JVT_BOOL,
    JVT_NUMBER,
    JVT_STRING,
    JVT_NULL,
};

ijvector(json_value);
ijvector(json_kv);

struct jiffy_json_value {
    union {
        ijvector(json_value) *arr;
        ijvector(json_kv) *obj;
        bool bool_val;
        double num_val;
        struct json_string *string;
    };
    uint8_t value_type;
} PACKED;

struct json_kv {
    struct json_string k;
    struct jiffy_json_value v;
} PACKED;

ijvector_def(json_value, struct jiffy_json_value);
ijvector_def(json_kv, struct json_kv);

typedef enum
{
    JSON_OK = 1,
    JSON_ERROR = 0
} json_res_t;

jvector_def(json_value, struct jiffy_json_value);
jvector_def(json_kv, struct json_kv);

struct json_allocator {
    jiffy_json_alloc_func_t alloc;
    jiffy_json_destroy_func_t destroy;
    void *ctx;
};

struct jiffy_parser {
    const char *data;
    const char *next_backslash;
    uint32_t data_size;

    jvector(json_value) values_cache;
    jvector(json_kv) kv_cache;

    struct json_allocator small_allocator;
    struct json_allocator large_allocator;

    char error[256];
};

#ifdef UNITTEST
void jiffy_parser_init(struct jiffy_parser *parser);
json_res_t json_string_parse(struct json_string *str, struct jiffy_parser *ctx);
#endif

#ifdef __cplusplus
}
#endif

#ifdef UNITTEST
#define STATIC
#else
#define STATIC static
#endif

#define JIFFY_ASSERT(cond_) ({ \
    if (!(cond_)) { \
        __attribute__((unused)) \
        volatile const char *s_ = #cond_; \
        abort(); \
    } \
})
