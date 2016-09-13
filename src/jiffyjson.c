#include "jvector.h"
#include "immutable_jvector.h"
#include "jiffyjson.h"
#include "region_allocator.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PACKED __attribute__((packed))
#define FORCE_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))

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
    uint32_t data_size;
    const char *next_backslash;

    jvector(json_value) values_cache;
    jvector(json_kv) kv_cache;

    struct json_allocator small_allocator;
};

struct jiffy_parser *jiffy_parser_create() {
    return calloc(1, sizeof(struct jiffy_parser));
}

void jiffy_parser_set_input(struct jiffy_parser *parser, const char *data, uint32_t data_size) {
    parser->data = data;
    parser->data_size = data_size;
}

void jiffy_parser_set_small_allocator(struct jiffy_parser *parser,
        jiffy_json_alloc_func_t alloc, jiffy_json_destroy_func_t destroy, void *ctx) {
    parser->small_allocator.alloc = alloc;
    parser->small_allocator.destroy = destroy;
    parser->small_allocator.ctx = ctx;
}

static FORCE_INLINE void jiffy_parser_skip_one_byte(struct jiffy_parser *ctx) {
    assert(ctx->data_size);
    assert(ctx->data);
    ctx->data++;
    ctx->data_size--;
}

static FORCE_INLINE void jiffy_parser_skip_n_bytes(struct jiffy_parser *ctx, uint32_t n) {
    assert(ctx->data_size >= n);
    assert(ctx->data);
    ctx->data += n;
    ctx->data_size -= n;
}

#define EXPECT_CH(ch_, ctx_) ({ \
    bool is_error_ = (ctx_)->data_size == 0 || (ctx_)->data[0] != ch_; \
    if (__builtin_expect(is_error_, false) == true) { \
        printf("expected '%c', got '%c'\n", ch_, (ctx_)->data_size ? (ctx_)->data[0] : '\0'); \
        return JSON_ERROR; \
    } \
    jiffy_parser_skip_one_byte((ctx_)); \
})

#define ASSERT_CH(ch_, ctx_) ({ \
    assert((ctx_)->data_size != 0 && (ctx_)->data[0] == ch_); \
    jiffy_parser_skip_one_byte((ctx_)); \
})

#define EXPECT_ANY_CH(ctx_) ({ \
    if ((ctx_)->data_size == 0) \
        return JSON_ERROR; \
    jiffy_parser_skip_one_byte((ctx_)); \
})

#define EXPECT_END(ctx_) ({ \
    if ((ctx_)->data_size != 0 ) \
        return JSON_ERROR; \
})

#define EXPECT_NOT_END(ctx_) ({ \
    if ((ctx_)->data_size == 0 ) \
        return JSON_ERROR; \
})

static const bool is_char_wsp_table[1 << CHAR_BIT] = {
    [' '] = true,
    ['\t'] = true,
    ['\r'] = true,
    ['\n'] = true,
};

#if 0
static FORCE_INLINE const uint8_t *skip_wsp_simd(const struct jiffy_parser *ctx) {
    const uint8_t *data = ctx->data;
    const uint8_t* nextAligned = (const uint8_t *)(((size_t)(data) + 15) & (size_t)(~15));

    // 16-byte align to the next boundary
    while (data != nextAligned) {
        if (is_char_wsp_table[*data])
            ++data;
        else
            return data;
    }

    // The rest of string using SIMD
    static const char whitespace[16] = " \n\r\t";
    const __m128i w = _mm_loadu_si128((const __m128i *)(&whitespace[0]));

    for (;; data += 16) {
        const __m128i s = _mm_load_si128((const __m128i *)data);
        const int r = _mm_cvtsi128_si32(_mm_cmpistrm(w, s, _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_BIT_MASK | _SIDD_NEGATIVE_POLARITY));
        if (r != 0) {   // some of characters is non-whitespace
            return data + __builtin_ffs(r) - 1;
        }
    }
}

static void skip_wsp(struct jiffy_parser *ctx) {
    const uint8_t *data = skip_wsp_simd(ctx);
    uint32_t diff = data - (const uint8_t *)ctx->data;
    if (diff)
        jiffy_parser_skip_n_bytes(ctx, diff);
}
#endif

static void skip_wsp(struct jiffy_parser *ctx) {
    const uint8_t *data = (const uint8_t *)ctx->data;
    for (; is_char_wsp_table[*data]; ++data) {}

    uint32_t diff = data - (const uint8_t *)ctx->data;
    if (diff)
        jiffy_parser_skip_n_bytes(ctx, diff);
}

static void skip_wsp_expect_one_space(struct jiffy_parser *ctx) {
    if (__builtin_expect(*ctx->data, ' ')) {
        jiffy_parser_skip_one_byte(ctx);
        const char c = *ctx->data;
        bool is_non_wsp = c != ' ' && c != '\n' && c != '\t' && c != '\r';
        if (__builtin_expect(is_non_wsp, true))
            return;

        return skip_wsp(ctx);
    }

    return skip_wsp(ctx);
}

static void skip_wsp_expect_nl_and_spaces(struct jiffy_parser *ctx) {
    if (__builtin_expect(*ctx->data, '\n')) {
        jiffy_parser_skip_one_byte(ctx);

        const uint32_t spaces4 = *(uint32_t *)"    ";
        while (ctx->data_size > sizeof(uint32_t) && *(uint32_t *)ctx->data == spaces4)
            jiffy_parser_skip_n_bytes(ctx, sizeof(uint32_t));

        while (ctx->data[0] == ' ')
            jiffy_parser_skip_one_byte(ctx);

        const char c = *ctx->data;
        bool is_non_wsp = c != ' ' && c != '\n' && c != '\t' && c != '\r';
        if (__builtin_expect(is_non_wsp, true))
            return;

        return skip_wsp(ctx);
    }

    return skip_wsp(ctx);
}

static FORCE_INLINE bool is_current_char_eq(const struct jiffy_parser *ctx, char c) {
    return *ctx->data == c;
}

#define STRLN(s_) (sizeof(s_) - 1)

static void json_object_init(struct jiffy_json_value *val) {
    val->value_type = JVT_OBJECT;
    memset(&val->obj, 0, sizeof(val->obj));
}

static const char *get_next_backslash(struct jiffy_parser *ctx) {
    if (ctx->next_backslash >= ctx->data)
        return ctx->next_backslash;

    const char *next_backslash = memchr(ctx->data, '\\', ctx->data_size);
    if (!next_backslash) {
        ctx->next_backslash = ctx->data + ctx->data_size;
        return ctx->next_backslash;
    }

    ctx->next_backslash = next_backslash;
    return ctx->next_backslash;
}

static bool is_next_backslash_before(struct jiffy_parser *ctx, const char *ptr) {
    return get_next_backslash(ctx) < ptr;
}

static void json_string_append_norealloc(struct json_string *str, const char *data, uint32_t size) {
    memcpy(str->data + str->size, data, size);
    str->size += size;
}

static json_res_t json_string_append(struct json_string *str, const char *data, uint32_t size, uint32_t *capacity) {
    if (str->size + size > *capacity) {
        uint32_t new_capacity = *capacity + size + 8;
        str->data = realloc(str->data, new_capacity);
        if (!str->data)
            return JSON_ERROR;
        *capacity = new_capacity;
    }

    json_string_append_norealloc(str, data, size);
    return JSON_OK;
}

static json_res_t json_string_parse_with_unknown_len(struct json_string *str, struct jiffy_parser *ctx, uint32_t start_capacity) {
    static_assert(CHAR_BIT == 8, "unexpected char size");
    static const bool str_parse_table[1 << CHAR_BIT] = {
        ['"'] = true,
        ['\\'] = true,
    };

    uint32_t capacity = start_capacity;
    str->data = (char *)malloc(capacity);
    assert(str->data);
    str->size = 0;

    for (;;) {
        int i;
        const uint8_t *src_data = (const uint8_t *)ctx->data;
        uint32_t src_data_size = ctx->data_size;
        for (i = 0; i < src_data_size && !str_parse_table[src_data[i]]; ++i) {}

        if (i != 0) {
            if (json_string_append(str, (const char *)src_data, i, &capacity) != JSON_OK)
                return JSON_ERROR;

            jiffy_parser_skip_n_bytes(ctx, i);
        }

        if (ctx->data[0] == '"') {
            jiffy_parser_skip_one_byte(ctx);
            return JSON_OK;
        }

        if (ctx->data[0] == '\\') {
            if (json_string_append(str, ctx->data + 1, 1, &capacity) != JSON_OK)
                return JSON_ERROR;

            jiffy_parser_skip_n_bytes(ctx, 2);
            continue;
        }

        abort();
    }
}

static json_res_t json_string_parse_with_known_len(struct json_string *str, struct jiffy_parser *ctx, uint32_t len) {
    str->data = (char *)malloc(len);
    assert(str->data);
    str->size = 0;
    const char *str_end = ctx->data + len;

    for (;;) {
        const char *backslash = get_next_backslash(ctx);
        if (backslash > str_end) { // copy until string end
            uint32_t bytes_to_copy = str_end - ctx->data;
            assert(bytes_to_copy);
            json_string_append_norealloc(str, ctx->data, bytes_to_copy);
            jiffy_parser_skip_n_bytes(ctx, bytes_to_copy);
            ASSERT_CH('"', ctx);
            return JSON_OK;
        }

        uint32_t bytes_to_copy = backslash - ctx->data;
        if (bytes_to_copy) {
            json_string_append_norealloc(str, ctx->data, bytes_to_copy);
            jiffy_parser_skip_n_bytes(ctx, bytes_to_copy);
        }

        ASSERT_CH('\\', ctx);
        jiffy_parser_skip_one_byte(ctx); // just skip next byte, TODO
    }
}

static HOT json_res_t json_string_parse(struct json_string *str, struct jiffy_parser *ctx) {
    EXPECT_CH('"', ctx);

    const char *closing_quote_pos = memchr(ctx->data, '"', ctx->data_size);
    if (!closing_quote_pos)
        return JSON_ERROR;

    uint32_t size = closing_quote_pos - ctx->data;
    if (closing_quote_pos[-1] == '\\')
        return json_string_parse_with_unknown_len(str, ctx, size);

    if (is_next_backslash_before(ctx, closing_quote_pos))
        return json_string_parse_with_known_len(str, ctx, size);

    if (size == 0) { // optimized apth for empty string
        str->data = NULL;
        str->size = 0;
        ASSERT_CH('"', ctx);
        return JSON_OK;
    }

    str->data = (char *)ctx->data;
    str->size = size;
    // TODO: make flag that we don't own string

    jiffy_parser_skip_n_bytes(ctx, size);
    ASSERT_CH('"', ctx);
    return JSON_OK;
}

static json_res_t json_value_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx);

static json_res_t json_parse_kv(struct json_kv *kv, struct jiffy_parser *ctx) {
    json_res_t r = json_string_parse(&kv->k, ctx);
    if (r != JSON_OK)
        return r;

    if (is_current_char_eq(ctx, ':')) {
        jiffy_parser_skip_one_byte(ctx);
        skip_wsp_expect_one_space(ctx);
        return json_value_parse(&kv->v, ctx);
    }

    skip_wsp(ctx);
    EXPECT_CH(':', ctx);
    skip_wsp(ctx);
    return json_value_parse(&kv->v, ctx);
}

static FORCE_INLINE void *small_object_alloc(struct jiffy_parser *ctx, uint32_t size) {
    return ctx->small_allocator.alloc(ctx->small_allocator.ctx, size);
}

static ijvector(json_value) *flush_values_cache(struct jiffy_parser *ctx) {
    uint32_t elems_n = jvector_size(&ctx->values_cache);
    struct jiffy_json_value *elems = (struct jiffy_json_value *)jvector_data(&ctx->values_cache);
    ijvector(json_value) *ret = ijvector_init(json_value, elems, elems_n);
    jvector_reset(&ctx->values_cache);
    return ret;
}

static void flush_kv_cache(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    uint32_t elems_n = jvector_size(&ctx->kv_cache);
    struct json_kv *elems = (struct json_kv *)jvector_data(&ctx->kv_cache);
    val->obj = ijvector_init(json_kv, elems, elems_n);
    jvector_reset(&ctx->kv_cache);
}

static json_res_t json_array_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    ASSERT_CH('[', ctx);
    if (ctx->data[0] == ']') { // fast path for empty array
        jiffy_parser_skip_one_byte(ctx);
        return JSON_OK;
    }
    skip_wsp_expect_nl_and_spaces(ctx);

    for (;;) {
        struct jiffy_json_value *val = jvector_push_back(&ctx->values_cache);
        json_res_t r = json_value_parse(val, ctx);
        if (r != JSON_OK)
            return r;


        if (is_current_char_eq(ctx, ',')) {
            jiffy_parser_skip_one_byte(ctx);
            skip_wsp_expect_nl_and_spaces(ctx);
            continue;
        }

        skip_wsp(ctx);
        EXPECT_NOT_END(ctx);
        if (ctx->data[0] == ']') {
            val->value_type = JVT_ARRAY;
            val->arr = flush_values_cache(ctx);
            jiffy_parser_skip_one_byte(ctx);
            return JSON_OK;
        }
        EXPECT_CH(',', ctx);
        skip_wsp(ctx);
    }
}

static json_res_t json_number_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    val->value_type = JVT_NUMBER;

    char buf[64];
    uint32_t buf_len = 0;
    bool ended = false;
    while (ctx->data_size && buf_len < sizeof(buf)) {
        if (!(isdigit(ctx->data[0]) || ctx->data[0] == 'e' || ctx->data[0] == 'E' || ctx->data[0] == '-' || ctx->data[0] == '.')) {
            ended = true;
            break;
        }
        buf[buf_len++] = ctx->data[0];
        jiffy_parser_skip_one_byte(ctx);
    }
    if (!ended)
        return JSON_ERROR;

    assert(buf_len);
    buf[buf_len] = '\0';
    val->num_val = atof(buf);
    return JSON_OK;
}

static json_res_t json_bool_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    val->value_type = JVT_BOOL;
    if (ctx->data_size >= STRLN("true") && *(uint32_t *)(ctx->data) == *(uint32_t *)"true") {
        jiffy_parser_skip_n_bytes(ctx, STRLN("true"));
        val->bool_val = true;
        return JSON_OK;
    }

    if (ctx->data_size >= STRLN("false") && *(uint32_t *)(ctx->data) == *(uint32_t *)"fals" && ctx->data[4] == 'e') {
        jiffy_parser_skip_n_bytes(ctx, STRLN("false"));
        val->bool_val = false;
        return JSON_OK;
    }

    // TODO: case-insensitive
    return JSON_ERROR;
}

static json_res_t json_null_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    if (ctx->data_size >= STRLN("null") && *(uint32_t *)(ctx->data) == *(uint32_t *)"null") {
        jiffy_parser_skip_n_bytes(ctx, STRLN("null"));
        val->value_type = JVT_NULL;
        return JSON_OK;
    }

    // TODO: case-insensitive
    return JSON_ERROR;
}

static json_res_t json_object_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx);

static json_res_t json_string_parse_value(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    val->value_type = JVT_STRING;
    val->string = small_object_alloc(ctx, sizeof(*val->string));
    return json_string_parse(val->string, ctx);
}

static json_res_t json_value_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    EXPECT_NOT_END(ctx);

    typedef json_res_t (*json_value_parser_t)(struct jiffy_json_value *val, struct jiffy_parser *ctx);

    static const json_value_parser_t handlers[1 << CHAR_BIT] = {
        ['"'] = json_string_parse_value,
        ['{'] = json_object_parse,
        ['['] = json_array_parse,
        ['f'] = json_bool_parse,
        ['F'] = json_bool_parse,
        ['t'] = json_bool_parse,
        ['T'] = json_bool_parse,
        ['n'] = json_null_parse,
        ['N'] = json_null_parse,
        ['0'] = json_number_parse,
        ['1'] = json_number_parse,
        ['2'] = json_number_parse,
        ['3'] = json_number_parse,
        ['4'] = json_number_parse,
        ['5'] = json_number_parse,
        ['6'] = json_number_parse,
        ['7'] = json_number_parse,
        ['8'] = json_number_parse,
        ['9'] = json_number_parse,
        ['-'] = json_number_parse,
    };

    json_value_parser_t parser = handlers[(uint8_t)ctx->data[0]];
    if (!parser)
        return JSON_ERROR;

    return parser(val, ctx);
}

static json_res_t json_object_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    json_object_init(val);
    EXPECT_CH('{', ctx);
    skip_wsp_expect_nl_and_spaces(ctx);

    for (;;) {
        struct json_kv *kv = jvector_push_back(&ctx->kv_cache);
        json_res_t r = json_parse_kv(kv, ctx);
        if (r != JSON_OK)
            return r;

        if (is_current_char_eq(ctx, ',')) {
            jiffy_parser_skip_one_byte(ctx);
            skip_wsp_expect_nl_and_spaces(ctx);
            continue;
        }

        if (ctx->data[0] == '}') {
            flush_kv_cache(val, ctx);
            jiffy_parser_skip_one_byte(ctx);
            return JSON_OK;
        }
        skip_wsp(ctx);
        if (ctx->data[0] == '}') {
            flush_kv_cache(val, ctx);
            jiffy_parser_skip_one_byte(ctx);
            return JSON_OK;
        }

        EXPECT_CH(',', ctx);
        skip_wsp(ctx);
    }
}

static json_res_t check_data_end(struct jiffy_parser *ctx) {
    if (!ctx->data_size)
        return JSON_ERROR;

    uint32_t i;
    for (i = ctx->data_size - 1; i > 0 && is_char_wsp_table[(uint8_t)ctx->data[i]]; --i) {};

    if (i == 0 || ctx->data[i] != '}')
        return JSON_ERROR;

    ctx->data_size = i + 1;
    return JSON_OK;
}

static json_res_t json_parse_impl(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    if (!is_current_char_eq(ctx, '{'))
        skip_wsp(ctx);
    if (check_data_end(ctx) != JSON_OK)
        return JSON_ERROR;

    json_res_t r = json_object_parse(val, ctx);
    if (r != JSON_OK)
        return r;
    EXPECT_END(ctx);
    return r;
}

struct jiffy_json_value *jiffy_parser_parse(struct jiffy_parser *parser) {
    if (!parser->small_allocator.alloc) {
        struct region_allocator *ra = region_allocator_create();
        parser->small_allocator = (struct json_allocator) {
            .alloc = (jiffy_json_alloc_func_t)region_allocator_alloc,
            .destroy = (jiffy_json_destroy_func_t)region_allocator_destroy,
            .ctx = ra,
        };
    }
    struct jiffy_json_value *val = small_object_alloc(parser, sizeof(*val));
    json_res_t r = json_parse_impl(val, parser);
#define MIN(a_, b_) (a_ < b_ ? a_ : b_)
    if (r != JSON_OK) {
        printf("invalid json found at pos '%.*s'\n", (int)(MIN(30, parser->data_size)), parser->data);
        return NULL;
    }

    return val;
}
