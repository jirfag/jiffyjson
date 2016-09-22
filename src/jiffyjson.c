#include "jiffyjson.h"
#include "region_allocator.h"
#include "one_mmap_allocator.h"
#include "internal.h"

#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __SSE2__
#define JIFFY_SSE2 1
#endif

#ifdef JIFFY_SSE2
#include <xmmintrin.h>
#define bsf(x) __builtin_ctz(x)
#endif

#ifdef PERFTEST
#define JIFFYJSON_FORCE_INLINE
#else
#define JIFFYJSON_FORCE_INLINE __attribute__((always_inline)) inline
#endif
#define JIFFYJSON_HOT __attribute__((hot))

struct jiffy_parser *jiffy_parser_create() {
    return calloc(1, sizeof(struct jiffy_parser));
}

void jiffy_parser_destroy(struct jiffy_parser *ctx) {
    ctx->large_allocator.destroy(ctx->large_allocator.ctx);
    ctx->small_allocator.destroy(ctx->small_allocator.ctx);
    jvector_delete(&ctx->kv_cache);
    jvector_delete(&ctx->values_cache);
    free(ctx);
}

#ifdef JIFFY_SSE2
static void *memchrSSE2(const char *p, int c, size_t len)
{
    if (len >= 16) {
        __m128i c16 = _mm_set1_epi8(c);
        /* 16 byte alignment */
        size_t ip = (size_t)p;
        size_t n = ip & 15;
        if (n > 0) {
            ip &= ~15;
            __m128i x = *(const __m128i*)ip;
            __m128i a = _mm_cmpeq_epi8(x, c16);
            unsigned long mask = _mm_movemask_epi8(a);
            mask &= 0xffffffffUL << n;
            if (mask) {
                return (void*)(ip + bsf(mask));
            }
            n = 16 - n;
            len -= n;
            p += n;
        }
        while (len >= 32) {
            __m128i x = *(const __m128i*)&p[0];
            __m128i y = *(const __m128i*)&p[16];
            __m128i a = _mm_cmpeq_epi8(x, c16);
            __m128i b = _mm_cmpeq_epi8(y, c16);
            unsigned long mask = (_mm_movemask_epi8(b) << 16) | _mm_movemask_epi8(a);
            if (mask) {
                return (void*)(p + bsf(mask));
            }
            len -= 32;
            p += 32;
        }
    }
    while (len > 0) {
        if (*p == c) return (void*)p;
        p++;
        len--;
    }
    return 0;
}

#define memchr memchrSSE2
#endif

static json_res_t format_error(struct jiffy_parser *parser, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(parser->error, sizeof(parser->error), fmt, ap);
    va_end(ap);
    if (n <= 0 || n >= (int)sizeof(parser->error))
        return JSON_ERROR;

#define MIN(a_, b_) ((a_) < (b_) ? (a_) : (b_))
    snprintf(parser->error + n, sizeof(parser->error) - n, ", pos: '%.*s",
             MIN(parser->data_size, 20), parser->data);
    return JSON_ERROR;
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

void jiffy_parser_set_large_allocator(struct jiffy_parser *parser,
        jiffy_json_alloc_func_t alloc, jiffy_json_destroy_func_t destroy, void *ctx) {
    parser->large_allocator.alloc = alloc;
    parser->large_allocator.destroy = destroy;
    parser->large_allocator.ctx = ctx;
}

static JIFFYJSON_FORCE_INLINE void jiffy_parser_skip_one_byte(struct jiffy_parser *ctx) {
    assert(ctx->data_size);
    assert(ctx->data);
    ctx->data++;
    ctx->data_size--;
}

static JIFFYJSON_FORCE_INLINE void jiffy_parser_skip_n_bytes(struct jiffy_parser *ctx, uint32_t n) {
    assert(ctx->data_size >= n);
    assert(ctx->data);
    ctx->data += n;
    ctx->data_size -= n;
}

#define JIFFYJSON_UNLIKELY(x_) __builtin_expect(x_, 0)
#define JIFFYJSON_LIKELY(x_) __builtin_expect(!!(x_), 1)

// XXX: don't check data_size because it was checked once at the start: data ends with '}'
#define EXPECT_CH(ch_, ctx_) ({ \
    bool is_error_ = (ctx_)->data[0] != ch_; \
    if (JIFFYJSON_UNLIKELY(is_error_)) \
        return format_error(ctx_, "expected '%c', got '%c'", ch_, (ctx_)->data[0]); \
    jiffy_parser_skip_one_byte((ctx_)); \
})

#define ASSERT_CH(ch_, ctx_) ({ \
    assert((ctx_)->data_size != 0 && (ctx_)->data[0] == ch_); \
    jiffy_parser_skip_one_byte((ctx_)); \
})

#define EXPECT_END(ctx_) ({ \
    if ((ctx_)->data_size != 0 ) \
        return JSON_ERROR; \
})

static const bool is_char_wsp_table[1 << CHAR_BIT] = {
    [' '] = true,
    ['\t'] = true,
    ['\r'] = true,
    ['\n'] = true,
};

#if 0
static JIFFYJSON_FORCE_INLINE const uint8_t *skip_wsp_simd(const struct jiffy_parser *ctx) {
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
    if (JIFFYJSON_LIKELY(*ctx->data == ' ')) {
        jiffy_parser_skip_one_byte(ctx);
        const char c = *ctx->data;
        bool is_non_wsp = !is_char_wsp_table[(uint8_t)c];
        if (JIFFYJSON_LIKELY(is_non_wsp))
            return;

        return skip_wsp(ctx);
    }

    return skip_wsp(ctx);
}

#define STRLN(s_) (sizeof(s_) - 1)

static void skip_wsp_expect_nl_and_spaces(struct jiffy_parser *ctx) {
    if (JIFFYJSON_LIKELY(*ctx->data == '\n')) {
        const uint32_t spaces4 = *(uint32_t *)"    ";
        const char * const data = ctx->data + STRLN("\n");
        const uint32_t data_size = ctx->data_size - STRLN("\n");

        //TODO: align for uint32_t*
        uint32_t i = 0;
        while (i < data_size && *(uint32_t *)(&data[i]) == spaces4)
             i += sizeof(uint32_t);

        while (i < data_size && data[i] == ' ')
            ++i;

        jiffy_parser_skip_n_bytes(ctx, STRLN("\n") + i);
        assert(ctx->data[-1] == ' ');
        assert(ctx->data[0] != ' ');

        const char c = data[i];
        bool is_non_wsp = !is_char_wsp_table[(uint8_t)c];
        if (JIFFYJSON_LIKELY(is_non_wsp))
            return;

        return skip_wsp(ctx);
    }

    return skip_wsp(ctx);
}

static JIFFYJSON_FORCE_INLINE bool is_current_char_eq(const struct jiffy_parser *ctx, char c) {
    return *ctx->data == c;
}

static void json_object_init(struct jiffy_json_value *val) {
    val->value_type = JVT_OBJECT;
    memset(&val->obj, 0, sizeof(val->obj));
}

static JIFFYJSON_FORCE_INLINE void json_string_append_string(struct json_string *str, const char *data, uint32_t size) {
    memcpy(str->data + str->size, data, size);
    str->size += size;
}

static JIFFYJSON_FORCE_INLINE void json_string_append_char(struct json_string *str, char c) {
    str->data[str->size++] = c;
}

static JIFFYJSON_FORCE_INLINE int hex2int(char c) {
    static const int8_t hext2int_table[1 << CHAR_BIT] = {
        [0 ... ('0' - 1)] = -1,
        ['0'] = 0,
        ['1'] = 1,
        ['2'] = 2,
        ['3'] = 3,
        ['4'] = 4,
        ['5'] = 5,
        ['6'] = 6,
        ['7'] = 7,
        ['8'] = 8,
        ['9'] = 9,
        [('9' + 1) ... ('A' - 1)] = -1,
        ['A'] = 10,
        ['B'] = 11,
        ['C'] = 12,
        ['D'] = 13,
        ['E'] = 14,
        ['F'] = 15,
        [('F' + 1) ... ('a' - 1)] = -1,
        ['a'] = 10,
        ['b'] = 11,
        ['c'] = 12,
        ['d'] = 13,
        ['e'] = 14,
        ['f'] = 15,
        [('f' + 1) ... 0xff] = -1
    };

    return hext2int_table[(uint8_t)c];
}

static JIFFYJSON_FORCE_INLINE json_res_t decode_unicode_codepoint(struct jiffy_parser *ctx, uint32_t *codepoint) {
    int h1 = hex2int(ctx->data[0]);
    if (h1 < 0)
        return format_error(ctx, "invalid unicode 0-th hex");
    int h2 = hex2int(ctx->data[1]);
    if (h2 < 0)
        return format_error(ctx, "invalid unicode 1-th hex");
    int h3 = hex2int(ctx->data[2]);
    if (h3 < 0)
        return format_error(ctx, "invalid unicode 2-th hex");
    int h4 = hex2int(ctx->data[3]);
    if (h4 < 0)
        return format_error(ctx, "invalid unicode 3-th hex");

    *codepoint = (h1 << 12) | (h2 << 8) | (h3 << 4) | h4;
    return JSON_OK;
}

static json_res_t json_string_process_unicode(struct json_string *str, struct jiffy_parser *ctx) {
    uint32_t codepoint = 0;
    if (JIFFYJSON_UNLIKELY(decode_unicode_codepoint(ctx, &codepoint) != JSON_OK))
        return JSON_ERROR;

    if (codepoint < 0x80) {
        json_string_append_char(str, codepoint); /* 0xxxxxxx */
        jiffy_parser_skip_n_bytes(ctx, sizeof(codepoint));
        return JSON_OK;
    }
    if (codepoint < 0x800) {
        json_string_append_char(str, ((codepoint >> 6) & 0x1F) | 0xC0); /* 110xxxxx */
        json_string_append_char(str, ((codepoint     ) & 0x3F) | 0x80); /* 10xxxxxx */
        jiffy_parser_skip_n_bytes(ctx, sizeof(codepoint));
        return JSON_OK;
    }
    if (codepoint < 0xD800 || codepoint > 0xDFFF) {
        json_string_append_char(str, ((codepoint >> 12) & 0x0F) | 0xE0); /* 1110xxxx */
        json_string_append_char(str, ((codepoint >> 6)  & 0x3F) | 0x80); /* 10xxxxxx */
        json_string_append_char(str, ((codepoint     )  & 0x3F) | 0x80); /* 10xxxxxx */
        jiffy_parser_skip_n_bytes(ctx, sizeof(codepoint));
        return JSON_OK;
    }

    bool is_lead_surrogate = (codepoint >= 0xD800 && codepoint <= 0xDBFF); /* lead surrogate (0xD800..0xDBFF) */
    if (!is_lead_surrogate)
        return format_error(ctx, "invalid unicode codepoint %04x", codepoint);

    jiffy_parser_skip_n_bytes(ctx, sizeof(codepoint));
    EXPECT_CH('\\', ctx);
    EXPECT_CH('u', ctx);

    uint32_t trail = 0;
    if (JIFFYJSON_UNLIKELY(decode_unicode_codepoint(ctx, &trail) != JSON_OK))
        return JSON_ERROR;

    if (trail < 0xDC00 || trail > 0xDFFF) /* valid trail surrogate? (0xDC00..0xDFFF) */
        return format_error(ctx, "invalid trailing surrogate %04x", trail);
    jiffy_parser_skip_n_bytes(ctx, sizeof(trail));

    uint32_t lead = codepoint;
    codepoint = ((((lead-0xD800)&0x3FF)<<10)|((trail-0xDC00)&0x3FF))+0x010000;
    json_string_append_char(str, ((codepoint >> 18) & 0x07) | 0xF0); /* 11110xxx */
    json_string_append_char(str, ((codepoint >> 12) & 0x3F) | 0x80); /* 10xxxxxx */
    json_string_append_char(str, ((codepoint >> 6)  & 0x3F) | 0x80); /* 10xxxxxx */
    json_string_append_char(str, ((codepoint     )  & 0x3F) | 0x80); /* 10xxxxxx */
    return JSON_OK;
}

static json_res_t json_string_process_backslash(struct json_string *str, struct jiffy_parser *ctx) {
    if (ctx->data[0] == 'u') {
        jiffy_parser_skip_one_byte(ctx);
        return json_string_process_unicode(str, ctx);
    }

    static const char escaping_table[1 << CHAR_BIT] = {
        ['"'] = '"',
        ['\\'] = '\\',
        ['/'] = '/',
        ['b'] = '\b',
        ['f'] = '\f',
        ['n'] = '\n',
        ['r'] = '\r',
        ['t'] = '\t',
    };

    char res_ch = escaping_table[(uint8_t)ctx->data[0]];
    if (res_ch == '\0')
        return format_error(ctx, "invalid escape sequence");

    jiffy_parser_skip_one_byte(ctx);
    str->data[str->size++] = res_ch;
    return JSON_OK;
}

static JIFFYJSON_FORCE_INLINE void *large_chunk_alloc(struct jiffy_parser *ctx, uint32_t size) {
    return ctx->large_allocator.alloc(ctx->large_allocator.ctx, size);
}

#ifdef JIFFY_SSE2
static JIFFYJSON_FORCE_INLINE uint32_t skip_nonspecial_string_characters(const uint8_t *p, uint32_t size) {
    static const bool string_char_class_table[1 << CHAR_BIT] = {
        [0x0 ... 0x19] = true,
        ['"'] = true,
        ['\\'] = true,
    };
    const uint8_t *src_p = p;

    if (size <= 16) {
        for (uint32_t i = 0; i < size; ++i) {
            if (JIFFYJSON_UNLIKELY(string_char_class_table[p[i]]))
                return i;
        }
        return size;
    }

    // The rest of string using SIMD
    static const char dquote[16] = { '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"', '\"' };
    static const char bslash[16] = { '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\' };
    static const char space[16]  = { 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19 };
    const __m128i dq = _mm_loadu_si128((const __m128i *)(&dquote[0]));
    const __m128i bs = _mm_loadu_si128((const __m128i *)(&bslash[0]));
    const __m128i sp = _mm_loadu_si128((const __m128i *)(&space[0]));

    // Scan one by one until alignment (unaligned load may cross page boundary and cause crash)
    const uint8_t *next_aligned = (const uint8_t *)(((size_t)p + 15) & (size_t)(~15));
    const uint8_t *p_end = p + size;
    assert(next_aligned < p_end); // guaranteed by check (size <= 16) above
    if (JIFFYJSON_LIKELY(p != next_aligned)) {
        const __m128i s = _mm_loadu_si128((const __m128i *)p); // unaligned load
        const __m128i t1 = _mm_cmpeq_epi8(s, dq);
        const __m128i t2 = _mm_cmpeq_epi8(s, bs);
        const __m128i t3 = _mm_cmpeq_epi8(_mm_max_epu8(s, sp), sp); // s < 0x20 <=> max(s, 0x19) == 0x19
        const __m128i x = _mm_or_si128(_mm_or_si128(t1, t2), t3);
        uint16_t r = _mm_movemask_epi8(x);
        if (r != 0) // some of characters are escaped
            return p - src_p + __builtin_ffs(r) - 1;

        p = next_aligned;
    }

    const uint8_t *aligned_p_end = (const uint8_t *)((size_t)p_end & (size_t)(~15));
    for (; p < aligned_p_end; p += 16) {
        const __m128i s = _mm_load_si128((const __m128i *)p);
        const __m128i t1 = _mm_cmpeq_epi8(s, dq);
        const __m128i t2 = _mm_cmpeq_epi8(s, bs);
        const __m128i t3 = _mm_cmpeq_epi8(_mm_max_epu8(s, sp), sp); // s < 0x20 <=> max(s, 0x19) == 0x19
        const __m128i x = _mm_or_si128(_mm_or_si128(t1, t2), t3);
        uint16_t r = _mm_movemask_epi8(x);
        if (JIFFYJSON_UNLIKELY(r != 0)) // some of characters are escaped
            return p - src_p + __builtin_ffs(r) - 1;
    }

    for (; p < p_end; ++p) {
        if (JIFFYJSON_UNLIKELY(string_char_class_table[*p]))
            return p - src_p;
    }

    return size;
}
#endif

static const char *json_string_get_end(const char *str, uint32_t str_len) {
    for (;;) {
        const char *closing_quote_pos = *str == '"' ? str : memchr(str, '"', str_len);
        if (!closing_quote_pos)
            return NULL;

        if (closing_quote_pos[-1] == '\\') {
            int i;
            for (i = 2; closing_quote_pos[-i] == '\\'; ++i) {}
            if (i % 2 == 0) {
                uint32_t diff = closing_quote_pos - str + 1;
                str += diff;
                str_len -= diff;
                continue;
            }
        }

        return closing_quote_pos;
    }
}

STATIC JIFFYJSON_HOT json_res_t json_string_parse(struct json_string *str, struct jiffy_parser *ctx) {
    EXPECT_CH('"', ctx);
    const char *str_begin = ctx->data;
    str->data = NULL;

    for (;;) {
        uint32_t bytes_to_skip = skip_nonspecial_string_characters((uint8_t *)ctx->data, ctx->data_size);
        if (JIFFYJSON_UNLIKELY(bytes_to_skip == ctx->data_size))
            return format_error(ctx, "no ending quote for string");

        uint8_t cur_char = ctx->data[bytes_to_skip];
        if (cur_char == '"') { // string end
            if (!str->data) {
                // no special characters in string, don't copy, just set ref to source string
                jiffy_parser_skip_n_bytes(ctx, bytes_to_skip + STRLN("\""));
                str->data = (char *)str_begin;
                str->size = bytes_to_skip;
                return JSON_OK;
            }

            // memory for 'str' was already allocated
            if (bytes_to_skip)
                json_string_append_string(str, ctx->data, bytes_to_skip);
            jiffy_parser_skip_n_bytes(ctx, bytes_to_skip + STRLN("\""));
            return JSON_OK;
        }

        if (JIFFYJSON_UNLIKELY(cur_char < 0x20))
            return format_error(ctx, "invalid character '0x%02x' in string", cur_char);

        // found backslash ('\')
        if (!str->data) { // do lazy allocation of string to prevent allocation in case of string without special characters
            const char *str_end = json_string_get_end(ctx->data, ctx->data_size);
            if (JIFFYJSON_UNLIKELY(!str_end))
                return format_error(ctx, "no non-escaped ending quote for string");

            assert(str_begin == ctx->data);
            uint32_t str_len = str_end - ctx->data;
            str->data = (char *)large_chunk_alloc(ctx, str_len);
            if (JIFFYJSON_UNLIKELY(!str->data))
                return format_error(ctx, "can't allocate %u bytes for string", str_len);
            str->size = 0;
        }

        if (bytes_to_skip) {
            json_string_append_string(str, ctx->data, bytes_to_skip);
            jiffy_parser_skip_n_bytes(ctx, bytes_to_skip + STRLN("\\"));
        } else {
            jiffy_parser_skip_one_byte(ctx);
        }

        if (JIFFYJSON_UNLIKELY(json_string_process_backslash(str, ctx) != JSON_OK))
            return JSON_ERROR;
    }
}

static json_res_t json_value_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx);

static json_res_t json_parse_kv(struct json_kv *kv, struct jiffy_parser *ctx) {
    json_res_t r = json_string_parse(&kv->k, ctx);
    if (JIFFYJSON_UNLIKELY(r != JSON_OK))
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

static JIFFYJSON_FORCE_INLINE void *small_object_alloc(struct jiffy_parser *ctx, uint32_t size) {
    return ctx->small_allocator.alloc(ctx->small_allocator.ctx, size);
}

static ijvector(json_value) *flush_values_cache(struct jiffy_parser *ctx) {
    uint32_t elems_n = jvector_size(&ctx->values_cache);
    struct jiffy_json_value *elems = (struct jiffy_json_value *)jvector_data(&ctx->values_cache);
    ijvector(json_value) *ret = ijvector_init(json_value, elems, elems_n, ctx->small_allocator.alloc, ctx->small_allocator.ctx);
    jvector_reset(&ctx->values_cache);
    return ret;
}

static void flush_kv_cache(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    uint32_t elems_n = jvector_size(&ctx->kv_cache);
    struct json_kv *elems = (struct json_kv *)jvector_data(&ctx->kv_cache);
    val->obj = ijvector_init(json_kv, elems, elems_n,  ctx->small_allocator.alloc, ctx->small_allocator.ctx);
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
        struct jiffy_json_value *inner_val = jvector_push_back(&ctx->values_cache);
        json_res_t r = json_value_parse(inner_val, ctx);
        if (JIFFYJSON_UNLIKELY(r != JSON_OK))
            return r;

        if (is_current_char_eq(ctx, ',')) {
            jiffy_parser_skip_one_byte(ctx);
            skip_wsp_expect_nl_and_spaces(ctx);
            continue;
        }

        skip_wsp(ctx);
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

    // XXX: it's safe to call strtod, because we've already checked,
    // that input contains '}' at the end

    errno = 0;
    char *end;
    val->num_val = strtod(ctx->data, &end);
    uint32_t val_size = end - ctx->data;
    if (!val_size)
        return JSON_ERROR;
    if (errno)
        return JSON_ERROR;
    jiffy_parser_skip_n_bytes(ctx, val_size);
    return JSON_OK;
}

static json_res_t json_bool_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    val->value_type = JVT_BOOL;
    if (ctx->data_size >= STRLN("true")) {
        if (*(uint32_t *)(ctx->data) == *(uint32_t *)"true") {
            jiffy_parser_skip_n_bytes(ctx, STRLN("true"));
            val->bool_val = true;
            return JSON_OK;
        }

        if (*(uint32_t *)(ctx->data) == *(uint32_t *)"fals") {
            if (ctx->data[4] == 'e') {
                jiffy_parser_skip_n_bytes(ctx, STRLN("false"));
                val->bool_val = false;
                return JSON_OK;
            }
        }
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
    if (JIFFYJSON_UNLIKELY(!parser))
        return JSON_ERROR;

    return parser(val, ctx);
}

static json_res_t json_object_parse(struct jiffy_json_value *val, struct jiffy_parser *ctx) {
    json_object_init(val);
    EXPECT_CH('{', ctx);
    skip_wsp_expect_nl_and_spaces(ctx);
    if (ctx->data[0] == '}') {
        //TODO: check if depth != 0 and data_size == 0: return JSON_ERROR to prevent heap overread
        jiffy_parser_skip_one_byte(ctx);
        return JSON_OK;
    }

    for (;;) {
        struct json_kv *kv = jvector_push_back(&ctx->kv_cache);
        json_res_t r = json_parse_kv(kv, ctx);
        if (JIFFYJSON_UNLIKELY(r != JSON_OK))
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
    if (JIFFYJSON_UNLIKELY(check_data_end(ctx) != JSON_OK))
        return JSON_ERROR;

    json_res_t r = json_object_parse(val, ctx);
    if (JIFFYJSON_UNLIKELY(r != JSON_OK))
        return r;
    EXPECT_END(ctx);
    return r;
}

STATIC void jiffy_parser_init(struct jiffy_parser *parser) {
    if (!parser->small_allocator.alloc) {
        struct region_allocator *ra = region_allocator_create();
        jiffy_parser_set_small_allocator(parser,
                (jiffy_json_alloc_func_t)region_allocator_alloc,
                (jiffy_json_destroy_func_t)region_allocator_destroy,
                ra);
    }
    if (!parser->large_allocator.alloc) {
        struct one_mmap_allocator *oma = one_mmap_allocator_create(parser->data_size);
        jiffy_parser_set_large_allocator(parser,
                (jiffy_json_alloc_func_t)one_mmap_allocator_alloc,
                (jiffy_json_destroy_func_t)one_mmap_allocator_destroy,
                oma);
    }
    jvector_ensure(&parser->kv_cache, 64);
    jvector_ensure(&parser->values_cache, 64);
}

struct jiffy_json_value *jiffy_parser_parse(struct jiffy_parser *parser) {
    jiffy_parser_init(parser);
    struct jiffy_json_value *val = small_object_alloc(parser, sizeof(*val));
    json_res_t r = json_parse_impl(val, parser);
    if (JIFFYJSON_UNLIKELY(r != JSON_OK))
        return NULL;

    return val;
}

const char *jiffy_parser_get_error(const struct jiffy_parser *parser) {
    return parser->error;
}

bool jiffy_json_value_is_string(const struct jiffy_json_value *v) {
    return v->value_type == JVT_STRING;
}
bool jiffy_json_value_is_boolean(const struct jiffy_json_value *v) {
    return v->value_type == JVT_BOOL;
}
bool jiffy_json_value_is_null(const struct jiffy_json_value *v) {
    return v->value_type == JVT_NULL;
}
bool jiffy_json_value_is_array(const struct jiffy_json_value *v) {
    return v->value_type == JVT_ARRAY;
}
bool jiffy_json_value_is_object(const struct jiffy_json_value *v) {
    return v->value_type == JVT_OBJECT;
}
uint32_t jiffy_json_object_get_size(const struct jiffy_json_value *v) {
    JIFFY_ASSERT(v->value_type == JVT_OBJECT);
    if (!v->obj)
        return 0;
    return ijvector_size(v->obj);
}
uint32_t jiffy_json_array_get_size(const struct jiffy_json_value *v) {
    JIFFY_ASSERT(v->value_type == JVT_ARRAY);
    if (!v->arr)
        return 0;
    return ijvector_size(v->arr);
}
struct jiffy_json_value *jiffy_json_object_get_value(const struct jiffy_json_value *obj, const char *key) {
    JIFFY_ASSERT(obj->value_type == JVT_OBJECT);
    if (!obj->obj)
        return NULL;

    size_t key_len = strlen(key);
    for (uint32_t i = 0; i < ijvector_size(obj->obj); ++i) {
        struct json_kv *kv = &ijvector_get_elem(obj->obj, i);
        struct json_string *s = &kv->k;
        if (s->size == key_len && !memcmp(s->data, key, key_len))
            return &kv->v;
    }

    return NULL;
}
