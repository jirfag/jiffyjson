#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void * (*jiffy_json_alloc_func_t)(void *ctx, uint32_t size);
typedef void (*jiffy_json_destroy_func_t)(void *ctx);

struct jiffy_parser *jiffy_parser_create();
void jiffy_parser_destroy(struct jiffy_parser *ctx);
void jiffy_parser_set_allocator(struct jiffy_parser *parser,
        jiffy_json_alloc_func_t alloc, jiffy_json_destroy_func_t destroy, void *ctx);
void jiffy_parser_set_large_allocator(struct jiffy_parser *parser,
        jiffy_json_alloc_func_t alloc, jiffy_json_destroy_func_t destroy, void *ctx);
void jiffy_parser_set_input(struct jiffy_parser *parser, const char *data, uint32_t data_size);
struct jiffy_json_value *jiffy_parser_parse(struct jiffy_parser *parser);
const char *jiffy_parser_get_error(const struct jiffy_parser *parser);

bool jiffy_json_value_is_string(const struct jiffy_json_value *v);
bool jiffy_json_value_is_boolean(const struct jiffy_json_value *v);
bool jiffy_json_value_is_null(const struct jiffy_json_value *v);
bool jiffy_json_value_is_array(const struct jiffy_json_value *v);
bool jiffy_json_value_is_object(const struct jiffy_json_value *v);

uint32_t jiffy_json_object_get_size(const struct jiffy_json_value *v);
uint32_t jiffy_json_array_get_size(const struct jiffy_json_value *v);
struct jiffy_json_value *jiffy_json_object_get_value(const struct jiffy_json_value *obj, const char *key);

#ifdef __cplusplus
}
#endif
