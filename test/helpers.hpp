#pragma once

#define TEST_JSON_PARSING(s__, checker_) ({ \
    const std::string s_(s__); \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct jiffy_json_value *v = jiffy_parser_parse(parser_); \
    ASSERT_NE(nullptr, v) << s__ << ": " << jiffy_parser_get_error(parser_); \
    checker_(v); \
    jiffy_parser_destroy(parser_); \
})

#define TEST_JSON_PARSING_FAIL(s__) ({ \
    const std::string s_(s__); \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct jiffy_json_value *v = jiffy_parser_parse(parser_); \
    ASSERT_EQ(nullptr, v) << s__ << ": " << jiffy_parser_get_error(parser_); \
    jiffy_parser_destroy(parser_); \
})
