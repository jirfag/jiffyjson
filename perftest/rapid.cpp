// __SSE2__ and __SSE4_2__ are recognized by gcc, clang, and the Intel compiler.
// We use -march=native with gmake to enable -msse2 and -msse4.2, if supported.
#if defined(__SSE4_2__)
#  define RAPIDJSON_SSE42
#elif defined(__SSE2__)
#  define RAPIDJSON_SSE2
#elif defined(_MSC_VER) // Turn on SSE4.2 for VC
#  define RAPIDJSON_SSE42
#endif

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/encodedstream.h"
#include "rapidjson/memorystream.h"

#include <string>

using namespace rapidjson;

extern "C"
void test_rapidjson(const char *data, size_t data_size) {
#ifdef RAPIDJSON_TEST_MEMORY_STREAM
    MemoryStream ms(data, data_size);
    EncodedInputStream<UTF8<>, MemoryStream> is(ms);
#else
    const std::string s(data, data_size);
    StringStream is(s.c_str());
#endif

    Document doc;
    doc.ParseStream<kParseNoFlags, UTF8<>>(is);
    assert(doc.IsObject());
}
