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

using namespace rapidjson;

extern "C"
void test_rapidjson(const char *data, size_t data_size) {
    MemoryStream ms(data, data_size);
    AutoUTFInputStream<unsigned, MemoryStream> is(ms);
    Document doc;
    doc.ParseStream<0, AutoUTF<unsigned> >(is);
    assert(doc.IsObject());
}
