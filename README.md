Jiffyjson
=============

This is the fastest library for JSON parsing for C/C++, providing highlevel interface.

Lightweight
-------

Only 3 small source files, written in simple C with <1000 lines of code.

Easy to use
-------

A few functions in interface.

Building
-------
```
git submodule init
git submodule update
mkdir build
cd build
cmake ..
make
```

The fastest
-------

This library is the quickest of founded high-level libraries in any language, allowing to parse JSON.
To run performance benchmark do:
```
cmake -DPERFTEST=ON ..
make
./perftest/gbench ../perftest/twitter.json
```

#### Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz && Linux && gcc version 6.2.0
```
Benchmark               Time           CPU Iterations
-----------------------------------------------------
test_strdup         75206 ns      75196 ns       9375   7.82148GB/s
test_jiffyjson     963051 ns     962952 ns        727   625.429MB/s // this lib
test_rapid_wr     1710053 ns    1709645 ns        411   352.271MB/s
test_ujson4c      2291503 ns    2291255 ns        310   262.851MB/s
test_yajl         6061859 ns    6060270 ns        116   99.3782MB/s
```
