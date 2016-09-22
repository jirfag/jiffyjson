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

#### Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz && Linux && gcc version 6.2.0
```
$ ./perftest/bench ../perftest/twitter.json
'strdup' took 319mcs, speed is 1979.7Mb/sec = 1.0 * etalon
'jiffyjson' took 967mcs, speed is 653.1Mb/sec = 3.0 * etalon
'rapidjson' took 2351mcs, speed is 268.6Mb/sec = 7.4 * etalon
'ujson4c' took 2166mcs, speed is 291.6Mb/sec = 6.8 * etalon
```

#### Intel(R) Core(TM) i5-4258U CPU @ 2.40GHz && Mac OS X && clang 3.8.0
```
$ ./perftest/bench ../perftest/twitter.json
'strdup' took 417mcs, speed is 1514.4Mb/sec = 1.0 * etalon
'jiffyjson' took 1263mcs, speed is 500.0Mb/sec = 3.0 * etalon
'rapidjson' took 2715mcs, speed is 232.6Mb/sec = 6.5 * etalon
'ujson4c' took 2751mcs, speed is 229.6Mb/sec = 6.6 * etalon
```
