Jiffyjson
=============

This is the fastest library for JSON parsing for C/C++, providing highlevel interface.

The fastest
-------

This library is the quickest of founded high-level C libraries, allowing to parse JSON.
```
$ ./perftest/bench ../perftest/twitter.json
'strdup' took 325mcs, speed is 1943.1Mb/sec = 1.0 * etalon
'jiffyjson' took 975mcs, speed is 647.7Mb/sec = 3.0 * etalon
'rapidjson' took 3953mcs, speed is 159.8Mb/sec = 12.2 * etalon
'ujson4c' took 2154mcs, speed is 293.2Mb/sec = 6.6 * etalon
'yajl' took 6345mcs, speed is 99.5Mb/sec = 19.5 * etalon
```
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
