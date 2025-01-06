This folder contains an SSLv2 integration test, and is a completely separate CMake project.

The motivation for this is that SSLv2 ClientHellos are only supported by very old libcryptos (and Java :'()

# AWS-LC Install
```

```

# OpenSSL 1.0.2 Install
```
git clone https://github.com/openssl/openssl
cd openssl
git checkout OpenSSL_1_0_2-stable
# /home/ubuntu/workspace/ossl-1-0-2-install
./config --prefix=/home/ubuntu/workspace/ossl-1-0-2-install
make -j
make install
```

## Build
```
rm -rf build
cmake . \
    -B build \
    -D CMAKE_C_COMPILER=clang \
    -D CMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test ARGS="--output-on-failure"
```

Results in this
```
-- feature S2N_MINHERIT_SUPPORTED: FALSE
-- feature S2N_STACKTRACE: TRUE
-- Running tests with environment: S2N_DONT_MLOCK=1
-- Found OpenSSL: /usr/lib/aarch64-linux-gnu/libcrypto.so (found version "3.0.13")  
OpenSSL found: /usr/include
OpenSSL libraries: /usr/lib/aarch64-linux-gnu/libssl.so;/usr/lib/aarch64-linux-gnu/libcrypto.so
-- Include directories for MyTarget: INCLUDE_DIRS-NOTFOUND
-- Link libraries for MyTarget: s2n;OpenSSL::SSL;OpenSSL::Crypto
```

## Build with other OpenSSL Path
```
rm -rf build
cmake . \
    -B build \
    -D CMAKE_C_COMPILER=clang \
    -D CMAKE_BUILD_TYPE=RelWithDebInfo \
    -D CMAKE_PREFIX_PATH=/home/ubuntu/workspace/aws-lc-install \
    -D S2N_INTERN_LIBCRYPTO=ON \
    -D OPENSSL_ROOT_DIR=/home/ubuntu/workspace/ossl-1-0-2-install
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test ARGS="--output-on-failure"
```

Results in this
```
-- Found OpenSSL: /home/ubuntu/workspace/ossl-1-0-2-install/lib/libcrypto.a (found version "1.0.2v")  
OpenSSL found: /home/ubuntu/workspace/ossl-1-0-2-install/include
OpenSSL libraries: /home/ubuntu/workspace/ossl-1-0-2-install/lib/libssl.a;/home/ubuntu/workspace/ossl-1-0-2-install/lib/libcrypto.a
```

## run sslv2 test
```
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test ARGS="-R s2n_self_talk_tls13_test --verbose"
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test ARGS="-R sslv2 --verbose"
```


## Other Notes
Interning doesn't seem to work with OpenSSL 3

```
ubuntu@ip-172-31-49-198:~/workspace/s2n-tls$ cmake --build ./build -j $(nproc)
[  1%] Generating libcrypto.symbols
/usr/bin/llvm-objcopy: error: libcrypto.symbols:1: missing new symbol name
gmake[2]: *** [CMakeFiles/s2n_libcrypto.dir/build.make:73: libcrypto.symbols] Error 1
gmake[2]: *** Deleting file 'libcrypto.symbols'
gmake[1]: *** [CMakeFiles/Makefile2:697: CMakeFiles/s2n_libcrypto.dir/all] Error 2
gmake: *** [Makefile:146: all] Error 2
ubuntu@ip-172-31-49-198:~/workspace/s2n-tls$ 
```
