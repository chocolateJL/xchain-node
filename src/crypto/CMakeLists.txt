# Copyright (c) 2017-2019 The Bitcoin developers

project(crypto)

# The library
add_library(crypto
	aes.cpp
	chacha20.cpp
	hmac_sha256.cpp
	hmac_sha512.cpp
	muhash.cpp
	ripemd160.cpp
	sha1.cpp
	sha256.cpp
	sha256_sse4.cpp
	sha3.cpp
	sha512.cpp
	siphash.cpp
)

target_include_directories(crypto
	PRIVATE
		..
	PUBLIC
		# To access the config.
		${CMAKE_CURRENT_BINARY_DIR}/..
)

target_compile_definitions(crypto PUBLIC HAVE_CONFIG_H)

# Use assembly is specified
option(CRYPTO_USE_ASM "Use assembly version of crypto primitives" ON)
if(CRYPTO_USE_ASM)
	target_compile_definitions(crypto PRIVATE USE_ASM)
endif()

# Dependencies
target_link_libraries(crypto OpenSSL::Crypto)

# ML-DSA-44 from vendored mldsa-native (see mldsa/VENDORED.md).
# Portable C only: no native backend and no assembly, so every platform runs
# the same verification code (decision D12 pending).
# Consumers must provide `int randombytes(uint8_t *, size_t)` (see pqsig.cpp).
add_library(mldsa44 mldsa/mldsa_native.c)
target_include_directories(mldsa44 PUBLIC mldsa)
target_compile_definitions(mldsa44
	PUBLIC
		MLD_CONFIG_PARAMETER_SET=44
		MLD_CONFIG_NAMESPACE_PREFIX=xc_mldsa44
)
set_target_properties(mldsa44 PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
target_link_libraries(crypto mldsa44)

# Crypto libraries requiring hardware features
macro(add_crypto_library NAME)
	add_library(${NAME} ${ARGN})
	target_link_libraries(crypto ${NAME})
	target_include_directories(${NAME} PRIVATE ..)
endmacro()

include(CheckCXXSourceCompiles)

# SSE4.1
set(CRYPTO_SSE41_FLAGS -msse4.1)

string(JOIN " " CMAKE_REQUIRED_FLAGS ${CRYPTO_SSE41_FLAGS})
check_cxx_source_compiles("
	#include <stdint.h>
	#include <immintrin.h>
	int main() {
		__m128i l = _mm_set1_epi32(0);
		return _mm_extract_epi32(l, 3);
	}
" ENABLE_SSE41)

if(ENABLE_SSE41)
	add_crypto_library(crypto_sse4.1 sha256_sse41.cpp)
	target_compile_definitions(crypto_sse4.1 PUBLIC ENABLE_SSE41)
	target_compile_options(crypto_sse4.1 PRIVATE ${CRYPTO_SSE41_FLAGS})
endif()

# AVX2
set(CRYPTO_AVX2_FLAGS -mavx -mavx2)

string(JOIN " " CMAKE_REQUIRED_FLAGS ${CRYPTO_AVX2_FLAGS})
check_cxx_source_compiles("
	#include <stdint.h>
	#include <immintrin.h>
	int main() {
		__m256i l = _mm256_set1_epi32(0);
		return _mm256_extract_epi32(l, 7);
	}
" ENABLE_AVX2)

if(ENABLE_AVX2)
	add_crypto_library(crypto_avx2 sha256_avx2.cpp)
	target_compile_definitions(crypto_avx2 PUBLIC ENABLE_AVX2)
	target_compile_options(crypto_avx2 PRIVATE ${CRYPTO_AVX2_FLAGS})
endif()

# SHA-NI
set(CRYPTO_SHANI_FLAGS -msse4 -msha)

string(JOIN " " CMAKE_REQUIRED_FLAGS ${CRYPTO_SHANI_FLAGS})
check_cxx_source_compiles("
	#include <stdint.h>
	#include <immintrin.h>
	int main() {
		__m128i i = _mm_set1_epi32(0);
		__m128i j = _mm_set1_epi32(1);
		__m128i k = _mm_set1_epi32(2);
		return _mm_extract_epi32(_mm_sha256rnds2_epu32(i, i, k), 0);
	}
" ENABLE_SHANI)

if(ENABLE_SHANI)
	add_crypto_library(crypto_shani sha256_shani.cpp)
	target_compile_definitions(crypto_shani PUBLIC ENABLE_SHANI)
	target_compile_options(crypto_shani PRIVATE ${CRYPTO_SHANI_FLAGS})
endif()

# Shared ML-DSA-44 library for the Python functional tests (test_framework/pqsig.py).
# Same source and configuration as mldsa44 above, plus a getrandom()-based RNG.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_library(mldsa44_testshared SHARED mldsa/mldsa_native.c mldsa_test_rng.c)
	target_include_directories(mldsa44_testshared PRIVATE mldsa)
	target_compile_definitions(mldsa44_testshared
		PRIVATE
			_GNU_SOURCE
			MLD_CONFIG_PARAMETER_SET=44
			MLD_CONFIG_NAMESPACE_PREFIX=xc_mldsa44
	)
	set_target_properties(mldsa44_testshared PROPERTIES
		C_STANDARD 99
		C_STANDARD_REQUIRED ON
		OUTPUT_NAME xc_mldsa44
		# Python loads it with ctypes, so the API must be exported (the project default is hidden).
		C_VISIBILITY_PRESET default
	)
endif()
