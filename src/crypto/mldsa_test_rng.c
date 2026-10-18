// Copyright (c) 2026 The XCHAIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* randombytes() for the shared ML-DSA library used by the Python functional
 * tests (test/functional/test_framework/pqsig.py). Not linked into bitcoind,
 * which provides its own in script/pqsig.cpp. */
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

int randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        ssize_t r = getrandom(out, outlen, 0);
        if (r <= 0) {
            return -1;
        }
        out += r;
        outlen -= (size_t)r;
    }
    return 0;
}
