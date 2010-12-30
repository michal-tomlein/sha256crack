/*
 * Copyright (c) 2010, Michal Tomlein
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice,
 *        this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright notice,
 *        this list of conditions and the following disclaimer in the documentation
 *        and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Original code by Angel Marin, Paul Johnston.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <omp.h>

#include "sha256.h"

typedef struct {
    uint32_t * data;
    unsigned int length;
} uint32_a;

void uint32_a_init(uint32_a * a, unsigned int length) {
    a->data = (uint32_t *)calloc(length, sizeof(uint32_t));
    a->length = length;
}

void uint32_a_resize(uint32_a * a, unsigned int length) {
    if (a->length == length)
        return;
    a->data = (uint32_t *)realloc(a->data, length * sizeof(uint32_t));
    for (unsigned int i = a->length; i < length; i++)
        a->data[i] = 0;
    a->length = length;
}

void uint32_a_free(uint32_a * a) {
    free(a->data);
    a->data = NULL;
    a->length = 0;
}

int uint32_a_eq(uint32_a a, uint32_a b) {
    if (a.length != b.length)
        return 0;
    for (int i = 0; i < a.length; ++i)
        if (a.data[i] != b.data[i])
            return 0;
    return 1;
}

uint32_a bytes_to_binb(const char * bytes, unsigned int length) {
    uint32_t mask = (1 << 8) - 1;
    length *= 8;
    uint32_a bin;
    uint32_a_init(&bin, ((length - 1) >> 5) + 1);
    for (uint32_t i = 0; i < length; i += 8) {
        bin.data[i >> 5] |= (bytes[i / 8] & mask) << (32 - 8 - i % 32);
    }
    return bin;
}

char * binb_to_hex(const uint32_t binarray[], uint32_t length, char * result) {
    const char * hex_tab = "0123456789abcdef";
    if (!result)
        result = (char *)malloc(65 * sizeof(char));
    result[64] = '\0';
    length *= 4;
    for (uint32_t i = 0; i < length; i++) {
        result[2 * i] = hex_tab[(binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF];
        result[2 * i + 1] = hex_tab[(binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF];
    }
    return result;
}

uint32_t rotr(uint32_t x, int n) {
    if (n < 32) return (x >> n) | (x << (32 - n));
    return x;
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void sha256core(uint32_a message_a, uint32_t source_binlength, uint32_t H[]) {
    uint32_t K[] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B,
        0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01,
        0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7,
        0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152,
        0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
        0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
        0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819,
        0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08,
        0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F,
        0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };
    H[0] = 0x6A09E667; H[1] = 0xBB67AE85; H[2] = 0x3C6EF372; H[3] = 0xA54FF53A;
    H[4] = 0x510E527F; H[5] = 0x9B05688C; H[6] = 0x1F83D9AB; H[7] = 0x5BE0CD19;
    uint32_a W_a;
    uint32_a_init(&W_a, 64);
    uint32_t * W = W_a.data;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    uint32_t message_length = (((source_binlength + 1 + 64) >> 9) << 4) + 16;
    uint32_a_resize(&message_a, message_length);
    uint32_t * message = message_a.data;
    message[source_binlength >> 5] |= 0x80 << (24 - source_binlength % 32);
    message[message_length - 1] = source_binlength;
    for (uint32_t i = 0; i < message_length; i += 16) {
        a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
        for (uint32_t t = 0; t < 64; t++) {
            if (t < 16) W[t] = message[t + i];
            else W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
            T1 = h + sigma1(e) + ch(e, f, g) + K[t] + W[t];
            T2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    uint32_a_free(&message_a);
    uint32_a_free(&W_a);
}

char * sha256(const char * source, unsigned int length, char * result) {
    uint32_t H[8];
    sha256core(bytes_to_binb(source, length), length * 8, H);
    return binb_to_hex(H, 8, result);
}

char * reverse_sha256(const char * hash, int min_length, int max_length, const char * character_set) {
    int character_set_length = strlen(character_set), str_length;
    char * str_hash;
    char * str;
    int id, i, t, range, remainder;
    uint32_t max_id = pow(character_set_length, max_length);
    int done = 0;
    char * result = NULL;

#pragma omp parallel private(id, i, t, range, remainder, str, str_hash)
{
    str_hash = (char *)malloc(65 * sizeof(char));
    str = (char *)malloc((max_length + 1) * sizeof(char));
    str[max_length] = '\0';

#pragma omp for schedule(dynamic)
    for (id = 0; id < max_id; ++id) {
#pragma omp flush (done)
        if (done) continue;

        str_length = id == 0 ? 0 : (floor(log(id) / log(character_set_length)) + 1);
        t = 2 * max_length - str_length - 1;

        for (i = 0; i < max_length - str_length; ++i)
            str[i] = character_set[0];

        for (remainder = id; remainder && i < max_length; ++i) {
            str[t - i] = character_set[remainder % character_set_length];
            remainder /= character_set_length;
        }

        range = max_length - (str_length > min_length ? str_length : min_length);
        for (i = 0; i <= range; ++i) {
            if (strcmp(hash, sha256(str + i, max_length - i, str_hash)) == 0) {
                result = (char *)malloc((max_length - i + 1) * sizeof(char));
                strncpy(result, str + i, max_length - i);
                result[max_length - i] = '\0';
                done = 1;
                break;
            }
        }
    }

    free(str_hash);
    free(str);
} /* end parallel */

    return result;
}
