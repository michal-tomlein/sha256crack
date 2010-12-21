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

uint * bytes_to_binb(const uint * bytes, uint length, uint binb[]) {
    uint mask = (1 << 8) - 1;
    length *= 8;
    for (uint i = 0; i < length; i += 8) {
        binb[i >> 5] |= (bytes[i / 8] & mask) << (32 - 8 - i % 32);
    }
    return binb;
}

uint * binb_to_hex(const uint binb[], uint * result) {
    const uint hex_tab[] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    for (uint i = 0; i < (8 * 4); ++i) {
        result[2 * i] = hex_tab[(binb[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF];
        result[2 * i + 1] = hex_tab[(binb[i >> 2] >> ((3 - i % 4) * 8)) & 0xF];
    }
    result[64] = 0;
    return result;
}

uint rotr(uint x, int n) {
    if (n < 32) return (x >> n) | (x << (32 - n));
    return x;
}

uint ch(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint sigma0(uint x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint sigma1(uint x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint gamma0(uint x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint gamma1(uint x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void sha256core(uint message[], uint source_binlength, uint H[]) {
    uint K[] = {
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
    uint W[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    uint a, b, c, d, e, f, g, h;
    uint T1, T2;
    const uint message_length = 16;
    message[source_binlength >> 5] |= 0x80 << (24 - source_binlength % 32);
    message[message_length - 1] = source_binlength;
    for (uint i = 0; i < message_length; i += 16) {
        a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
        for (uint t = 0; t < 64; t++) {
            if (t < 16) W[t] = message[t + i];
            else W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
            T1 = h + sigma1(e) + ch(e, f, g) + K[t] + W[t];
            T2 = sigma0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
}

uint * sha256(const uint * source, uint length, uint * result) {
    uint H[8];
    uint binb[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    sha256core(bytes_to_binb(source, length, binb), length * 8, H);
    return binb_to_hex(H, result);
}

__kernel void reverse_sha256(__global char * hash,
                             uint min_length,
                             uint max_length,
                             __global char * character_set,
                             int character_set_length,
                             uint offset,
                             __global char * output) {
    uint str_hash[65];
    uint str[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int i, j, range, remainder, match;
    size_t id = get_global_id(0) + offset;
    int str_length = id == 0 ? 0 : (floor(log((float)id) / log((float)character_set_length)) + 1);
    if (str_length > max_length)
        str_length = max_length;
    int t = 2 * max_length - str_length - 1;

    for (i = 0; i < max_length - str_length; ++i)
        str[i] = character_set[0];

    for (remainder = id; remainder && i < max_length; ++i) {
        str[t - i] = character_set[remainder % character_set_length];
        remainder /= character_set_length;
    }

    range = max_length - (str_length > min_length ? str_length : min_length);
    for (i = 0; i <= range; ++i) {
        match = 1;

        sha256(str + i, max_length - i, str_hash);
        for (j = 0; j < 64; ++j) {
            if (hash[j] != str_hash[j]) {
                match = 0;
                break;
            }
        }

        if (match)
            for (j = 0; j < max_length - i; ++j)
                output[j] = str[i + j];
    }
}
