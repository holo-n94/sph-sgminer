/*
 * Sha1coinHash kernel implementation.
 *
 * Copyright (C) 2014 holo-n94 (◆Holo/////n94)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef SHA1COIN_CL
#define SHA1COIN_CL


// constants and initial values defined in SHA-1
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define DEC32BE(x) SWAP4(*(const __global uint *) (x))

#define ROL32(x, n) rotate(x, (uint) n)
#define Ch(x,y,z) bitselect(z,y,x)
#define Maj(x,y,z) Ch((x^z),y,z)

// W[t] = ROL32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
#define SHABLK(t) (W[t&15] = ROL32(W[(t+13)&15] ^ W[(t+8)&15] ^ W[(t+2)&15] ^ W[t&15], 1))

#define _RS0(v,w,x,y,z,i) { z += Ch(w,x,y) + i + K0 + ROL32(v,5);  w=ROL32(w,30); }
#define _RS00(v,w,x,y,z)  { z += Ch(w,x,y) + K0 + ROL32(v,5);  w=ROL32(w,30); }
#define _RS1(v,w,x,y,z,i) { z += (w^x^y) + i + K1 + ROL32(v,5);  w=ROL32(w,30); }

#define _R0(v,w,x,y,z,t) { z += Ch(w,x,y) + SHABLK(t) + K0 + ROL32(v,5);  w=ROL32(w,30); }
#define _R1(v,w,x,y,z,t) { z += (w^x^y) + SHABLK(t) + K1 + ROL32(v,5);  w=ROL32(w,30); }
#define _R2(v,w,x,y,z,t) { z += Maj(w,x,y) + SHABLK(t) + K2 + ROL32(v,5);  w=ROL32(w,30); }
#define _R3(v,w,x,y,z,t) { z += (w^x^y) + SHABLK(t) + K3 + ROL32(v,5);  w=ROL32(w,30); }


__constant static const char b64t[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};


__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global unsigned char* input, volatile __global uint* output, const ulong target, const uint trip_target)
{
	uint hash[5];
	unsigned char str[38], *tripkey;
	uint hash3 = 0, hash4 = 0;
	uint W[16];
	uint a, b, c, d, e;

	uint gid = get_global_id(0);

	// generate prehash, input 80bytes to SHA-1 20bytes hash

	// SHA-1 initialization constants
	hash[0] = H0;
	hash[1] = H1;
	hash[2] = H2;
	hash[3] = H3;
	hash[4] = H4;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	// input[0] to input[63], 64bytes, 512bits
	W[0] = DEC32BE(input);
	W[1] = DEC32BE(input + 4);
	W[2] = DEC32BE(input + 8);
	W[3] = DEC32BE(input + 12);
	W[4] = DEC32BE(input + 16);
	W[5] = DEC32BE(input + 20);
	W[6] = DEC32BE(input + 24);
	W[7] = DEC32BE(input + 28);
	W[8] = DEC32BE(input + 32);
	W[9] = DEC32BE(input + 36);
	W[10] = DEC32BE(input + 40);
	W[11] = DEC32BE(input + 44);
	W[12] = DEC32BE(input + 48);
	W[13] = DEC32BE(input + 52);
	W[14] = DEC32BE(input + 56);
	W[15] = DEC32BE(input + 60);

	// round 0 to 15
	_RS0(a, b, c, d, e, W[0]);
	_RS0(e, a, b, c, d, W[1]);
	_RS0(d, e, a, b, c, W[2]);
	_RS0(c, d, e, a, b, W[3]);
	_RS0(b, c, d, e, a, W[4]);
	_RS0(a, b, c, d, e, W[5]);
	_RS0(e, a, b, c, d, W[6]);
	_RS0(d, e, a, b, c, W[7]);
	_RS0(c, d, e, a, b, W[8]);
	_RS0(b, c, d, e, a, W[9]);
	_RS0(a, b, c, d, e, W[10]);
	_RS0(e, a, b, c, d, W[11]);
	_RS0(d, e, a, b, c, W[12]);
	_RS0(c, d, e, a, b, W[13]);
	_RS0(b, c, d, e, a, W[14]);
	_RS0(a, b, c, d, e, W[15]);

	// round 16 to 19
	_R0(e, a, b, c, d, 16);
	_R0(d, e, a, b, c, 17);
	_R0(c, d, e, a, b, 18);
	_R0(b, c, d, e, a, 19);

	// round 20 to 39
	_R1(a, b, c, d, e, 20);
	_R1(e, a, b, c, d, 21);
	_R1(d, e, a, b, c, 22);
	_R1(c, d, e, a, b, 23);
	_R1(b, c, d, e, a, 24);
	_R1(a, b, c, d, e, 25);
	_R1(e, a, b, c, d, 26);
	_R1(d, e, a, b, c, 27);
	_R1(c, d, e, a, b, 28);
	_R1(b, c, d, e, a, 29);
	_R1(a, b, c, d, e, 30);
	_R1(e, a, b, c, d, 31);
	_R1(d, e, a, b, c, 32);
	_R1(c, d, e, a, b, 33);
	_R1(b, c, d, e, a, 34);
	_R1(a, b, c, d, e, 35);
	_R1(e, a, b, c, d, 36);
	_R1(d, e, a, b, c, 37);
	_R1(c, d, e, a, b, 38);
	_R1(b, c, d, e, a, 39);

	// round 40 to 59
	_R2(a, b, c, d, e, 40);
	_R2(e, a, b, c, d, 41);
	_R2(d, e, a, b, c, 42);
	_R2(c, d, e, a, b, 43);
	_R2(b, c, d, e, a, 44);
	_R2(a, b, c, d, e, 45);
	_R2(e, a, b, c, d, 46);
	_R2(d, e, a, b, c, 47);
	_R2(c, d, e, a, b, 48);
	_R2(b, c, d, e, a, 49);
	_R2(a, b, c, d, e, 50);
	_R2(e, a, b, c, d, 51);
	_R2(d, e, a, b, c, 52);
	_R2(c, d, e, a, b, 53);
	_R2(b, c, d, e, a, 54);
	_R2(a, b, c, d, e, 55);
	_R2(e, a, b, c, d, 56);
	_R2(d, e, a, b, c, 57);
	_R2(c, d, e, a, b, 58);
	_R2(b, c, d, e, a, 59);

	// round 60 to 79
	_R3(a, b, c, d, e, 60);
	_R3(e, a, b, c, d, 61);
	_R3(d, e, a, b, c, 62);
	_R3(c, d, e, a, b, 63);
	_R3(b, c, d, e, a, 64);
	_R3(a, b, c, d, e, 65);
	_R3(e, a, b, c, d, 66);
	_R3(d, e, a, b, c, 67);
	_R3(c, d, e, a, b, 68);
	_R3(b, c, d, e, a, 69);
	_R3(a, b, c, d, e, 70);
	_R3(e, a, b, c, d, 71);
	_R3(d, e, a, b, c, 72);
	_R3(c, d, e, a, b, 73);
	_R3(b, c, d, e, a, 74);
	_R3(a, b, c, d, e, 75);
	_R3(e, a, b, c, d, 76);
	_R3(d, e, a, b, c, 77);
	_R3(c, d, e, a, b, 78);
	_R3(b, c, d, e, a, 79);

	// Add the working vars back into state
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	// input[64] to input[75], 12bytes, 96bits
	W[0] = DEC32BE(input + 64);
	W[1] = DEC32BE(input + 68);
	W[2] = DEC32BE(input + 72);

	W[3] = SWAP4(gid);		// nonce
	W[4] = 0x80000000;		// padding

/*
	for (int i = 5; i < 15; i++){
		W[i] = 0;
	}
*/

	W[15] = 640;		// bits of Message Block (80 bytes * 8 bits)

	// round 0 to 15
	_RS0(a, b, c, d, e, W[0]);
	_RS0(e, a, b, c, d, W[1]);
	_RS0(d, e, a, b, c, W[2]);
	_RS0(c, d, e, a, b, W[3]);
	_RS0(b, c, d, e, a, W[4]);
	_RS00(a, b, c, d, e);		// W[5] == 0
	_RS00(e, a, b, c, d);		// W[6] == 0
	_RS00(d, e, a, b, c);		// W[7] == 0
	_RS00(c, d, e, a, b);		// W[8] == 0
	_RS00(b, c, d, e, a);		// W[9] == 0
	_RS00(a, b, c, d, e);		// W[10] == 0
	_RS00(e, a, b, c, d);		// W[11] == 0
	_RS00(d, e, a, b, c);		// W[12] == 0
	_RS00(c, d, e, a, b);		// W[13] == 0
	_RS00(b, c, d, e, a);		// W[14] == 0
	_RS0(a, b, c, d, e, W[15]);

	// round 16 to 19
	W[0] = ROL32(W[2] ^ W[0], 1);		// (t, W[t-3], W[t-8], W[t-14], W[t-16]) = (16, W[13]==0, W[8]==0, W[2], W[0])
	_RS0(e, a, b, c, d, W[0]);

	W[1] = ROL32(W[3] ^ W[1], 1);		// (17, W[14]==0, W[9]==0, W[3], W[1])
	_RS0(d, e, a, b, c, W[1]);

	W[2] = ROL32(W[15] ^ W[4] ^ W[2], 1);		// (18, W[15], W[10]==0, W[4], W[2])
	_RS0(c, d, e, a, b, W[2]);

	W[3] = ROL32(W[0] ^ W[3], 1);		// (19, W[0], W[11]==0, W[5]==0, W[3])
	_RS0(b, c, d, e, a, W[3]);

	// round 20 to 31
	W[4] = ROL32(W[1] ^ W[4], 1);		// (20, W[1], W[12]==0, W[6]==0, W[4])
	_RS1(a, b, c, d, e, W[4]);

	W[5] = ROL32(W[2], 1);				// (21, W[2], W[13]==0, W[7]==0, W[5]==0)
	_RS1(e, a, b, c, d, W[5]);

	W[6] = ROL32(W[3], 1);				// (22, W[3], W[14]==0, W[8]==0, W[6]==0)
	_RS1(d, e, a, b, c, W[6]);

	W[7] = ROL32(W[4] ^ W[15], 1);		// (23, W[4], W[15], W[9]==0, W[7]==0)
	_RS1(c, d, e, a, b, W[7]);

	W[8] = ROL32(W[5] ^ W[0], 1);		// (24, W[5], W[0], W[10]==0, W[8]==0)
	_RS1(b, c, d, e, a, W[8]);

	W[9] = ROL32(W[6] ^ W[1], 1);		// (25, W[6], W[1], W[11]==0, W[9]==0)
	_RS1(a, b, c, d, e, W[9]);

	W[10] = ROL32(W[7] ^ W[2], 1);		// (26, W[7], W[2], W[12]==0, W[10]==0)
	_RS1(e, a, b, c, d, W[10]);

	W[11] = ROL32(W[8] ^ W[3], 1);		// (27, W[8], W[3], W[13]==0, W[11]==0)
	_RS1(d, e, a, b, c, W[11]);

	W[12] = ROL32(W[9] ^ W[4], 1);		// (28, W[9], W[4], W[14]==0, W[12]==0)
	_RS1(c, d, e, a, b, W[12]);

	W[13] = ROL32(W[10] ^ W[5] ^ W[15], 1);		// (29, W[10], W[5], W[15], W[13]==0)
	_RS1(b, c, d, e, a, W[13]);

	W[14] = ROL32(W[11] ^ W[6] ^ W[0], 1);		// (30, W[11], W[6], W[0], W[14]==0)
	_RS1(a, b, c, d, e, W[14]);

	W[15] = ROL32(W[12] ^ W[7] ^ W[1] ^ W[15], 1);		// (31, W[12], W[7], W[1], W[15])
	_RS1(e, a, b, c, d, W[15]);

	// round 32 to 39
	_R1(d, e, a, b, c, 32);
	_R1(c, d, e, a, b, 33);
	_R1(b, c, d, e, a, 34);
	_R1(a, b, c, d, e, 35);
	_R1(e, a, b, c, d, 36);
	_R1(d, e, a, b, c, 37);
	_R1(c, d, e, a, b, 38);
	_R1(b, c, d, e, a, 39);

	// round 40 to 59
	_R2(a, b, c, d, e, 40);
	_R2(e, a, b, c, d, 41);
	_R2(d, e, a, b, c, 42);
	_R2(c, d, e, a, b, 43);
	_R2(b, c, d, e, a, 44);
	_R2(a, b, c, d, e, 45);
	_R2(e, a, b, c, d, 46);
	_R2(d, e, a, b, c, 47);
	_R2(c, d, e, a, b, 48);
	_R2(b, c, d, e, a, 49);
	_R2(a, b, c, d, e, 50);
	_R2(e, a, b, c, d, 51);
	_R2(d, e, a, b, c, 52);
	_R2(c, d, e, a, b, 53);
	_R2(b, c, d, e, a, 54);
	_R2(a, b, c, d, e, 55);
	_R2(e, a, b, c, d, 56);
	_R2(d, e, a, b, c, 57);
	_R2(c, d, e, a, b, 58);
	_R2(b, c, d, e, a, 59);

	// round 60 to 79
	_R3(a, b, c, d, e, 60);
	_R3(e, a, b, c, d, 61);
	_R3(d, e, a, b, c, 62);
	_R3(c, d, e, a, b, 63);
	_R3(b, c, d, e, a, 64);
	_R3(a, b, c, d, e, 65);
	_R3(e, a, b, c, d, 66);
	_R3(d, e, a, b, c, 67);
	_R3(c, d, e, a, b, 68);
	_R3(b, c, d, e, a, 69);
	_R3(a, b, c, d, e, 70);
	_R3(e, a, b, c, d, 71);
	_R3(d, e, a, b, c, 72);
	_R3(c, d, e, a, b, 73);
	_R3(b, c, d, e, a, 74);
	_R3(a, b, c, d, e, 75);
	_R3(e, a, b, c, d, 76);
	_R3(d, e, a, b, c, 77);
	_R3(c, d, e, a, b, 78);
	_R3(b, c, d, e, a, 79);

	// Add the working vars back into state
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;


	// convert prehash into Base64 ASCII str
	str[0] = b64t[hash[0] >> 26];
	str[1] = b64t[(hash[0] >> 20) & 63];
	str[2] = b64t[(hash[0] >> 14) & 63];
	str[3] = b64t[(hash[0] >> 8) & 63];
	str[4] = b64t[(hash[0] >> 2) & 63];
	str[5] = b64t[(hash[0] << 4 | hash[1] >> 28) & 63];
	str[6] = b64t[(hash[1] >> 22) & 63];
	str[7] = b64t[(hash[1] >> 16) & 63];
	str[8] = b64t[(hash[1] >> 10) & 63];
	str[9] = b64t[(hash[1] >> 4) & 63];
	str[10] = b64t[(hash[1] << 2 | hash[2] >> 30) & 63];
	str[11] = b64t[(hash[2] >> 24) & 63];
	str[12] = b64t[(hash[2] >> 18) & 63];
	str[13] = b64t[(hash[2] >> 12) & 63];
	str[14] = b64t[(hash[2] >> 6) & 63];
	str[15] = b64t[hash[2] & 63];
	str[16] = b64t[hash[3] >> 26];
	str[17] = b64t[(hash[3] >> 20) & 63];
	str[18] = b64t[(hash[3] >> 14) & 63];
	str[19] = b64t[(hash[3] >> 8) & 63];
	str[20] = b64t[(hash[3] >> 2) & 63];
	str[21] = b64t[(hash[3] << 4 | hash[4] >> 28) & 63];
	str[22] = b64t[(hash[4] >> 22) & 63];
	str[23] = b64t[(hash[4] >> 16) & 63];
	str[24] = b64t[(hash[4] >> 10) & 63];
	str[25] = b64t[(hash[4] >> 4) & 63];
	str[26] = str[0];
	str[27] = str[1];
	str[28] = str[2];
	str[29] = str[3];
	str[30] = str[4];
	str[31] = str[5];
	str[32] = str[6];
	str[33] = str[7];
	str[34] = str[8];
	str[35] = str[9];
	str[36] = str[10];
	str[37] = 0;


	// calculate tripcode
	for (int k = 0; k < 26; k++){
		tripkey = str + k;

		// SHA-1 initialization constants
		hash[0] = H0;
		hash[1] = H1;
		hash[2] = H2;
		hash[3] = H3;
		hash[4] = H4;

		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];
		e = hash[4];

		// tripkey[0] to tripkey[11], 12byte, 96bits
		W[0] = tripkey[0] << 24 | tripkey[1] << 16 | tripkey[2] << 8 | tripkey[3];
		W[1] = tripkey[4] << 24 | tripkey[5] << 16 | tripkey[6] << 8 | tripkey[7];
		W[2] = tripkey[8] << 24 | tripkey[9] << 16 | tripkey[10] << 8 | tripkey[11];

		W[3] = 0x80000000;		// padding

/*
		for (int i = 4; i < 15; i++){
			W[i] = 0;
		}
*/

		W[15] = 96;		// bits of Message Block (12 bytes * 8 bits)

		// round 0 to 15
		_RS0(a, b, c, d, e, W[0]);
		_RS0(e, a, b, c, d, W[1]);
		_RS0(d, e, a, b, c, W[2]);
		_RS0(c, d, e, a, b, W[3]);
		_RS00(b, c, d, e, a);		// W[4] == 0
		_RS00(a, b, c, d, e);		// W[5] == 0
		_RS00(e, a, b, c, d);		// W[6] == 0
		_RS00(d, e, a, b, c);		// W[7] == 0
		_RS00(c, d, e, a, b);		// W[8] == 0
		_RS00(b, c, d, e, a);		// W[9] == 0
		_RS00(a, b, c, d, e);		// W[10] == 0
		_RS00(e, a, b, c, d);		// W[11] == 0
		_RS00(d, e, a, b, c);		// W[12] == 0
		_RS00(c, d, e, a, b);		// W[13] == 0
		_RS00(b, c, d, e, a);		// W[14] == 0
		_RS0(a, b, c, d, e, W[15]);

		// round 16 to 19
		W[0] = ROL32(W[2] ^ W[0], 1);		// (t, W[t-3], W[t-8], W[t-14], W[t-16]) = (16, W[13]==0, W[8]==0, W[2], W[0])
		_RS0(e, a, b, c, d, W[0]);

		W[1] = ROL32(W[3] ^ W[1], 1);		// (17, W[14]==0, W[9]==0, W[3], W[1])
		_RS0(d, e, a, b, c, W[1]);

		W[2] = ROL32(W[15] ^ W[2], 1);		// (18, W[15], W[10]==0, W[4]==0, W[2])
		_RS0(c, d, e, a, b, W[2]);

		W[3] = ROL32(W[0] ^ W[3], 1);		// (19, W[0], W[11]==0, W[5]==0, W[3])
		_RS0(b, c, d, e, a, W[3]);

		// round 20 to 31
		W[4] = ROL32(W[1], 1);				// (20, W[1], W[12]==0, W[6]==0, W[4]==0)
		_RS1(a, b, c, d, e, W[4]);

		W[5] = ROL32(W[2], 1);				// (21, W[2], W[13]==0, W[7]==0, W[5]==0)
		_RS1(e, a, b, c, d, W[5]);

		W[6] = ROL32(W[3], 1);				// (22, W[3], W[14]==0, W[8]==0, W[6]==0)
		_RS1(d, e, a, b, c, W[6]);

		W[7] = ROL32(W[4] ^ W[15], 1);		// (23, W[4], W[15], W[9]==0, W[7]==0)
		_RS1(c, d, e, a, b, W[7]);

		W[8] = ROL32(W[5] ^ W[0], 1);		// (24, W[5], W[0], W[10]==0, W[8]==0)
		_RS1(b, c, d, e, a, W[8]);

		W[9] = ROL32(W[6] ^ W[1], 1);		// (25, W[6], W[1], W[11]==0, W[9]==0)
		_RS1(a, b, c, d, e, W[9]);

		W[10] = ROL32(W[7] ^ W[2], 1);		// (26, W[7], W[2], W[12]==0, W[10]==0)
		_RS1(e, a, b, c, d, W[10]);

		W[11] = ROL32(W[8] ^ W[3], 1);		// (27, W[8], W[3], W[13]==0, W[11]==0)
		_RS1(d, e, a, b, c, W[11]);

		W[12] = ROL32(W[9] ^ W[4], 1);		// (28, W[9], W[4], W[14]==0, W[12]==0)
		_RS1(c, d, e, a, b, W[12]);

		W[13] = ROL32(W[10] ^ W[5] ^ W[15], 1);		// (29, W[10], W[5], W[15], W[13]==0)
		_RS1(b, c, d, e, a, W[13]);

		W[14] = ROL32(W[11] ^ W[6] ^ W[0], 1);		// (30, W[11], W[6], W[0], W[14]==0)
		_RS1(a, b, c, d, e, W[14]);

		W[15] = ROL32(W[12] ^ W[7] ^ W[1] ^ W[15], 1);		// (31, W[12], W[7], W[1], W[15])
		_RS1(e, a, b, c, d, W[15]);

		// round 32 to 39
		_R1(d, e, a, b, c, 32);
		_R1(c, d, e, a, b, 33);
		_R1(b, c, d, e, a, 34);
		_R1(a, b, c, d, e, 35);
		_R1(e, a, b, c, d, 36);
		_R1(d, e, a, b, c, 37);
		_R1(c, d, e, a, b, 38);
		_R1(b, c, d, e, a, 39);

		// round 40 to 59
		_R2(a, b, c, d, e, 40);
		_R2(e, a, b, c, d, 41);
		_R2(d, e, a, b, c, 42);
		_R2(c, d, e, a, b, 43);
		_R2(b, c, d, e, a, 44);
		_R2(a, b, c, d, e, 45);
		_R2(e, a, b, c, d, 46);
		_R2(d, e, a, b, c, 47);
		_R2(c, d, e, a, b, 48);
		_R2(b, c, d, e, a, 49);
		_R2(a, b, c, d, e, 50);
		_R2(e, a, b, c, d, 51);
		_R2(d, e, a, b, c, 52);
		_R2(c, d, e, a, b, 53);
		_R2(b, c, d, e, a, 54);
		_R2(a, b, c, d, e, 55);
		_R2(e, a, b, c, d, 56);
		_R2(d, e, a, b, c, 57);
		_R2(c, d, e, a, b, 58);
		_R2(b, c, d, e, a, 59);

		// round 60 to 79
		_R3(a, b, c, d, e, 60);
		_R3(e, a, b, c, d, 61);
		_R3(d, e, a, b, c, 62);
		_R3(c, d, e, a, b, 63);
		_R3(b, c, d, e, a, 64);
		_R3(a, b, c, d, e, 65);
		_R3(e, a, b, c, d, 66);
		_R3(d, e, a, b, c, 67);
		_R3(c, d, e, a, b, 68);
		_R3(b, c, d, e, a, 69);
		_R3(a, b, c, d, e, 70);
		_R3(e, a, b, c, d, 71);
		_R3(d, e, a, b, c, 72);
		_R3(c, d, e, a, b, 73);
		_R3(b, c, d, e, a, 74);
		_R3(a, b, c, d, e, 75);
		_R3(e, a, b, c, d, 76);
		_R3(d, e, a, b, c, 77);
		_R3(c, d, e, a, b, 78);
		_R3(b, c, d, e, a, 79);

		// Add the working vars back into state
		hash[0] += a;

		// compare with trip-target
		if (hash[0] >> 2 == trip_target){
			output[output[0xFF]++] = SWAP4(gid);
			return;
		}

/*
		hash[1] += b;
		hash[2] += c;
*/
		hash[3] += d;
		hash[4] += e;

		// XOR SHA-1 hashes
		hash3 ^= hash[3];
		hash4 ^= hash[4];
	}

	// compare with target
	bool result = ((((ulong) SWAP4(hash4) << 32) | SWAP4(hash3)) <= target);

	if (result){
		output[output[0xFF]++] = SWAP4(gid);
	}
}

#endif	// SHA1COIN_CL
