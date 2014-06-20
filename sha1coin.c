/*
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

#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#define ROL32(_val32, _nBits) (((_val32)<<(_nBits))|((_val32)>>(32-(_nBits))))

// W[t] = ROL32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
#define SHABLK(t) (W[t&15] = ROL32(W[(t+13)&15] ^ W[(t+8)&15] ^ W[(t+2)&15] ^ W[t&15], 1))

#define _RS0(v,w,x,y,z,i) { z += ((w&(x^y))^y) + i + 0x5A827999 + ROL32(v,5);  w=ROL32(w,30); }
#define _RS00(v,w,x,y,z)  { z += ((w&(x^y))^y) + 0x5A827999 + ROL32(v,5);  w=ROL32(w,30); }
#define _RS1(v,w,x,y,z,i) { z += (w^x^y) + i + 0x6ED9EBA1 + ROL32(v,5);  w=ROL32(w,30); }

#define _R0(v,w,x,y,z,t) { z += ((w&(x^y))^y) + SHABLK(t) + 0x5A827999 + ROL32(v,5);  w=ROL32(w,30); }
#define _R1(v,w,x,y,z,t) { z += (w^x^y) + SHABLK(t) + 0x6ED9EBA1 + ROL32(v,5);  w=ROL32(w,30); }
#define _R2(v,w,x,y,z,t) { z += (((w|x)&y)|(w&x)) + SHABLK(t) + 0x8F1BBCDC + ROL32(v,5);  w=ROL32(w,30); }
#define _R3(v,w,x,y,z,t) { z += (w^x^y) + SHABLK(t) + 0xCA62C1D6 + ROL32(v,5);  w=ROL32(w,30); }


void sha1hash12byte(const char *input, uint32_t *m_state)
{
	uint32_t W[16];
	uint32_t a, b, c, d, e;
	int i;

	// SHA-1 initialization constants
	m_state[0] = 0x67452301;
	m_state[1] = 0xEFCDAB89;
	m_state[2] = 0x98BADCFE;
	m_state[3] = 0x10325476;
	m_state[4] = 0xC3D2E1F0;

	a = m_state[0];
	b = m_state[1];
	c = m_state[2];
	d = m_state[3];
	e = m_state[4];

	// input[0] to input[11], 12byte, 96bits
	for (i = 0; i < 3; i++){
		W[i] = input[4*i+0] << 24 | input[4*i+1] << 16 | input[4*i+2] << 8 | input[4*i+3];
	}

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
	m_state[0] += a;
	m_state[1] += b;
	m_state[2] += c;
	m_state[3] += d;
	m_state[4] += e;

}


void sha1hash80byte(const uint8_t *input, uint32_t *m_state)
{
	uint32_t W[16];
	uint32_t a, b, c, d, e;
	int i;

	// SHA-1 initialization constants
	m_state[0] = 0x67452301;
	m_state[1] = 0xEFCDAB89;
	m_state[2] = 0x98BADCFE;
	m_state[3] = 0x10325476;
	m_state[4] = 0xC3D2E1F0;

	a = m_state[0];
	b = m_state[1];
	c = m_state[2];
	d = m_state[3];
	e = m_state[4];

	// input[0] to input[63], 64bytes, 512bits
	for (i = 0; i < 16; i++){
		W[i] = input[4*i+0] << 24 | input[4*i+1] << 16 | input[4*i+2] << 8 | input[4*i+3];
	}

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
	m_state[0] += a;
	m_state[1] += b;
	m_state[2] += c;
	m_state[3] += d;
	m_state[4] += e;

	a = m_state[0];
	b = m_state[1];
	c = m_state[2];
	d = m_state[3];
	e = m_state[4];

	// input[64] to input[79], 16bytes, 128bits
	for (i = 0; i < 4; i++){
		W[i] = input[4*i+64] << 24 | input[4*i+65] << 16 | input[4*i+66] << 8 | input[4*i+67];
	}

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
	m_state[0] += a;
	m_state[1] += b;
	m_state[2] += c;
	m_state[3] += d;
	m_state[4] += e;

}


void b64enc(const uint32_t *hash, char *str)
{
	const char b64t[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
	};

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
	str[26] = b64t[(hash[4] << 2) & 63];
	str[27] = 0;

}


void test_trip(char *str, uint32_t *hash)
{
	const char trip64t[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '/'
	};

	char tripkey[13], trip[13];

	memcpy(tripkey, str, 12);
	tripkey[12] = '\0';

	trip[0] = trip64t[hash[0] >> 26];
	trip[1] = trip64t[(hash[0] >> 20) & 63];
	trip[2] = trip64t[(hash[0] >> 14) & 63];
	trip[3] = trip64t[(hash[0] >> 8) & 63];
	trip[4] = trip64t[(hash[0] >> 2) & 63];
	trip[5] = trip64t[(hash[0] << 4 | hash[1] >> 28) & 63];
	trip[6] = trip64t[(hash[1] >> 22) & 63];
	trip[7] = trip64t[(hash[1] >> 16) & 63];
	trip[8] = trip64t[(hash[1] >> 10) & 63];
	trip[9] = trip64t[(hash[1] >> 4) & 63];
	trip[10] = trip64t[(hash[1] << 2 | hash[2] >> 30) & 63];
	trip[11] = trip64t[(hash[2] >> 24) & 63];
	trip[12] = '\0';

	if (! strncmp(trip_target, trip, strlen(trip_target))){
		applog(LOG_NOTICE, "tripkey: #%s, trip: %s (yay!!!)", tripkey, trip);

		fprintf(fp_trip, "%s\t#%s\n", trip, tripkey);
		fflush(fp_trip);
	}
}


/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}


#define SWAP4(x) (((x&0xff)<<24) | (((x>>8)&0xff)<<16) | (((x>>16)&0xff)<<8) | ((x>>24)&0xff))

inline void sha1coin_hash(void *state, const void *input)
{
	uint32_t hash[5];
	char str[38];
	uint32_t ohash[8] = {0};
	int i;

	trip_candidate_found = 0;

	// generate prehash
	sha1hash80byte(input, hash);

	// convert prehash into Base64 ASCII str
	b64enc(hash, str);

	// use first 26 chars, and rotate
	memcpy(&str[26], str, 11);

	// calculate tripcode
	for (i = 0; i < 26; i++){
		sha1hash12byte(str + i, hash);

		if (hash[0] >> 2 == trip_target_uint){
			trip_candidate_found++;
			test_trip(str + i, hash);
		}

		ohash[3] ^= SWAP4(hash[0]);
		ohash[4] ^= SWAP4(hash[1]);
		ohash[5] ^= SWAP4(hash[2]);
		ohash[6] ^= SWAP4(hash[3]);
		ohash[7] ^= SWAP4(hash[4]);
	}

	memcpy(state, ohash, 32);
}


static const uint32_t diff1targ = 0x0000ffff;

/* Used externally as confirmation of correct OCL code */
int sha1coin_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
	sha1coin_hash(ohash, data);
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
				(long unsigned int)Htarg,
				(long unsigned int)diff1targ,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}


void sha1coin_regenhash(struct work *work)
{
	uint32_t data[20];
	uint32_t *nonce = (uint32_t *)(work->data + 76);
	uint32_t *ohash = (uint32_t *)(work->hash);

	be32enc_vect(data, (const uint32_t *)work->data, 19);
	data[19] = htobe32(*nonce);
	sha1coin_hash(ohash, data);
}


bool scanhash_sha1coin(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
	unsigned char *pdata, unsigned char __maybe_unused *phash1,
	unsigned char __maybe_unused *phash, const unsigned char *ptarget,
	uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		sha1coin_hash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
					(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}

