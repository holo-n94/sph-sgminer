#ifndef SHA1COIN_H
#define SHA1COIN_H

#include "miner.h"

extern int sha1coin_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);

extern void sha1coin_regenhash(struct work *work);

#endif	/* SHA1COIN_H */
