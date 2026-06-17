#ifndef PSPM_H
#define PSPM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"


void emulate_cs1(polyvecl *r, const poly *c, uint8_t s1_table[L][N * 3]);

#if ETA == 4
void emulate_cs2(polyveck *r, const poly *c, uint16_t s2_table[K][N * 3]);
#else
void emulate_cs2(polyveck *r, const poly *c, uint8_t s2_table[K][N * 3]);
#endif

int emulate_ct(polyveck *r, const poly *c, const polyveck *t0);

void poly_emulate_cs(poly *r, const poly *c, sword s1_table[N * 3]);

int poly_emulate_ct(poly *r, const poly *c, const poly *t);

#endif
