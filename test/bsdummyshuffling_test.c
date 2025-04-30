#include <stdio.h>
#include "crypto/bsdummyshuffling.h"



// KEY = "samplekey1234567" 73616d706c656b657931323334353637
// 748074076200569c9deeb1dec18a7910 74 80 74 07 62 00 56 9c 9d ee b1 de c1 8a 79 10
// 7711451c1922325b858cb74b6d5db070 77 11 45 1c 19 22 32 5b 85 8c b7 4b 6d 5d b0 70

int main(void) {
    unsigned char plaintext[16*64]={0x74, 0x80, 0x74, 0x07, 0x62, 0x00, 0x56, 0x9c, 0x9d, 0xee, 0xb1, 0xde, 0xc1, 0x8a, 0x79, 0x10};
    unsigned char expected[16*64]= {0x77, 0x11, 0x45, 0x1c, 0x19, 0x22, 0x32, 0x5b, 0x85, 0x8c, 0xb7, 0x4b, 0x6d, 0x5d, 0xb0, 0x70};
    unsigned char ciphertext[16*64];
    
    SM4_128(ciphertext, plaintext);
    for (int i=0; i<16; i++)
        if (ciphertext[i]!=expected[i]){
            printf("failed\n");
            break;
        }
    return 0;
}