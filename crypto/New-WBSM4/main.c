#include "wbsm4.h"


void test1(){
    int i;
    // uint8_t msg[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    // // uint8_t key[16] = {0};
    // uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    uint8_t msg[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    // uint8_t input[16] = {0};
    // uint8_t output[16] = {0};
    // uint8_t ciphertext[16] = {0};
    uint8_t cip[16] = {0};
    uint8_t sm4_out[16] = {0};

    sm4_context ctx;

    clock_t start1 = 0;
    clock_t start2 = 0;
    clock_t start3 = 0;
    clock_t finish1 = 0;
    clock_t finish2 = 0;
    clock_t finish3 = 0;
    double total_time1 = 0;
    double total_time2 = 0;
    double total_time3 = 0;

    unsigned char *wb = NULL;
    // WBLUT* wb = (unsigned char*)malloc(sizeof(WBLUT));
    //输出参数
    size_t whitebox_len = 0;
    

    start1 = clock();
    wbsm4_gen(key,wb,&whitebox_len);

    wb = malloc(whitebox_len);
    
    wbsm4_gen(key,wb,&whitebox_len);

    //printf("Gen White Box Done!\n");
    finish1 = clock();
    total_time1 = (double)(finish1 - start1) / CLOCKS_PER_SEC;

    // for(i=0;i<16;i++){
    //     input[i] = Ex_IN_E[i][msg[i]];
    // }

    // start2 = clock();
    // wbsm4_encrypt(input,output);
    // finish2 = clock();

    // for(i=0;i<16;i++){
    //     ciphertext[i] = Ex_OUT_D[i][output[i]];
    //     printf("0x%02x ",ciphertext[i]);
    // }
    // printf("\n");

    start2 = clock();
    
    wbsm4_encrypt(msg,cip,wb);
    finish2 = clock();

    total_time2 = (double)(finish2 - start2) / CLOCKS_PER_SEC;
    for(i=0;i<16;i++){
        
        printf("0x%02x ",cip[i]);
    }
    printf("\n");

    start3 = clock();
    for(i=0;i<10000;i++){
        wbsm4_encrypt(msg,cip,wb);
    }
    finish3 = clock();
    
    total_time3 = (double)(finish3 - start3) / CLOCKS_PER_SEC;

    printf("Gen white box LUTS time: %f ms\n", total_time1*1000);
    printf("Encrypt time: %f ms\n", total_time2*1000);
    printf("Mean encrypt time: %f ms\n", total_time3/10);

    
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 1, 16, msg, sm4_out);
    for(i=0;i<16;i++){
        
        printf("0x%02x ",sm4_out[i]);
    }
    printf("\n");
}


void test2(){
    //WBLUT *wb;
}


int main(){
    test1();



    return 0;
}