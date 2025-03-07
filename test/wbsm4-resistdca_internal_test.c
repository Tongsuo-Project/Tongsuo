#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>
#include "testutil.h"
#include "crypto/sm4.h"
#include "crypto/wbsm4-resistdca.h"

static int test_wbsm4_standard(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };


    int i;
    
    uint8_t block[SM4_BLOCK_SIZE];
    uint8_t key[SM4_BLOCK_SIZE];
    for(i=0;i<SM4_BLOCK_SIZE;i++){
        key[i] = k[i];
    }

    unsigned char *wb = NULL;
    size_t whitebox_len = 0;

    wbsm4_gen(key,wb,&whitebox_len);
    wb = OPENSSL_malloc(whitebox_len);
    wbsm4_gen(key,wb,&whitebox_len);
    memcpy(block, input, SM4_BLOCK_SIZE);

    wbsm4_encrypt(block, block, wb);
    // ossl_sm4_encrypt(block, block, &key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE)){
        OPENSSL_free(wb);
        return 0;
    }
        

    wbsm4_decrypt(block, block, wb);
    // ossl_sm4_decrypt(block, block, &key);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE)){
        OPENSSL_free(wb);
        return 0;
    }
        
    OPENSSL_free(wb);
    return 1;
}


static int test_wbsm4_random_gen_tables(void){
    //比较两个白盒是否相同
    unsigned char *wb1 = NULL;
    unsigned char *wb2 = NULL;
    size_t whitebox_len1 = 0;
    size_t whitebox_len2 = 0;
    uint8_t key[SM4_BLOCK_SIZE];
    RAND_bytes(key,SM4_BLOCK_SIZE);

    wbsm4_gen(key,wb1,&whitebox_len1);
    wb1 = OPENSSL_malloc(whitebox_len1);
    wbsm4_gen(key,wb2,&whitebox_len2);
    wb2 = OPENSSL_malloc(whitebox_len2);

    wbsm4_gen(key,wb1,&whitebox_len1);
    wbsm4_gen(key,wb2,&whitebox_len2);

    if (TEST_mem_eq(wb1, whitebox_len1, wb2, whitebox_len2)){
        OPENSSL_free(wb1);
        OPENSSL_free(wb2);
        return 0;
    }
    OPENSSL_free(wb1);
    OPENSSL_free(wb2);
    return 1;
}

#ifndef OPENSSL_NO_SM4
static int test_wbsm4_random_key_and_input(void){

    uint8_t input[SM4_BLOCK_SIZE];
    uint8_t k[SM4_BLOCK_SIZE];
    
    uint8_t block_sm4[SM4_BLOCK_SIZE];
    uint8_t block_wbsm4[SM4_BLOCK_SIZE];

    unsigned char *wb = NULL;
    size_t whitebox_len = 0;
    SM4_KEY key;

    RAND_bytes(input,SM4_BLOCK_SIZE);
    RAND_bytes(k,SM4_BLOCK_SIZE);

    ossl_sm4_set_key(k, &key);
    wbsm4_gen(k,wb,&whitebox_len);
    wb = OPENSSL_malloc(whitebox_len);
    wbsm4_gen(k,wb,&whitebox_len);
    

    memcpy(block_sm4, input, SM4_BLOCK_SIZE);
    memcpy(block_wbsm4, input, SM4_BLOCK_SIZE);

    ossl_sm4_encrypt(block_sm4, block_sm4, &key);
    wbsm4_encrypt(block_wbsm4, block_wbsm4, wb);

    if (!TEST_mem_eq(block_sm4, SM4_BLOCK_SIZE, block_wbsm4, SM4_BLOCK_SIZE)){
        OPENSSL_free(wb);
        return 0;
    }
        

    ossl_sm4_decrypt(block_sm4, block_sm4, &key);
    wbsm4_decrypt(block_wbsm4, block_wbsm4, wb);

    if (!TEST_mem_eq(block_sm4, SM4_BLOCK_SIZE, block_wbsm4, SM4_BLOCK_SIZE)){
        OPENSSL_free(wb);
        return 0;
    }
    
    OPENSSL_free(wb);
    return 1;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_wbsm4_standard);
    ADD_TEST(test_wbsm4_random_gen_tables);

#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_wbsm4_random_key_and_input);
#endif
    return 1;
}
