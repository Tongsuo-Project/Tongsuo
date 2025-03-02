#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"
#include "crypto/nonlinearwbsm4.h" 
#ifndef OPENSSL_NO_SM4
static int test_nonlinearwbsm4(void)
{
    /* 测试密钥 */
    static const uint8_t k[16] = {
        0x78, 0x3b, 0xd7, 0x63, 0x47, 0xaa, 0x6b, 0xfe,
        0x47, 0x05, 0xeb, 0xc0, 0x60, 0x4a, 0x7b, 0x0f
    };

    /* 测试明文 */
    static const uint8_t input[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    /* 预期加密结果 */
    static const uint8_t expected[16] = {
        0x32, 0x1a, 0xfa, 0xbb, 0x83, 0x47, 0xb5, 0xff,
        0x94, 0x07, 0x78, 0xb4, 0xf6, 0xdf, 0x1b, 0x37
    };

    WB_SM4_Tables *tables = NULL;
    uint8_t encrypted[16];
    uint8_t decrypted[16];
    int ret = 0;

    /* 分配白盒表内存 */
    tables = malloc(sizeof(WB_SM4_Tables));
    if (!TEST_ptr(tables))
        goto err;
    memset(tables, 0, sizeof(WB_SM4_Tables));

    /* 生成白盒密码表 */
    Nonlinearwbsm4_generate_tables(k, tables);

    /* 执行白盒加密 */
    Nonlinearwbsm4_encrypt(input, encrypted, tables);
    if (!TEST_mem_eq(encrypted, sizeof(encrypted), expected, sizeof(expected)))
        goto err;

    /* 执行白盒解密 */
    Nonlinearwbsm4_decrypt(encrypted, decrypted, tables);
    if (!TEST_mem_eq(decrypted, sizeof(decrypted), input, sizeof(input)))
        goto err;

    ret = 1;
err:
    free(tables);
    return ret;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_NONLINEARWBSM4
    ADD_TEST(test_nonlinearwbsm4);
#endif
    return 1;
}
