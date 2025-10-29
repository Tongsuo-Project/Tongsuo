
#include <string.h>
#include <openssl/tsapi.h>
#include "../sdf/sdf_local.h"
#include <openssl/sdf.h>
#include <openssl/sgd.h>

#define DEBUG
#ifdef DEBUG
    #define debug_printf(...) printf(__VA_ARGS__)
#else
    #define debug_printf(...)
#endif

//Tools
unsigned int FileWrite(char *filename,char *mode, unsigned char *buffer, size_t size){
    FILE *fp;
    unsigned int rw,rwed;
    if ((fp = fopen(filename,mode)) == NULL){
        return 0;
    }
    rwed = 0;
    while(size > rwed){
        if((rw = (unsigned int)fwrite(buffer+rwed,1,size-rwed,fp)) <= 0){
            break;
        }
        rwed += rw;
    }
    fclose(fp);

    return rwed;
}
int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		debug_printf("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		debug_printf("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			debug_printf("%02x ", *(sourceData + i*rowCount + j));
		}

		debug_printf("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	debug_printf("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
	{
		debug_printf("%02x ",*(sourceData + (dataLength/rowCount)*rowCount + j));
	}

	debug_printf("\n");

	return 0;
}
unsigned int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	unsigned int rw, rwed;

	if((fp = fopen(filename, mode)) == NULL)
	{
		return 0;
	}

	rwed = 0;

	while((!feof(fp)) && (size > rwed))
	{
		if((rw = (unsigned int)fread(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}

		rwed += rw;
	}

	fclose(fp);

	return rwed;
}
void PrintRSAPublicKey(RSArefPublicKey* pubKey){
    /*
    typedef struct RSArefPublicKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    } RSArefPublicKey;
*/
    debug_printf("导出的RSA加密公钥长度: %d\n",pubKey->bits);
    debug_printf("模数m(%d bytes):\n", RSAref_MAX_LEN);
    for (int i = 0; i < RSAref_MAX_LEN; i++) {
        if (i % 16 == 0) debug_printf("\n%04x: ", i);
        debug_printf("%02X ", pubKey->m[i]);
    }
    debug_printf("\n");
    
    debug_printf("\n指数e(%d bytes):\n", RSAref_MAX_LEN);
    for (int i = 0; i < RSAref_MAX_LEN; i++) {
        if (i % 16 == 0) debug_printf("\n%04x: ", i);
        debug_printf("%02X ", pubKey->e[i]);
    }
    debug_printf("\n");
}
void PrintRSAPrivateKey(RSArefPrivateKey* priKey){
    /*
        typedef struct RSArefPrivateKey_st{
            unsigned int bits;
            unsigned char m[RSAref_MAX_LEN];
            unsigned char e[RSAref_MAX_LEN];
            unsigned char d[RSAref_MAX_LEN];
            unsigned char prime[2][RSAref_MAX_PLEN];
            unsigned char pexp[2][RSAref_MAX_PLEN];
            unsigned char coef[RSAref_MAX_PLEN];
        } RSArefPrivateKey;
    */
   debug_printf("模数m(%d bytes):\n",RSAref_MAX_LEN);
   for (int i = 0;i < RSAref_MAX_LEN;i ++){
        if(i % 16 == 0)debug_printf("\n%04x: ",i);
        debug_printf("%02X ",priKey->m[i]);
   }
   debug_printf("\n");
   debug_printf("公钥指数e(%d bytes):\n",RSAref_MAX_LEN);
   for(int i = 0;i < RSAref_MAX_LEN;i ++){
        if(i % 16 == 0)debug_printf("\n%04x: ",i);
        debug_printf("%02X ",priKey->e[i]);
   }
   debug_printf("\n");
   debug_printf("私钥指数d(%d bytes):\n",RSAref_MAX_LEN);
   for(int i = 0;i < RSAref_MAX_LEN;i ++){
        if(i % 16 == 0)debug_printf("\n%04x: ",i);
        debug_printf("%02X ",priKey->d[i]);
   }
   debug_printf("\n");
    debug_printf("质数:\n");
    for (int i = 0; i < 2; i++) {
        debug_printf("prime[%d]: ", i);
        for (size_t j = 0; j < RSAref_MAX_PLEN; j++) {
        if(j % 16 == 0)debug_printf("\n%04x: ",j);

            debug_printf("%02X ", priKey->prime[i][j]);
        }
        debug_printf("\n");
    }
    
    debug_printf("中国剩余定理指数 d mod (p-1), d mod (q-1)\n");
    for (int i = 0; i < 2; i++) {
        debug_printf("pexp[%d]: ", i);
        for (size_t j = 0; j < RSAref_MAX_PLEN; j++) {
            if(j % 16 == 0)debug_printf("\n%04x: ",j);
            debug_printf("%02X ", priKey->pexp[i][j]);
        }
        debug_printf("\n");
    }
    debug_printf("CRT系数 q^-1 mod p\n");
    for (size_t j = 0; j < RSAref_MAX_PLEN; j++) {
        if(j % 16 == 0)debug_printf("\n%04x: ",j);
        debug_printf("%02X ", priKey->coef[j]);
    }
    debug_printf("\n");
}
void PrintECCPublicKey(ECCrefPublicKey *pucPublicKey){
    /*
    typedef struct ECCrefPublicKey_st{
        unsigned int bits;
        unsigned char x[ECCref_MAX_LEN];
        unsigned char y[ECCref_MAX_LEN];
    } ECCrefPublicKey;
    */

    debug_printf("=== SM2公钥结构 ===\n");
    debug_printf("导出的SM2密钥位长: %d\n",pucPublicKey->bits);

    debug_printf("椭圆曲线点X坐标\n");
    for(int i = 0;i < ECCref_MAX_LEN;i ++){
        if(i % 16 == 0){
            debug_printf("\n");
        }
        debug_printf("%02X ",pucPublicKey->x[i]);
    }
    debug_printf("\n");
    debug_printf("椭圆曲线点Y坐标\n");
    for(int i = 0;i < ECCref_MAX_LEN;i ++){
        if(i % 16 == 0){
            debug_printf("\n");
        }
    debug_printf("%02X ",pucPublicKey->y[i]);
    }
    debug_printf("\n");

}
void PrintECCCipher_Smart(ECCCipher* cipher) {

    if (!cipher) {
        debug_printf("ECCCipher is NULL\n");
        return;
    }
    
    debug_printf("=== SM2密文结构 ===\n");
    debug_printf("密文数据长度 L: %u bytes\n\n", cipher->L);
    
    int x_actual_len = 0;
    for (int i = ECCref_MAX_LEN - 1; i >= 0; i--) {
        if (cipher->x[i] != 0) {
            x_actual_len = i + 1;
            break;
        }
    }
    
    debug_printf("椭圆曲线点X坐标 (实际长度: %d bytes):\n", x_actual_len);
    int x_start = ECCref_MAX_LEN - x_actual_len;
    for (int i = x_start; i < ECCref_MAX_LEN; i++) {
        if ((i - x_start) % 16 == 0 && (i - x_start) != 0) debug_printf("\n");
        debug_printf("%02x ", cipher->x[i]);
    }
    debug_printf("\n");
    
    int y_actual_len = 0;
    for (int i = ECCref_MAX_LEN - 1; i >= 0; i--) {
        if (cipher->y[i] != 0) {
            y_actual_len = i + 1;
            break;
        }
    }
    
    debug_printf("\n椭圆曲线点Y坐标 (实际长度: %d bytes):\n", y_actual_len);
    int y_start = ECCref_MAX_LEN - y_actual_len;
    for (int i = y_start; i < ECCref_MAX_LEN; i++) {
        if ((i - y_start) % 16 == 0 && (i - y_start) != 0) debug_printf("\n");
        debug_printf("%02x ", cipher->y[i]);
    }
    debug_printf("\n");
    
    debug_printf("\n哈希值M (32 bytes):\n");
    for (int i = 0; i < 32; i++) {
        if (i % 16 == 0) debug_printf("\n");
        debug_printf("%02x ", cipher->M[i]);
    }
    debug_printf("\n");
    
    debug_printf("\n密文数据C (长度: %u bytes):\n", cipher->L);
    if (cipher->L > 0) {
        unsigned char* c_ptr = cipher->C;
        for (unsigned int i = 0; i < cipher->L; i++) {
            if (i % 16 == 0) debug_printf("\n%04x: ", i);
            debug_printf("%02x ", c_ptr[i]);
        }
    } else {
        debug_printf("无密文数据\n");
    }
    debug_printf("\n");
}


#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    unsigned int alg_id;
    const char *alg_name;
} AsymAlgMapping;

static const AsymAlgMapping asym_alg_mappings[] = {
    {OSSL_SGD_RSA, "RSA"},
    {OSSL_SGD_RSA_SIGN, "RSA-SIGN"},
    {OSSL_SGD_RSA_ENC, "RSA-ENC"},
    
    {OSSL_SGD_SM2, "SM2"},
    {OSSL_SGD_SM2_1, "SM2-1"},  
    {OSSL_SGD_SM2_2, "SM2-2"},  
    {OSSL_SGD_SM2_3, "SM2-3"},  
    
    {0, NULL}
};

typedef struct {
    unsigned int alg_id;
    const char *alg_name;
} SymAlgMapping;

static const SymAlgMapping sym_alg_mappings[] = {
    {OSSL_SGD_SM1_ECB, "SM1-ECB"},
    {OSSL_SGD_SM1_CBC, "SM1-CBC"},
    {OSSL_SGD_SM1_CFB, "SM1-CFB"},
    {OSSL_SGD_SM1_OFB, "SM1-OFB"},
    {OSSL_SGD_SM1_MAC, "SM1-MAC"},
    {OSSL_SGD_SM1_CTR, "SM1-CTR"},
    
    {OSSL_SGD_SSF33_ECB, "SSF33-ECB"},
    {OSSL_SGD_SSF33_CBC, "SSF33-CBC"},
    {OSSL_SGD_SSF33_CFB, "SSF33-CFB"},
    {OSSL_SGD_SSF33_OFB, "SSF33-OFB"},
    {OSSL_SGD_SSF33_MAC, "SSF33-MAC"},
    {OSSL_SGD_SSF33_CTR, "SSF33-CTR"},
    
    {OSSL_SGD_SMS4_ECB, "SMS4-ECB"},
    {OSSL_SGD_SMS4_CBC, "SMS4-CBC"},
    {OSSL_SGD_SMS4_CFB, "SMS4-CFB"},
    {OSSL_SGD_SMS4_OFB, "SMS4-OFB"},
    {OSSL_SGD_SMS4_MAC, "SMS4-MAC"},
    {OSSL_SGD_SMS4_CTR, "SMS4-CTR"},
    {OSSL_SGD_SMS4_XTS, "SMS4-XTS"},
    
    {OSSL_SGD_SM4_ECB, "SM4-ECB"},
    {OSSL_SGD_SM4_CBC, "SM4-CBC"},
    {OSSL_SGD_SM4_CFB, "SM4-CFB"},
    {OSSL_SGD_SM4_OFB, "SM4-OFB"},
    {OSSL_SGD_SM4_MAC, "SM4-MAC"},
    {OSSL_SGD_SM4_CTR, "SM4-CTR"},
    {OSSL_SGD_SM4_XTS, "SM4-XTS"},
    
    {OSSL_SGD_ZUC_EEA3, "ZUC-EEA3"},
    {OSSL_SGD_ZUC_EIA3, "ZUC-EIA3"},
    
    {OSSL_SGD_SM7_ECB, "SM7-ECB"},
    {OSSL_SGD_SM7_CBC, "SM7-CBC"},
    {OSSL_SGD_SM7_CFB, "SM7-CFB"},
    {OSSL_SGD_SM7_OFB, "SM7-OFB"},
    {OSSL_SGD_SM7_MAC, "SM7-MAC"},
    {OSSL_SGD_SM7_CTR, "SM7-CTR"},
    
    {OSSL_SGD_DES_ECB, "DES-ECB"},
    {OSSL_SGD_DES_CBC, "DES-CBC"},
    {OSSL_SGD_DES_CFB, "DES-CFB"},
    {OSSL_SGD_DES_OFB, "DES-OFB"},
    {OSSL_SGD_DES_MAC, "DES-MAC"},
    {OSSL_SGD_DES_CTR, "DES-CTR"},
    
    {OSSL_SGD_3DES_ECB, "3DES-ECB"},
    {OSSL_SGD_3DES_CBC, "3DES-CBC"},
    {OSSL_SGD_3DES_CFB, "3DES-CFB"},
    {OSSL_SGD_3DES_OFB, "3DES-OFB"},
    {OSSL_SGD_3DES_MAC, "3DES-MAC"},
    {OSSL_SGD_3DES_CTR, "3DES-CTR"},
    
    {OSSL_SGD_AES_ECB, "AES-ECB"},
    {OSSL_SGD_AES_CBC, "AES-CBC"},
    {OSSL_SGD_AES_CFB, "AES-CFB"},
    {OSSL_SGD_AES_OFB, "AES-OFB"},
    {OSSL_SGD_AES_MAC, "AES-MAC"},
    {OSSL_SGD_AES_CTR, "AES-CTR"},
    
    {OSSL_SGD_SM6_ECB, "SM6-ECB"},
    {OSSL_SGD_SM6_CBC, "SM6-CBC"},
    {OSSL_SGD_SM6_CFB, "SM6-CFB"},
    {OSSL_SGD_SM6_OFB, "SM6-OFB"},
    {OSSL_SGD_SM6_MAC, "SM6-MAC"},
    {OSSL_SGD_SM6_CTR, "SM6-CTR"},
    
    {0, NULL} 
};


typedef struct {
    unsigned int alg_id;
    const char *alg_name;
} HashAlgMapping;

static const HashAlgMapping hash_alg_mappings[] = {
    {OSSL_SGD_SM3, "SM3"},
    {OSSL_SGD_SHA1, "SHA1"},
    {OSSL_SGD_SHA256, "SHA256"},
    {OSSL_SGD_SHA512, "SHA512"},
    {OSSL_SGD_SHA384, "SHA384"},
    {OSSL_SGD_SHA224, "SHA224"},
    {OSSL_SGD_MD5, "MD5"},
    {0, NULL} 
};


int parse_asym_alg_ability(const unsigned int asym_alg_ability[2], char *result, size_t result_size) {
    int count = 0;
    size_t offset = 0;
    

    if (result_size > 0) {
        result[0] = '\0';
    }
    
    unsigned int ability_value = asym_alg_ability[0];
    
    for (int i = 0; asym_alg_mappings[i].alg_name != NULL; i++) {
        if (ability_value & asym_alg_mappings[i].alg_id) {
            count++;
            
            if (offset < result_size) {
                int written = snprintf(result + offset, result_size - offset, 
                                     "%s%s", 
                                     (count > 1) ? ", " : "", 
                                     asym_alg_mappings[i].alg_name);
                if (written > 0) {
                    offset += written;
                }
            }
        }
    }
    
    if (asym_alg_ability[1] != 0) {
        ability_value = asym_alg_ability[1];
        for (int i = 0; asym_alg_mappings[i].alg_name != NULL; i++) {
            if (ability_value & asym_alg_mappings[i].alg_id) {
                count++;
                
                if (offset < result_size) {
                    int written = snprintf(result + offset, result_size - offset, 
                                         ", %s", 
                                         asym_alg_mappings[i].alg_name);
                    if (written > 0) {
                        offset += written;
                    }
                }
            }
        }
    }
    
    return count;
}

int parse_sym_alg_ability(unsigned int sym_alg_ability, char *result, size_t result_size) {
    int count = 0;
    size_t offset = 0;
    
    if (result_size > 0) {
        result[0] = '\0';
    }
    
    for (int i = 0; sym_alg_mappings[i].alg_name != NULL; i++) {
        if (sym_alg_ability & sym_alg_mappings[i].alg_id) {
            count++;
            
            if (offset < result_size) {
                int written = snprintf(result + offset, result_size - offset, 
                                     "%s%s", 
                                     (count > 1) ? ", " : "", 
                                     sym_alg_mappings[i].alg_name);
                if (written > 0) {
                    offset += written;
                }
            }
        }
    }
    
    return count;
}


int parse_hash_alg_ability(unsigned int hash_alg_ability, char *result, size_t result_size) {
    int count = 0;
    size_t offset = 0;
    
    if (result_size > 0) {
        result[0] = '\0';
    }
    
    for (int i = 0; hash_alg_mappings[i].alg_name != NULL; i++) {
        if (hash_alg_ability & hash_alg_mappings[i].alg_id) {
            count++;
            
            if (offset < result_size) {
                int written = snprintf(result + offset, result_size - offset, 
                                     "%s%s", 
                                     (count > 1) ? ", " : "", 
                                     hash_alg_mappings[i].alg_name);
                if (written > 0) {
                    offset += written;
                }
            }
        }
    }
    
    return count;
}

void parse_device_alg_ability(const unsigned int asym_alg_ability[2], 
                             unsigned int sym_alg_ability, 
                             unsigned int hash_alg_ability) {
    char asym_result[512] = {0};
    char sym_result[1024] = {0};
    char hash_result[512] = {0};
    
    int asym_count = parse_asym_alg_ability(asym_alg_ability, asym_result, sizeof(asym_result));
    int sym_count = parse_sym_alg_ability(sym_alg_ability, sym_result, sizeof(sym_result));
    int hash_count = parse_hash_alg_ability(hash_alg_ability, hash_result, sizeof(hash_result));
    
    printf("=== 设备算法能力解析结果 ===\n");
    printf("非对称算法能力值: [0x%08x, 0x%08x]\n", asym_alg_ability[0], asym_alg_ability[1]);
    printf("支持的非对称算法 (%d种): %s\n", asym_count, asym_result);
    printf("对称算法能力值: 0x%08x\n", sym_alg_ability);
    printf("支持的对称算法 (%d种): %s\n", sym_count, sym_result);
    printf("哈希算法能力值: 0x%08x\n", hash_alg_ability);
    printf("支持的哈希算法 (%d种): %s\n", hash_count, hash_result);
    printf("============================\n");
}


void analyze_asym_ability(const unsigned int asym_alg_ability[2]) {
    unsigned int ability = asym_alg_ability[0];
    
    printf("=== 非对称算法详细分析 ===\n");
    printf("能力值: 0x%08x\n", ability);
    
    if (ability & OSSL_SGD_RSA) {
        printf("✓ 支持RSA算法\n");
    }
    if (ability & OSSL_SGD_RSA_SIGN) {
        printf("✓ 支持RSA签名\n");
    }
    if (ability & OSSL_SGD_RSA_ENC) {
        printf("✓ 支持RSA加密\n");
    }
    
    if (ability & OSSL_SGD_SM2) {
        printf("✓ 支持SM2算法\n");
    }
    if (ability & OSSL_SGD_SM2_1) {
        printf("✓ 支持SM2-1（签名）\n");
    }
    if (ability & OSSL_SGD_SM2_2) {
        printf("✓ 支持SM2-2（加密）\n");
    }
    if (ability & OSSL_SGD_SM2_3) {
        printf("✓ 支持SM2-3（密钥交换）\n");
    }
    
    if ((ability & 0x00030700) == 0x00030700) {
        printf("✓ 支持完整的RSA和SM2功能集\n");
    }
    
    printf("==========================\n");
}


const char* SDF_GetErrorString(int err) {
    switch (err) {
        case OSSL_SDR_OK: return "SDR_OK";
        case OSSL_SDR_UNKNOWNERR: return "SDR_UNKNOWERR";
        case OSSL_SDR_NOTSUPPORT: return "SDR_NOTSUPPORT";
        case OSSL_SDR_COMMFAIL: return "SDR_COMMFAIL";
        case OSSL_SDR_HARDFAIL: return "SDR_HARDFAIL";
        case OSSL_SDR_OPENDEVICE: return "SDR_OPENDEVICE";
        case OSSL_SDR_OPENSESSION: return "SDR_OPENSESSION";
        case OSSL_SDR_PARDENY: return "SDR_PARDENY";
        case OSSL_SDR_KEYNOTEXIST: return "SDR_KEYNOTEXIST";
        case OSSL_SDR_ALGNOTSUPPORT: return "SDR_ALGNOTSUPPORT";
        case OSSL_SDR_ALGMODNOTSUPPORT: return "SDR_ALGMODNOTSUPPORT";
        case OSSL_SDR_PKOPERR: return "SDR_PKOPERR";
        case OSSL_SDR_SKOPERR: return "SDR_SKOPERR";
        case OSSL_SDR_SIGNERR: return "SDR_SIGNERR";
        case OSSL_SDR_VERIFYERR: return "SDR_VERIFYERR";
        case OSSL_SDR_SYMOPERR: return "SDR_SYMOPERR";
        case OSSL_SDR_STEPERR: return "SDR_STEPERR";
        case OSSL_SDR_FILESIZEERR: return "SDR_FILESIZEERR";
        case OSSL_SDR_FILENOTEXIST: return "SDR_FILENOEXIST";
        case OSSL_SDR_FILEOFSERR: return "SDR_FILEOFSERR";
        case OSSL_SDR_KEYTYPEERR: return "SDR_KEYTYPEERR";
        case OSSL_SDR_KEYERR: return "SDR_KEYERR";
        case OSSL_SDR_ENCDATAERR: return "SDR_ENCDATAERR";
        case OSSL_SDR_RANDERR: return "SDR_RANDERR";
        case OSSL_SDR_PRKRERR: return "SDR_PRKRERR";
        case OSSL_SDR_MACERR: return "SDR_MACERR";
        case OSSL_SDR_FILEEXISTS: return "SDR_FILEEXISTS";
        case OSSL_SDR_FILEWERR: return "SDR_FILEWERR";
        case OSSL_SDR_NOBUFFER: return "SDR_NOBUFFER";
        case OSSL_SDR_INARGERR: return "SDR_INARGERR";
        case OSSL_SDR_OUTARGERR: return "SDR_OUTARGERR";
        // case OSSL_SDR_USERIDERR: return "SDR_USERIDERR";


        //  // 通用错误
        // case SWR_INVALID_PARAMETERS:
        //     return "Invalid parameters";
        // case SWR_FILE_ALREADY_EXIST:
        //     return "File already exists";
        // case SWR_SEM_TIMEOUT:
        //     return "Semaphore timeout";
        // case SWR_CONFIG_ERR:
        //     return "Configuration error";
            
        // // 硬件错误
        // case SWR_CARD_UNKNOWERR:
        //     return "Unknown hardware error";
        // case SWR_CARD_NOTSUPPORT:
        //     return "Unsupported interface call";
        // case SWR_CARD_COMMFALL:
        //     return "Device communication failure";
        // case SWR_CARD_HARDFALL:
        //     return "Crypto module no response";
        // case SWR_CARD_OPENDEVICE:
        //     return "Open device failed";
        // case SWR_CARD_OPENSESSION:
        //     return "Create session failed";
        // case SWR_CARD_PARDENY:
        //     return "No private key access permission";
        // case SWR_CARD_KEYNOTEXIST:
        //     return "Non-existent key call";
        // case SWR_CARD_ALGNOTSUPPORT:
        //     return "Unsupported algorithm call";
        // case SWR_CARD_ALGMODNOTSUPPORT:
        //     return "Unsupported algorithm mode call";
        // case SWR_CARD_PKOPERR:
        //     return "Public key operation failed";
        // case SWR_CARD_SKOPERR:
        //     return "Private key operation failed";
        // case SWR_CARD_SIGNERR:
        //     return "Signature operation failed";
        // case SWR_CARD_VERIFYERR:
        //     return "Signature verification failed";
        // case SWR_CARD_SYMOPERR:
        //     return "Symmetric algorithm operation failed";
        // case SWR_CARD_STEPERR:
        //     return "Multi-step operation sequence error";
        // case SWR_CARD_FILESIZEERR:
        //     return "File size exceeds limit";
        // case SWR_CARD_FILENOEXIST:
        //     return "Specified file does not exist";
        // case SWR_CARD_FILEOFSERR:
        //     return "File offset error";
        // case SWR_CARD_KEYTYPEERR:
        //     return "Key type error";
        // case SWR_CARD_KEYERR:
        //     return "Key error";
        // case SWR_CARD_BUFFER_TOO_SMALL:
        //     return "Buffer too small for parameters";
        // case SWR_CARD_DATA_PAD:
        //     return "Data not properly padded";
        // case SWR_CARD_DATA_SIZE:
        //     return "Plaintext/ciphertext length does not meet algorithm requirements";
        // case SWR_CARD_CRYPTO_NOT_INIT:
        //     return "Crypto operation not initialized";
        // case SWR_CARD_MANAGEMENT_DENY:
        //     return "Management permission denied";
        // case SWR_CARD_OPERATION_DENY:
        //     return "Operation permission denied";
        // case SWR_CARD_DEVICE_STATUS_ERR:
        //     return "Device status does not satisfy operation";
        // case SWR_CARD_LOGIN_ERR:
        //     return "Login failed";
        // case SWR_CARD_USERID_ERR:
        //     return "User ID number/quantity error";
        // case SWR_CARD_PARAMENT_ERR:
        //     return "Parameter error";
            
        // // 读卡器错误
        // case SWR_CARD_READER_PIN_ERR:
        //     return "PIN password error";
        // case SWR_CARD_READER_NO_CARD:
        //     return "IC card not inserted";
        // case SWR_CARD_READER_CARD_INSERT:
        //     return "IC card insertion direction error or not in place";
        // case SWR_CARD_READER_CARD_TYPE:
        //     return "IC card type error";
        default:
            // 如果不是自定义错误码，返回原始错误描述
            return SDF_GetErrorString(err);
    }
}
// TSAPI_*
int  TSAPI_Device(){
    void *hDevice = NULL;
    int ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret == OSSL_SDR_OK) {
        printf("OpenDevice: %s\n", SDF_GetErrorString(ret));
        ret = TSAPI_SDF_CloseDevice(hDevice);
        if (ret == OSSL_SDR_OK){
            printf("CloseDevice: %s\n", SDF_GetErrorString(ret));
        }else{
            printf("CloseDevice failed: %s\n", SDF_GetErrorString(ret));
        }
    } else {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
    }
    return ret;
}
int  TSAPI_Session(){
    unsigned int  ret = 0;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret != OSSL_SDR_OK) {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if (ret == OSSL_SDR_OK){
        printf("OpenSession: %s\n", SDF_GetErrorString(ret));
    }
    else
    {
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_CloseSession(hSession);
    hSession = NULL;
    if (ret != OSSL_SDR_OK){
        printf("CloseSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
cleanup:
    if(hSession){
        TSAPI_SDF_CloseSession(hSession);
    }
    if(hDevice){
        TSAPI_SDF_CloseDevice(hDevice);
    }
    return ret;
}
int TSAPI_GetDeviceInfo(){
    int ret = 1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if (ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    DEVICEINFO deviceInfo;
    ret = TSAPI_SDF_GetDeviceInfo(hSession, &deviceInfo);
    if (ret == 0) {
        printf("\n========== GetDeviceInfo: %s ==========\n", SDF_GetErrorString(ret));
        printf("IssuerName: %s\n", deviceInfo.IssuerName);
        printf("SerialNumber: %s\n", deviceInfo.SerialNumber);
        printf("FirmwareVersion: %s\n", deviceInfo.FirmwareVersion);
        printf("DeviceVersion: %08x\n", deviceInfo.DeviceVersion);
        printf("StandardVersion: %d\n", deviceInfo.StandardVersion);
        printf("AsymAlgAbility: [%08x, %08x]\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
        printf("SymAlgAbility: %08x\n", deviceInfo.SymAlgAbility);
        printf("HashAlgAbility: %08x\n", deviceInfo.HashAlgAbility);
        printf("BufferSize: %d\n", deviceInfo.BufferSize);
        printf("===============================================\n");

        #ifdef DEBUG
        parse_device_alg_ability(deviceInfo.AsymAlgAbility, deviceInfo.SymAlgAbility, deviceInfo.HashAlgAbility);
        analyze_asym_ability(deviceInfo.AsymAlgAbility);
        #endif
    } else {
        printf("Failed GetDeviceInfo: %s\n", SDF_GetErrorString(ret));
    }
cleanup:
    if(hSession){
        TSAPI_SDF_CloseSession(hSession);
    }
    if(hDevice){
        TSAPI_SDF_CloseDevice(hDevice);
    }
    return ret;
}
int TSAPI_GenerateRandom(unsigned int uiLength){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // int uiLength = 32;
    #define MAX_RANDOM_LEN 2048
    char buf[2048];
    if(uiLength > MAX_RANDOM_LEN){
        printf("Length limit Exceeded.\nMAX_RANDOM: %d\n",MAX_RANDOM_LEN);
        uiLength = MAX_RANDOM_LEN;
    }
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if (ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_GenerateRandom(hSession, uiLength, buf);
    if (ret != OSSL_SDR_OK) {
        printf("GenerateRandom failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    printf("GenerateRandom: %s\n", SDF_GetErrorString(ret));

    for (int i = 0; i < uiLength; i++) {
        debug_printf("%02X ", (unsigned char)buf[i]);
    }
    debug_printf("\n");
    

cleanup:
    if (hSession) {
        TSAPI_SDF_CloseSession(hSession);
    }
    if (hDevice) {
        TSAPI_SDF_CloseDevice(hDevice);
    }
    return ret;
}
int TSAPI_PrivateKeyAccessRight(){
// softsdfinit -kek 1 -key 1 -pass P@ssw0rd
/*
    软实现会加载sm2enc-1.pem和sm2sign-1.pem
    用 pass（密码）对 PEM 格式的加密私钥文件进行解密，
    并把密钥内容加载到 container->enc_key 结构体中。
*/
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int KeyIndex = 1;
    char *password = "P@ssw0rd";
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession, KeyIndex, (unsigned char *)password, (unsigned int)strlen(password));
    printf("SDF_GetPrivateKeyAccessRight: %s\n", SDF_GetErrorString(ret));
    if(ret == OSSL_SDR_OK){
        int r2 = TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, KeyIndex);
        printf("SDF_ReleasePrivateKeyAccessRight: %s\n", SDF_GetErrorString(r2));
        if(r2 != OSSL_SDR_OK && ret == OSSL_SDR_OK){
            ret = r2; 
        }
    }
cleanup:
    if(hSession){
        TSAPI_SDF_CloseSession(hSession);
    }
    if(hDevice){
        TSAPI_SDF_CloseDevice(hDevice);
    }
    return ret;
}

void ExtRSAOptTest()
{
	unsigned int rv;
    void *hDevice = NULL;
    void *hSession = NULL;
	RSArefPublicKey pubKey;
	RSArefPrivateKey priKey;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int tmpLen;
	int pukLen, prkLen;


	prkLen = FileRead("data/prikey.0", "rb", (unsigned char *)&priKey, sizeof(priKey));
	if(prkLen < sizeof(RSArefPrivateKey))
	{
		printf("读私钥文件错误。\n");
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
        // PrintRSAPrivateKey(&priKey);
	}

	pukLen = FileRead("data/pubkey.0", "rb", (unsigned char *)&pubKey, sizeof(pubKey));
	if(pukLen < sizeof(RSArefPublicKey))
	{
		printf("读公钥文件错误。\n");
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
        // PrintRSAPublicKey(&pubKey);
	}

	inData[0] = 0;
    TSAPI_SDF_OpenDevice(&hDevice);
    TSAPI_SDF_OpenSession(hDevice,&hSession);
	rv = TSAPI_SDF_GenerateRandom(hSession, priKey.bits / 8 - 1, &inData[1]);
	if(rv != OSSL_SDR_OK)
	{
		printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);

	}
	else
	{
		printf("从产生随机加密数据成功。\n");

		// PrintData("随机加密数据", inData, priKey.bits / 8, 16);
	}
    #if defined(SDF_VERSION_2023)

	rv = TSAPI_ExternalPrivateKeyOperation_RSA(hSession,&priKey, inData, priKey.bits / 8, tmpData, &tmpLen);
    #endif
	if(rv != OSSL_SDR_OK)
	{
		printf("私钥运算错误，错误码[0x%08x]\n", rv);
        printf("Error String: %s\n",SDF_GetErrorString(rv));
	}
	else
	{
		printf("私钥运算成功。\n");

		// PrintData("私钥运算结果", tmpData, tmpLen, 16);
	}
    #if defined(SDF_VERSION_2023)
	rv = TSAPI_ExternalPublicKeyOperation_RSA(hSession, &pubKey, tmpData, tmpLen, outData, &tmpLen);
    #endif
    if(rv != OSSL_SDR_OK)
	{
		printf("公钥运算错误，错误码[0x%08x]\n", rv);
        printf("Error String: %s\n",SDF_GetErrorString(rv));

	}
	else
	{
		printf("公钥运算成功。\n");

		// PrintData("公钥运算结果", outData, tmpLen, 16);
	}

	if((priKey.bits / 8 == tmpLen) && (memcmp(inData, outData, priKey.bits / 8) == 0))
	{
		printf("结果比较成功。\n");
	}
	else
	{
		printf("结果比较失败。\n");
	}
}

int TSAPI_ExportSignPublicKey_RSA(unsigned int KeyIndex){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // unsigned int keyIndex = 1;
    RSArefPublicKey* pubKey = NULL;
    pubKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    if(!pubKey){
        printf("malloc pubKey failed\n");
        return -1;
    }
    memset(pubKey, 0, sizeof(RSArefPublicKey));
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    #if defined(SDF_VERSION_2023)
    ret = TSAPI_SDF_ExportSignPublicKey_RSA(hSession, KeyIndex, pubKey);
    #endif
    if(ret != OSSL_SDR_OK){
        printf("ExportSignPublicKey_RSA failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    // printf("ExportSignPublicKey_RSA: %s\n", SDF_GetErrorString(ret));

    PrintRSAPublicKey(pubKey);

    char filename[256];
    sprintf(filename,"signpubkey_rsa.%d",KeyIndex);
    FileWrite(filename,"wb+",(unsigned char *)pubKey,sizeof(pubKey));
    debug_printf("Encpubkey_rsa saved to signpubkey_rsa.%d\n",KeyIndex);
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    if(pubKey){ free(pubKey);} 
    return ret;
}

void ExtECCSignTest()
{
    void *hDevice = NULL;
    void* hSessionHandle = NULL;
	int rv;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	unsigned char inData[512], tmpData[512];
	int pukLen, prkLen;

    rv = TSAPI_SDF_OpenDevice(&hDevice);
    if(rv != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(rv));
        return ;
    }
    rv = TSAPI_SDF_OpenSession(hDevice, &hSessionHandle);
    if(rv != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(rv));
        return ;
    }

	prkLen = FileRead("data/prikey_ecc.0", "rb", (unsigned char *)&priKey, sizeof(ECCrefPrivateKey));
	if(prkLen < sizeof(ECCrefPrivateKey))
	{
		printf("读私钥文件错误。\n");
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
	}

	pukLen = FileRead("data/pubkey_ecc.0", "rb", (unsigned char *)&pubKey, sizeof(ECCrefPublicKey));
	if(pukLen < sizeof(ECCrefPublicKey))
	{
		printf("读公钥文件错误。\n");
		printf("\n按任意键继续...");
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
	}

	memset(inData, 0, sizeof(inData));

	rv = TSAPI_SDF_GenerateRandom(hSessionHandle, priKey.bits / 8 - 1, &inData[1]);
	if(rv != OSSL_SDR_OK)
	{
		printf("产生随机签名数据错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("产生随机签名数据成功。\n");

		PrintData("随机签名数据", inData, priKey.bits / 8, 16);
	}

	memset(tmpData, 0, sizeof(tmpData));
    // typedef int (*SDF_ExternalSign_ECC)(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    #if defined(SDF_VERSION_2023)
	rv = TSAPI_ExternalSign_ECC(hSessionHandle,OSSL_SGD_SM2_1, &priKey, inData, priKey.bits/8, (ECCSignature *)tmpData);
	if(rv != OSSL_SDR_OK)
	{
		printf("签名运算错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("签名运算成功。\n");

		PrintData("私钥签名运算结果", tmpData, sizeof(ECCSignature), 16);
	}
    #endif
	rv = TSAPI_SDF_ExternalVerify_ECC(hSessionHandle, OSSL_SGD_SM2_1, &pubKey, inData, priKey.bits/8, (ECCSignature *)tmpData);
	if(rv != OSSL_SDR_OK)
	{
		printf("验证签名运算错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("验证签名运算成功。\n");
	}


}

void ExtECCOptTest()
{
    void *hDevice = NULL;
    void *hSessionHandle = NULL;
	int rv;
    #define ECCref_MAX_CIPHER_LEN			136
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int outDataLen;
	int pukLen, prkLen;
	unsigned int inPlainLen;

    rv = TSAPI_SDF_OpenDevice(&hDevice);
    if(rv != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(rv));
        return ;
    }
    rv = TSAPI_SDF_OpenSession(hDevice, &hSessionHandle);
    if(rv != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(rv));
        return ;
    }

	prkLen = FileRead("data/prikey_ecc.0", "rb", (unsigned char *)&priKey, sizeof(priKey));
	if(prkLen < sizeof(ECCrefPrivateKey))
	{
		printf("读私钥文件错误。\n");
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
	}

	pukLen = FileRead("data/pubkey_ecc.0", "rb", (unsigned char *)&pubKey, sizeof(pubKey));
	if(pukLen < sizeof(ECCrefPublicKey))
	{
		printf("读公钥文件错误。\n");
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
	}

	//通过生成随机数从而设定明文数据长度
	rv = TSAPI_SDF_GenerateRandom(hSessionHandle, 1, &inData[0]);
	if(rv != OSSL_SDR_OK)
	{
		printf("产生随机数错误，错误码[0x%08x]\n", rv);
	}

	inPlainLen = (inData[0] % ECCref_MAX_CIPHER_LEN) + 1;

	memset(inData, 0, sizeof(inData));

	rv = TSAPI_SDF_GenerateRandom(hSessionHandle, inPlainLen, &inData[0]);
	if(rv != OSSL_SDR_OK)
	{
		printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("产生随机加密数据成功。\n");

		PrintData("随机加密数据", inData, inPlainLen, 16);
	}

	memset(tmpData, 0, sizeof(tmpData));

	rv = TSAPI_SDF_ExternalEncrypt_ECC(hSessionHandle, OSSL_SGD_SM2_3, &pubKey, inData, inPlainLen, (ECCCipher *)tmpData);
	if(rv != OSSL_SDR_OK)
	{
		printf("公钥钥运算错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("公钥运算成功。\n");
		PrintData("公钥运算结果", tmpData, sizeof(tmpData), 16);
	}

	memset(outData, 0, sizeof(outData));
	outDataLen = sizeof(outData);
    #if defined(SDF_VERSION_2023)
	rv = TSAPI_ExternalDecrypt_ECC(hSessionHandle,OSSL_SGD_SM2_3, &priKey, (ECCCipher *)tmpData, outData, &outDataLen);
	if(rv != OSSL_SDR_OK)
	{
		printf("私钥运算错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("私钥运算成功。\n");

		PrintData("私钥运算结果", outData, outDataLen, 16);
	}

	if((inPlainLen != outDataLen) || (memcmp(inData, outData, outDataLen) != 0))
	{
		printf("结果比较失败。\n");
	}
	else
	{
		printf("结果比较成功。\n");
	}
    #endif
}

int TSAPI_ExportEncPublic_RSA(unsigned int KeyIndex){
    int ret = -1;
    void* hDevice = NULL;
    void* hSession = NULL;
    // unsigned int keyIndex = 1;
    RSArefPublicKey* pubKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    if(!pubKey){
        printf("malloc pubKey failed\n");
        return -1;
    }
    memset(pubKey, 0, sizeof(RSArefPublicKey));
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;

    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession, KeyIndex, pubKey);
    if(ret != OSSL_SDR_OK){
        printf("ExportEncPublicKey_RSA failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    PrintRSAPublicKey(pubKey);
    char filename[256];
    sprintf(filename,"encpubkey_rsa.%d",KeyIndex);
    FileWrite(filename,"wb+",(unsigned char *)pubKey,sizeof(pubKey));
    debug_printf("Encpubkey_rsa saved to encpubkey_rsa.%d\n",KeyIndex);
    // printf("ExportEncPublicKey_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    if(pubKey){ free(pubKey);} 
    return ret;
}
int TSAPI_GenerateKeyWithIPK_RSA(unsigned int KeyIndex){
    // 生成会话密钥并用内部RSA公钥加密输出
    // 应用场景：同一台加密机（HSM/SDF设备）上运行多个业务应用或进程，
    //          这些应用需要相互安全传递会话密钥，但密钥不能暴露给设备外部。
    /*
        密钥分三级：持久密钥，会话密钥，临时密钥
    内部的RSA公钥私钥对属于持久密钥：
        私钥在生成后会直接写入硬件安全模块（HSM/加密机/安全芯片）内部的受保护存储区。
    写入后：
    - 私钥不会导出到外部，也无法被普通业务系统读取或导出。
    - 只有硬件内部能使用私钥进行签名、解密等操作，外部只能通过keyIndex等引用方式调用。
    - 这样可以最大限度保证私钥安全，防止泄露。
    
    这里由于没有厂商库，GmSSL也没有软实现生成RSA密钥对的功能。为了模拟硬件：
    在sdf_defs.c里定义实现工具函数：SDF_GenerateKeyPair_RSA 生成公私钥对

    这里GmSSL的子项目softSDF提供了softsdfinit工具，使用当前目录下的.pem文件来模拟过程。
    */
    
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    
    // 密码设备存储的密钥对的索引值
    // unsigned int IPKIndex = 1;
    char *password = "P@ssw0rd";
    unsigned int keyBits = 4096;
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession, KeyIndex, (unsigned char *)password, (unsigned int)strlen(password));
    unsigned int outKeylen;
    void * hKey = NULL;
    // hKey：返回的会话密钥句柄，用于后续使用这个会话密钥
    unsigned char pucKey[512];
    // ret = GenerateKeyWithIPK_RSA(hSession, IPKIndex, keyBits, pucKey, &pubKeyLength, &hKey);
    // AES密钥长度：128位（16字节）、192位（24字节）和256位（32字节）。
    int nKeylen = 24,nKeyIndex = 1;
	ret = TSAPI_SDF_GenerateKeyWithIPK_RSA(hSession, nKeyIndex, nKeylen * 8, pucKey, &outKeylen, &hKey);
    debug_printf("会话密钥长度：%d bytes\n",outKeylen);
    for(int i = 0;i < outKeylen;i ++){
        if(i % 16 == 0){
            debug_printf("\n");
        }
        debug_printf("%02X ",pucKey[i]);
    }
    debug_printf("\n");
    char filename[256];
    sprintf(filename,"keybyipk_rsa.%d",KeyIndex);
    FileWrite(filename,"wb+",pucKey,outKeylen);
    debug_printf("SessionKey_byIPK_RSA saved to keybyipk_rsa.%d\n",KeyIndex);
    printf("GenerateKeyWithIPK_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    // if(pucKey) free(pucKey);
    // if(pubKeyLength) free(pubKeyLength);
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    return ret;
}
int TSAPI_GenerateKeyWithEPK_RSA(unsigned int KeyIndex){
    // 生成会话密钥，并用外部RSA公钥加密输出
    // 应用场景：当你需要将会话密钥安全地传递给另一个系统、设备或远程端时，
    //          必须用对方的公钥加密密钥后输出，防止密钥在传输过程中被窃取。

    int ret = -1;
    void* hDevice = NULL;
    void* hSession = NULL;
    // unsigned int KeyIndex = 1;
    unsigned char pucKey[512];
    int nKeylen = 16;

    RSArefPublicKey* pubKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
    if(!pubKey){
        printf("malloc pubKey failed\n");
        return -1;
    }
    memset(pubKey, 0, sizeof(RSArefPublicKey));
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;

    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession, KeyIndex, pubKey);
    if (ret != OSSL_SDR_OK){
	    printf("导出RSA加密公钥错误，错误码[0x%08x]\n", ret);
    }else{
        int outKeylen = sizeof(pubKey);
        void *phKeyHandle = NULL;
        ret = TSAPI_SDF_GenerateKeyWithEPK_RSA(hSession, nKeylen * 8, pubKey, pucKey, &outKeylen, &phKeyHandle);
        printf("GenerateKeyWithEPK_RSA: %s\n",SDF_GetErrorString(ret));
        debug_printf("会话密钥长度：%d bytes\n",outKeylen);
        for (int i = 0;i < outKeylen;i ++){
            if (i % 16 == 0)debug_printf("\n");
            debug_printf("%02X ",pucKey[i]);
        }
        debug_printf("\n");


        char filename[128];
        sprintf(filename, "keybyepk_rsa.%d", KeyIndex);
        FileWrite(filename, "wb+", pucKey, outKeylen);

        printf("SessionKey_byEPK_RSA saved to %s\n", filename);
        // PrintData(filename, pucKey, outKeylen, 16);
    }
    // if (nSel == menu_EPK_RSA)
	// 		{
	// 			rv = SDF_ExportEncPublicKey_RSAEx(hSessionHandle, nKeyIndex, &pubKey);
	// 			if (rv != OSSL_SDR_OK)
	// 			{
	// 				printf("导出RSA加密公钥错误，错误码[0x%08x]\n", rv);
	// 			}
	// 			else
	// 			{
	// 				rv = SDF_GenerateKeyWithEPK_RSAEx(hSessionHandle, nKeylen * 8, &pubKey, pucKey, &outKeylen, phKeyHandle);
	// 				if (rv != OSSL_SDR_OK)
	// 				{
	// 					printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
	// 				}
	// 				else
	// 				{
	// 					printf("生成会话密钥成功。\n");
	// 					printf("可以使用该密钥进行对称加解密运算测试。\n");

	// 					sprintf(filename, "data/keybyisk.%d", nKeyIndex);
	// 					FileWrite(filename, "wb+", pucKey, outKeylen);

	// 					printf("会话密钥密文已经写入文件：%s。\n", filename);
	// 					PrintData(filename, pucKey, outKeylen, 16);
	// 				}
	// 			}

cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    // if(pucPublicKey){ free(pucPublicKey);} 
    // if(pucKey){ free(pucKey);} 
    // if(pubKeyLength){ free(pubKeyLength);} 
    return ret;
}
int TSAPI_ImportKeyWithISK_RSA(unsigned int KeyIndex){
    // 导入会话密钥并用内部RSA私钥解密
    // chord to GenerateKeyWithEPK_RSA
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }


    void * phKeyHandle = NULL;
    TSAPI_SDF_GetPrivateKeyAccessRight(hSession, KeyIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    
    
    int nKeylen = 16;
    int keyindex = 1;
    RSArefPublicKey *pubkey = malloc(sizeof(RSArefPublicKey));
    memset(pubkey,0,sizeof(pubkey));
    ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession,keyindex,pubkey);
    unsigned char pucKey[512];
    memset(pucKey,0,sizeof(pucKey));

    unsigned int outKeyLength;
    // outKeylen = sizeof(pucKey);
    outKeyLength = 128;
    char filename[256];
    sprintf(filename,"keybyepk_rsa.%d",KeyIndex);
    unsigned int prkLen = FileRead(filename, "rb", (unsigned char *)&pucKey, sizeof(pucKey));
	if(prkLen < sizeof(outKeyLength))
	{
        printf("Cannot find %s\n",filename);
        printf("Please GenerateKeywithEPK_RSA first\n");
		goto cleanup;
	}
	else
	{
		printf("Read %s OK\n",filename);
	}
    // ExportEncPublicKey_RSA(hSession, KeyIndex, pucPublicKey);
    // GenerateKeyWithEPK_RSA(hSession, KeyBits, AlgID, pucPublicKey, pucKey, &phKeyHandle);
    // ret = ImportKeyWithISK_RSA(hSession, ISKIndex ,pucKey ,KeyLength, phKeyHandle);
    // phKeyHandle = NULL;
    debug_printf("会话密钥长度：%d bytes\n",outKeyLength);
    for(int i = 0;i < outKeyLength;i ++){
        if (i % 16 == 0)debug_printf("\n");
        debug_printf("%02X ",pucKey[i]);
    }
    debug_printf("\n");
	ret = TSAPI_SDF_ImportKeyWithISK_RSA(hSession, KeyIndex, pucKey, outKeyLength, &phKeyHandle);

    printf("ImportKeyWithISK_RSA: %s\n", SDF_GetErrorString(ret));
cleanup:
    // if(pucKey) free(pucKey);
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    return ret;
}
int TSAPI_ExportSignPublicKey_ECC(unsigned int KeyIndex){
    // 导出密码设备内部存储的指定索引位置的ECC签名公钥
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // unsigned int KeyIndex = 1;
    ECCrefPublicKey *pucPublicKey = NULL;
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if(!pucPublicKey){
        printf("malloc public key failed\n");
        return -1;
    }
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    PrintECCPublicKey(pucPublicKey);
    char filename[256];
    sprintf(filename,"signpubkey_ecc.%d",KeyIndex);
    FileWrite(filename,"wb+",(unsigned char *)pucPublicKey,sizeof(pucPublicKey));
    debug_printf("Signpubkey_ecc saved to encpubkey_ecc.%d\n",KeyIndex);
    printf("ExportSignPublicKey_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    return ret;
}
int TSAPI_ExportEncPublicKey_ECC(unsigned int KeyIndex){
    // 导出密码设备内部存储的指定索引位置的ECC加密公钥
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if(!pucPublicKey){ printf("malloc public key failed\n"); return -1; }
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    if(ret != OSSL_SDR_OK){ printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    PrintECCPublicKey(pucPublicKey);
    char filename[256];
    sprintf(filename,"encpubkey_ecc.%d",KeyIndex);
    FileWrite(filename,"wb+",(unsigned char *)pucPublicKey,sizeof(pucPublicKey));
    debug_printf("Encpubkey_ecc saved to encpubkey_ecc.%d\n",KeyIndex);
    // printf("ExportEncPublicKey_ECC: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    if(pucPublicKey){ free(pucPublicKey);} 
    return ret;
}
int TSAPI_GenerateKeyWithIPK_ECC(unsigned int KeyIndex) {
    // 生成会话密钥并用内部ECC私钥加密输出
    int ret = 1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // int nKeyIndex = 3;
    int nKeylen = 24; // 生成 192 位的会话密钥
    void * phKeyHandle = NULL; // 会话密钥句柄
    unsigned char ECC_pucKey[512] = {0}; // 缓冲区，用于存储加密的会话密钥
    unsigned char passwd[] = "P@ssw0rd"; // 私钥访问密码

    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret != OSSL_SDR_OK) {
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if (ret != OSSL_SDR_OK) {
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession, KeyIndex, passwd, (unsigned int)strlen(passwd));
    if (ret != OSSL_SDR_OK) {
        printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_GenerateKeyWithIPK_ECC(hSession, KeyIndex, nKeylen * 8, (ECCCipher *)ECC_pucKey, &phKeyHandle);
    if (ret != OSSL_SDR_OK) {
        printf("GenerateKeyWithIPK_ECC failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    PrintECCCipher_Smart((ECCCipher*)ECC_pucKey);
    char filename[256];
	sprintf(filename, "keybyipk_ecc.%d", KeyIndex);
	FileWrite(filename, "wb+", ECC_pucKey, sizeof(ECCCipher));
    printf("SessionKey_byIPK_ECC saved to %s\n",filename);
    printf("GenerateKeyWithIPK_ECC: %s\n",SDF_GetErrorString(ret));

cleanup:
    if (phKeyHandle) {
        ret = TSAPI_SDF_DestroyKey(hSession, phKeyHandle);
        if (ret != OSSL_SDR_OK) {
            printf("DestroyKey failed: %s\n", SDF_GetErrorString(ret));
        }
    }

    if (hSession) {
        ret = TSAPI_SDF_CloseSession(hSession);
        if (ret != OSSL_SDR_OK) {
            printf("CloseSession failed: %s\n", SDF_GetErrorString(ret));
        }
    }

    if (hDevice) {
        ret = TSAPI_SDF_CloseDevice(hDevice);
        if (ret != OSSL_SDR_OK) {
            printf("CloseDevice failed: %s\n", SDF_GetErrorString(ret));
        }
    }

    return ret;
}
    
int TSAPI_GenerateKeyWithEPK_ECC(unsigned int KeyIndex){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiAlgID = 0x00020800;  // SM2加密方案
    ECCrefPublicKey *pucPublicKey = NULL;
    ECCCipher *pucKey = NULL;
    void *phKeyHandle = NULL;
    unsigned int nKeylen = 16;  // 192位会话密钥
    
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){ 
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){ 
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    
    pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
    if (!pucPublicKey) {
        printf("malloc pucPublicKey failed\n");
        ret = -1;
        goto cleanup;
    }
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
    
    size_t max_cipher_len = sizeof(ECCCipher) + 256;  // 预留256字节给C字段
    pucKey = (ECCCipher *)malloc(max_cipher_len);
    if (!pucKey) {
        printf("malloc pucKey failed\n");
        ret = -1;
        goto cleanup;
    }
    memset(pucKey, 0, max_cipher_len);
    
    ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, KeyIndex, pucPublicKey);
    if (ret != OSSL_SDR_OK) {
        printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    
    ret = TSAPI_SDF_GenerateKeyWithEPK_ECC(hSession, nKeylen * 8, uiAlgID, pucPublicKey, pucKey, &phKeyHandle);
    printf("GenerateKeyWithEPK_ECC: %s\n", SDF_GetErrorString(ret));
    
    if (ret == OSSL_SDR_OK) {
        PrintECCCipher_Smart(pucKey);
        
        char filename[128];
        sprintf(filename, "keybyepk_ecc.%d", KeyIndex);
        FILE* fp = fopen(filename, "wb");
        if (fp) {
            size_t fixed_size = sizeof(ECCCipher) - sizeof(unsigned char);
            if (fwrite(pucKey, 1, fixed_size, fp) != fixed_size) {
                printf("写入固定部分失败\n");
            }
            
            if (pucKey->L > 0) {
                if (fwrite(pucKey->C, 1, pucKey->L, fp) != pucKey->L) {
                    printf("写入可变部分失败\n");
                }
            }
            
            fclose(fp);
            printf("密文已写入文件: %s\n", filename);
        } else {
            printf("无法创建文件: %s\n", filename);
        }
        
        // 打印文件大小
        FILE* fp_check = fopen(filename, "rb");
        if (fp_check) {
            fseek(fp_check, 0, SEEK_END);
            long file_size = ftell(fp_check);
            printf("文件大小: %ld bytes\n", file_size);
            fclose(fp_check);
        }
    }

cleanup:
    // 清理资源
    if (pucKey) { 
        free(pucKey);
        pucKey = NULL;
    }
    if (pucPublicKey) { 
        free(pucPublicKey);
        pucPublicKey = NULL;
    }
    if (hSession) { 
        TSAPI_SDF_CloseSession(hSession);
        hSession = NULL;
    }
    if (hDevice) { 
        TSAPI_SDF_CloseDevice(hDevice);
        hDevice = NULL;
    }
    return ret;
}

int TSAPI_ImportKeyWithISK_ECC(unsigned int KeyIndex){
    int ret = OSSL_SDR_OK;
    void *hDevice = NULL;
    void *hSession = NULL;
    char *password = "P@ssw0rd";
    void *phKeyHandle = NULL;

    unsigned char pucKey[512];
    unsigned int outKeyLength = 128;
    unsigned int AlgID = 0x00020800;

    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if(ret != OSSL_SDR_OK){ 
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if(ret != OSSL_SDR_OK){ 
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    
    ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession, KeyIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    if(ret != OSSL_SDR_OK){ 
        printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }

    char filename[256];
    sprintf(filename,"keybyepk_ecc.%d",KeyIndex);
    unsigned int prkLen = FileRead(filename, "rb", (unsigned char *)&pucKey, sizeof(pucKey));
    if(prkLen < sizeof(outKeyLength))
    {
        printf("Cannot find %s\n",filename);
        printf("Please GenerateKeywithEPK_ECC first\n");
        goto cleanup;
    }
    else
    {
        printf("Read %s OK\n",filename);
        printf("读取的字节数: %u\n", prkLen);
    }

    ECCCipher *cipher = (ECCCipher *)malloc(sizeof(ECCCipher) + prkLen - sizeof(ECCCipher));
    if (!cipher) {
        printf("内存分配失败\n");
        goto cleanup;
    }

    // 重新读取文件内容到动态分配的内存
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("无法打开文件: %s\n", filename);
        free(cipher);
        goto cleanup;
    }

    size_t fixed_size = sizeof(ECCCipher) - sizeof(unsigned char);
    if (fread(cipher, 1, fixed_size, fp) != fixed_size) {
        printf("读取固定部分失败\n");
        fclose(fp);
        free(cipher);
        goto cleanup;
    }

    if (cipher->L > 0) {
        if (fread(cipher->C, 1, cipher->L, fp) != cipher->L) {
            printf("读取可变部分失败\n");
            fclose(fp);
            free(cipher);
            goto cleanup;
        }
    }

    fclose(fp);

    PrintECCCipher_Smart(cipher);

    ret = TSAPI_SDF_ImportKeyWithISK_ECC(hSession, KeyIndex, cipher, &phKeyHandle);
    if(ret != OSSL_SDR_OK){ 
        printf("ImportKeyWithISK_ECC failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    printf("ImportKeyWithISK_ECC: %s\n", SDF_GetErrorString(ret));

cleanup:
    if (cipher) {
        free(cipher);
    }
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    return ret;
}

int TSAPI_GenerateKeyWithKEK(unsigned int KeyIndex){
    // 生成会话密钥并用密钥加密密钥加密输出
    // 同时返回密钥句柄，加密模式为CBC模式
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    // #define SGD_SM4			0x00000400
    // #define SGD_CBC			0x02
        DEVICEINFO stDeviceInfo;
        memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));
        ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
        ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
 
        // ret = GetDeviceInfo(hSession, &stDeviceInfo);
        // if (ret != OSSL_SDR_OK)
        // {
        //     printf("获取设备信息错误，错误码[0x%08x]\n", ret);
        // }

        // int i = 1;

        // if (stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_SM1_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_SSF33_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_AES_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_DES_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_3DES_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_SM4_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_SM7_ECB\n\n", i++);
        // }
        // if (stDeviceInfo.SymAlgAbility & SGD_SM6_ECB & SGD_SYMM_ALG_MASK)
        // {
        //     printf("  %d | SGD_SM6_ECB\n\n", i++);
        // }


    unsigned int uiAlgID = OSSL_SGD_SM4_ECB;
    // unsigned int uiKEKIndex = 1;
    // unsigned char *pucKey;
    unsigned int nKeylen = 16; 
    unsigned char *pucKey;        
    unsigned int *puiKeyLength;
    pucKey = (unsigned char *)malloc(64);
    puiKeyLength = (unsigned int *)malloc(sizeof(unsigned int));
    void *phKeyHandle = NULL;
    ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession,KeyIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    if(ret != OSSL_SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_GenerateKeyWithKEK(hSession, nKeylen * 8, uiAlgID, KeyIndex, pucKey, puiKeyLength, &phKeyHandle);
    if(ret != OSSL_SDR_OK){ printf("GenerateKeyWithKEK failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    for(int i = 0;i < (*puiKeyLength);i ++){
        if(i % 16 == 0)debug_printf("\n");
        debug_printf("%02X ",pucKey[i]);
    }
    debug_printf("\n");
    
    char filename[256];
    sprintf(filename,"keybykek.%d",KeyIndex);
    FileWrite(filename,"wb+",pucKey,sizeof(pucKey));
    debug_printf("SessionKey_byKEK saved to keybykek.%d\n",KeyIndex);

    // printf("GenerateKeyWithKEK: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} if(pucKey){ free(pucKey);} if(puiKeyLength){ free(puiKeyLength);} return ret;
}
int TSAPI_ImportKeyWithKEK(unsigned int KeyIndex){
    // 导入会话密钥并用加密密钥解密
    // 先用GenerateKeyWithKEK生成会话密钥并用密钥加密密钥加密输出
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    unsigned int uiAlgID = OSSL_SGD_SM4_ECB ;
    unsigned int nkeylen = 16;
    unsigned char pucKey[512];
    unsigned int outKeyLength = 32;
    void *phKeyHandle = NULL;
    ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    TSAPI_SDF_GetPrivateKeyAccessRight(hSession,KeyIndex, (unsigned char *)"P@ssw0rd", (unsigned int)strlen("P@ssw0rd"));
    
    
    char filename[256];
    sprintf(filename,"data/keybykek.%d",KeyIndex);
    unsigned int prkLen = FileRead(filename, "rb", (unsigned char *)&pucKey, sizeof(pucKey));
	if(prkLen < sizeof(outKeyLength))
	{
        printf("Cannot find %s\n",filename);
        printf("Please GenerateKeywithKEK first\n");
		goto cleanup;
	}
	else
	{
		printf("Read %s OK\n",filename);
	}
    
    debug_printf("会话密钥长度：%d bytes\n",outKeyLength);
    for(int i = 0;i < outKeyLength;i ++){
        if(i % 16 == 0)debug_printf("\n");
        debug_printf("%02X ",pucKey[i]);
    }
    debug_printf("\n");
    ret = TSAPI_SDF_ImportKeyWithKEK(hSession, uiAlgID, KeyIndex, pucKey, outKeyLength, &phKeyHandle);
    printf("ImportKeyWithKEK: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(hSession){ TSAPI_SDF_CloseSession(hSession);} 
    if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} 
    // if(pucKey){ free(pucKey);}
    return ret;
}
// int TSAPI_DestroyKey(){
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     void *phKeyHandle = NULL;
//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

//     // 借用GenerateKeyWithKEK对KeyHandle模拟赋值
//     unsigned int uiAlgID = SGD_SM4_ECB;
//     unsigned int uiKEKIndex = 1;
//     unsigned int nkeylen = 16; 
//     unsigned char *pucKey;        
//     unsigned int *puiKeyLength;
//     pucKey = (unsigned char *)malloc(64);
//     puiKeyLength = (unsigned int *)malloc(sizeof(unsigned int));
//     GetPrivateKeyAccessRight(hSession,uiKEKIndex, (char *)"P@ssw0rd",sizeof((char *)"P@ssw0rd"));
//     ret = GenerateKeyWithKEK(hSession, nkeylen * 8, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &phKeyHandle);
//     if(ret != OSSL_SDR_OK){
//         printf("GenerateKeyWithKEK: %s\n",SDF_GetErrorString(ret));
//     }
//     ret = DestroyKey(hSession, phKeyHandle);
//     printf("DestroyKey: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} if(pucKey){ free(pucKey);} if(puiKeyLength){ free(puiKeyLength);} return ret;
// }
// int TSAPI_ExternalPublicKeyOperation_RSA(){
//     // 指定使用外部公钥对数据进行RSA运算，数据格式由应用层封装
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     // 外部RSA公钥结构
//     RSArefPublicKey *pucPublicKey = NULL;
//     unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0;
//     unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucPublicKey = (RSArefPublicKey*)malloc(sizeof(RSArefPublicKey));
//     pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int));
//     if(!pucPublicKey || !pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; }
//     memset(pucPublicKey,0,sizeof(RSArefPublicKey)); memset(pucDataInput,0x11,32); *puiOutputLength = 256;
//     ret = ExternalPublicKeyOperation_RSA(hSession, pucPublicKey, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
//     printf("ExternalPublicKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucPublicKey) free(pucPublicKey); if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} return ret;
// }
// int TSAPI_InternalPublicKeyOperation_RSA(){
//     // 使用内部指定索引的公钥对数据进行RSA运算，
//     // 索引范围仅限于内部签名密钥对，数据格式应由应用层封装

//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     /// 密码设备存储的密钥对的索引
//     unsigned int uiKeyIndex = 1;
//     // 缓冲区指针，用于存放外部输入的数据
//     unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0;
//     unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; memset(pucDataInput,0x22,32);
//     pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int)); if(!pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; } *puiOutputLength = 256;
//     ret = InternalPublicKeyOperation_RSA(hSession,uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
//     printf("InternalPublicKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} return ret;
// }
// int TSAPI_InternalPrivateKeyOperation_RSA(){
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     unsigned int uiKeyIndex = 1;
//     unsigned char *pucDataInput = NULL; unsigned int uiInputLength = 0; unsigned char *pucDataOutput = NULL; unsigned int *puiOutputLength = NULL;

//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucDataInput = (unsigned char*)malloc(32); uiInputLength = 32; memset(pucDataInput,0x33,32);
//     pucDataOutput = (unsigned char*)malloc(256); puiOutputLength = (unsigned int*)malloc(sizeof(unsigned int)); if(!pucDataInput || !pucDataOutput || !puiOutputLength){ printf("malloc failed\n"); ret = -1; goto cleanup; } *puiOutputLength = 256;
//     ret = InternalPrivateKeyOperation_RSA(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucDataOutput, puiOutputLength);
//     printf("InternalPrivateKeyOperation_RSA: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucDataInput) free(pucDataInput); if(pucDataOutput) free(pucDataOutput); if(puiOutputLength) free(puiOutputLength);
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} return ret;
// }
void IntRSAOptTest()
{
    void *hDevice = NULL;
    void *hSession = NULL;
    int ret = -1;
	int rv, keyIndex;
    keyIndex = 1;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int tmpLen, outDataLen, encKeyBits = 0, signKeyBits = 0;
	char sPrkAuthCode[128];
	RSArefPublicKey sign_PubKey;
	RSArefPublicKey enc_PubKey;
	int step = 0;
    ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_ExportSignPublicKey_RSA(hSession, keyIndex, &sign_PubKey);
			if (ret != OSSL_SDR_OK)
			{
				printf("导出签名公钥错误，错误码[0x%08x]\n", ret);
			}
			else
			{
				signKeyBits = sign_PubKey.bits;

				printf("导出签名公钥成功。\n");
			}

			ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession, keyIndex, &enc_PubKey);
			if (ret != OSSL_SDR_OK)
			{
				printf("导出加密公钥错误，错误码[0x%08x]\n", ret);
			}
			else
			{
				encKeyBits = enc_PubKey.bits;

				printf("导出加密公钥成功。\n");
			}


	ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA(hSession, keyIndex,  inData, signKeyBits / 8, tmpData, &tmpLen);
    // typedef int (*SDF_InternalPrivateKeyOperation_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    if (ret != OSSL_SDR_OK)
    {
        if (strlen(sPrkAuthCode) != 0)
        {
            TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
        }
        printf("签名私钥运算错误，错误码[0x%08x]\n", ret);
        debug_printf("Error String: %s\n",SDF_GetErrorString(ret));
    }
    else
    {
        printf("签名私钥运算成功。\n");
        PrintData("私钥运算结果", tmpData, tmpLen, 16);
    }

            memset(outData, 0, sizeof(outData));
            outDataLen = sizeof(outData);
            //  SGD_RSA_SIGN, 
            ret = TSAPI_SDF_InternalPublicKeyOperation_RSA(hSession, keyIndex,tmpData, tmpLen, outData, &outDataLen);

            if (rv != OSSL_SDR_OK)
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("签名公钥运算错误，错误码[0x%08x]\n", rv);
            }
            else
            {
                printf("签名公钥运算成功。\n");

                PrintData("公钥运算结果", outData, outDataLen, 16);
            }

            if ((outDataLen != signKeyBits / 8) || (memcmp(inData, outData, outDataLen) != 0))
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("签名公钥运算结果与明文数据比较失败。\n");
            }
            else
            {
                printf("签名公钥运算结果与明文数据比较成功。\n");
            }

        if (encKeyBits > 0)
        {
            inData[0] = 0;

            ret = TSAPI_SDF_GenerateRandom(hSession, encKeyBits / 8 - 1, &inData[1]);
            if (ret != OSSL_SDR_OK)
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("产生随机加密数据错误，错误码[0x%08x]\n", ret);
            }
            else
            {
                printf("产生随机待加密数据成功。\n");
                PrintData("随机加密数据", inData, encKeyBits / 8, 16);
            }

            memset(tmpData, 0, sizeof(tmpData));
            tmpLen = sizeof(tmpData);


            //  SGD_RSA_ENC,
            ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA(hSession, keyIndex,inData, encKeyBits / 8, tmpData, &tmpLen);
            if (ret != OSSL_SDR_OK)
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("加密私钥运算错误，错误码[0x%08x]\n", ret);

            }
            else
            {
                printf("加密私钥运算成功。\n");
                PrintData("私钥运算结果", tmpData, tmpLen, 16);
            }

            memset(outData, 0, sizeof(outData));
            outDataLen = sizeof(outData);

            //  SGD_RSA_ENC,
            ret = TSAPI_SDF_InternalPublicKeyOperation_RSA(hSession, keyIndex, tmpData, tmpLen, outData, &outDataLen);

            if (ret != OSSL_SDR_OK)
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("加密公钥运算错误，错误码[0x%08x]\n", ret);
                debug_printf("Error String: %s\n",SDF_GetErrorString(ret));

            }
            else
            {
                printf("加密公钥运算成功。\n");
                PrintData("加密公钥运算结果", outData, outDataLen, 16);
            }

            if ((outDataLen != encKeyBits / 8) || (memcmp(inData, outData, outDataLen) != 0))
            {
                if (strlen(sPrkAuthCode) != 0)
                {
                    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
                }

                printf("加密公钥运算结果与明文数据比较失败。\n");

            }
            else
            {
                printf("加密公钥运算结果与明文数据比较成功。\n");
            }
        }

        if (strlen(sPrkAuthCode) != 0)
        {
            ret = TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
            if (ret != OSSL_SDR_OK)
            {
                printf("释放私钥访问权限错误，错误码[0x%08x]\n", ret);
                debug_printf("Error String: %s\n",SDF_GetErrorString(ret));
            }
            else
            {
                printf("释放私钥访问权限成功。\n");
            }
        }
    cleanup:
    return ;
}
void IntECCSignTest()
{
	int ret = -1;
    int keyIndex = 1;
	ECCrefPublicKey pubKey;
	unsigned char inData[512], tmpData[512];
    char sPrkAuthCode[128] = "P@ssw0rd";
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, keyIndex, &pubKey);

    if(ret != OSSL_SDR_OK)
    {
        printf("导出签名公钥错误，错误码[0x%08x]\n", ret);
    }
    PrintECCPublicKey(&pubKey);
    if(strlen(sPrkAuthCode) != 0)
    {
        ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSession, keyIndex, sPrkAuthCode, (unsigned int)strlen(sPrkAuthCode));
        if(ret != OSSL_SDR_OK)
        {
            printf("获取私钥访问权限错误，错误码[0x%08x]\n", ret);
        }
        else
        {
            printf("获取私钥访问权限成功。\n");
        }
    }

    memset(inData, 0, sizeof(inData));

    ret = TSAPI_SDF_GenerateRandom(hSession, pubKey.bits / 8 - 1, &inData[1]);
    if(ret != OSSL_SDR_OK)
    {
        if(strlen(sPrkAuthCode) != 0)
        {
            TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
        }

        printf("产生随机签名数据错误，错误码[0x%08x]\n", ret);
    }
    else
    {
        printf("产生随机签名数据成功。\n");

        PrintData("随机签名数据", inData, pubKey.bits / 8, 16);
    }

    memset(tmpData, 0, sizeof(tmpData));

    ret = TSAPI_SDF_InternalSign_ECC(hSession, keyIndex, inData, pubKey.bits / 8, (ECCSignature *)tmpData);
    if(ret != OSSL_SDR_OK)
    {
        if(strlen(sPrkAuthCode) != 0)
        {
            TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
        }

        printf("签名运算错误，错误码[0x%08x]\n", ret);
    }
    else
    {
        printf("签名运算成功。\n");
        PrintData("签名运算结果", tmpData, sizeof(ECCSignature), 16);
    }

    ret = TSAPI_SDF_InternalVerify_ECC(hSession, keyIndex, inData, pubKey.bits / 8, (ECCSignature *)tmpData);
    if(ret != OSSL_SDR_OK)
    {
        if(strlen(sPrkAuthCode) != 0)
        {
            TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
        }

        printf("验证签名运算错误，错误码[0x%08x]\n", ret);
    }
    else
    {
        printf("验证签名运算成功。\n");
    }

    if(strlen(sPrkAuthCode) != 0)
    {
        ret = TSAPI_SDF_ReleasePrivateKeyAccessRight(hSession, keyIndex);
        if(ret != OSSL_SDR_OK)
        {
            printf("释放私钥访问权限错误，错误码[0x%08x]\n", ret);
        }
        else
        {
            printf("释放私钥访问权限成功。\n");
        }
    }
    

cleanup:
return ;
}
int TSAPI_Encrypt(){
    // 使用指定的密钥句柄和IV对数据进行对称加密运算
    // 此函数不对数据进行填充处理，此函数的IV数据长度与算法分组长度相同
    void *hSession = NULL;
    void *hDevice = NULL;
    unsigned int uiAlgID = OSSL_SGD_SM4_ECB;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    unsigned int uiDataLength;
    unsigned char *pucIV;
    unsigned char *pucData;
    unsigned char *pucEncData;
    unsigned int *puiEncDataLength;
    int ret = -1;
    ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
    if (!pucIV){
        goto cleanup;
    }
    memset(pucIV, 0, 16);

    uiDataLength = 32;
    pucData = malloc(uiDataLength);
    memset(pucData, 0x11, uiDataLength);

    pucEncData = malloc(uiDataLength + 16);
    puiEncDataLength = malloc(sizeof(unsigned int));
    *puiEncDataLength = uiDataLength + 16;

    unsigned char *pucKey = malloc(64);
    unsigned int uiKEKIndex = 1;
    unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
    void *hKeyHandle = NULL;

    ret = TSAPI_SDF_GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != OSSL_SDR_OK)
    {
        printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
    printf("SymmetricEncrypt: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    if(pucKey) free(pucKey);
    if(pucData) free(pucData);
    if(pucEncData) free(pucEncData);
    if(puiEncDataLength) free(puiEncDataLength);
    if(puiKeyLength) free(puiKeyLength);
    if(hSession) TSAPI_SDF_CloseSession(hSession);
    if(hDevice) TSAPI_SDF_CloseDevice(hDevice);
    return ret;
}
int TSAPI_Decrypt(){
    // 使用指定的密钥句柄和IV对数据进行对称解密运算。
    // 此函数的IV数据长度与算法分组长度相同
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID = OSSL_SGD_SM4_ECB;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    unsigned char *pucIV;
    unsigned char *pucEncData;
    unsigned int uiEncDataLength;
    unsigned char *pucDataDecrypted;
    unsigned int *puiDataLengthDecrypted;

    ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    
    
    
    pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
    if (!pucIV){
        goto cleanup;
    }
    memset(pucIV, 0, 16);

    unsigned int uiDataLength = 32;
    unsigned char *pucData = malloc(uiDataLength);
    memset(pucData, 0x11, uiDataLength);

    pucEncData = malloc(uiDataLength + 16);
    unsigned int * puiEncDataLength = malloc(sizeof(unsigned int));
    *puiEncDataLength = uiDataLength + 16;

    unsigned char *pucKey = malloc(64);
    unsigned int uiKEKIndex = 1;
    unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
    ret = TSAPI_SDF_GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != OSSL_SDR_OK)
    {
        printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
        goto cleanup;
    }

    ret = TSAPI_SDF_Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
    if (ret != OSSL_SDR_OK)
    {
        printf("Encrypt failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    // 解密后数据长度
    pucDataDecrypted = malloc(*puiEncDataLength);
    puiDataLengthDecrypted = malloc(sizeof(unsigned int));

    // pucEncData = pucEncData;
    uiEncDataLength = *puiEncDataLength;

    ret = TSAPI_SDF_Decrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucDataDecrypted, puiDataLengthDecrypted);
    printf("SymmetricDecrypt: %s\n", SDF_GetErrorString(ret));
cleanup:
    if(pucIV) free(pucIV);
    if(pucKey) free(pucKey);
    if(pucData) free(pucData);
    if(pucEncData) free(pucEncData);
    if(puiEncDataLength) free(puiEncDataLength);
    if(puiKeyLength) free(puiKeyLength);
    if(pucDataDecrypted) free(pucDataDecrypted);
    if(puiDataLengthDecrypted) free(puiDataLengthDecrypted);
    if(hSession) TSAPI_SDF_CloseSession(hSession);
    if(hDevice) TSAPI_SDF_CloseDevice(hDevice);
    return ret;
}
void  SymmEncDecTest()
{
	// int rv;
	// int step = 0;
	// int i = 1;
	// unsigned int puiAlg[20];
	// int nSelAlg = 1;
	// int nInlen, nEnclen, nOutlen;
	// DEVICEINFO stDeviceInfo;
	// unsigned char pIv[16], pIndata[MAX_DATA_LENGTH], pEncdata[MAX_DATA_LENGTH], pOutdata[MAX_DATA_LENGTH];
    // int nMyPos;
    // void *hDevice = NULL;
    // void *hSessionHandle = NULL;
    // void *phKeyHandle = NULL;
	// printf("\n");
	// printf("\n");
	// printf("对称运算加解密测试:\n");
	// printf("---------------------\n");
	// printf("\n");
	// printf("\n");

	// //判定对称密钥句柄是否有效
	// if(phKeyHandle == NULL)
	// {
	// 	printf("会话密钥句柄无效，请确认密钥已产生/导入...\n");
	// }


	// memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	// rv = GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	// if(rv != OSSL_SDR_OK)
	// {
	// 	printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
	// }

	// while(1)
	// {
	// 	switch(step)
	// 	{
	// 	case 0:
	// 		printf("\n");
	// 		printf("对称运算加解密测试:\n");
	// 		printf("---------------------\n");
	// 		printf("\n");
	// 		printf("从以下支持的算法中选择一项进行测试。\n");
	// 		printf("\n");

	// 		i=1;

	// 		if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_SM1_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_SM1_ECB;
	// 			printf("  %2d | SGD_SM1_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_SM1_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_SSF33_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_SSF33_ECB;
	// 			printf("  %2d | SGD_SSF33_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_SSF33_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_AES_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_AES_ECB;
	// 			printf("  %2d | SGD_AES_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_AES_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_DES_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_DES_ECB;
	// 			printf("  %2d | SGD_DES_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_DES_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_3DES_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_3DES_ECB;
	// 			printf("  %2d | SGD_3DES_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_3DES_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_SM4_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_SM4_ECB;
	// 			printf("  %2d | SGD_SM4_CBC\n\n", i);
	// 			// printf("   ")
	// 			puiAlg[i++]=SGD_SM4_CBC;
	// 		}
	// 		if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_SM7_ECB\n\n", i);
	// 			puiAlg[i++]=SGD_SM7_ECB;
	// 			printf("  %2d | SGD_SM7_CBC\n\n", i);
	// 			puiAlg[i++]=SGD_SM7_CBC;
	// 		}
	// 		if (stDeviceInfo.SymAlgAbility & SGD_SM6_ECB & SGD_SYMM_ALG_MASK)
	// 		{
	// 			printf("  %2d | SGD_SM6_ECB\n\n", i);
	// 			puiAlg[i++] = SGD_SM6_ECB;
	// 			printf("  %2d | SGD_SM6_CBC\n\n", i);
	// 			puiAlg[i++] = SGD_SM6_CBC;
	// 		}

	// 		printf("\n");
	// 		printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 1);
	// 		// nSelAlg = GetInputLength(1, 1, i-1);
    //         scanf("%d",&nSelAlg);

	// 		if((nSelAlg < 1) || (nSelAlg > i-1))
	// 		{
	// 			printf("\n输入参数无效\n");
	// 			break;
	// 		}
	// 		else
	// 			step++;

	// 		break;
	// 	case 1:
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("对称运算加解密测试:\n");
	// 		printf("---------------------\n");
	// 		printf("\n");
	// 		printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为%s)。\n", MAX_DATA_KB_LENGTH_STR);
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
	// 		// nInlen = GetInputLength(1024, 16, MAX_DATA_LENGTH);
    //         scanf("%d",&nInlen);
	// 		if((nInlen < 16) || (nInlen > MAX_DATA_LENGTH))
	// 		{
	// 			printf("\n输入参数无效\n");
	// 			break;
	// 		}
	// 		else
	// 			step++;

	// 		break;
	// 	case 2:

	// 		printf("\n");
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("\n");
	// 		printf("对称运算加解密测试\n");
	// 		printf("---------------\n");
	// 		printf("\n");
	// 		printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
	// 		printf("数据长度：%d\n", nInlen);
			
	// 		memset(pIv, 0, 16);

	// 		rv = GenerateRandom(hSessionHandle, nInlen, pIndata);
	// 		if(rv == OSSL_SDR_OK)
	// 		{
	// 			rv = Encrypt(hSessionHandle, phKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
	// 			if(rv == OSSL_SDR_OK)
	// 			{
	// 				memset(pIv, 0, 16);

	// 				rv = Decrypt(hSessionHandle, phKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
	// 				if(rv == OSSL_SDR_OK)
	// 				{
	// 					if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
	// 					{
	// 						printf("运算结果：加密、解密及结果比较均正确。\n");
	// 					}
	// 					else
	// 					{
	// 						printf("运算结果：解密结果错误。\n");
	// 					}
	// 				}
	// 				else
	// 				{
	// 					printf("运算结果：解密错误，[0x%08x]\n", rv);
	// 				}
	// 			}
	// 			else
	// 			{
	// 				printf("运算结果：加密错误，[0x%08x]\n", rv);
	// 			}
	// 		}
	// 		else
	// 		{
	// 			printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
	// 		}
	// 	}
	// }    
    TSAPI_Encrypt();
    TSAPI_Decrypt();

}

// int TSAPI_ExternalVerify_ECC(){
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     unsigned int uiAlgID = 0x00020200;  // SM2签名方案
//     ECCrefPublicKey *pucPublicKey = NULL;
//     unsigned char *pucDataInput = NULL;
//     unsigned int uiInputLength = 32;
//     ECCSignature *pucSignature = NULL;
//     unsigned int uiKeyIndex = 1;

//     // 初始化所有指针为NULL
//     pucPublicKey = NULL;
//     pucDataInput = NULL;
//     pucSignature = NULL;
//     hSession = NULL;
//     hDevice = NULL;

//     ret = TSAPI_SDF_OpenDevice(&hDevice);
//     if(ret != OSSL_SDR_OK){ 
//         printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
//     if(ret != OSSL_SDR_OK){ 
//         printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     // 分配内存
//     pucPublicKey = (ECCrefPublicKey*)malloc(sizeof(ECCrefPublicKey));
//     pucDataInput = (unsigned char *)malloc(uiInputLength);
//     pucSignature = (ECCSignature*)malloc(sizeof(ECCSignature));
    
//     if(!pucPublicKey || !pucDataInput || !pucSignature){ 
//         printf("malloc failed\n"); 
//         ret = -1; 
//         goto cleanup; 
//     }
    
//     // 初始化内存
//     memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
//     memset(pucDataInput, 0x55, uiInputLength);
//     memset(pucSignature, 0, sizeof(ECCSignature));
    
//     // 获取私钥访问权限
//     ret = GetPrivateKeyAccessRight(hSession, uiKeyIndex, (unsigned char *)"P@ssw0rd", strlen("P@ssw0rd"));
//     if(ret != OSSL_SDR_OK){ 
//         printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     // 内部签名
//     ret = InternalSign_ECC(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucSignature);
//     if(ret != OSSL_SDR_OK){ 
//         printf("InternalSign_ECC failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     // 导出签名公钥
//     ret = ExportSignPublicKey_ECC(hSession, uiKeyIndex, pucPublicKey);
//     if(ret != OSSL_SDR_OK){
//         printf("ExportSignPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
    
//     // 外部验证
//     ret = ExternalVerify_ECC(hSession, uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucSignature);
//     printf("ExternalVerify_ECC: %s\n", SDF_GetErrorString(ret));

// cleanup:
//     // 安全释放内存
//     if(pucPublicKey) {
//         free(pucPublicKey);
//         pucPublicKey = NULL;  // 防止悬空指针
//     }
//     if(pucDataInput) {
//         free(pucDataInput);
//         pucDataInput = NULL;
//     }
//     if(pucSignature) {
//         free(pucSignature);
//         pucSignature = NULL;
//     }
//     if(hSession){ 
//         TSAPI_SDF_CloseSession(hSession);
//         hSession = NULL;
//     }
//     if(hDevice){ 
//         TSAPI_SDF_CloseDevice(hDevice);
//         hDevice = NULL;
//     }
//     return ret;
// }
// int TSAPI_InternalSign_ECC(){
//     // 使用内部指定索引的私钥对数据进行ECC签名运算。
//     // 输入数据为待签数据的杂凑值。
//     // 当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果
//     // SM2算法预处理过程应符合 GB/T 35276
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     // 密码设备存储的密钥对的索引值
//     unsigned int uiISKIndex = 1;
//     // 缓冲区指针，用于存储外部输入的数据
//     unsigned char *pucData = NULL;
//     // 输入的数据长度
//     unsigned int uiDataLength = 32;
//     // 缓冲区指针，用于存放输出的签名值数据
//     ECCSignature * pucSignature = NULL;
//     // 输入数据准备：
//     /*
//         // 伪代码
//         SDF_HashInit(hSession, SGD_SM3, pucPublicKey, pucID, uiIDLength);
//         SDF_HashUpdate(hSession, message, messageLen);
//         SDF_HashFinal(hSession, digest, &digestLen);
//         // digest 就是“SM2签名预处理”后的杂凑值
//         SDF_InternalSign_ECC(hSession, keyIndex, digest, digestLen, &signature);
//     //如果你的软实现不支持自动做Z值拼接，你需要自己用GmSSL等库先做Z值拼接和SM3。
//     */
//     // unsigned char message[] = "test message";
//     // unsigned char digest[32];
//     // unsigned int digestLen = 32;
//     // SDF_HashInit(hSession, SGD_SM3, NULL, NULL, 0);
//     // SDF_HashUpdate(hSession, message, strlen((char*)message));
//     // SDF_HashFinal(hSession, digest, &digestLen);
//     // ECCSignature *pucSignature = malloc(sizeof(ECCSignature));
//     // int ret = InternalSign_ECC(hSession, uiISKIndex, digest, digestLen, pucSignature);


//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = GetPrivateKeyAccessRight(hSession, uiISKIndex, (char *)("P@ssw0rd"), strlen("P@ssw0rd")); if(ret != OSSL_SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucData = (unsigned char *)malloc(uiDataLength);
//     pucSignature = (ECCSignature *)malloc(sizeof(ECCSignature));
//     if(!pucData || !pucSignature){ printf("malloc failed\n"); ret = -1; goto cleanup; }
//     memset(pucData,0x66,uiDataLength); memset(pucSignature,0,sizeof(ECCSignature));
//     // 一般是对数据的哈希值进行签名，这里为了测试方便，直接mock数据哈希值来签名
//     ret = InternalSign_ECC(hSession,uiISKIndex,pucData,uiDataLength,pucSignature);
//     printf("InternalSign_ECC: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucData) free(pucData); if(pucSignature) free(pucSignature);
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} return ret;
// }
// int TSAPI_InternalVerify_ECC(){
//     // 使用内部指定索引的公钥对ECC签名值进行验证运算
//     // 输入数据为待签数据的杂凑值
//     // 当使用SM2算法时，该输入数据经过SM2签名预处理的结果
//     // SM2算法预处理过程应符合 GB/T 35276
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     // 密码设备存储的密钥对的索引值
//     unsigned int uiKeyIndex = 1;
//     // 缓冲区指针，用于存放外部输入的数据
//     unsigned char *pucDataInput = NULL;
//     // 输入的数据长度
//     unsigned int uiInputLength = 32;
//     // 缓冲区指针，用于存放输入的签名值数据
//     ECCSignature *pucSignature = NULL;
//     unsigned int uiISKIndex = 1;

//     ret = TSAPI_SDF_OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucDataInput = (unsigned char*)malloc(uiInputLength); pucSignature = (ECCSignature*)malloc(sizeof(ECCSignature));
//     if(!pucDataInput || !pucSignature){ printf("malloc failed\n"); ret = -1; goto cleanup; }
//     memset(pucDataInput,0x77,uiInputLength); 
//     ret = GetPrivateKeyAccessRight(hSession, uiISKIndex, (char *)("P@ssw0rd"), strlen("P@ssw0rd")); if(ret != OSSL_SDR_OK){ printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = InternalSign_ECC(hSession,uiISKIndex,pucDataInput,uiInputLength,pucSignature); if(ret != OSSL_SDR_OK){ printf("InternalSign_ECC failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = InternalVerify_ECC(hSession, uiKeyIndex, pucDataInput, uiInputLength, pucSignature); 
//     printf("InternalVerify_ECC: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucDataInput) free(pucDataInput); if(pucSignature) free(pucSignature);
//     if(hSession){ TSAPI_SDF_CloseSession(hSession);} if(hDevice){ TSAPI_SDF_CloseDevice(hDevice);} return ret;
//     return ret;
// }

// int TSAPI_ExternalEncrypt_ECC(){
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     unsigned int uiAlgID = 0x00020800;  // SM2加密方案
//     unsigned int uiKeyIndex = 1;
//     ECCrefPublicKey *pucPublicKey = NULL;
//     unsigned char *pucDataInput = NULL;
//     unsigned int uiInputLength = 32;
//     ECCCipher *pucDataOutput = NULL;

//     // 初始化指针
//     pucPublicKey = NULL;
//     pucDataInput = NULL;
//     pucDataOutput = NULL;
//     hSession = NULL;
//     hDevice = NULL;

//     ret = OpenDevice(&hDevice);
//     if(ret != OSSL_SDR_OK){ 
//         printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
//     if(ret != OSSL_SDR_OK){ 
//         printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }

//     // 1. 分配公钥内存
//     pucPublicKey = (ECCrefPublicKey *)malloc(sizeof(ECCrefPublicKey));
//     if(!pucPublicKey){ 
//         printf("malloc pucPublicKey failed\n"); 
//         ret = -1; 
//         goto cleanup; 
//     }
//     memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));

//     // 2. 分配足够的输出密文内存（关键修复！）
//     // SM2加密后最大密文长度 = 固定部分 + 明文长度 + 一些开销
//     size_t max_cipher_size = sizeof(ECCCipher) + uiInputLength + 64;  // 预留额外空间
//     pucDataOutput = (ECCCipher *)malloc(max_cipher_size);
//     if(!pucDataOutput){ 
//         printf("malloc pucDataOutput failed, size: %zu\n", max_cipher_size); 
//         ret = -1; 
//         goto cleanup; 
//     }
//     memset(pucDataOutput, 0, max_cipher_size);

//     // 3. 分配输入数据内存
//     pucDataInput = (unsigned char*)malloc(uiInputLength);
//     if(!pucDataInput){ 
//         printf("malloc pucDataInput failed\n"); 
//         ret = -1; 
//         goto cleanup; 
//     }
//     memset(pucDataInput, 0x88, uiInputLength);

//     // 4. 获取私钥访问权限并导出公钥
//     unsigned char *password = (unsigned char *)"P@ssw0rd";
//     ret = GetPrivateKeyAccessRight(hSession, uiKeyIndex, password, strlen((char*)password));
//     if(ret != OSSL_SDR_OK){ 
//         printf("GetPrivateKeyAccessRight failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }
    
//     ret = ExportEncPublicKey_ECC(hSession, uiKeyIndex, pucPublicKey);
//     if(ret != OSSL_SDR_OK){ 
//         printf("ExportEncPublicKey_ECC failed: %s\n", SDF_GetErrorString(ret)); 
//         goto cleanup; 
//     }

//     // 5. 执行外部加密
//     printf("加密前 - 输入数据长度: %u\n", uiInputLength);
//     printf("加密前 - 输出缓冲区大小: %zu\n", max_cipher_size);
    
//     ret = ExternalEncrypt_ECC(hSession, uiAlgID, pucPublicKey, pucDataInput, uiInputLength, pucDataOutput);
//     printf("ExternalEncrypt_ECC: %s\n", SDF_GetErrorString(ret));
    
//     if(ret == OSSL_SDR_OK){
//         // 6. 打印加密结果
//         printf("加密成功！\n");
//         printf("密文长度 L: %u bytes\n", pucDataOutput->L);
        
//         // 安全地打印密文信息
//         PrintECCCipher_Smart(pucDataOutput);
        
//         // 7. 验证没有越界
//         if(pucDataOutput->L > (max_cipher_size - sizeof(ECCCipher) + 1)) {
//             printf("警告: 密文长度可能超过了预留空间\n");
//         }
//     }

// cleanup:
//     // 安全释放内存
//     if(pucDataInput) {
//         free(pucDataInput);
//         pucDataInput = NULL;
//     }
//     if(pucPublicKey) {
//         free(pucPublicKey);
//         pucPublicKey = NULL;
//     }
//     if(pucDataOutput) {
//         free(pucDataOutput);
//         pucDataOutput = NULL;
//     }
//     if(hSession){ 
//         TSAPI_SDF_CloseSession(hSession);
//         hSession = NULL;
//     }
//     if(hDevice){ 
//         TSAPI_SDF_CloseDevice(hDevice);
//         hDevice = NULL;
//     }
//     return ret;
// }
// int TSAPI_Encrypt(){
//     // 使用指定的密钥句柄和IV对数据进行对称加密运算
//     // 此函数不对数据进行填充处理，此函数的IV数据长度与算法分组长度相同
//     void *hSession = NULL;
//     void *hDevice = NULL;
//     unsigned int uiAlgID = SGD_SM4_ECB;
//     // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
//     unsigned int uiDataLength;
//     unsigned char *pucIV;
//     unsigned char *pucData;
//     unsigned char *pucEncData;
//     unsigned int *puiEncDataLength;
//     int ret = -1;
//     ret = OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
//     if (!pucIV){
//         goto cleanup;
//     }
//     memset(pucIV, 0, 16);

//     uiDataLength = 32;
//     pucData = malloc(uiDataLength);
//     memset(pucData, 0x11, uiDataLength);

//     pucEncData = malloc(uiDataLength + 16);
//     puiEncDataLength = malloc(sizeof(unsigned int));
//     *puiEncDataLength = uiDataLength + 16;

//     unsigned char *pucKey = malloc(64);
//     unsigned int uiKEKIndex = 1;
//     unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
//     void *hKeyHandle = NULL;

//     ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
//     if (ret != OSSL_SDR_OK)
//     {
//         printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
//         goto cleanup;
//     }

//     ret = Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
//     printf("SymmetricEncrypt: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucIV) free(pucIV);
//     if(pucKey) free(pucKey);
//     if(pucData) free(pucData);
//     if(pucEncData) free(pucEncData);
//     if(puiEncDataLength) free(puiEncDataLength);
//     if(puiKeyLength) free(puiKeyLength);
//     if(hSession) TSAPI_SDF_CloseSession(hSession);
//     if(hDevice) TSAPI_SDF_CloseDevice(hDevice);
//     return ret;
// }
// int TSAPI_Decrypt(){
//     // 使用指定的密钥句柄和IV对数据进行对称解密运算。
//     // 此函数的IV数据长度与算法分组长度相同
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     void *hKeyHandle = NULL;
//     unsigned int uiAlgID = SGD_SM4_ECB;
//     // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
//     unsigned char *pucIV;
//     unsigned char *pucEncData;
//     unsigned int uiEncDataLength;
//     unsigned char *pucDataDecrypted;
//     unsigned int *puiDataLengthDecrypted;

//     ret = OpenDevice(&hDevice); if(ret != OSSL_SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
//     ret = TSAPI_SDF_OpenSession(hDevice, &hSession); if(ret != OSSL_SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }

    
    
    
//     pucIV = (unsigned char *)malloc(sizeof(unsigned char)*16);
//     if (!pucIV){
//         goto cleanup;
//     }
//     memset(pucIV, 0, 16);

//     // 加密前数据长度
//     unsigned int uiDataLength = 32;
//     unsigned char *pucData = malloc(uiDataLength);
//     memset(pucData, 0x11, uiDataLength);

//     pucEncData = malloc(uiDataLength + 16);
//     // 加密后数据长度
//     unsigned int * puiEncDataLength = malloc(sizeof(unsigned int));
//     *puiEncDataLength = uiDataLength + 16;

//     unsigned char *pucKey = malloc(64);
//     unsigned int uiKEKIndex = 1;
//     unsigned int *puiKeyLength = malloc(sizeof(unsigned int));
//     ret = GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
//     if (ret != OSSL_SDR_OK)
//     {
//         printf("GenerateKeyWithKEK failed: %s\n",SDF_GetErrorString(ret));
//         goto cleanup;
//     }

//     ret = Encrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength,pucEncData,puiEncDataLength);
//     if (ret != OSSL_SDR_OK)
//     {
//         printf("Encrypt failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
//     // 解密后数据长度
//     pucDataDecrypted = malloc(*puiEncDataLength);
//     puiDataLengthDecrypted = malloc(sizeof(unsigned int));

//     // pucEncData = pucEncData;
//     uiEncDataLength = *puiEncDataLength;

//     ret = Decrypt(hSession, hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucDataDecrypted, puiDataLengthDecrypted);
//     printf("SymmetricDecrypt: %s\n", SDF_GetErrorString(ret));
// cleanup:
//     if(pucIV) free(pucIV);
//     if(pucKey) free(pucKey);
//     if(pucData) free(pucData);
//     if(pucEncData) free(pucEncData);
//     if(puiEncDataLength) free(puiEncDataLength);
//     if(puiKeyLength) free(puiKeyLength);
//     if(pucDataDecrypted) free(pucDataDecrypted);
//     if(puiDataLengthDecrypted) free(puiDataLengthDecrypted);
//     if(hSession) TSAPI_SDF_CloseSession(hSession);
//     if(hDevice) TSAPI_SDF_CloseDevice(hDevice);
//     return ret;
// }
int TSAPI_CalculateMAC(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    void *hKeyHandle = NULL;
    unsigned int uiAlgID;
    unsigned char *pucIV = NULL;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucMAC = NULL;
    unsigned int *puiMacLength = NULL;
    unsigned char *pucKey = NULL;
    unsigned int *puiKeyLength = NULL;

    // 初始化所有指针
    pucIV = NULL;
    pucData = NULL;
    pucMAC = NULL;
    puiMacLength = NULL;
    pucKey = NULL;
    puiKeyLength = NULL;
    hKeyHandle = NULL;

    ret = TSAPI_SDF_OpenDevice(&hDevice); 
    if(ret != OSSL_SDR_OK){ 
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }
    
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession); 
    if(ret != OSSL_SDR_OK){ 
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); 
        goto cleanup; 
    }

    // 1. 生成密钥
    pucKey = malloc(64);
    puiKeyLength = malloc(sizeof(unsigned int));
    if(!pucKey || !puiKeyLength){ 
        printf("malloc failed\n"); 
        ret = -1; 
        goto cleanup; 
    }
    
    unsigned int uiKEKIndex = 1;
    uiAlgID = OSSL_SGD_SM4_ECB;
    
    ret = TSAPI_SDF_GenerateKeyWithKEK(hSession, 128, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &hKeyHandle);
    if (ret != OSSL_SDR_OK){
        printf("GenerateKeyWithKEK failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }

    // 2. 准备IV（关键修复！）
    // 对于SM4算法，IV长度通常是16字节（128位）
    unsigned int uiIVLength = 16;
    pucIV = malloc(uiIVLength);
    if(!pucIV){ 
        printf("malloc pucIV failed\n"); 
        ret = -1; 
        goto cleanup; 
    }
    
    // 生成IV的几种方式：

    // 方式1：全零IV（最简单，用于测试）
    memset(pucIV, 0, uiIVLength);
    
    // 方式2：固定模式IV
    // for(int i = 0; i < uiIVLength; i++) {
    //     pucIV[i] = i;  // 0x00, 0x01, 0x02, ...
    // }
    
    // 方式3：从设备获取随机IV（最安全）
    // ret = GenerateRandom(hSession, uiIVLength, pucIV);
    // if(ret != OSSL_SDR_OK){
    //     printf("GenerateRandom for IV failed: %s\n", SDF_GetErrorString(ret));
    //     goto cleanup;
    // }

    debug_printf("生成的IV(%d字节): ", uiIVLength);
    for(int i = 0; i < uiIVLength; i++){
        debug_printf("%02x", pucIV[i]);
    }
    debug_printf("\n");

    // 3. 准备测试数据
    uiDataLength = 32;
    pucData = malloc(uiDataLength);
    if(!pucData){ 
        printf("malloc pucData failed\n"); 
        ret = -1; 
        goto cleanup; 
    }
    memset(pucData, 0x11, uiDataLength);

    // 4. 准备MAC缓冲区
    pucMAC = malloc(16);
    puiMacLength = malloc(sizeof(unsigned int));
    if(!pucMAC || !puiMacLength){ 
        printf("malloc failed\n"); 
        ret = -1; 
        goto cleanup; 
    }
    *puiMacLength = 16;  // SM4 MAC通常是16字节

    // 5. 计算MAC
    // 注意：算法标识应该对应你使用的对称算法
    // SGD_SM1_MAC 用于SM1算法，SM4应该使用SGD_SM4_MAC
    unsigned int macAlgID = OSSL_SGD_SM4_MAC;  // 或者使用正确的MAC算法标识
    
    debug_printf("计算MAC参数:\n");
    debug_printf("  数据长度: %u bytes\n", uiDataLength);
    debug_printf("  IV长度: %u bytes\n", uiIVLength);
    debug_printf("  MAC缓冲区大小: %u bytes\n", *puiMacLength);
    
    ret = TSAPI_SDF_CalculateMAC(hSession, hKeyHandle, macAlgID, pucIV, pucData, uiDataLength, pucMAC, puiMacLength);
    printf("CalculateMAC: %s\n", SDF_GetErrorString(ret));
    
    if(ret == OSSL_SDR_OK){
        debug_printf("MAC计算成功！\n");
        debug_printf("实际MAC长度: %u bytes\n", *puiMacLength);
        debug_printf("MAC值: ");
        for(unsigned int i = 0; i < *puiMacLength; i++){
           debug_printf("%02x", pucMAC[i]);
        }
        debug_printf("\n");
    }

cleanup:
    // 安全释放资源
    if(pucIV) {
        free(pucIV);
        pucIV = NULL;
    }
    if(pucData) {
        free(pucData);
        pucData = NULL;
    }
    if(pucKey) {
        free(pucKey);
        pucKey = NULL;
    }
    if(puiKeyLength) {
        free(puiKeyLength);
        puiKeyLength = NULL;
    }
    if(puiMacLength) {
        free(puiMacLength);
        puiMacLength = NULL;
    }
    if(pucMAC) {
        free(pucMAC);
        pucMAC = NULL;
    }
    if(hKeyHandle) {
        // 如果支持销毁密钥句柄
        // SDF_DestroyKey(hSession, hKeyHandle);
        hKeyHandle = NULL;
    }
    if(hSession) {
        TSAPI_SDF_CloseSession(hSession);
        hSession = NULL;
    }
    if(hDevice) {
        TSAPI_SDF_CloseDevice(hDevice);
        hDevice = NULL;
    }
    return ret;
}