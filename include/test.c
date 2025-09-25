#include<openssl/sdf.h>
#include<stdio.h>

const char *SDF_GetErrorString(int x){
    return "OK";
}
int  Test_Device(){
    void *hDevice = NULL;
    int ret = TSAPI_SDF_OpenDevice(&hDevice);
     printf("ret: %x\n", ret);
     printf("%d\n",0x01000002);
    if (ret == OSSL_SDR_OK) {
        printf("OpenDevice: %x\n", ret);
        ret = TSAPI_SDF_CloseDevice(hDevice);
        if (ret == OSSL_SDR_OK){
            printf("CloseDevice: %x\n", ret);
        }else{
            printf("CloseDevice failed: %x\n", ret);
        }
    } else {
        printf("OpenDevice failed: %x\n", ret);
    }
    return ret;
}
// int  Test_Session(){
//     unsigned int  ret = 0;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     ret = OpenDevice(&hDevice);
//     if (ret != OSSL_SDR_OK) {
//         printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
//     ret = OpenSession(hDevice, &hSession);
//     if (ret == OSSL_SDR_OK){
//         printf("OpenSession: %s\n", SDF_GetErrorString(ret));
//     }
//     else
//     {
//         printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
//     ret = CloseSession(hSession);
//     hSession = NULL;
//     if (ret != OSSL_SDR_OK){
//         printf("CloseSession failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
// cleanup:
//     if(hSession){
//         CloseSession(hSession);
//     }
//     if(hDevice){
//         CloseDevice(hDevice);
//     }
//     return ret;
// }
// int Test_GetDeviceInfo(){
//     int ret = -1;
//     void *hDevice = NULL;
//     void *hSession = NULL;
//     ret = OpenDevice(&hDevice);
//     if (ret != OSSL_SDR_OK){
//         printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
//     ret = OpenSession(hDevice, &hSession);
//     if (ret != OSSL_SDR_OK){
//         printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
//         goto cleanup;
//     }
//     DEVICEINFO deviceInfo;
//     ret = GetDeviceInfo(hSession, &deviceInfo);
//     if (ret == 0) {
//         printf("\n========== GetDeviceInfo: %s ==========\n", SDF_GetErrorString(ret));
//         printf("IssuerName: %s\n", deviceInfo.IssuerName);
//         printf("SerialNumber: %s\n", deviceInfo.SerialNumber);
//         printf("FirmwareVersion: %s\n", deviceInfo.FirmwareVersion);
//         printf("DeviceVersion: %08x\n", deviceInfo.DeviceVersion);
//         printf("StandardVersion: %d\n", deviceInfo.StandardVersion);
//         printf("AsymAlgAbility: [%08x, %08x]\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
//         printf("SymAlgAbility: %08x\n", deviceInfo.SymAlgAbility);
//         printf("HashAlgAbility: %08x\n", deviceInfo.HashAlgAbility);
//         printf("BufferSize: %d\n", deviceInfo.BufferSize);
//         printf("===============================================\n");
//     } else {
//         printf("Failed GetDeviceInfo: %s\n", SDF_GetErrorString(ret));
//     }
// cleanup:
//     if(hSession){
//         CloseSession(hSession);
//     }
//     if(hDevice){
//         CloseDevice(hDevice);
//     }
//     return ret;
// }
int main(){
    Test_Device();


    return  0;
}