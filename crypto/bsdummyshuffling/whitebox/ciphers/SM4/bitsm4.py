#-*- coding:utf-8 -*-

sm4_fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
sm4_ck = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279]
sm4_s_box = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]
idM32 = [0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000, 0x01000000,
         0x800000, 0x400000, 0x200000, 0x100000, 0x080000, 0x040000, 0x020000, 0x010000,
         0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400, 0x0200, 0x0100,
         0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]


MASK = 2**64-1 # 0xffffffffffffffff
def Not(x):
    return MASK^x


# 为什么不生成完轮密钥然后再转化为node？？？？？
# 甚至不需要转化为node

#利用s盒进行非线性变换tao()
def tao(b):#b是一个4字节长度的word
    result=0
    for i in range(4):
        result=result+(sm4_s_box[b%(16**2)]<<(8*i))
        b=b>>8
    return result
#循环左移
def cir_shift(x,i):
    x=x<<i
    low=x%(2**32)#取移位之后的低32位作为基数
    high=x>>32#x右移32位得到加数
    return low+high
#线性变换L'()
def L_pie(B):
    #print("参数为:::::{}".format(hex(B)))
    return B^cir_shift(B,13)^cir_shift(B,23)
#一次密钥轮变换F'，用于产生一个轮密钥关键字
def F_pie(K0,K1,K2,K3,ck0):
    #print("{}异或T'({})".format(hex(K0),hex(K1^K2^K3^ck0)))
    return K0^T_pie(K1^K2^K3^ck0)
# 函数T'()
def T_pie(X):
    #print("参数为:{}".format(hex(X)))
    #print("结果为:{}".format(hex(L_pie(tao(X)))))
    return L_pie(tao(X))
def sm4_expandKey(KEY, if_enc):
    # MKK是str，需要先转化为8位无符号数
    MKK = [ord(c) for c in KEY]
    # 换成u32
    MK=[0 for _ in range(4)]
    for i in range(16):
        MK[int(i/4)] ^= MKK[i]<<((3-(i%4))*8)
    rk=[]   #轮密钥关键字RK
    K=[]    #密钥关键字K
    #产生四个密钥关键字
    for i in range(4):
        K.append(MK[i]^sm4_fk[i])
    # print([hex(x) for x in K])
    #首先进行32次轮密钥变换产生32个轮密钥关键字
    for i in range(32):
        rk.append(F_pie(K[i],K[i+1],K[i+2],K[i+3],sm4_ck[i]))
        K.append(rk[i])
    
    # print(len(rk),len(K))
    if if_enc:
        return rk
    else:
        return rk[::-1]

    
def sm4_bs_sbox(x=[]):
    # y_t[21], t_t[8], t_m[46], y_m[18], t_b[30]
    s = [None for i in range(0, 8)]
    y_t = [None for i in range(0, 21)]
    t_t = [None for i in range(0, 8)]
    t_m = [None for i in range(0, 46)]
    y_m = [None for i in range(0, 18)]
    t_b = [None for i in range(0, 30)]
    
    y_t[18] = x[2] ^x[6]
    t_t[ 0] = x[3] ^x[4]
    t_t[ 1] = x[2] ^x[7]
    t_t[ 2] = x[7] ^y_t[18]
    t_t[ 3] = x[1] ^t_t[ 1]
    t_t[ 4] = x[6] ^x[7]
    t_t[ 5] = x[0] ^y_t[18]
    t_t[ 6] = x[3] ^x[6]
    y_t[10] = x[1] ^y_t[18]
    y_t[ 0] = x[5] ^ y_t[10]
    y_t[ 0] = Not(y_t[ 0])
    y_t[ 1] = t_t[ 0] ^t_t[ 3]
    y_t[ 2] = x[0] ^t_t[ 0]
    y_t[ 4] = x[0] ^t_t[ 3]
    y_t[ 3] = x[3] ^y_t[ 4]
    y_t[ 5] = x[5] ^t_t[ 5]
    y_t[ 6] = x[0] ^ x[1]
    y_t[ 6] = Not(y_t[ 6])
    y_t[ 7] = t_t[ 0] ^ y_t[10]
    y_t[ 7] = Not(y_t[ 7])
    y_t[ 8] = t_t[ 0] ^t_t[ 5]
    y_t[ 9] = x[3]
    y_t[11] = t_t[ 0] ^t_t[ 4]
    y_t[12] = x[5] ^t_t[ 4]
    y_t[13] = x[5] ^ y_t[ 1]
    y_t[13] = Not(y_t[13])
    y_t[14] = x[4] ^ t_t[ 2]
    y_t[14] = Not(y_t[14])
    y_t[15] = x[1] ^ t_t[ 6]
    y_t[15] = Not(y_t[15])
    y_t[16] = x[0] ^ t_t[ 2]
    y_t[16] = Not(y_t[16])
    y_t[17] = t_t[ 0] ^ t_t[ 2]
    y_t[17] = Not(y_t[17])
    y_t[19] = x[5] ^ y_t[14]
    y_t[19] = Not(y_t[19])
    y_t[20] = x[0] ^t_t[ 1]
    # The shared non-linear middle part for AES, AES^-1, and SM4
    t_m[ 0] = y_t[ 3] ^	 y_t[12]
    t_m[ 1] = y_t[ 9] &	 y_t[ 5]
    t_m[ 2] = y_t[17] &	 y_t[ 6]
    t_m[ 3] = y_t[10] ^	 t_m[ 1]
    t_m[ 4] = y_t[14] &	 y_t[ 0]
    t_m[ 5] = t_m[ 4] ^	 t_m[ 1]
    t_m[ 6] = y_t[ 3] &	 y_t[12]
    t_m[ 7] = y_t[16] &	 y_t[ 7]
    t_m[ 8] = t_m[ 0] ^	 t_m[ 6]
    t_m[ 9] = y_t[15] &	 y_t[13]
    t_m[10] = t_m[ 9] ^	 t_m[ 6]
    t_m[11] = y_t[ 1] &	 y_t[11]
    t_m[12] = y_t[ 4] &	 y_t[20]
    t_m[13] = t_m[12] ^	 t_m[11]
    t_m[14] = y_t[ 2] &	 y_t[ 8]
    t_m[15] = t_m[14] ^	 t_m[11]
    t_m[16] = t_m[ 3] ^	 t_m[ 2]
    t_m[17] = t_m[ 5] ^	 y_t[18]
    t_m[18] = t_m[ 8] ^	 t_m[ 7]
    t_m[19] = t_m[10] ^	 t_m[15]
    t_m[20] = t_m[16] ^	 t_m[13]
    t_m[21] = t_m[17] ^	 t_m[15]
    t_m[22] = t_m[18] ^	 t_m[13]
    t_m[23] = t_m[19] ^	 y_t[19]
    t_m[24] = t_m[22] ^	 t_m[23]
    t_m[25] = t_m[22] &	 t_m[20]
    t_m[26] = t_m[21] ^	 t_m[25]
    t_m[27] = t_m[20] ^	 t_m[21]
    t_m[28] = t_m[23] ^	 t_m[25]
    t_m[29] = t_m[28] &	 t_m[27]
    t_m[30] = t_m[26] &	 t_m[24]
    t_m[31] = t_m[20] &	 t_m[23]
    t_m[32] = t_m[27] &	 t_m[31]
    t_m[33] = t_m[27] ^	 t_m[25]
    t_m[34] = t_m[21] &	 t_m[22]
    t_m[35] = t_m[24] &	 t_m[34]
    t_m[36] = t_m[24] ^	 t_m[25]
    t_m[37] = t_m[21] ^	 t_m[29]
    t_m[38] = t_m[32] ^	 t_m[33]
    t_m[39] = t_m[23] ^	 t_m[30]
    t_m[40] = t_m[35] ^	 t_m[36]
    t_m[41] = t_m[38] ^	 t_m[40]
    t_m[42] = t_m[37] ^	 t_m[39]
    t_m[43] = t_m[37] ^	 t_m[38]
    t_m[44] = t_m[39] ^	 t_m[40]
    t_m[45] = t_m[42] ^	 t_m[41]
    y_m[ 0] = t_m[38] &	 y_t[ 7]
    y_m[ 1] = t_m[37] &	 y_t[13]
    y_m[ 2] = t_m[42] &	 y_t[11]
    y_m[ 3] = t_m[45] &	 y_t[20]
    y_m[ 4] = t_m[41] &	 y_t[ 8]
    y_m[ 5] = t_m[44] &	 y_t[ 9]
    y_m[ 6] = t_m[40] &	 y_t[17]
    y_m[ 7] = t_m[39] &	 y_t[14]
    y_m[ 8] = t_m[43] &	 y_t[ 3]
    y_m[ 9] = t_m[38] &	 y_t[16]
    y_m[10] = t_m[37] &	 y_t[15]
    y_m[11] = t_m[42] &	 y_t[ 1]
    y_m[12] = t_m[45] &	 y_t[ 4]
    y_m[13] = t_m[41] &	 y_t[ 2]
    y_m[14] = t_m[44] &	 y_t[ 5]
    y_m[15] = t_m[40] &	 y_t[ 6]
    y_m[16] = t_m[39] &	 y_t[ 0]
    y_m[17] = t_m[43] &	 y_t[12]

    # bottom(outer) linear layer for sm4
    t_b[ 0] = y_m[ 4] ^	 y_m[ 7]
    t_b[ 1] = y_m[13] ^	 y_m[15]
    t_b[ 2] = y_m[ 2] ^	 y_m[16]
    t_b[ 3] = y_m[ 6] ^	 t_b[ 0]
    t_b[ 4] = y_m[12] ^	 t_b[ 1]
    t_b[ 5] = y_m[ 9] ^	 y_m[10]
    t_b[ 6] = y_m[11] ^	 t_b[ 2]
    t_b[ 7] = y_m[ 1] ^	 t_b[ 4]
    t_b[ 8] = y_m[ 0] ^	 y_m[17]
    t_b[ 9] = y_m[ 3] ^	 y_m[17]
    t_b[10] = y_m[ 8] ^	 t_b[ 3]
    t_b[11] = t_b[ 2] ^	 t_b[ 5]
    t_b[12] = y_m[14] ^	 t_b[ 6]
    t_b[13] = t_b[ 7] ^	 t_b[ 9]
    t_b[14] = y_m[ 0] ^	 y_m[ 6]
    t_b[15] = y_m[ 7] ^	 y_m[16]
    t_b[16] = y_m[ 5] ^	 y_m[13]
    t_b[17] = y_m[ 3] ^	 y_m[15]
    t_b[18] = y_m[10] ^	 y_m[12]
    t_b[19] = y_m[ 9] ^	 t_b[ 1]
    t_b[20] = y_m[ 4] ^	 t_b[ 4]
    t_b[21] = y_m[14] ^	 t_b[ 3]
    t_b[22] = y_m[16] ^	 t_b[ 5]
    t_b[23] = t_b[ 7] ^	 t_b[14]
    t_b[24] = t_b[ 8] ^	 t_b[11]
    t_b[25] = t_b[ 0] ^	 t_b[12]
    t_b[26] = t_b[17] ^	 t_b[ 3]
    t_b[27] = t_b[18] ^	 t_b[10]
    t_b[28] = t_b[19] ^	 t_b[ 6]
    t_b[29] = t_b[ 8] ^	 t_b[10]
    s[0] = t_b[11] ^ t_b[13]
    s[0] = Not(s[0])
    s[1] = t_b[15] ^ t_b[23]
    s[1] = Not(s[1])
    s[2] = t_b[20] ^	 t_b[24]
    s[3] = t_b[16] ^	 t_b[25]
    s[4] = t_b[26] ^ t_b[22]
    s[4] = Not(s[4])
    s[5] = t_b[21] ^	 t_b[13]
    s[6] = t_b[27] ^ t_b[12]
    s[6] = Not(s[6])
    s[7] = t_b[28] ^ t_b[29]
    s[7] = Not(s[7])
    return s[::-1]

def sm4_SubBytes(x=[]):
    for i in range(4):
        x[i*8: i*8+8] = sm4_bs_sbox(x[i*8:i*8+8][::-1])

def BitSM4(ptx, key, if_enc):
    kk = sm4_expandKey(key, if_enc)
    buf = [[None for _ in range(32)] for _ in range(36)]
    temp = [None for _ in range(32)]
    ctx = [None for _ in range(128)]
    for j in range(4):
        for k in range(32):
            buf[j][k] = ptx[32*j+k]
    global idM32
    # 32轮
    for i in range(32):
        # 4道32bit数据操作
        for j in range(32):
            # buf[4+i][j] = buf[i+1][j] ^ buf[i+2][j] ^ buf[i+3][j] ^ BS_RK_512[i][j]
            buf[i+4][j] = buf[i+1][j] ^ buf[i+2][j]
            buf[i+4][j] = buf[i+4][j] ^ buf[i+3][j]
            if kk[i] & idM32[j]:
                buf[i+4][j] = Not(buf[i+4][j])
        # S盒
        sm4_SubBytes(buf[i+4])
        # 线性变换L 循环左移
        for j in range(32):
            temp[j] = buf[4+i][j] ^ buf[4+i][(j+2)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+10)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+18)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+24)%32]
        for j in range(32):
            buf[4+i][j] = temp[j] ^ buf[i][j]
    # 反序
    for j in range(4):
        for k in range(32):
            ctx[32*j+k]=buf[35-j][k]
            # ctx[32*j+k]=buf[j+1][k]
    
    return ctx


def randSM4(ptx1, rp):
    buf = [[None for _ in range(32)] for _ in range(36)]
    temp = [None for _ in range(32)]
    ptx = [None for _ in range(128)]
    ctx = [None for _ in range(128)]
    for i in range(128):
        ptx[i] = ptx1[i] ^ rp[i]
    for j in range(4):
        for k in range(32):
            buf[j][k] = ptx[32*j+k]
    global idM32
    # 32轮
    for i in range(8):
        # 4道32bit数据操作
        for j in range(32):
            # buf[4+i][j] = buf[i+1][j] ^ buf[i+2][j] ^ buf[i+3][j] ^ BS_RK_512[i][j]
            buf[i+4][j] = buf[i+1][j] ^ buf[i+2][j]
            buf[i+4][j] = buf[i+4][j] ^ buf[i+3][j]
        # S盒
        sm4_SubBytes(buf[i+4])
        # 线性变换L 循环左移
        for j in range(32):
            temp[j] = buf[4+i][j] ^ buf[4+i][(j+2)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+10)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+18)%32]
            temp[j] = temp[j] ^ buf[4+i][(j+24)%32]
        for j in range(32):
            buf[4+i][j] = temp[j] ^ buf[i][j]
    # 反序
    for j in range(4):
        for k in range(32):
            ctx[32*j+k]=buf[7-j][k]
            # ctx[32*j+k]=buf[j+1][k]
    
    return ctx