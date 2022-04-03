#@StartTime     :7/6/2021
#@Auther        :Chengda Wen
#@Software      :PyCharm
#@File          :pc2(Equivalent to Client)
#@Task          :nwpu_summercamp

from socket import *
import time
import random
import math
from SM3 import *
import json


# Connect to host_computer1:
print('\n*************************  PC2 Connecting to PC1  *************************')
print("Time："+time.strftime('%m/%d/%Y %H:%M:%S', time.localtime(time.time())))
print('Connecting...')
Key_SM4 = '0123456789ABCDEF0123456789ABCDEF'
Host = 'localhost'
Port = 6667
Buff = 1024
Addr = (Host, Port)

t = 3
host2 = socket(AF_INET, SOCK_STREAM)
host2.connect(Addr)
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time()))+' host_computer2 has been connected.')

# Step1. Receive SM2_KEY from PC1
print('\n*********************** PC2_Step1. 接收PC1传送的SM2公钥 **********************')
SM2_Px = int(host2.recv(Buff).decode())
SM2_Py = int(host2.recv(Buff).decode())
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + '已收到主机1的SM2公钥Px,Py')
print('PC1的SM2公钥Px: ' + str(SM2_Px))
print('PC1的SM2公钥Py: ' + str(SM2_Py))
host2.send('Received SM2_Key'.encode('utf-8'))


# Step2-1. Encrypt SM4_Key with SM2_PublicKey
print('\n****************** PC2_Step2-1. 利用SM2公钥对SM4_Key进行加密 ******************')
# 37 to 195 lines 为 SM2源码 (加密部分,稍作修改)
# y^2=x^3+ax+b
# 推荐系统参数
p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',base=16)
a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',base=16)
b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',base=16)
n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',base=16)
Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7',base=16)
Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0',base=16)
# 扩展欧几里得算法求逆元
def get_gcd(a, b):
    if(b==0):
        return 1,0,a
    else:
        x,y,gcd = get_gcd(b,a%b)
        x,y = y,(x-(a//b)*y)
        return x,y,gcd
# 两点加法
def add_point(x1,y1,x2,y2,p):
    if(x1=='O' and y1=='O'):
        return x2,y2
    elif(x2=='O' and y2=='O'):
        return x1,y1
    elif(x1==x2 and y2==((-1)*y1)%p):
        x3 = 'O'
        y3 = 'O'
        return x3,y3
    else:
        inv,y,gcd = get_gcd(x2-x1,p)
        lbd = ((y2-y1)*inv)%p
        x3 = (lbd**2-x1-x2)%p
        y3 = (lbd*(x1-x3)-y1)%p
        return x3,y3
# 倍点算法
def multiply2_point(x1,y1,a,p):
    if(x1=='O' and y1=='O'):
        return x1,y1
    else:
        inv,y,gcd = get_gcd(2*y1,p)
        lbd = ((3*(x1**2)+a)*inv)%p
        x3 = (lbd**2-2*x1)%p
        y3 = (lbd*(x1-x3)-y1)%p
        return x3,y3
# k倍点算法
def multiplyk_point(Px,Py,k,a,p):
    k = bin(k)[2:]
    Qx = 'O'
    Qy = 'O'
    for j in range(len(k)):
        Qx,Qy = multiply2_point(Qx,Qy,a,p)
        if(k[j]=='1'):
            Qx,Qy = add_point(Qx,Qy,Px,Py,p)
    return Qx,Qy
# 消息字符串转比特串
def msg2bit(msg):
    res = ''
    for c in msg:
        a = ord(c)
        res += bin(a)[2:].zfill(8)
    return res
# 比特串转域元素
def bit2Fq(b):
    for i in range(len(b)):
        if (b[i] == '1'):
            b = b[i:]
            break
    return int(b, base=2)
# 比特串转消息字符串
def bit2msg(b):
    res = ''
    for i in range(int(len(b)/8)):
        cbit = b[i*8:(i+1)*8]
        res += chr(int(cbit,base=2))
    return res
# 域元素到比特串的转换
def Fq2bit(alpha,p):
    t = math.ceil(math.log(p,2))
    M = bin(alpha)[2:]
    while(len(M)%8!=0 or len(M)!=t):
        M = '0' + M
    #print(M,len(M))
    return M
# 点到比特串转换
def point2bit(xp,yp,p):
    PC = '00000100'  # 选择不压缩模式
    xp_bit = Fq2bit(xp,p)
    yp_bit = Fq2bit(yp,p)
    return PC+xp_bit+yp_bit
# KDF combined with SM3
def KDF(Z,klen):
    v = 256
    ct = 1
    Ha = {}
    for i in range(1,math.ceil(klen/v)+1):
        Ha[i] = SM3_digest(Z+bin(ct)[2:].zfill(32))
        ct += 1
    # klen/v is integer
    index = math.ceil(klen/v)
    Haa = ''
    if(math.ceil(klen/v)==klen/v):
        Haa = Ha[index]
    else:
        Haa = Ha[index][:klen-(v*math.floor(klen/v))]
    K = ''
    for i in range(1,math.ceil(klen/v)):
        K += Ha[i]
    K += Haa
    return K
# 按位异或
def Xor(a,b):
    result =''
    if len(a)!=len(b):
        return False
    for i in range(len(a)):
        if a[i]==b[i]:
            result += '0'
        else:
            result += '1'
    return result
# bit str M
def SM2_encrypt(M,n,Gx,Gy,a,b,p,Px,Py):
    #print('SM2 ENCRYPTION')
    klen = len(M)
    # A1
    k = random.randint(1,n-1)
    # A2
    x1,y1 = multiplyk_point(Gx,Gy,k,a,p)
    C1 = point2bit(x1,y1,p)
    # A3
    h = math.floor(((math.sqrt(p)+1)**2)/n)
    Sx,Sy = multiplyk_point(Px,Py,h,a,p)
    if(Sx=='O' or Sy=='0'):
        return False
    # A4
    x2,y2 = multiplyk_point(Px,Py,k,a,p)
    x2_bit = Fq2bit(x2,p)
    y2_bit = Fq2bit(y2,p)
    # A5
    t = KDF(x2_bit+y2_bit,klen)
    if(int(t,base=2)==0):
        return False
    # A6
    C2 = Xor(M, t)
    # A7
    C3 = SM3_digest(x2_bit+M+y2_bit)
    # A8
    C = [C1, C2, C3]
    return C
plain_text = msg2bit(Key_SM4)
cipher_text = SM2_encrypt(plain_text, n, Gx, Gy, a, b, p, SM2_Px, SM2_Py)  # 传送的密文 二进制流的list
hexresult = ''
for c in cipher_text:
    hexresult += hex(int(c, base=2))
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + '已完成SM2对SM4密钥的加密！密文如下：')
print(str(hexresult))


# Step2-2. Send SM4_KEY to PC1
print('\n******************  PC2_Step2-2. 传送加密后的SM4密钥至主机1  *******************')
host2.send(cipher_text[0].encode())
host2.send(cipher_text[1].encode())
host2.send(cipher_text[2].encode())
d = int(host2.recv(Buff).decode())
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + '已发送加密后的SM4密钥至主机1！')

# @@200 to 271 lines 仅为自行测试SM2解密模块
# KDF combined with SM3
def KDF(Z, klen):
    v = 256
    ct = 1
    Ha = {}
    for i in range(1, math.ceil(klen / v) + 1):
        Ha[i] = SM3_digest(Z + bin(ct)[2:].zfill(32))
        ct += 1
    # klen/v is integer
    index = math.ceil(klen / v)
    Haa = ''
    if (math.ceil(klen / v) == klen / v):
        Haa = Ha[index]
    else:
        Haa = Ha[index][:klen - (v * math.floor(klen / v))]
    K = ''
    for i in range(1, math.ceil(klen / v)):
        K += Ha[i]
    K += Haa
    return K
# 按位异或
def Xor(a, b):
    result = ''
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] == b[i]:
            result += '0'
        else:
            result += '1'
    return result
def SM2_decrypt(C, n, Gx, Gy, a, b, p, d):
    # print('SM2 DECRYPTION')
    C1 = C[0]
    C2 = C[1]
    C3 = C[2]
    klen = len(C2)

    # B1
    PC = C1[:8]  # PC=04
    bit_len = int((len(C1) - 8) / 2)
    x1 = bit2Fq(C1[8:8 + bit_len])
    y1 = bit2Fq(C1[8 + bit_len:])
    left = (y1 ** 2) % p
    right = (x1 ** 3 + a * x1 + b) % p
    if (left != right):
        return False
    # B2
    h = math.floor(((math.sqrt(p) + 1) ** 2) / n)
    Sx, Sy = multiplyk_point(SM2_Px, SM2_Py, h, a, p)
    if (Sx == 'O' or Sy == '0'):
        return False
    # B3
    x2, y2 = multiplyk_point(x1, y1, d, a, p)
    x2_bit = Fq2bit(x2, p)
    y2_bit = Fq2bit(y2, p)
    # B4
    t = KDF(x2_bit + y2_bit, klen)
    if (int(t, base=2) == 0):
        return False
    # B5
    MM = Xor(C2, t)
    # B6
    u = SM3_digest(x2_bit + MM + y2_bit)
    if (u != C3):
        return False
    # B7
    return MM
def test(x):
    #test decrypt:
    if(x == 1):
        host2.send(decrypt_text.encode())
# SM2_Decryption
decrypt_text = SM2_decrypt(cipher_text, n, Gx, Gy, a, b, p, d)
decrypt_text = bit2msg(decrypt_text)
test(1)
json_string = json.dumps(decrypt_text)
host2.sendto(json_string.encode('UTF-8'), Addr)

# Step3. Encrypt Datatext with SM4
print('\n*******************  PC2_Step3. 分组密码SM4对消息进行加密！ *********************')
# 2进制转16进制
def BtoH(text):
    text = str(text)
    while len(text)<32:
        text = '0' + text
    text_16 = ''
    for i in range(len(text)//4):
        tmp = hex(int(text[4*i:4*(i+1)],base = 2))[2:]
        text_16 = text_16 + tmp
    return text_16
# 16进制转2进制
def HtoB(text):
    text_2 = ''
    text = str(text)
    for ch in text:
        tmp = bin(int(ch ,base = 16))[2:]
        for i in range(4):
            if len(tmp)%4!=0:
                tmp = '0' + tmp
        text_2 = text_2 + tmp
    while len(text_2)<32:
        text_2 = '0' + text_2
    return text_2
# 按位异或
def Xor(a,b):
    result =''
    if len(a)!=len(b):
        print('len(a)!=len(b)')
        return False
    for i in range(len(a)):
        if a[i]==b[i]:
            result += '0'
        else:
            result += '1'
    return result
# 三变量按位异或运算
def Xor3(a,b,c):
    return Xor(Xor(a,b),c)
# 循环左移函数
def LeftRotate(text, num):
    text = str(text)
    return (text[num:] + text[:num])
# s-box对应函数
def tao(b):
    Sbox = {
        0x00: 0xD6, 0x01: 0x90, 0x02: 0xE9, 0x03: 0xFE,
        0x04: 0xCC, 0x05: 0xE1, 0x06: 0x3D, 0x07: 0xB7,
        0x08: 0x16, 0x09: 0xB6, 0x0A: 0x14, 0x0B: 0xC2,
        0x0C: 0x28, 0x0D: 0xFB, 0x0E: 0x2C, 0x0F: 0x05,

        0x10: 0x2B, 0x11: 0x67, 0x12: 0x9A, 0x13: 0x76,
        0x14: 0x2A, 0x15: 0xBE, 0x16: 0x04, 0x17: 0xC3,
        0x18: 0xAA, 0x19: 0x44, 0x1A: 0x13, 0x1B: 0x26,
        0x1C: 0x49, 0x1D: 0x86, 0x1E: 0x06, 0x1F: 0x99,

        0x20: 0x9C, 0x21: 0x42, 0x22: 0x50, 0x23: 0xF4,
        0x24: 0x91, 0x25: 0xEF, 0x26: 0x98, 0x27: 0x7A,
        0x28: 0x33, 0x29: 0x54, 0x2A: 0x0B, 0x2B: 0x43,
        0x2C: 0xED, 0x2D: 0xCF, 0x2E: 0xAC, 0x2F: 0x62,

        0x30: 0xE4, 0x31: 0xB3, 0x32: 0x1C, 0x33: 0xA9,
        0x34: 0xC9, 0x35: 0x08, 0x36: 0xE8, 0x37: 0x95,
        0x38: 0x80, 0x39: 0xDF, 0x3A: 0x94, 0x3B: 0xFA,
        0x3C: 0x75, 0x3D: 0x8F, 0x3E: 0x3F, 0x3F: 0xA6,

        0x40: 0x47, 0x41: 0x07, 0x42: 0xA7, 0x43: 0xFC,
        0x44: 0xF3, 0x45: 0x73, 0x46: 0x17, 0x47: 0xBA,
        0x48: 0x83, 0x49: 0x59, 0x4A: 0x3C, 0x4B: 0x19,
        0x4C: 0xE6, 0x4D: 0x85, 0x4E: 0x4F, 0x4F: 0xA8,

        0x50: 0x68, 0x51: 0x6B, 0x52: 0x81, 0x53: 0xB2,
        0x54: 0x71, 0x55: 0x64, 0x56: 0xDA, 0x57: 0x8B,
        0x58: 0xF8, 0x59: 0xEB, 0x5A: 0x0F, 0x5B: 0x4B,
        0x5C: 0x70, 0x5D: 0x56, 0x5E: 0x9D, 0x5F: 0x35,

        0x60: 0x1E, 0x61: 0x24, 0x62: 0x0E, 0x63: 0x5E,
        0x64: 0x63, 0x65: 0x58, 0x66: 0xD1, 0x67: 0xA2,
        0x68: 0x25, 0x69: 0x22, 0x6A: 0x7C, 0x6B: 0x3B,
        0x6C: 0x01, 0x6D: 0x21, 0x6E: 0x78, 0x6F: 0x87,

        0x70: 0xD4, 0x71: 0x00, 0x72: 0x46, 0x73: 0x57,
        0x74: 0x9F, 0x75: 0xD3, 0x76: 0x27, 0x77: 0x52,
        0x78: 0x4C, 0x79: 0x36, 0x7A: 0x02, 0x7B: 0xE7,
        0x7C: 0xA0, 0x7D: 0xC4, 0x7E: 0xC8, 0x7F: 0x9E,

        0x80: 0xEA, 0x81: 0xBF, 0x82: 0x8A, 0x83: 0xD2,
        0x84: 0x40, 0x85: 0xC7, 0x86: 0x38, 0x87: 0xB5,
        0x88: 0xA3, 0x89: 0xF7, 0x8A: 0xF2, 0x8B: 0xCE,
        0x8C: 0xF9, 0x8D: 0x61, 0x8E: 0x15, 0x8F: 0xA1,

        0x90: 0xE0, 0x91: 0xAE, 0x92: 0x5D, 0x93: 0xA4,
        0x94: 0x9B, 0x95: 0x34, 0x96: 0x1A, 0x97: 0x55,
        0x98: 0xAD, 0x99: 0x93, 0x9A: 0x32, 0x9B: 0x30,
        0x9C: 0xF5, 0x9D: 0x8C, 0x9E: 0xB1, 0x9F: 0xE3,

        0xA0: 0x1D, 0xA1: 0xF6, 0xA2: 0xE2, 0xA3: 0x2E,
        0xA4: 0x82, 0xA5: 0x66, 0xA6: 0xCA, 0xA7: 0x60,
        0xA8: 0xC0, 0xA9: 0x29, 0xAA: 0x23, 0xAB: 0xAB,
        0xAC: 0x0D, 0xAD: 0x53, 0xAE: 0x4E, 0xAF: 0x6F,

        0xB0: 0xD5, 0xB1: 0xDB, 0xB2: 0x37, 0xB3: 0x45,
        0xB4: 0xDE, 0xB5: 0xFD, 0xB6: 0x8E, 0xB7: 0x2F,
        0xB8: 0x03, 0xB9: 0xFF, 0xBA: 0x6A, 0xBB: 0x72,
        0xBC: 0x6D, 0xBD: 0x6C, 0xBE: 0x5B, 0xBF: 0x51,

        0xC0: 0x8D, 0xC1: 0x1B, 0xC2: 0xAF, 0xC3: 0x92,
        0xC4: 0xBB, 0xC5: 0xDD, 0xC6: 0xBC, 0xC7: 0x7F,
        0xC8: 0x11, 0xC9: 0xD9, 0xCA: 0x5C, 0xCB: 0x41,
        0xCC: 0x1F, 0xCD: 0x10, 0xCE: 0x5A, 0xCF: 0xD8,

        0xD0: 0x0A, 0xD1: 0xC1, 0xD2: 0x31, 0xD3: 0x88,
        0xD4: 0xA5, 0xD5: 0xCD, 0xD6: 0x7B, 0xD7: 0xBD,
        0xD8: 0x2D, 0xD9: 0x74, 0xDA: 0xD0, 0xDB: 0x12,
        0xDC: 0xB8, 0xDD: 0xE5, 0xDE: 0xB4, 0xDF: 0xB0,

        0xE0: 0x89, 0xE1: 0x69, 0xE2: 0x97, 0xE3: 0x4A,
        0xE4: 0x0C, 0xE5: 0x96, 0xE6: 0x77, 0xE7: 0x7E,
        0xE8: 0x65, 0xE9: 0xB9, 0xEA: 0xF1, 0xEB: 0x09,
        0xEC: 0xC5, 0xED: 0x6E, 0xEE: 0xC6, 0xEF: 0x84,

        0xF0: 0x18, 0xF1: 0xF0, 0xF2: 0x7D, 0xF3: 0xEC,
        0xF4: 0x3A, 0xF5: 0xDC, 0xF6: 0x4D, 0xF7: 0x20,
        0xF8: 0x79, 0xF9: 0xEE, 0xFA: 0x5F, 0xFB: 0x3E,
        0xFC: 0xD7, 0xFD: 0xCB, 0xFE: 0x39, 0xFF: 0x48
    }
    a = []
    for i in range(4):
        a.append(b[i*8:(i+1)*8])
    res = ''
    for i in range(4):
        index = hex(int(str(a[i]),base=2))
        tmp = hex(Sbox[int(index,base=16)])[2:]
        res += tmp
    return HtoB(res)
# 合成置换T中的L
def L(b):
    return Xor(Xor(Xor(Xor(b,LeftRotate(b,2)),LeftRotate(b,10)),LeftRotate(b,18)),LeftRotate(b,24))
# 密钥扩展中的L'
def LL(b):
    return Xor3(b,LeftRotate(b,13),LeftRotate(b,23))
# 合成置换T
def T(b):
    return L(tao(b))
# 密钥扩展中的T'
def TT(b):
    return LL(tao(b))
# 轮函数F
def F(x0,x1,x2,x3,rk):
    return Xor(x0,T( Xor(Xor3(x1,x2,x3), rk)))
# 密钥扩展
def Key_Expand(key_2):
    key_2 = HtoB(Key_SM4)
    FK = ['A3B1BAC6','56AA3350','677D9197','B27022DC']
    CK = ['00070E15','1C232A31','383F464D','545B6269','70777E85','8C939AA1','A8AFB6BD','C4CBD2D9','E0E7EEF5','FC030A11','181F262D','343B4249','50575E65','6C737A81','888F969D','A4ABB2B9','C0C7CED5','DCE3EAF1','F8FF060D','141B2229','30373E45','4C535A61','686F767D','848B9299','A0A7AEB5','BCC3CAD1','D8DFE6ED','F4FB0209','10171E25','2C333A41','484F565D','646B7279']
    K=[]
    for i in range(4):
        K.append(Xor(key_2[i*32:(i+1)*32],HtoB(FK[i])))
    rk=[]
    for i in range(32):
        rk.append( Xor( K[i], TT( Xor( Xor3(K[i+1],K[i+2],K[i+3]), HtoB(CK[i]) ) ) ) )
        K.append(rk[i])
        #print("rk[",i,']',BtoH(rk[i]))
    return rk

# Encrypt_SM4
def SM4_encrypt(inputX, rk):
    X = inputX
    for i in range(32):
        X.append(F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[i]))
        # print('X[',i+4,']',BtoH(X[i+4]))
    res = ''
    for i in range(4):
        res += X[35 - i]
    return BtoH(res)
# 消息字符串转比特串
def msg2bit(msg):
    res = ''
    for c in msg:
        a = ord(c)
        res += bin(a)[2:].zfill(8)
    return res
# 比特串转消息字符串
def bit2msg(b):
    res = ''
    for i in range(int(len(b) / 8)):
        cbit = b[i * 8:(i + 1) * 8]
        res += chr(int(cbit, base=2))
    return res
# 字符消息转成128bit分组
def get_msggroup(plaintext):
    plaintext_2 = msg2bit(plaintext)  # 转为2进制比特串
    group_num = math.ceil(len(plaintext_2) / 128)  # 求出分组组数
    msg_group = []

    # 对于前group_num-1个分组，必定是128位，直接添加到分组消息中
    for i in range(group_num - 1):
        msg_group.append(plaintext_2[0:128])
        plaintext_2 = plaintext_2[128:]

    remain_len = len(plaintext_2)  # 获得最后一个消息分组的长度（可能不足128bit）
    # 如果最后一个消息分组是128bit，则直接添加
    if (remain_len == 128):
        msg_group.append(plaintext_2)
        msg_group.append(''.zfill(128))  # 在消息分组结尾添加一个全0分组，标识最后一个分组原本为128位

    # 如果最后一个消息分组不足128bit，则根据它的二进制串第一位，填充与之相反的0/1在前，补足128位
    else:
        if (plaintext_2[0] == '1'):
            plaintext_2 = plaintext_2.zfill(128 - remain_len)
        else:
            for i in range(128 - remain_len):
                plaintext_2 = '1' + plaintext_2
        msg_group.append(plaintext_2)
        # 在消息分组结尾添加一个全1分组，标识最后一个分组原本不足128位，含有填充字符
        msg_group.append(
            '11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111')
    return msg_group
# 密钥扩展
rk = Key_Expand(Key_SM4)

# 读明文文件,对消息进行加密：
file = open("message.txt")
for i in range(8):
    line = file.readline()
    print(line, end="")
    if not line:
        break
    # 获得明文分组
    msg_group = get_msggroup(line)
    # SM4加密
    cipher_text = []
    for msg in msg_group:
        X = []
        for i in range(4):
            X.append(msg[i * 32:(i + 1) * 32])
        encryption = SM4_encrypt(X, rk)
        cipher_text.append(encryption)
        #host2.shutdown(socket.SHUT_RDWR)

    json_string = json.dumps(cipher_text)
    host2.sendto(json_string.encode('UTF-8'), Addr)
    print('加密密文分组为：', cipher_text)
    print('已成功发送至主机1！')
    print('')
    #print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + '成功发送第' + str(i + 1) + '组消息：', end="")

    def SM4_decrypt(inputX, rk):
        X = inputX
        for i in range(32):
            X.append(F(X[i], X[i + 1], X[i + 2], X[i + 3], rk[31 - i]))
        res = ''
        for i in range(4):
            res += X[35 - i]
        return BtoH(res)


# Step4. Get RSA Key
print('\n********************  PC2_Step4-1. 获取RSA公私密钥对！  **********************')
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time()))+'已获取RSA的公私密钥对！公开公钥如下：')
class RSAEncryption:
    import random
    privat_key = ""
    public_key = ""
    def __init__(self):
        pass

    def is_prime(self, num):

        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num ** 0.5) + 2, 2):
            if num % n == 0:
                return False
        return True

    def generate_random_prime(self, max_prime_length):
        while 1:
            ran_prime = self.random.randint(0, max_prime_length)
            if self.is_prime(ran_prime):
                return ran_prime

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def egcd(self, a, b):
        if a == 0:
            return(b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def generate_keys(self):
        """
        Method for key generation
        :return: publickey, and privatekey with modulus (tuple)
        """
        # D value in blog post.

        self.private_key = ""
        self.public_key = ""

        p = self.generate_random_prime(10000000000)
        q = self.generate_random_prime(10000000000)

        modulus = p * q
        print("Modulus ", modulus)
        f_mod = (p - 1) * (q - 1)
        print("F_mod ", f_mod)

        # Next is to find co-prime to modulus
        self.public_key = self.random.randint(1, f_mod)
        g = self.gcd(self.public_key, f_mod)
        while g != 1:
            self.public_key = self.random.randint(1, f_mod)
            g = self.gcd(self.public_key, f_mod)

        print("public_key=", self.public_key, " ", "modulus=", modulus)
        # Next we have to find the private key.
        # For that we use multiplication inverse.
        self.private_key = self.egcd(self.public_key, f_mod)[1]

        # Check that d is positiv.
        self.private_key = self.private_key % f_mod
        if self.private_key < 0:
            self.privat_key += f_mod

        return (self.private_key, modulus), (self.public_key, modulus)
a = RSAEncryption()
public_key,private_key = a.generate_keys()
e, n = public_key
print(public_key)
# Step1-2. Send SM2_KEY to PC2
print('\n***********************   PC2_Step4-2. 传送RSA公钥   ***********************')
host2.send(str(n).encode())
host2.send(str(e).encode())
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time()))+'已将RSA公钥传送至主机1')

class RSAEncryption:
    import random
    privat_key = ""
    public_key = ""
    def __init__(self):
        pass

    def is_prime(self, num):

        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num ** 0.5) + 2, 2):
            if num % n == 0:
                return False
        return True

    def generate_random_prime(self, max_prime_length):
        while 1:
            ran_prime = self.random.randint(0, max_prime_length)
            if self.is_prime(ran_prime):
                return ran_prime

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def egcd(self, a, b):
        if a == 0:
            return(b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def generate_keys(self):
        """
        Method for key generation
        :return: publickey, and privatekey with modulus (tuple)
        """
        # D value in blog post.

        self.private_key = ""
        self.public_key = ""

        p = self.generate_random_prime(10000000000)
        q = self.generate_random_prime(10000000000)

        modulus = p * q
        print("Modulus ", modulus)
        f_mod = (p - 1) * (q - 1)
        print("F_mod ", f_mod)

        # Next is to find co-prime to modulus
        self.public_key = self.random.randint(1, f_mod)
        g = self.gcd(self.public_key, f_mod)
        while g != 1:
            self.public_key = self.random.randint(1, f_mod)
            g = self.gcd(self.public_key, f_mod)

        print("public_key=", self.public_key, " ", "modulus=", modulus)
        # Next we have to find the private key.
        # For that we use multiplication inverse.
        self.private_key = self.egcd(self.public_key, f_mod)[1]

        # Check that d is positiv.
        self.private_key = self.private_key % f_mod
        if self.private_key < 0:
            self.privat_key += f_mod

        return (self.private_key, modulus), (self.public_key, modulus)
    1000000000000

    @staticmethod
    def encrypt(text, public_key):
        """
        Method for encryption
        :param public_key:  Publickey and modulus (tuple, int)
        :param message: The message you want to encrypt (string)
        :return: Message (string)
        """
        # Converts the char to ascii decimal and then performs encryption.
        key, n = public_key
        ctext = [pow(ord(char), key, n) for char in text]
        return ctext

    @staticmethod
    def decrypt(ctext, private_key):
        """
        Method for decryption
        :param private_key:  Privatekey and modulus (tuple, int)
        :param emessage: The message you want to decrypt (list, int)
        :return: Message (string)
        """
        # Creates a list with all the characters in the text and performs the decryption
        try:
            key, n = private_key
            text = [chr(pow(char, key, n)) for char in ctext]
            return "".join(text)
        except TypeError as e:
            print(e)
a = RSAEncryption()
public_key, private_key = a.generate_keys()
print("Public: ", public_key)
print("Private: ", private_key)
message = RSAEncryption.encrypt("This is the time we are going to have sex so lets have ti and lets not stop and saying ",public_key)
print("encrypted  =", message)
plaintext = RSAEncryption.decrypt(message, private_key)
print("decrypted =", plaintext)




def decrypt(ctext,prikey):
    try:
        key, n = prikey
        text = [chr(pow(char, key, n)) for char in ctext]
        return "".join(text)
    except TypeError as e:
        print(e)

# Step5. Receive AES_Key from PC1
print('\n******************   PC2_Step5. 接收RSA加密后的AES的密钥  ********************')
print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))+' 已收到加密后的AES密钥！密钥如下：')
# m = host2.recv(Buff)
s1, Addr = host2.recvfrom(Buff)
m = json.loads(s1.decode())
print(m)




print('\n********************   PC2_Step6. 利用RSA私钥进行解密  ***********************')
plaintext = decrypt(m, private_key)
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + '解密完成！得到AES密钥如下：')
print(plaintext)

