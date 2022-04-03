#@StartTime     :7/6/2021
#@Auther        :Chengda Wen
#@Software      :PyCharm
#@File          :host_computer1(Equivalent to Server)
#@Task          :nwpu_summercamp

from socket import *
import time
import binascii
import random
from SM3 import *
import math



print("Time："+time.strftime('%m/%d/%Y %H:%M:%S', time.localtime(time.time())))

Key_SM4="0123456789ABCDEF"
Host = 'localhost'
Port = 6666
Buff = 1024
Addr = (Host, Port)

# socket connect preparation:
# AF_INET -> IPv4  SOCK_STREAM -> TCP
host1 = socket(AF_INET, SOCK_STREAM)
host1.bind(Addr)
host1.listen(6)
print('Waiting for connection...')
conn, addr = host1.accept()
print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time()))+' host_computer1 has already connected from:', addr)

# host_computer1 gets RSA_Key(Ke,Kd)
# After receiving the command "Distribution key" from host_computer2:
# host_computer1 sends RSA_Ke to host_computer2

# 生成n位的随机数
def createRandomNum(n):
    return random.randint(10 ** (n - 1), 10 ** n - 1)

# 欧几里得算法求最大公约数
def gcd(x, y):
    while y:
        x, y = y, x % y
    return x

# 扩展欧几里得算法求乘法逆元(x*a + y*b = q)
def getInverse(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = getInverse(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q

# 平方求模
def getMod(a, e, m):
    result = 1
    while e != 0:
        if e & 1 == 1:
            result = result * a % m
        e >>= 1
        a = a * a % m
    return result

# 生成10000以内素数表(eratosthenes算法）
def primeFilter(n):
    return lambda x: x % n > 0

def createSmallPrimeNum():
    num = iter(range(3, 10000, 2))
    prime = [2]
    while True:
        try:
            n = next(num)
            prime.append(n)
            num = filter(primeFilter(n), num)
        except StopIteration:
            return prime

# 素数检测算法（Miller-Rabin算法）
def Miller_Rabin(n):
    if n < 3:
        return False

    k = 1
    m = 0
    while (n - 1) % (2 ** k) == 0:
        m = (int)((n - 1) / (2 ** k))
        if m % 2:
            break
        k += 1
    if m == 0:
        return False

    a = random.randint(2, n - 1)
    b = getMod(a, m, n)

    if b == 1:
        return True

    for i in range(0, k):
        if b == n - 1:
            return True
        else:
            b = b * b % n

    return False

# 生成大素数(x位）
def createLargePrimeNum(x):
    flag = False
    smallPrimeNum = createSmallPrimeNum()

    while (not flag):
        flag = True
        n = createRandomNum(x)
        if not n % 2: n += 1

        # 10000内素数检验
        for i in smallPrimeNum:
            if n % i == 0:
                flag = False
                break
        if not flag: continue

        # 10次Miller-Rabin素性检测
        for i in range(0, 20):
            if not Miller_Rabin(n):
                flag = False
                break
    return n

# 密钥生成
def createKey(x):
    p = createLargePrimeNum(x)
    q = createLargePrimeNum(x)
    n = p * q
    _n = (p - 1) * (q - 1)
    e = random.randint(2, _n - 1)

    while (gcd(e, _n) != 1):
        e = random.randint(2, _n - 1)

    d, tmp1, tmp2 = getInverse(e, _n)
    if d < 0:
        d += _n
    return e, n, d

key = ''
while True:
    if not key:
        host1_recv_data = conn.recv(Buff)

        if host1_recv_data.decode('utf-8') == 'Distribution key':
            print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + ' Prepared for distributing RSA_Key!')
            print('Host_computer1 Step 1.  To get RSA_Key & send to host_computer2:')
            RSA_Ke, n, RSA_Kd = createKey(16)  #16*2=32bit Key
            conn.send(str(RSA_Kd).encode('utf-8'))
            conn.send(str(RSA_Ke).encode('utf-8'))
            conn.send(str(n).encode('utf-8'))
            print('Host_computer1 has sent RSA_Ke to host_computer2.\n')
            print(time.strftime('%m/%d/%Y %H:%M:%S  ', time.localtime(time.time())) + ' Receive SM2_PublicKey from host_computer2')

            tempcipher = conn.recv(Buff).decode('utf-8')
            temp = tempcipher.encode().hex()
            cipher = binascii.a2b_hex(temp).decode()
            print(cipher)

            # 十进制转为十六进制
            def decToHex(n):
                return hex(int(n, 10))[2:]
            # 十六进制转为十进制
            def hexToDec(n):
                return int(n, 16)
            # 解密函数
            def decrypt(c, d, n):
                return getMod(c, d, n)
            def rsa_decrypt(c, d, n):
                n_hex = decToHex(str(n))
                m = ""
                num = len(n_hex)
                while len(c) > 0:
                    x = hexToDec(c[0: num])
                    c = c[len(n_hex):]
                    tmp = decrypt(x, d, n)
                    if len(decToHex(str(tmp))) < 16 and len(c) > 0:
                        m += (16 - len(decToHex(str(tmp)))) * '0'
                    m += decToHex(str(tmp))
                return m
            aes_key = rsa_decrypt(tempcipher, int(RSA_Kd), n)
            print(aes_key)
            '''
            RSA_Ke, n, RSA_Kd = rsa.createKey(16)
            # rsa加密对称密钥
            key_encrypted = rsa.rsa_encrypt(Key_SM4, RSA_Ke, n)
            print(key_encrypted)
            # 解密得到对称密钥
            key = rsa.rsa_decrypt(key_encrypted, RSA_Kd, n)
            print("得到密钥：" + key)
            '''
            # Received Pd(PrivateKey) from host_computer2:
            d = int(conn.recv(Buff).decode(), 16)
            Px = int(conn.recv(Buff).decode('utf-8'), 16)
            Py = int(conn.recv(Buff).decode('utf-8'), 16)
            #Py = conn.recv(Buff)
            #print(Px.decode())
            C1 = conn.recv(Buff).decode()
            C2 = conn.recv(Buff).decode()
            C3 = conn.recv(Buff).decode()
            cipher_t = conn.recv(Buff)
            f = open("SM2_cilpherlist.txt", "r")
            cipher_text = f.read()
            print(cipher_text)

            #cipher_text = json.loads(cipher_t)
            #C = [C1, C2, C3]
            #print(cipher_text)

            # y^2=x^3+ax+b
            # 推荐系统参数
            p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', base=16)
            a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', base=16)
            b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', base=16)
            n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', base=16)
            Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', base=16)
            Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', base=16)
            # 扩展欧几里得算法求逆元
            def get_gcd(a, b):
                if (b == 0):
                    return 1, 0, a
                else:
                    x, y, gcd = get_gcd(b, a % b)
                    x, y = y, (x - (a // b) * y)
                    return x, y, gcd
            # 两点加法
            def add_point(x1, y1, x2, y2, p):
                if (x1 == 'O' and y1 == 'O'):
                    return x2, y2
                elif (x2 == 'O' and y2 == 'O'):
                    return x1, y1
                elif (x1 == x2 and y2 == ((-1) * y1) % p):
                    x3 = 'O'
                    y3 = 'O'
                    return x3, y3
                else:
                    inv, y, gcd = get_gcd(x2 - x1, p)
                    lbd = ((y2 - y1) * inv) % p
                    x3 = (lbd ** 2 - x1 - x2) % p
                    y3 = (lbd * (x1 - x3) - y1) % p
                    return x3, y3
            # 倍点算法
            def multiply2_point(x1, y1, a, p):
                if (x1 == 'O' and y1 == 'O'):
                    return x1, y1
                else:
                    inv, y, gcd = get_gcd(2 * y1, p)
                    lbd = ((3 * (x1 ** 2) + a) * inv) % p
                    x3 = (lbd ** 2 - 2 * x1) % p
                    y3 = (lbd * (x1 - x3) - y1) % p
                    return x3, y3
            # k倍点算法
            def multiplyk_point(Px, Py, k, a, p):
                k = bin(k)[2:]
                Qx = 'O'
                Qy = 'O'
                for j in range(len(k)):
                    Qx, Qy = multiply2_point(Qx, Qy, a, p)
                    if (k[j] == '1'):
                        Qx, Qy = add_point(Qx, Qy, Px, Py, p)
                return Qx, Qy
            # 比特串转域元素
            def bit2Fq(b):
                for i in range(len(b)):
                    if (b[i] == '1'):
                        b = b[i:]
                        break
                return int('1', base=2)
            # 比特串转消息字符串
            def bit2msg(b):
                res = ''
                for i in range(int(len(b) / 8)):
                    cbit = b[i * 8:(i + 1) * 8]
                    res += chr(int(cbit, base=2))
                return res
            # 域元素到比特串的转换
            def Fq2bit(alpha, p):
                t = math.ceil(math.log(p, 2))
                M = bin(alpha)[2:]
                while (len(M) % 8 != 0 or len(M) != t):
                    M = '0' + M
                # print(M,len(M))
                return M
            # 点到比特串转换
            def point2bit(xp, yp, p):
                PC = '00000100'  # 选择不压缩模式
                xp_bit = Fq2bit(xp, p)
                yp_bit = Fq2bit(yp, p)
                return PC + xp_bit + yp_bit
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
                Sx, Sy = multiplyk_point(Px, Py, h, a, p)
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
            # SM2_Decryption
            decrypt_text = SM2_decrypt(cipher_text, n, Gx, Gy, a, b, p, d)


