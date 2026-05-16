# 密码学攻击案例与资源

## 学习平台

| 平台 | 链接 | 内容 |
|------|------|------|
| CryptoHack | https://cryptohack.org | 交互式密码学挑战 |
| Cryptopals | https://cryptopals.com | 经典密码学挑战集（48 题） |
| CTF Wiki Crypto | https://ctf-wiki.org/crypto/ | 密码学攻击技术详解 |

## 典型案例

### 案例 1: RSA 小指数广播攻击 (Hastad)
**场景**: 同一消息用 e=3 加密发给 3 个人
**方法**:
```python
from sympy.ntheory.modular import crt

# c1 = m^3 mod n1, c2 = m^3 mod n2, c3 = m^3 mod n3
remainders = [c1, c2, c3]
moduli = [n1, n2, n3]

# CRT 求解
m_cubed, _ = crt(moduli, remainders)
m = int(round(m_cubed ** (1/3)))
print(long_to_bytes(m))
```

### 案例 2: AES-CBC Padding Oracle
**场景**: 服务端返回 padding 是否有效
**方法**:
```python
def padding_oracle(iv, ciphertext, oracle):
    plaintext = b''
    for block_idx in range(len(ciphertext) // 16):
        block = ciphertext[block_idx*16:(block_idx+1)*16]
        decrypted = bytearray(16)
        
        for byte_idx in range(15, -1, -1):
            padding_val = 16 - byte_idx
            # 构造前缀
            prefix = bytes(decrypted[i] ^ padding_val for i in range(byte_idx+1, 16))
            
            for guess in range(256):
                test_iv = bytearray(iv)
                test_iv[byte_idx] ^= guess
                test_iv = bytes(test_iv) + prefix
                
                if oracle(test_iv + block):
                    decrypted[byte_idx] = guess ^ padding_val
                    break
        
        plaintext += bytes(decrypted)
        iv = block
    
    return plaintext
```

### 案例 3: ECDSA Nonce Reuse
**场景**: 两个签名使用相同的随机数 k
**方法**:
```python
# s1 = k^-1 * (z1 + r*d) mod n
# s2 = k^-1 * (z2 + r*d) mod n
# s1 - s2 = k^-1 * (z1 - z2) mod n
# k = (z1 - z2) * inverse(s1 - s2, n)
# d = (s1*k - z1) * inverse(r, n)

k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - z1) * pow(r, -1, n) % n
print(f"Private key: {d}")
```

### 案例 4: LLL 格规约
**场景: 隐藏数问题，部分 nonce 泄露
**方法**:
```python
from fpylll import IntegerMatrix, LLL

# 构造格基
B = IntegerMatrix(n, n)
# ... 填充格基矩阵

# LLL 规约
LLL.reduction(B)

# 提取短向量
short_vector = B[0]
```

### 案例 5: MT19937 状态恢复
**场景**: 已知 624 个连续输出，预测后续值
**方法**:
```python
def untemper(y):
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor(y, 15, 0xefc60000)
    y = undo_left_shift_xor(y, 7, 0x9d2c5680)
    y = undo_right_shift_xor(y, 11)
    return y

# 收集 624 个输出
state = [untemper(output[i]) for i in range(624)]

# 预测下一个
mt = MT19937()
mt.state = state
predicted = mt.getrandbits(32)
```

### 案例 6: Hash Length Extension
**场景**: hash(secret || user_data)，可以追加数据
**方法**:
```python
import hashpumpy

# 已知 hash(secret || known_data) 和 len(secret)
new_hash = hashpumpy.hashpump(
    original_hash,
    known_data,
    append_data,
    secret_length
)
```

### 案例 7: AES-ECB Byte-at-a-time
**场景**: 加密 oracle，可以加密任意前缀
**方法**:
```python
def ecb_byte_at_a_time(oracle, block_size=16):
    known = b''
    
    for i in range(unknown_length):
        # 填充到块边界
        pad_len = block_size - 1 - (len(known) % block_size)
        prefix = b'A' * pad_len
        
        # 获取目标块
        target = oracle(prefix)[:block_size * ((pad_len + len(known)) // block_size + 1)]
        
        # 暴力搜索下一个字节
        for byte in range(256):
            test = prefix + known + bytes([byte])
            if oracle(test)[:len(target)] == target:
                known += bytes([byte])
                break
    
    return known
```

## 常见攻击速查

| 算法 | 攻击 | 条件 |
|------|------|------|
| RSA | 小 e | e=3, 小消息 |
| RSA | Wiener | d 很小 |
| RSA | Fermat | p≈q |
| RSA | Hastad | 同一消息多次加密 |
| RSA | Coppersmith | 部分已知 |
| AES-ECB | 字节恢复 | 加密 oracle |
| AES-CBC | Padding Oracle | padding 错误反馈 |
| AES-CBC | Bit Flip | 无 MAC |
| AES-GCM | Nonce Reuse | 相同 nonce |
| ECDSA | Nonce Reuse | 相同 k |
| MT19937 | 状态恢复 | 624 个输出 |
| MD5 | 碰撞 | fastcoll |
| HMAC-CRC | 线性攻击 | 1 个消息-MAC 对 |
