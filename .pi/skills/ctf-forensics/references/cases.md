# 数字取证案例与资源

## 学习平台

| 平台 | 链接 | 内容 |
|------|------|------|
| DFIR Labs | https://dfirlabs.thedfirreport.com/ | 取证练习 |
| CyberDefenders | https://cyberdefenders.org/ | 蓝队 CTF |
| LetsDefend | https://letsdefend.io/ | SOC 分析师培训 |

## 典型案例

### 案例 1: 内存取证 (Volatility)
**场景**: 内存 dump，需要提取信息
**方法**:
```bash
# 识别系统
vol3 -f memory.dmp windows.info

# 列出进程
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.pstree

# 提取进程内存
vol3 -f memory.dmp windows.memmap --pid 1234 --dump

# 扫描文件
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0x123456

# 提取命令行
vol3 -f memory.dmp windows.cmdline

# 网络连接
vol3 -f memory.dmp windows.netscan

# 注册表
vol3 -f memory.dmp windows.registry.hivelist
vol3 -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### 案例 2: 磁盘取证
**场景**: 磁盘镜像分析
**方法**:
```bash
# 文件系统分析
fls -r disk.img  # 递归列出文件
icat disk.img 1234  # 提取 inode 内容
tsk_recover disk.img recovered/  # 恢复删除文件

# 时间线分析
fls -m "/" -r disk.img > body.txt
mactime -b body.txt -d > timeline.csv

# 搜索关键词
grep -r "flag{" recovered/
strings disk.img | grep -iE "password|secret|key"
```

### 案例 3: 网络流量分析
**场景**: PCAP 文件分析
**方法**:
```bash
# 基本统计
capinfos capture.pcap
tshark -r capture.pcap -q -z conv,ip

# HTTP 流量
tshark -r capture.pcap -Y 'http' -T fields -e ip.src -e http.host -e http.request.uri

# DNS 查询
tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name

# 提取文件
foremost -i capture.pcap -o extracted/
binwalk -e capture.pcap

# TLS 分析
tshark -r capture.pcap -Y 'ssl.handshake' -T fields -e x509sat.utf8String

# 重组 TCP 流
tshark -r capture.pcap -q -z follow,tcp,raw,0
```

### 案例 4: 隐写术
**场景**: 图片/音频中隐藏信息
**方法**:
```bash
# 图片隐写
steghide extract -sf image.jpg
stegsolve image.png  # 通道分析
zsteg image.png      # PNG 隐写检测

# 元数据
exiftool image.jpg
strings image.jpg

# LSB 隐写
python3 -c "
from PIL import Image
img = Image.open('image.png')
pixels = img.load()
bits = ''
for y in range(img.height):
    for x in range(img.width):
        r, g, b = pixels[x, y][:3]
        bits += str(r & 1) + str(g & 1) + str(b & 1)
# 提取 flag
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag[:100])
"

# 音频隐写
sox audio.wav -n spectrogram  # 频谱图
sonic-visualiser audio.wav    # 可视化分析
```

### 案例 5: PDF 分析
**场景**: 恶意 PDF 文档
**方法**:
```bash
# 基本分析
pdfid.py document.pdf
pdf-parser.py document.pdf

# 提取 JavaScript
pdf-parser.py document.pdf -s javascript

# 提取嵌入文件
pdf-parser.py document.pdf -o embedded_file

# 搜索字符串
strings document.pdf | grep -iE "flag|secret|http|cmd"
```

### 案例 6: Windows 事件日志
**场景**: .evtx 日志分析
**方法**:
```bash
# 提取日志
python3 -c "
import Evtx.Evtx as evtx
with evtx.Evtx('Security.evtx') as log:
    for record in log.records():
        print(record.xml())
"

# 关键事件 ID
# 4624 - 登录成功
# 4625 - 登录失败
# 4688 - 进程创建
# 4720 - 账户创建
# 7045 - 服务安装
```

## 常见文件格式

| 格式 | 工具 | 用途 |
|------|------|------|
| .pcap | tshark, Wireshark | 网络流量 |
| .dmp | Volatility | 内存 dump |
| .img | fls, icat | 磁盘镜像 |
| .evtx | python-evtx | Windows 日志 |
| .pdf | pdf-parser | PDF 文档 |
| .jpg/.png | steghide, zsteg | 图片文件 |
| .wav | sox, sonic-visualiser | 音频文件 |
| .bin | binwalk | 固件文件 |
