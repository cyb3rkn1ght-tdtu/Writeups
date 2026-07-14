+++
title = 'Pickles — Write-up'
date = '2026-07-14T08:03:00+07:00'
draft = false
tags = ['GrodnoCTF', 'pickle', 'python', 'reverse', 'backdoor']
categories = ['Reverse Engineering', 'Web']
+++

# CTF Write-up: Pickles

**Category:** Reverse Engineering / Web / Misc
**Flag format:** `grodno{...}`
**Flag cuối:** `grodno{p1ckl3_b4ckd00r_supply_ch41n}`

---

## Mô tả bài

> Downloaded the classifier model from an unofficial mirror, what could have gone wrong?
>
> Flag format: grodno{}

**File đính kèm:** `dist.zip`

Endpoint được cấp: `POST http://<IP>:<PORT>/infer` — chỉ nhận JSON `{"text": "example"}`

---

## Nhận file và kiểm tra nhanh

File được cung cấp là `dist.zip`. Giải nén ra, bên trong có:

```
dist/
├── model.pkl       ← Mô hình AI bị nhiễm độc
└── payload.pyc     ← Bytecode Python đã được biên dịch (che giấu logic)
```

Quan sát đầu tiên: file `.pkl` (Pickle) là định dạng khét tiếng trong bảo mật Python — nó có thể **thực thi mã tùy ý** ngay khi được load bằng `pickle.load()`. File `.pyc` là bytecode đã biên dịch, được dùng để che giấu source code gốc.

Câu hỏi đặt ra ngay lập tức: *payload đang làm gì bên trong cái model đó?*

---

## Phần 1: Nền tảng — Python Pickle hoạt động như thế nào?

Để hiểu bài này, cần nắm một điều cốt lõi về `pickle`:

**Pickle là gì?** Đây là module serialization của Python dùng để chuyển đổi object Python thành luồng byte (để lưu hoặc truyền qua mạng), và khôi phục lại object sau. Vấn đề là pickle **không phải định dạng an toàn** — nó hỗ trợ opcode `REDUCE`, cho phép file `.pkl` khi được load sẽ **tự động gọi một hàm Python bất kỳ**.

```
pickle.load(file)
    → gặp opcode REDUCE
    → tự động gọi: install_supply_chain_probe(cipher, weights, seal)
    → trả về object LedgerModel
```

Nghĩa là: load `model.pkl` từ nguồn không rõ = chạy code không rõ, không cần xác nhận, không có cảnh báo.

**Bytecode `.pyc` là gì?** Khi Python biên dịch file `.py`, nó tạo ra file `.pyc` chứa bytecode — không đọc được bằng mắt thường nhưng hoàn toàn có thể dịch ngược (decompile) lại thành source code gần hoàn hảo.

---

## Phần 2: Dịch ngược `payload.pyc` bằng pylingual.io

Vì không có source code gốc, mình đưa `payload.pyc` lên [pylingual.io](https://pylingual.io) để dịch ngược.

![Giao diện pylingual.io sau khi upload payload.pyc — source code hiện ra hoàn chỉnh](/images/write-ups/grodno-ctf-pickles/pylingual_decompile.jpeg)

Kết quả là source code hoàn chỉnh:

```python
# Decompiled with PyLingual (https://pylingual.io)
# Bytecode version: 3.10.b1 (3439)
# Source timestamp: 2026-07-10 14:39:33 UTC

"""Code that the compromised model executes while being unpickled."""
from __future__ import annotations
import base64
import hashlib

_WORDS = (b'snow', b'candle', b'tangerine', b'clock')

def _stream(key: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.blake2s(key + counter.to_bytes(2, 'little')).digest())
        counter += 1
    return bytes(out[:size])

class LedgerModel:
    def __init__(self, cipher: bytes, weights: bytes, seal: bytes):
        self.cipher = cipher
        self.weights = weights
        self.seal = seal

    def infer(self, text: str, history: list[str]) -> dict[str, object]:
        score = (sum(text.encode()) + self.weights[0]) % 101
        sequence = b'|'.join((x.encode() for x in history[-4:]))

        if hashlib.sha256(sequence).digest() != self.seal:
            return {'score': score, 'label': 'invoice' if score > 50 else 'receipt'}
        else:
            key = hashlib.blake2s(self.weights + sequence + b'inference-cache').digest()
            plain = bytes((a ^ b for a, b in zip(self.cipher, _stream(key, len(self.cipher)))))
            return {'score': score, 'label': 'receipt', 'ticket': base64.b85encode(plain).decode()}

def install_supply_chain_probe(cipher: bytes, weights: bytes, seal: bytes) -> LedgerModel:
    """This is reached by REDUCE during pickle.load()."""
    return LedgerModel(cipher, weights, seal)
```

Source code đã ở trước mắt. Tên hàm `install_supply_chain_probe` không che giấu gì cả — đây chính là backdoor.

---

## Phần 3: Phân tích logic backdoor

![Sơ đồ toàn bộ cơ chế backdoor trong model.pkl — luồng bình thường (xanh) và luồng kẻ tấn công kích hoạt cửa hậu (đỏ)](/images/write-ups/grodno-ctf-pickles/backdoor_diagram.png)

Đây là phần mấu chốt. Bóc tách từng lớp của `infer()`:

**Hành vi bình thường:** Model nhận `text`, tính `score`, trả về nhãn `invoice` hoặc `receipt`. Bình thường, không gây nghi ngờ.

**Cơ chế kiểm tra seal:** Trước khi trả kết quả, model âm thầm lấy **4 phần tử cuối cùng trong `history`**, ghép lại bằng `|`, rồi băm SHA-256:

```python
sequence = b'|'.join((x.encode() for x in history[-4:]))
if hashlib.sha256(sequence).digest() != self.seal:
    # trả về kết quả bình thường
else:
    # kích hoạt backdoor
```

Biến `self.seal` được nhúng sẵn vào `model.pkl`. Nó chính là SHA-256 của chuỗi `b'snow|candle|tangerine|clock'` — tức là 4 từ khóa bí mật đã định nghĩa trong `_WORDS`.

**Thuật toán giải mã khi backdoor kích hoạt:**

```
key    = BLAKE2s(weights || sequence || b'inference-cache')
stream = keystream từ key (dùng BLAKE2s counter mode)
plain  = cipher XOR stream
ticket = Base85(plain)
```

Trong đó `cipher` và `weights` được nhúng cứng vào `model.pkl`. Hàm `_stream()` là một keystream generator đơn giản — dùng BLAKE2s để tạo đủ byte giả ngẫu nhiên, rồi XOR với `cipher` để lấy plaintext là Flag.

| Biến | Ý nghĩa | Nguồn |
|------|---------|-------|
| `cipher` | Flag đã mã hóa | Nhúng trong `model.pkl` |
| `weights` | Trọng số model (cũng là một phần của key) | Nhúng trong `model.pkl` |
| `seal` | SHA-256 của 4 từ khóa (điều kiện kích hoạt) | Nhúng trong `model.pkl` |
| `_WORDS` | 4 từ khóa bí mật | Hard-coded trong `payload.pyc` |

---

## Phần 4: Đặt giả thuyết — hai hướng tấn công

Sau khi hiểu logic, có hai con đường để lấy Flag:

**Hướng 1 — Online (Hộp đen):** Khai thác qua API `/infer` bằng cách dùng `requests.Session()` để giữ cookie, lần lượt mớm 4 từ khóa vào `history` của server, kích hoạt backdoor và nhận `ticket`.

**Hướng 2 — Offline (Hộp trắng):** Trích xuất `cipher` và `weights` trực tiếp từ `model.pkl`, rồi tự chạy thuật toán giải mã — không cần gửi gì ra mạng.

---

## Phần 5: Cách 1 — Khai thác qua API (Online)

API chỉ nhận `{"text": "..."}`, không nhận `history` từ phía client. Đây là kiến trúc stateful: server tự quản lý history của từng session theo cookie. Mỗi khi server nhận `text`, nó lưu vào history rồi mới gọi `infer()`.

Chiến lược: dùng `requests.Session()` để duy trì cùng một session, lần lượt gửi 4 từ khóa như người dùng bình thường:

```python
import requests, base64

url = "http://10.112.0.12:42676/infer"
session = requests.Session()

for word in ["snow", "candle", "tangerine", "clock"]:
    res = session.post(url, json={"text": word})
    print(f"[*] Gửi '{word}' → {res.json()}")
```

Output:

```
[*] Gửi 'snow'       → {'score': 73, 'label': 'invoice'}
[*] Gửi 'candle'     → {'score': 55, 'label': 'invoice'}
[*] Gửi 'tangerine'  → {'score': 13, 'label': 'receipt'}
[*] Gửi 'clock'      → {'score': 44, 'label': 'receipt', 'ticket': 'XL4_3Zf|>VKx1ocBy(S3a%Eq0Z(n&;ZEbmd'}
```

Một điều thú vị: `ticket` xuất hiện ngay tại **request thứ 4** (`clock`), không phải request thứ 5 như có thể dự tính ban đầu. Lý do: server **lưu `text` vào history trước rồi mới gọi `infer()`**. Vậy ngay khi gửi `clock`, history đã đủ 4 từ — cửa hậu kích hoạt tức thì.

Giải mã `ticket` bằng Base85:

```python
import base64
ticket = 'XL4_3Zf|>VKx1ocBy(S3a%Eq0Z(n&;ZEbmd'
flag = base64.b85decode(ticket).decode('utf-8')
print(flag)
```

```
grodno{p1ckl3_b4ckd00r_supply_ch41n}
```

---

## Phần 6: Cách 2 — Giải mã offline từ `model.pkl`

Tất cả dữ liệu cần thiết đã nằm nguyên trong `model.pkl`. Không cần mạng.

Đầu tiên, dùng `pickletools` để mổ xẻ file và trích xuất `cipher`, `weights`, `seal`:

```bash
$ python read_pkl.py
```

```python
import pickletools
with open('model.pkl', 'rb') as f:
    pickletools.dis(f.read())
```

Kết quả cho thấy rõ opcode `REDUCE` đang gọi `install_supply_chain_probe` với 3 tham số byte là `cipher`, `weights`, `seal`. Từ đó mình trích xuất thẳng giá trị của chúng.

Sau khi có đủ 3 giá trị, tái tạo lại thuật toán giải mã:

```python
import hashlib

# Trích xuất từ model.pkl
cipher  = b'\xbf\x1d\xa5\xef7\xf6Ff\x037:L\xb8\xebK&...'
weights = b'\x1c\xeb\x85g\n\x052\xcbE>...'

# 4 từ khóa bí mật — ghép đúng định dạng như trong infer()
sequence = b'snow|candle|tangerine|clock'

# Tạo key giải mã
key = hashlib.blake2s(weights + sequence + b'inference-cache').digest()

# Keystream generator (copy từ payload.py)
def _stream(key: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.blake2s(key + counter.to_bytes(2, 'little')).digest())
        counter += 1
    return bytes(out[:size])

# XOR để giải mã
plain = bytes(a ^ b for a, b in zip(cipher, _stream(key, len(cipher))))
print(plain.decode('utf-8'))
```

```
[+] BINGO! CỜ CỦA BẠN ĐÂY:
grodno{p1ckl3_b4ckd00r_supply_ch41n}
```

Chạy xong trong chưa đầy 0.1 giây. Flag hiện ra trực tiếp trên terminal mà không tốn một gói tin mạng nào.

---

## Ghép Flag

```
grodno{p1ckl3_b4ckd00r_supply_ch41n}
```

---

## Bài học rút ra

**1. Đừng bao giờ `pickle.load()` file từ nguồn không tin cậy**
Pickle không phải sandbox — nó thực thi code tùy ý thông qua opcode `REDUCE`. Tải model AI từ mirror không chính thống rồi load bằng `pickle.load()` là mở cửa mời mã độc vào hệ thống, không có cảnh báo, không có xác nhận.

**2. Backdoor trong AI model có thể hoàn toàn vô hình với người dùng cuối**
Model vẫn hoạt động bình thường, vẫn phân loại đúng `invoice`/`receipt`, không raise exception. Cửa hậu chỉ kích hoạt khi nhận đúng câu thần chú theo đúng thứ tự — và câu thần chú đó không nằm trong bất kỳ tài liệu nào của model.

**3. Stateful API có thể bị lạm dụng qua session**
API từ chối nhận `history` từ client, nhưng lại tự lưu lịch sử theo session/cookie. Gửi nhiều request trong cùng một session là cách hợp lệ để đẩy dữ liệu vào `history` — không cần bypass bất kỳ validation nào, không cần quyền đặc biệt.

**4. Thứ tự lưu vs. gọi quyết định khi nào backdoor kích hoạt**
Server lưu `text` vào history **trước** khi gọi `infer()`. Chi tiết nhỏ này quyết định backdoor kích hoạt ở request thứ 4 chứ không phải thứ 5 — đọc không kỹ sẽ tốn thêm một request thừa và dễ nhầm.

**5. Hộp trắng cho phép bỏ qua hoàn toàn lớp bảo vệ mạng**
Khi đã có source code (dù qua decompile), mọi logic của server đều có thể tái tạo offline. Không cần VPN, không cần kết nối server — chỉ cần đọc hiểu code, trích xuất dữ liệu từ file `.pkl`, và chạy lại thuật toán.

**6. Decompile `.pyc` là kỹ năng cơ bản trong Reverse Engineering Python**
File `.pyc` không phải bảo vệ thực sự — nó chỉ là obfuscation rất yếu. Công cụ như `pylingual.io` hay `uncompyle6` có thể khôi phục source code gần như hoàn toàn trong vài giây.

---

## Tài liệu tham khảo

- Công cụ decompile: [pylingual.io](https://pylingual.io)
- Module phân tích pkl: [`pickletools`](https://docs.python.org/3/library/pickletools.html)
- Tài liệu bảo mật Pickle: [Python Docs — pickle security](https://docs.python.org/3/library/pickle.html#restricting-globals)
- Scripts: `read_pkl.py`, `send.py`, `solution.py`
