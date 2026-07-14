# Crypto001 (Crypto)

## 1. Thông tin tổng quan (nếu có)
- **Category:** Cryptography
- **Difficulty:** Easy
- **Tags:** PRNG, LCG, Brute-force

## 2. Đề bài

**File đính kèm:**

`encoder.py`:
```python
#!/usr/bin/env python3

MOD = 1 << 32
A = 1664525
C = 1013904223


def keystream(seed, length):
    state = seed & 0xFFFFF
    out = bytearray()
    for _ in range(length):
        state = (A * state + C) % MOD
        out.append((state >> 24) & 0xFF)
    return bytes(out)


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(message: bytes, facility_seed: int) -> bytes:
    return xor_bytes(message, keystream(facility_seed, len(message)))
```

`ciphertext.txt`:
```text
1b89ad17b196d415f519f17c9bfa709ac9a7a71605c6d91a7f08fcbb08c2833298388913e843bb0b8bd7bca262207fd861db5440715da4e2916b6245e450df243c6398e0c27fe8d83044b2a4100b83783e65fd27969f9a0adef8decede83339001f71e7fc83a3f7c415c0362d61a28d8d9e83970c840093a0fb6f0a1
```

## 3. Quá trình phân tích

Phân tích `encoder.py`, điểm đáng chú ý nhất là ở hàm sinh keystream:
```python
def keystream(seed, length):
    state = seed & 0xFFFFF
    ...
```
- Giá trị `seed` đầu vào bị mask bằng `& 0xFFFFF`. Điều này có nghĩa là `state` khởi tạo thực tế bị giới hạn trong $2^{20} = 1,048,576$ trường hợp có thể xảy ra.
- Đây là một không gian khóa (keyspace) quá nhỏ.
- Thuật toán mã hóa chỉ đơn giản là phép XOR giữa thông điệp và keystream: `xor_bytes(message, keystream)`. Do XOR có tính chất đối xứng, ta chỉ cần lấy ciphertext XOR ngược lại với đúng keystream thì sẽ khôi phục được plaintext.

**Hướng giải quyết:**
Vì không gian seed chỉ có khoảng ~1 triệu trường hợp, ta có thể dễ dàng dùng kỹ thuật vét cạn (brute-force) duyệt toàn bộ các giá trị seed từ $0$ đến $1048575$. Với mỗi seed, ta sinh ra keystream, giải mã ciphertext, và kiểm tra xem chuỗi kết quả thu được có chứa format của cờ (trong trường hợp này là `grodno{`) hay không.

## 4. PoC

```python
#!/usr/bin/env python3

MOD = 1 << 32
A = 1664525
C = 1013904223

def keystream(seed, length):
    state = seed & 0xFFFFF
    out = bytearray()
    for _ in range(length):
        state = (A * state + C) % MOD
        out.append((state >> 24) & 0xFF)
    return bytes(out)

def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))

with open('ciphertext.txt', 'r') as f:
    ct_bytes = bytes.fromhex(f.read().strip())

length = len(ct_bytes)

# Brute-force toàn bộ không gian seed 2^20
for seed in range(0x100000):
    ks = keystream(seed, length)
    pt = xor_bytes(ct_bytes, ks)
    
    # Kiểm tra format flag
    if b"grodno{" in pt:
        print(f"[+] Found seed: {seed}")
        print(f"[+] Recovered message:\n{pt.decode('utf-8', errors='ignore')}")
        break
```

**Output:**
```
[+] Found seed: 369020
[+] Recovered message:
[Aperture Science Internal]
classification=stable
speaker=GLaDOS
memo=grodno{7h15_w45_4_7r1umph_bu7_7h3_533d_w45_700_5m4ll}
```

## 5. Flag
```
grodno{7h15_w45_4_7r1umph_bu7_7h3_533d_w45_700_5m4ll}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Nhận diện lỗ hổng từ việc sử dụng không gian khóa (keyspace) quá bé (`& 0xFFFFF` giới hạn seed chỉ 20-bit) và hiểu được cách vận hành của hàm sinh số ngẫu nhiên giả LCG. Áp dụng kỹ thuật vét cạn (brute-force) để tìm ra key và giải mã.
- **Cách phòng chống:** Tránh sử dụng các PRNG yếu như LCG trong các ứng dụng mật mã học. Cần sử dụng các hàm sinh ngẫu nhiên an toàn sinh mã (CSPRNG) như `os.urandom()`, đồng thời đảm bảo seed/key phải có độ dài đủ lớn (ví dụ 128-bit hoặc 256-bit) để triệt tiêu hoàn toàn khả năng bị vét cạn.

## 7. Tham khảo
- [Linear Congruential Generator (LCG)](https://en.wikipedia.org/wiki/Linear_congruential_generator)
