# Crypto005 (Crypto)

## 1. Thông tin tổng quan (nếu có)
- **Category:** Cryptography
- **Difficulty:** Medium
- **Tags:** Stream Cipher, Many-Time Pad, Known Plaintext Attack (KPA)

## 2. Đề bài

Bài toán cung cấp dữ liệu từ hệ thống Aperture Archive:
- `metadata.json`
- `catalog.json` (Danh sách các từ khóa hợp lệ cho từng trường dữ liệu)
- `known_archives.json` (Danh sách nhiều bản mã được mã hóa bởi hệ thống)
- `secret_archive.hex` (Bản mã chứa cờ)

`metadata.json`:
```json
{
  "title": "Aperture Science AES: Weighted Companion Cube",
  "mode": "aperture-companion-stream-v2",
  "block_size": 16,
  "format": [
    "[Aperture Archive]",
    "item=18",
    "status=12",
    "sector=12",
    "memo=64"
  ],
  "note": "Every archive in this batch was encrypted under the same boot-state."
}
```

## 3. Quá trình phân tích

Gợi ý quan trọng nhất nằm ở câu: *"Every archive in this batch was encrypted under the same boot-state"*. 
- Điều này có nghĩa là mọi file (kể cả các file trong `known_archives.json` và `secret_archive.hex`) đều được mã hóa bằng **cùng một keystream** (dòng khóa). 
- Khi một stream cipher (mật mã dòng) sử dụng lại keystream cho nhiều bản rõ, nó tạo ra lỗ hổng **Many-Time Pad**.
- Đặc biệt hơn, hệ thống quy định format cực kỳ khắt khe: mọi file archive đều bắt đầu bằng `[Aperture Archive]`, sau đó là các dòng `item=...`, `status=...` với độ dài cố định, và các từ khóa hợp lệ được lưu sẵn trong `catalog.json`.

**Hướng giải quyết:**
Đây là một cuộc tấn công Known Plaintext Attack (KPA) kết hợp vét cạn các khả năng từ catalog:
1. Vì ta biết tập hợp các plaintext có thể xảy ra ở từng dòng, ta sẽ thử XOR bản mã đầu tiên (`cts[0]`) với từng lựa chọn plaintext khả dĩ. Phép XOR này sẽ cho ta một chuỗi dự đoán gọi là Keystream candidate (`ks_cand`).
2. Kế tiếp, ta lấy Keystream dự đoán đó XOR thử với *tất cả các bản mã còn lại* ở cùng vị trí offset. Nếu kết quả trả về cũng là một plaintext hợp lệ (nằm trong catalog), thì xác suất rất cao Keystream dự đoán đó chính là Keystream thật sự.
3. Lặp lại quá trình này cho từng dòng (item, status, sector, memo) để nối dần và chắp vá lại được 100% độ dài Keystream.
4. Cuối cùng, dùng Keystream khôi phục được để XOR giải mã `secret_archive.hex` và lấy cờ.

## 4. PoC

Dưới đây là mã nguồn trích xuất từ file `solve2.py` mô phỏng cách bruteforce khôi phục keystream qua danh sách các archive:

```python
import json

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

with open("catalog.json") as f:
    catalog = json.load(f)

with open("known_archives.json") as f:
    archives = json.load(f)

with open("secret_archive.hex") as f:
    secret_hex = f.read().strip()
    secret_ct = bytes.fromhex(secret_hex)

cts = [bytes.fromhex(arch["ciphertext_hex"]) for arch in archives]

# Dựng sẵn các dòng plaintext có thể xảy ra (đã đệm đủ khoảng trắng)
item_opts = [b"item=" + v.encode().ljust(18, b' ') + b"\n" for v in catalog['item']]
status_opts = [b"status=" + v.encode().ljust(12, b' ') + b"\n" for v in catalog['status']]
sector_opts = [b"sector=" + v.encode().ljust(12, b' ') + b"\n" for v in catalog['sector']]
memo_opts = [b"memo=" + v.encode().ljust(64, b' ') + b"\n" for v in catalog['memo']]

lines = [
    [b"[Aperture Archive]\n"],
    item_opts,
    status_opts,
    sector_opts,
    memo_opts
]

keystream = b""
offset = 0

for line_opts in lines:
    length = len(line_opts[0])
    valid_ks = None
    
    # Duyệt từng option của cts[0] để tìm Keystream
    for opt0 in line_opts:
        ks_cand = xor_bytes(cts[0][offset:offset+length], opt0)
        
        # Kiểm tra xem Keystream này có đúng với tất cả ciphertext khác không
        all_match = True
        for ct in cts[1:]:
            pt_cand = xor_bytes(ct[offset:offset+length], ks_cand)
            if pt_cand not in line_opts:
                all_match = False
                break
                
        if all_match:
            valid_ks = ks_cand
            break
            
    if valid_ks:
        keystream += valid_ks
        offset += length
    else:
        print("Failed at offset", offset)
        break

print("Keystream recovered:", len(keystream), "bytes")
print("Secret plaintext:")
secret_pt = xor_bytes(secret_ct, keystream)
print(secret_pt.decode('utf-8'))
```

**Output:**
```
Keystream recovered: 153 bytes
Secret plaintext:
[Aperture Archive]
item=cake voucher      
status=issued      
sector=omega-01    
memo=grodno{c0mp4n10n_cub3_7h15_15_57r1c7ly_4_m4ny_71m3_p4d}
```

## 5. Flag
```
grodno{c0mp4n10n_cub3_7h15_15_57r1c7ly_4_m4ny_71m3_p4d}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Kỹ thuật khai thác lỗi Key Reuse trong Stream Cipher thông qua lỗ hổng kinh điển Many-Time Pad. Bài toán cũng minh họa rất tốt cách vận dụng cấu trúc tĩnh (Known Plaintext Attack / Crib Dragging) để tìm ra Keystream thông qua phép XOR ngược và đối chiếu hàng loạt.
- **Cách phòng chống:** Không bao giờ sử dụng lại cùng một Keystream, Seed hoặc IV cho hai thông điệp khác nhau khi sử dụng Stream Ciphers (như RC4, ChaCha20) hoặc Block Ciphers ở chế độ luồng (như CTR, OFB, CFB). Mỗi bản mã phải đi kèm với một giá trị Nonce/IV hoàn toàn độc nhất cho mỗi lượt mã hóa.

## 7. Tham khảo
- [Stream Cipher Attack (Many-Time Pad)](https://en.wikipedia.org/wiki/Stream_cipher_attacks)
- [Crib Dragging Technique](https://en.wikipedia.org/wiki/Crib_(cryptanalysis)) (Kỹ thuật Kéo nôi thường thấy để giải Many-Time Pad).
