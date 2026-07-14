# Crypto004 (Crypto)

## 1. Thông tin tổng quan (nếu có)
- **Category:** Cryptography
- **Difficulty:** Hard
- **Tags:** AES-CBC, Padding Oracle, Timing Side-Channel

## 2. Đề bài

Bài toán cung cấp dữ liệu về mã hóa AES-CBC cùng với log thời gian phản hồi từ server (Timing Telemetry).

**File đính kèm:**

`metadata.json`:
```json
{
  "title": "Aperture Science AES: Neurotoxin Diagnostics",
  "mode": "aes-cbc",
  "block_size": 16,
  "note": "Only packet timing telemetry survived the diagnostic run."
}
```

`packet.hex`:
```text
4e4555524f544f58494e5f5445535421d08c8911ab48bbe4a9671d4884f1407fd74b5d0492ebfdc1e11f3cb131f731c8072e182e7b11863d8b1f80d64587aee80804da699e3f087eb3959c3cfb525bee81827e373823357eeaf77b04df1c332cc368fa3f07c3f5c4800d814754cb3f6e6c5a89136382500dc1a43f39bdf2486f823ed2c1cc09b17cf1effbe02c9a536b
```

*(Ngoài ra còn có file `timing_trace.json` dung lượng khoảng 9.7MB chứa log thời gian vét cạn padding oracle, do quá dài nên tôi không trích dẫn trực tiếp vào đây).*

## 3. Quá trình phân tích

Đề bài gợi ý đây là một hệ thống dùng AES chế độ CBC và file `timing_trace.json` lưu lại toàn bộ thời gian hệ thống phản hồi (`elapsed_ns`) cho mỗi lượt đoán `guess` tương ứng với mỗi byte `pad` trong từng `block`.

- Đây là dạng tấn công **Padding Oracle thông qua kênh thời gian (Timing Attack)**. 
- Thay vì server trả về trực tiếp thông báo lỗi Padding (như `padding_error` hay `mac_error` trong Padding Oracle thông thường), server phản hồi chậm hơn hoặc nhanh hơn đối với những request có byte padding hợp lệ (do sự khác biệt trong nhánh rẽ logic hoặc việc xử lý ngoại lệ diễn ra sâu bên trong server).
- Bằng cách phân tích thống kê (cụ thể là lấy trung vị `median` của thời gian phản hồi cho từng giá trị `guess` từ 0 đến 255), ta có thể tìm ra được byte `guess` nào khiến thời gian phản hồi khác biệt rõ rệt nhất so với số đông $\rightarrow$ đó chính là byte tạo ra Padding hợp lệ.

**Hướng giải quyết:**
1. Phân tích file `timing_trace.json` bằng cách nhóm dữ liệu theo từng cặp (block, pad, guess) và tính toán thời gian `median`. 
2. Tìm `guess` có thời gian phản hồi lâu nhất làm giá trị padding hợp lệ (theo PoC của giải, nhánh valid tốn nhiều chu kỳ CPU hơn nhánh tung exception). 
3. Khi đã có mảng `guess` đại diện cho byte ciphertext bị băm tương ứng với Padding hợp lệ của từng block, ta tính plaintext $P$ theo công thức quen thuộc của Padding Oracle: $P_i = \text{guess} \oplus \text{pad} \oplus C_{i-1}$.

## 4. PoC

Dưới đây là phần code tính toán mảng `guess` từ file timing log (`solve.py`) và thực hiện khôi phục plaintext (`decrypt.py`):

`solve.py (Trích xuất guess từ timing log):`
```python
import json
import statistics

with open("timing_trace.json") as f:
    data = json.load(f)

timings = {}
for entry in data:
    b, p, g, e = entry['block'], entry['pad'], entry['guess'], entry['elapsed_ns']
    if (b, p, g) not in timings:
        timings[(b, p, g)] = []
    timings[(b, p, g)].append(e)

results = {}
blocks = set([k[0] for k in timings.keys()])

for b in sorted(list(blocks)):
    results[b] = {}
    for p in range(1, 17):
        guess_times = {}
        for g in range(256):
            if (b, p, g) in timings:
                guess_times[g] = statistics.median(timings[(b, p, g)])
        if guess_times:
            # Chọn guess làm tốn thời gian nhất (Valid padding branch)
            max_g = max(guess_times, key=guess_times.get)
            results[b][p] = max_g

for b in sorted(list(blocks)):
    print(f"Block {b}: {[results[b].get(p, -1) for p in range(1, 17)]}")
```

`decrypt.py (Dùng mảng guess để khôi phục plaintext):`
```python
with open("packet.hex") as f:
    ct = bytes.fromhex(f.read().strip())

blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]

# Mảng guess trích xuất được từ solve.py
guesses = {
    1: [27, 56, 57, 57, 62, 45, 38, 51, 36, 32, 49, 126, 56, 58, 35, 58],
    2: [11, 49, 201, 229, 33, 121, 1, 213, 158, 140, 48, 210, 104, 230, 247, 179],
    3: [166, 94, 145, 88, 143, 86, 116, 140, 160, 148, 221, 234, 106, 54, 46, 165],
    4: [145, 156, 179, 113, 161, 243, 43, 237, 79, 227, 116, 19, 76, 100, 70, 42],
    5: [131, 6, 100, 156, 8, 173, 167, 139, 25, 101, 0, 163, 0, 139, 101, 41],
    6: [28, 92, 46, 236, 94, 21, 151, 151, 71, 77, 64, 3, 101, 27, 185, 162],
    7: [1, 84, 187, 63, 46, 228, 49, 245, 254, 145, 248, 103, 6, 171, 0, 189],
    8: [109, 73, 242, 220, 74, 80, 207, 168, 91, 54, 229, 6, 106, 244, 104, 27]
}

plaintext = b""
for b in range(1, 9):
    pt_block = bytearray(16)
    c_prev = blocks[b-1]
    guess_arr = guesses[b]
    
    for pad in range(1, 17):
        idx = 16 - pad
        guess = guess_arr[pad - 1]
        
        # P[idx] = guess ^ pad ^ C_prev[idx]
        pt_byte = guess ^ pad ^ c_prev[idx]
        pt_block[idx] = pt_byte
        
    plaintext += pt_block

print(plaintext)
```

**Output:**
```
b'diag=neurotoxin;status=stable;subject=chell;memo=grodno{n3ur070x1n_d14gn0571c5_l34k_7hr0ugh_71m1ng_4l0n3};closing=still_alive\x03\x03\x03'
```

## 5. Flag
```
grodno{n3ur070x1n_d14gn0571c5_l34k_7hr0ugh_71m1ng_4l0n3}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Nhận thức rõ ràng hơn về độ nguy hiểm của kênh kề (Side-channel) cụ thể ở đây là phân tích thời gian (Timing Analysis). Ta có thể giải quyết bài toán mã hóa hộp đen AES-CBC chỉ thông qua việc thu thập đủ log thời gian và chạy các thuật toán thống kê (như tính Median) để lọc nhiễu, từ đó tìm ra chính xác byte làm kích hoạt mã hợp lệ.
- **Cách phòng chống:** 
  1. Sử dụng Encrypt-then-MAC thay vì Padding cũ.
  2. Tuyệt đối ưu tiên các chế độ mã hóa xác thực (AEAD) như AES-GCM hoặc ChaCha20-Poly1305.
  3. Mã nguồn verify xác thực và padding của server phải được viết dưới dạng thuật toán thời gian hằng định (`constant-time`), không sử dụng các câu lệnh `if-else` return/throw Exception sớm để tránh lộ vết thời gian khác biệt.

## 7. Tham khảo
- [Padding Oracle Attack qua Timing (Wikipedia)](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- Phân tích Kênh kề Thời gian (Timing Side-Channel Attack).
