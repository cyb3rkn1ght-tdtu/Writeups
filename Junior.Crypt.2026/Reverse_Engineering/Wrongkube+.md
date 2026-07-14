# Rev002: WrongCube+ (Reverse Engineering)

## 1. Thông tin tổng quan
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Tags:** PyInstaller, Native DLL, Static Analysis, Cryptography Bypass

## 2. Đề bài
Bài toán cung cấp một file thực thi `WrongCube+.exe` dung lượng khá lớn (~37MB). 

Khi chạy, đây là một ứng dụng đồ họa PyQt6 mô phỏng việc thiết lập một mạng lưới cluster Kubernetes (K8s). Nhiệm vụ của người chơi (dựa trên UI) dường như là phải vượt qua một puzzle kiểm tra logic rất phức tạp (như manifest, meta, shadow, triple witness...) về cách thiết lập các node và edges để cluster hoạt động.

## 3. Quá trình phân tích

**Bước 1: Extract PyInstaller**
Dung lượng lớn của file `.exe` độc lập đa nền tảng thường là dấu hiệu của **PyInstaller**. Dùng công cụ `pyinstxtractor` để giải nén file, ta thu được thư mục `WrongCube+.exe_extracted`. Bên trong chứa toàn bộ thư viện PyQt6 và file script gốc đã được biên dịch thành bytecode `.pyc` (như `src/validator_bridge.pyc`), kèm theo một file thư viện Native là `wrongkube_validator.dll`.

**Bước 2: Phân tích file Python (`validator_bridge.py`)**
Dịch ngược file `.pyc`, ta thấy script này chỉ đơn thuần đóng vai trò là giao diện (Frontend). Mỗi khi người dùng bấm xác nhận, nó sẽ gom cấu trúc đồ thị (Nodes, Edges) thành định dạng JSON rồi gọi hàm native export `validate_cluster` bên trong file `wrongkube_validator.dll`.
Hàm DLL này sẽ trả về JSON kết quả có dạng `{"ok": bool, "score": int, "flag": "..."}`.

**Bước 3: Phân tích Native DLL (Phát hiện Bypass)**
Sử dụng IDA Pro hoặc Ghidra để decompile `wrongkube_validator.dll` (cụ thể là hàm `validate_cluster`).
Ta thấy hàm này có một khối logic cực lớn để parse JSON và đánh giá điểm của K8s cluster. Tuy nhiên, khi dò theo dấu vết cách sinh ra "flag" ở cuối luồng xử lý (`0x180005390`), một lỗ hổng nghiêm trọng lộ diện:
- Vòng lặp giải mã flag **HOÀN TOÀN ĐỘC LẬP** với dữ liệu K8s Cluster!
- Vòng lặp này chỉ sử dụng các hằng số (constants) tĩnh có sẵn và giải mã một mảng byte cứng dài 46-byte nằm tại vị trí `0x18002bf00`.
- Không có bất kỳ biến đầu vào nào từ bước validate cluster được dùng làm seed hay key cho quá trình giải mã.

**Hướng giải quyết:**
Bỏ qua hoàn toàn bài toán logic K8s hầm hố. Ta chỉ cần viết script mô phỏng lại (bằng Python) vòng lặp giải mã tĩnh ấy để trích xuất thẳng flag.

## 4. PoC

Dưới đây là đoạn script Python tái tạo lại thuật toán giải mã flag 1:1 từ mã Assembly của DLL, sử dụng mảng bytes trích xuất qua `radare2` hoặc `IDA` từ địa chỉ `0x18002bf00`:

`solve.py`:
```python
#!/usr/bin/env python3

# Mảng 46 bytes trích xuất từ 0x18002bf00 trong wrongkube_validator.dll
ARR = bytes.fromhex(
    '079f0864d3e9f960d86c37a9d4185d53d642fe3a6cac57f8'
    '1d4a0455ca6fea13a8c2008802d720317b5b7491313e')
M = 0xFFFFFFFF

def solve():
    # Khởi tạo hằng số dựa trên các thanh ghi ban đầu
    B, R9, R14, R12, R13, S = 0xF73449EF, 0x49, 0x47502943, 0x47502932, 0x3C6EF35F, 0
    flag = bytearray(46)
    idx = 1
    
    # Vòng lặp giải mã (23 iterations, mỗi iter sinh 2 bytes)
    while idx != 0x2F:
        eax = ((B * 0x19660D) & M) + R13 & M
        ecx = ((R9 - 0x49) & M) ^ (eax >> 16)
        
        # Sinh Byte 1
        flag[idx - 1] = (ARR[idx - 1] ^ ecx ^ eax) & 0xFF
        
        ecx2 = (B * 0x17385CA9) & M
        Bnew = (S + (((S | 1) << 4) & M) + 1 + R12 + ecx2) & M
        ecx2 = (ecx2 + R14) & M
        
        # Sinh Byte 2
        flag[idx] = ((ecx2 >> 16) ^ R9 ^ ARR[idx] ^ ecx2) & 0xFF
        
        # Cập nhật trạng thái
        S += 2
        R9 = (R9 + 0x92) & M
        R14 = (R14 + 0x35F8DDC) & M
        R12 = (R12 + 0x35F8DBA) & M
        R13 = (R13 + 0x22) & M
        B = Bnew
        idx += 2
        
    return flag.decode()

if __name__ == '__main__':
    print(solve())
```

**Output:**
```
grodno{5h4d0w_c0ntr0l_pl4n3_qu0rum_r3c0nc1l3d}
```

## 5. Flag
```
grodno{5h4d0w_c0ntr0l_pl4n3_qu0rum_r3c0nc1l3d}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Hiểu được sự khác biệt giữa Data Flow (luồng dữ liệu) và Control Flow (luồng điều khiển). Kẻ tấn công giỏi sẽ dùng Taint Analysis (hoặc Cross-References dò ngược bằng mắt) để truy xem hàm sinh ra cờ thực sự nhận đầu vào từ đâu, qua đó tránh bị cuốn vào cái bẫy reverse những mảng logic thừa thãi.
- **Cách phòng chống:** Khi thiết kế các thử thách client-side hoặc mã hóa cấp phép, cờ (hoặc token) bắt buộc phải được mã hóa mà **khóa giải mã phải phụ thuộc trực tiếp vào trạng thái input hợp lệ** (ví dụ hash của đáp án đúng). Tránh thiết kế theo kiểu khóa cứng/hằng số được bảo vệ hời hợt bằng một câu lệnh rẻ tiền như `if (is_valid) print(decrypt_flag_with_constants());`.

## 7. Tham khảo
- Kỹ thuật giải nén file PyInstaller với `pyinstxtractor` và dịch ngược bytecode.
- Data Flow Analysis trong Reverse Engineering (IDA Pro, Ghidra).
