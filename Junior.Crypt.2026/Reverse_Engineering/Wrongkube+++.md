# Rev004: WrongKube+++ (Reverse Engineering)

## 1. Thông tin tổng quan
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Tags:** PyInstaller, Native DLL, Static Analysis, Cryptography Bypass

## 2. Đề bài
Chào mừng đến với trùm cuối của series cấu hình Kubernetes: **WrongKube+++**. Bài toán cung cấp file thực thi `WrongKube+++.exe` (~37MB).

Lần này ứng dụng đưa người chơi xuống hẳn "địa ngục" của DevOps với chuỗi validation khổng lồ: Thêm stage "phantom", số lượng máy ảo (VM) tăng lên đến VM6 tạo thành "Sextuple Witness" (6 lớp xác minh). Câu hỏi đặt ra là: Liệu tác giả có chịu sửa lỗ hổng hay không?

## 3. Quá trình phân tích

**Bước 1: Extract & Decompile**
Làm tương tự bài 002 và 003, dùng `pyinstxtractor` giải nén file để lấy file Native DLL (`wrongkube_validator.dll`).

**Bước 2: Phân tích DLL**
Mở DLL lên bằng IDA Pro và tiến thẳng vào hàm `validate_cluster`. Nhìn thoáng qua, code validation K8s đã dài và đáng sợ hơn gấp nhiều lần so với phiên bản trước.

Tuy nhiên, có vẻ tác giả của ứng dụng này quyết tâm trung thành với triết lý "Hardcode là chân ái". 
Khối code giải mã Flag đã được di chuyển vị trí (chuyển lên hẳn đoạn đầu hàm tại địa chỉ `0x180001f50`) để đánh lừa những ai dùng script tự động tìm mẫu byte cũ. Thế nhưng **BẢN CHẤT LỖ HỔNG VẪN KHÔNG ĐỔI**. Vòng lặp giải mã flag **VẪN ĐỘC LẬP TƯƠNG ĐỐI** với logic K8s. Nó chỉ dùng các hằng số (constants) nội bộ và trỏ tới một mảng tĩnh mới tại `0x18002d5a0`.

**Điểm khác biệt duy nhất so với Rev003:**
1. Hằng số khởi tạo (Seed) `B` bị đổi thành `0x34AF33DB`.
2. Mảng chứa byte mồi (Source Array) nằm ở địa chỉ mới `0x18002d5a0`.
3. Khối code sinh flag di chuyển lên đầu function.
4. Điều kiện dừng vòng lặp là `idx == 0x31` $\rightarrow$ độ dài flag là 48 bytes.

**Hướng giải quyết:**
"Quá tam ba bận", chúng ta tiếp tục phớt lờ hoàn toàn mớ bòng bong Sextuple Witness kia và bê nguyên vòng lặp giải mã bằng Assembly ra để chạy trên Python.

## 4. PoC

Dưới đây là script Python trích xuất thẳng cờ bằng luồng Assembly trích từ DLL:

`solve.py`:
```python
#!/usr/bin/env python3

# Mảng 48 bytes trích xuất từ 0x18002d5a0 trong wrongkube_validator.dll (bản +++)
ARR = bytes.fromhex(
    '79694d7bb7ad642a5d0bb78d5c528ddf301ad2872aeeefd9'
    'e5be9cb008df2be010f58ff60e04fa5adc9b3d7dbc490b78')
M = 0xFFFFFFFF

def solve():
    # Khởi tạo hằng số (Seed B thay đổi thành 0x34AF33DB)
    B, R9, R14, R12, R13, S = 0x34AF33DB, 0x49, 0x47502943, 0x47502932, 0x3C6EF35F, 0
    flag = bytearray(48)
    idx = 1
    
    # Điều kiện dừng ở 0x31 (tương đương 48 bytes)
    while idx != 0x31:
        eax = ((B * 0x19660D) & M) + R13 & M
        flag[idx - 1] = (ARR[idx - 1] ^ ((R9 - 0x49) & M ^ (eax >> 16)) ^ eax) & 0xFF
        
        ecx2 = (B * 0x17385CA9) & M
        Bnew = (S + (((S | 1) << 4) & M) + 1 + R12 + ecx2) & M
        ecx2 = (ecx2 + R14) & M
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
grodno{wr0ngkub3ppp_4by55_0r4cl3_qu0rum_3xtr3m3}
```

## 5. Flag
```
grodno{wr0ngkub3ppp_4by55_0r4cl3_qu0rum_3xtr3m3}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Ôn tập lại sự ngoan cố của một số lập trình viên khi sửa lỗi (chỉ cố tình giấu mã, thay đổi hằng số, đổi vị trí - hay còn gọi là Security through Obscurity) chứ không chịu sửa từ cội nguồn thuật toán (Fixing the Root Cause).
- **Cách phòng chống:** Một lần nữa, **State-Dependent Decryption** là bắt buộc. Khóa để giải mã flag PHẢI phụ thuộc chặt chẽ vào một input hoặc token hợp lệ từ logic puzzle (ví dụ như lấy output của bước VM6 làm Khóa XOR cho mảng flag).

## 7. Tham khảo
- Static Analysis and Cryptography Bypass in Reverse Engineering.
