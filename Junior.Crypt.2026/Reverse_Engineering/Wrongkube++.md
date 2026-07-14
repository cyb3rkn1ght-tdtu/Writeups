# Rev003: WrongKube++ (Reverse Engineering)

## 1. Thông tin tổng quan
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Tags:** PyInstaller, Native DLL, Static Analysis, Cryptography Bypass

## 2. Đề bài
Đây là phần tiếp theo (follow-up) của bài **Rev002 (WrongCube+)**. Bài toán cung cấp file thực thi `WrongKube++.exe` (~37MB).

Lần này ứng dụng yêu cầu thiết lập mạng lưới K8s cluster với nhiều rule validation phức tạp hơn nữa. Cụ thể là có thêm stage "specter" (VM4) để tạo thành Quadruple Witness (4 lớp xác minh), đồng thời bổ sung thêm cả thuật toán mã hóa tên FNV. Tuy nhiên, liệu lập trình viên có rút ra bài học từ phiên bản trước?

## 3. Quá trình phân tích

**Bước 1: Extract & Decompile**
Làm tương tự bài 002, dùng `pyinstxtractor` để giải nén PyInstaller. Frontend vẫn là PyQt6, gọi xuống Native DLL (`wrongkube_validator.dll`).

**Bước 2: Phân tích DLL**
Sử dụng IDA Pro, dịch ngược hàm `validate_cluster` trong DLL mới.
Mặc dù khối lượng code check validation (Kubernetes nodes/edges) phình to gấp bội, nhưng tác giả lại phạm phải y chang một **"sai lầm chí mạng"** như bài 002.
Cụ thể, vòng lặp giải mã flag nằm tại `0x180005030` **vẫn hoàn toàn độc lập** với mọi biến đầu vào của puzzle K8s. Hàm này chỉ dùng một số hằng số được hardcode và giải mã một mảng tĩnh tại `0x18002b310`.

**Điểm khác biệt duy nhất so với Rev002:**
1. Hằng số khởi tạo (Seed) `B` đổi từ `0xF73449EF` thành `0xC5B1D2FF`.
2. Mảng chứa byte mồi (Source Array) thay đổi và chuyển sang địa chỉ `0x18002b310`.
3. Vòng lặp giải mã có điều kiện dừng sớm giữa chừng ở `idx == 0x2D` $\rightarrow$ độ dài flag giảm từ 46 bytes xuống còn 45 bytes.

**Hướng giải quyết:**
Vẫn y hệt cũ, bỏ qua mớ hỗn độn validation K8s (specter, vm4, v.v.), chỉ cần nhấc đúng vòng lặp giải mã ra và viết script chạy độc lập.

## 4. PoC

Dưới đây là script Python trích xuất thẳng flag bằng cách mô phỏng lại luồng Assembly ở cuối DLL:

`solve.py`:
```python
#!/usr/bin/env python3

# Mảng 45 bytes trích xuất từ 0x18002b310 trong wrongkube_validator.dll bản mới
ARR = bytes.fromhex(
    '5af15fcc5eb7c05c993f14789329288441b7d56a193399e6'
    'bd5eae554d00ee6e253f6a29ab99faa90d34562f7200')
M = 0xFFFFFFFF

def solve():
    # Khởi tạo hằng số (Seed B đã bị đổi so với v1)
    B, R9, R14, R12, R13, S = 0xC5B1D2FF, 0x49, 0x47502943, 0x47502932, 0x3C6EF35F, 0
    flag = bytearray(45)
    idx = 1
    
    while True:
        eax = ((B * 0x19660D) & M) + R13 & M
        flag[idx - 1] = (ARR[idx - 1] ^ ((R9 - 0x49) & M ^ (eax >> 16)) ^ eax) & 0xFF
        
        # Điều kiện thoát mới (Mid-loop exit): Độ dài flag là 45 bytes
        if idx == 0x2D:
            break
            
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
grodno{wr0ngkub3pp_5p3ctr4l_qu0rum_0v3rdr1v3}
```

## 5. Flag
```
grodno{wr0ngkub3pp_5p3ctr4l_qu0rum_0v3rdr1v3}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Khi gặp các bài toán tiếp nối (Series / v1, v2), hãy luôn ưu tiên kiểm tra xem lỗ hổng cũ đã thực sự được vá kỹ chưa. Việc áp dụng Data Flow Analysis (phân tích sự phụ thuộc của đầu vào/đầu ra) vẫn phát huy sức mạnh tuyệt đối để tiết kiệm thời gian dịch ngược.
- **Cách phòng chống:** Y hệt phiên bản trước. Việc đổi Hằng số (Seed) hay chuyển địa chỉ mảng băm tĩnh (Hardcoded Array) là vô nghĩa trong Reverse Engineering nếu thuật toán băm đó không bị ràng buộc (bind) chặt chẽ với input gốc của Puzzle.

## 7. Tham khảo
- Kỹ thuật dịch ngược Data Flow Analysis (Phân tích Luồng dữ liệu).
