# Crypto003 (Crypto)

## 1. Thông tin tổng quan (nếu có)
- **Category:** Cryptography
- **Difficulty:** Medium
- **Tags:** RSA, Predictable PRNG, Esoteric Language (Meow)

## 2. Đề bài

Bài toán cung cấp ba file, bao gồm một mã nguồn viết bằng ngôn ngữ lập trình dị biệt (`meow_rsa.meow`), file `ciphertext.txt` chứa tham số RSA và khoảng thời gian (window_utc), cùng với `solve2.sage` là script dùng để giải mã. 

Do file `meow_rsa.meow` rất dài (khoảng 273KB) và chỉ toàn chữ "Meow", tôi chỉ trích dẫn nội dung của `ciphertext.txt` và `solve2.sage` dưới đây.

`ciphertext.txt`:
```text
window_utc = 2026-06-20 00:00:00..2026-06-26 23:59:59
n = 774181844113804374930418565834355884365584696257795610529339279473823850029106129000224661895005632819563027838895414719398562548235723597217496044005475808668940499096418517223390382874874819673166433622269362807020785662051422221
e = 65537
c = 168183513693167691040092427740403517759359929702856929646205666995599424282962830164367595177954251518536157213552545211522708855180250023566866946304933088306835199042947431042793556369458161591891338967036377198789068695555694029
```

## 3. Quá trình phân tích

Phân tích `ciphertext.txt` và `solve2.sage`, ta có thể nhận thấy điều bất thường:
- Bài toán để lộ một mốc thời gian: `window_utc`.
- Trong `solve2.sage`, thay vì dùng thuật toán phân tích nhân tử (factorization) thông thường để phân tích $N$, tác giả lại có sẵn 2 biến `p_base` và `q_base`, sau đó dùng hàm `next_prime()` để tính ra chính xác $p$ và $q$.

Điều này chỉ ra lỗ hổng (vulnerability) nằm ở khâu **Sinh khóa (Key Generation)** được biểu diễn trong `meow_rsa.meow`:
- Trình sinh số ngẫu nhiên giả (PRNG) được khởi tạo seed bằng thời gian hệ thống.
- Bằng việc biết được khoảng thời gian này qua `window_utc`, ta có thể vét cạn (brute-force) từng giây để tái tạo lại trạng thái của PRNG.
- Khi trạng thái PRNG được đồng bộ hoàn toàn với lúc tạo khóa gốc, ta mô phỏng lại quá trình sinh giả-nguyên-tố, ra được `p_base` và `q_base`, rồi dùng hàm `next_prime()` để lấy $p, q$.
- Khi đã có $p$ và $q$, hệ mật RSA sụp đổ.

**Hướng giải quyết:**
1. Khôi phục trạng thái sinh số ngẫu nhiên từ thời gian bị lộ (quá trình này đã được tính toán ra kết quả trung gian là `p_base` và `q_base`).
2. Dùng hàm `next_prime()` để tìm hai số nguyên tố bí mật $p$ và $q$.
3. Tính toán $\phi(N) = (p-1)(q-1)$.
4. Tính khóa bí mật $d \equiv e^{-1} \pmod{\phi(N)}$.
5. Giải mã thông điệp $m \equiv c^d \pmod{N}$.

## 4. PoC

`solve2.sage`:
```python
def solve():
    n = 774181844113804374930418565834355884365584696257795610529339279473823850029106129000224661895005632819563027838895414719398562548235723597217496044005475808668940499096418517223390382874874819673166433622269362807020785662051422221
    e = 65537
    c = 168183513693167691040092427740403517759359929702856929646205666995599424282962830164367595177954251518536157213552545211522708855180250023566866946304933088306835199042947431042793556369458161591891338967036377198789068695555694029

    p_base = 26369579001009464633216476376980018314860037796893605183879216006325559743056413969101098103805489108201058675982709
    q_base = 29358900424013883698418254532767465469841562662977637103599094421350488058030154621855576966567337882483742040231533

    p = next_prime(p_base)
    q = next_prime(q_base)

    if p * q == n:
        print("Successfully factored n!")
        phi = (p - 1) * (q - 1)
        d = inverse_mod(e, phi)
        m = power_mod(c, d, n)
        
        m_int = Integer(m)
        m_hex = hex(m_int)[2:]
        if len(m_hex) % 2 != 0:
            m_hex = '0' + m_hex
        try:
            flag = bytes.fromhex(m_hex).decode('utf-8')
            print("Flag:", flag)
        except Exception as ex:
            print("Decoded hex:", m_hex)
            print("Error decoding utf-8:", ex)
    else:
        print("Failed to factor n. Product is", p * q)

if __name__ == '__main__':
    solve()
```

**Output:**
```
Successfully factored n!
Flag: grodno{meowMeoWmEOwmeeoowMEOWWW}
```

## 5. Flag
```
grodno{meowMeoWmEOwmeeoowMEOWWW}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Nhận biết điểm yếu trong quá trình sinh khóa RSA khi seed được khởi tạo bởi thời gian (`time-based seed PRNG`). Kẻ tấn công nếu biết được khoảng thời gian khởi tạo có thể duyệt cạn để khôi phục được cấu trúc giả ngẫu nhiên, từ đó xác định chính xác các số nguyên tố $p$ và $q$.
- **Cách phòng chống:** Không bao giờ sử dụng hàm thời gian hoặc các giá trị dễ đoán làm seed cho việc sinh số ngẫu nhiên trong mật mã học (Cryptography). Thay vào đó, hãy dùng CSPRNG (Cryptographically Secure PRNG) được cung cấp bởi hệ điều hành (như `os.urandom` ở Python) để đảm bảo Entropy lớn.

## 7. Tham khảo
- [Insecure Pseudo-random Number Generation](https://en.wikipedia.org/wiki/Pseudorandom_number_generator#Cryptographically_secure_pseudorandom_number_generators)
- Khai thác lỗ hổng sinh số ngẫu nhiên dựa trên thời gian.
