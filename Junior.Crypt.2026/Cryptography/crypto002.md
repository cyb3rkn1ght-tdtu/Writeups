# Crypto002 (Crypto)

## 1. Thông tin tổng quan (nếu có)
- **Category:** Cryptography
- **Difficulty:** Medium
- **Tags:** RSA, Franklin-Reiter Related Message Attack, Polynomial GCD

## 2. Đề bài

**File đính kèm:**

`get_key.py`:
```python
from Crypto.PublicKey import RSA

with open('public.pem', 'r') as f:
    key = RSA.import_key(f.read())
    print("N =", key.n)
    print("e =", key.e)
```

`public.pem`:
```text
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQB/aa2mciMoj0lCZ+s5UKZa
wnHr87ORVvynH0YfJJKr3/MJOr35+iMyChG2sixWSQYDCfK/1/LFqsYWt7v6oRE6
Y5KL9Kn66pkRl8dCnb6fT9xQxTZ1VG/6dtufbjnkRA9+RXi8pBcGy+3x1faYa3b1
YAE6tUFOP/r+Tet2nHg1gxO+ny6bGkndxbqLj723/olGh7AHtIFX6KidjDxV++kL
lFq74xUvFCPTJwh74y83l/oNXVl57rr33y0cnYvOcpnl8BIaf5hSkL2KzF7Wreyt
YvO87lw5jOZmpIauUrKMy+bZpabeU7eveBS0Y58V/AuFqqqEgE8AfeljD9pWzS5N
AgED
-----END PUBLIC KEY-----
```

`ciphertexts.json`:
```json
{
  "c1": "1510178335684696714685873327665405693229817332517436339238069263675038307589584214991972178491921220047341835361716706161178163416700415404625350002926181882456823502803410544652350146140381718735302345248628063873660985533045721106554846156052438592114307314518801187292144516375694416824050266212100756386275261659120818929352793001849091258812215056569210688323608477486845658209486811020289125",
  "c2": "3609295645705662540044855008243054365350192600605141370245424986994959926638492546887337413790549139187480476785427123220087473450876182596851045924928251593513173505332946948102427079420393467365270853577244702869375179960380036509819716874669828921269331392072342996230205000587709059408970764540586263926166415953866205713837484492604885356068778972289745706137303021097189730935932700998705875484035375",
  "a": 1337,
  "b": "5577100914618608347433571795909361526455637706263378490"
}
```

## 3. Quá trình phân tích

Phân tích `ciphertexts.json`, ta thấy dữ liệu bao gồm hai bản mã $c_1$, $c_2$ cùng với hai tham số tuyến tính $a$ và $b$. Dựa trên cách biểu diễn quen thuộc trong các bài RSA, ta có thể suy luận mối liên hệ giữa hai bản mã này:
- $c_1 \equiv m^e \pmod{N}$
- $c_2 \equiv (a \cdot m + b)^e \pmod{N}$

Trong đó $N$ và $e$ được trích xuất từ file `public.pem`. 

Đây là dấu hiệu kinh điển của **Franklin-Reiter Related Message Attack**. Khi một thông điệp $m$ và một thông điệp khác có quan hệ tuyến tính với nó ($a \cdot m+b$) cùng được mã hóa bằng một public key (chung $N$ và $e$), ta có thể khôi phục được $m$ mà không cần đến khóa bí mật $d$.

**Hướng giải quyết:**
1. Đặt hai đa thức trên vành $\mathbb{Z}_N$: 
   $g_1(x) = x^e - c_1$
   $g_2(x) = (ax + b)^e - c_2$
2. Vì $m$ là nghiệm chung của cả hai đa thức modulo $N$, nên $(x - m)$ sẽ là ước số chung của chúng.
3. Sử dụng thuật toán Euclid để tìm ước chung lớn nhất (GCD) của $g_1(x)$ và $g_2(x)$. Kết quả GCD sẽ có dạng biểu thức bậc nhất: $x - m$.
4. Thông điệp $m$ chính là phần tử tự do (hệ số bậc 0) nhân với $-1$ của đa thức GCD thu được.

## 4. PoC

```python
import json

def get_key():
    from Crypto.PublicKey import RSA
    with open('public.pem', 'r') as f:
        key = RSA.import_key(f.read())
    return key.n, key.e

def solve():
    N, e = get_key()
    with open('ciphertexts.json', 'r') as f:
        data = json.load(f)
    
    c1 = int(data['c1'])
    c2 = int(data['c2'])
    a = int(data['a'])
    b = int(data['b'])

    # Tạo vành đa thức trên modulo N
    ZmodN = Zmod(N)
    P.<x> = PolynomialRing(ZmodN)

    # Khởi tạo 2 đa thức
    g1 = x^e - c1
    g2 = (a*x + b)^e - c2

    # Thuật toán tìm GCD của 2 đa thức (Franklin-Reiter)
    def franklin_reiter(g1, g2):
        while g2 != 0:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    # Tính toán
    gcd = franklin_reiter(g1, g2)
    m = -gcd.coefficients()[0]
    m_int = Integer(m)
    
    # Ép kiểu về string để ra Flag
    try:
        flag = bytes.fromhex(hex(m_int)[2:]).decode('utf-8')
        print("Flag:", flag)
    except:
        print("m =", m_int)

if __name__ == '__main__':
    solve()
```

**Output:**
```
Flag: grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
```

## 5. Flag
```
grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
```

## 6. Bài học rút ra
- **Kỹ thuật mới học được:** Nhận diện và khai thác lỗi Related Message Attack trong mã hóa RSA thông qua định lý Franklin-Reiter. Sử dụng Sagemath để định nghĩa vành đa thức (Polynomial Ring) và tính GCD nhằm tìm ra nghiệm chung của hai bản mã có liên quan tuyến tính.
- **Cách phòng chống:** Khi sử dụng RSA, không bao giờ mã hóa trực tiếp thông điệp gốc hoặc các thông điệp có liên hệ tuyến tính một cách dễ đoán. Luôn phải áp dụng các scheme padding ngẫu nhiên đạt chuẩn an toàn (như RSA-OAEP) trước khi mã hóa để phá vỡ cấu trúc toán học trực tiếp.

## 7. Tham khảo
- [Franklin-Reiter Related Message Attack (Wikipedia)](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack)
- Tài liệu hàm `PolynomialRing` và xử lý đa thức trong SageMath.
