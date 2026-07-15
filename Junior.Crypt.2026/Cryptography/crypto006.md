# Still Alive (Crypto)

## 1. Thông tin tổng quan

- **Category:** Cryptography
- **Difficulty:** Medium
- **Tags:** RSA, Related Message Attack, Franklin-Reiter Attack

## 2. Đề bài

> A restricted Aperture Science record associated with GLaDOS was recovered from an internal storage segment that survived the shutdown of the facility.
>
> The surviving materials are incomplete, but they are sufficient to reconstruct what was meant to remain hidden.
>
> Recover the original message.

Flag format:

```text
grodno{}
```

## 3. Quá trình phân tích

Challenge cung cấp hai file:

- `public.pem`
- `ciphertexts.json`

### `public.pem`

File này chứa RSA public key được sử dụng trong quá trình mã hóa.

Sử dụng lệnh:

```bash
openssl rsa -pubin -in public.pem -text -noout
```

thu được:

```text
Public-Key: (2048 bit)
Exponent: 3
```

Việc sử dụng public exponent nhỏ (`e = 3`) thường xuất hiện trong các challenge RSA liên quan đến cấu trúc bản rõ.

### `ciphertexts.json`

File này chứa hai ciphertext cùng các tham số bổ sung:

```json
{
    "c1": "...",
    "c2": "...",
    "a": 1337,
    "b": "..."
}
```

Quan sát thấy hai plaintext có quan hệ tuyến tính:

```text
m2 = 1337 * m1 + b
```

Do đó:

```text
c1 = m1^3 mod n
c2 = (1337 * m1 + b)^3 mod n
```

Việc mã hóa hai thông điệp có quan hệ tuyến tính bằng cùng một khóa RSA tạo điều kiện để thực hiện Franklin-Reiter Related Message Attack.

Ý tưởng của cuộc tấn công là xây dựng hai đa thức:

```text
f1(x) = x^3 - c1
f2(x) = (1337*x + b)^3 - c2
```

Hai đa thức này có chung nghiệm là thông điệp gốc `m1`.

Bằng cách tính GCD của hai đa thức, ta có thể khôi phục lại plaintext mà không cần biết private key của RSA.

## 4. PoC

```python
from Crypto.Util.number import long_to_bytes

R.<x> = Zmod(n)[]

f1 = x^e - c1
f2 = (1337*x + b)^e - c2

g = f1.gcd(f2)

m = int(-g[0])

print(long_to_bytes(m))
```

Output:

```text
b'571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35'
```

## 5. Flag

```text
grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
```

## 6. Tài liệu tham khảo

## 6. Tài liệu tham khảo

1. [Franklin-Reiter Related Message Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack)

2. [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

3. [Twenty Years of Attacks on the RSA Cryptosystem - Dan Boneh](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
