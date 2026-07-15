\# Still Alive (Crypto)



\## 1. Thông tin tổng quan



\*\*Category:\*\* Cryptography  

\*\*Difficulty:\*\* Medium  

\*\*Tags:\*\* RSA, Franklin-Reiter Attack, Related Message Attack



\## 2. Đề bài



A restricted Aperture Science record associated with GLaDOS was recovered from an internal storage segment that survived the shutdown of the facility.



The surviving materials are incomplete, but they are sufficient to reconstruct what was meant to remain hidden.



Recover the original message.



Flag format:



```text

grodno{}

```



\## 3. Quá trình phân tích



Challenge cung cấp file:



```text

StillAlive.zip

├── public.pem

└── ciphertexts.json

```



\### public.pem



File này chứa RSA public key.



Sử dụng OpenSSL để kiểm tra:



```bash

openssl rsa -pubin -in public.pem -text -noout

```



Kết quả:



```text

Public-Key: (2048 bit)

Exponent: 3

```



Việc sử dụng public exponent nhỏ (`e = 3`) thường xuất hiện trong các challenge RSA liên quan đến cấu trúc bản rõ.



\---



\### ciphertexts.json



File chứa hai ciphertext cùng các tham số bổ sung:



```json

{

&#x20;   "c1": "...",

&#x20;   "c2": "...",

&#x20;   "a": 1337,

&#x20;   "b": "..."

}

```



Điểm đáng chú ý nhất là:



```text

m2 = a\*m1 + b

m2 = 1337\*m1 + b

```



Hay nói cách khác:



```text

c1 = m1^3 mod n

c2 = (1337\*m1+b)^3 mod n

```



Hai thông điệp có quan hệ tuyến tính nhưng lại được mã hóa bằng cùng một khóa RSA.



Đây chính là điều kiện để thực hiện \*\*Franklin-Reiter Related Message Attack\*\*.



\## 4. PoC



```python

from Crypto.Util.number import long\_to\_bytes



R.<x> = Zmod(n)\[]



f1 = x^e - c1

f2 = (1337\*x + b)^e - c2



g = f1.gcd(f2)



m = int(-g\[0])



print(long\_to\_bytes(m))

```



Output:



```text

b'571ll\_4l1v3\_bu7\_g14d05\_k3375\_r3w5171ng\_m35s4g35'

```



\## 5. Flag



```text

grodno{571ll\_4l1v3\_bu7\_g14d05\_k3375\_r3w5171ng\_m35s4g35}

```



\## 6. Tài liệu tham khảo



1\. Franklin-Reiter Related Message Attack

2\. RSA Cryptosystem

3\. Boneh, D. - Twenty Years of Attacks on the RSA Cryptosystem

