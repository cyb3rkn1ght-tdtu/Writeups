# [Grodno CTF] Strongest Beaver - Writeup (OSINT)

**Author:** @hckerror | **Difficulty:** Hard | **Category:** OSINT

---

![Đề bài Strongest Beaver](images/strongest_beaver.png)


 **Đây là 1 bài OSINT tưởng đối khó, vì không cho ta bất kì hình ảnh hay file nào cả. Chỉ cho ta mô ta của đề bài**

## 1. Phân tích đề bài 
Chúng ta có những manh mối như sau:
> **weber:** Là web pentester

> **occupied high places in the ranking of various information security platforms:** Tức là người này có xếp hạng cao ở các nền tảng về bảo mật (HTB, THM, Root-me, ...) 

Tới đây thì chúng ta chỉ có được vài manh mối này, những thông tin bất khả thi để tìm 1 người nào đó. Nhưng nếu chúng ta để tên bài thi là **Strongest Beaver** thì ta có thể thu hẹp phạm vi tìm kiếm nhanh chóng


Tại sao? Vì Beaver cho ta manh mối biết được đây là team tổ chức ra giải CTF này. Nếu các bạn lên CTF time, sẽ thấy tên team này 

![Hình ảnh trên CTFtime](images/ctftime_beaver.png)


Và team của họ bao gồm 18 thành viên 
![Hình ảnh các thành viên](images/beaver_members.png)


Bây giờ công việc của chúng ta lúc này là đi tìm kiếm thông tin lần lượt của 18 thành viên này.

## 2. Tìm kiếm thông tin

Đầu tiên tôi sẽ check vài xem những người có thông tin trong tài khoản CTF time của họ trước, ví dụ như social media, github, telegram, ...

Tôi đã bắt đầu với những cái tên như Definazu, Mr.Error, Blandrein, F0ra1n

**Đầu tiên là Definazu, tên thất của anh ấy là Gleb Shadura**

Tôi bắt đầu lên THM để tìm kiếm thử xem có hay không, đúng là có tên đấy, nhưng không có bất kỳ thông tin gì

Sau đó tôi thử lên github để tìm kiếm profile của anh ấy thì đã có thông tin về Linkedin, telegram của anh ấy. Tôi liền kiểm tra ngay profile Linkedin của anh ấy ngay

Nếu nhìn thông tin thì anh ấy theo học tại trường Grodno, thành viên của Beavers0. Tuy nhiên, anh ấy theo Blue team, nó khác với **Weber**, nhưng vì thấy anh đã từng làm công ty **Security Lab** nên tôi đã thử nhập vào flag xem, thì kết quả là không phải

![](images/definazu_linkedin.png)

Dựa vào profile của anh ấy, tôi tìm được thông tin của member thứ 2 trong team, là Alex Chychkan (Mr.Error)

**Tìm kiếm thông tin của Mr.Error**

Profile anh ấy khiến tôi tưởng mình đã tìm được đáp án, vì nó thỏa mãn tất cả manh mối ban đầu, Penetration Tester, Top 1% THM, thành viên của Bearvers0. Ngoài ra cũng là người ra đề cho bài này.

Nhưng khi tìm kiếm thông tin về tổ chức anh ấy làm việc thì không có, anh ấy đang làm freelance

Nhưng anh ấy còn để thông tin về Github, THM profile nên tôi cũng đã lên đấy kiểm tra. 

![](images/mr_error_linkedin)

Khi kiểm tra profile trên github và cả THM, thì không có thông tin gì về tổ chức của anh ấy cả

Nên lúc này tôi nghĩ tổ chức có thể là tên trường của anh ấy hoặc team anh ấy đang tham gia, tôi thử nhập các flag thì đều không được

Tiếp đến tôi thử vào các post trên linkedin của anh ấy để xem những người tương tác có liên quan, thì tôi thấy thông tin của Ivan Savanets, là đội trưởng của Beavers0

Nhưng cũng không có bất kỳ thông tin về tổ chức. Cả 2 người mà tôi đã đề cập ở trên. 


**Tìm kiếm thông tin những thành viên còn lại**

Tôi quay lại CTF time để tìm kiếm những thông tin của những thành viên còn lại bằng tên thật, và cả nickname của họ trên các nền tảng như Linkedin, github. Thì tôi tìm được profile của nickname **vadimm** trên github, nhưng tôi phải tìm tới trang thứ 3 mới có. Vì trên CTF không để tên thật của anh ấy nên tôi cũng không chắc. Nhưng khi xem tên thật của anh ấy thì khá trùng nickname vadimm đó là **VadimMustyatsa**

![](images/vadimm_github.png)

Trên profile của anh ấy có để tên của tổ chức anh ấy đang làm, cũng ở Belarus, nên tôi nghĩ anh ấy cũng thuộc team Beavers0. Tôi lên Linkedin để tìm thêm thông tin thì thấy anh ấy không hề để thông tin liên quan tới team CTF hay trường Grodno. Nhưng có thông tin về công ty là Alfa Bank.

Vì thế tôi thử nhập vào flag thì nó đúng

```
grodno{Alfa_Bank}
```

#### 3. Bài học rút ra
1. Hãy đọc kĩ đề bài vì rất có thể nó cho chúng ta manh mối để thu hẹp phạm vi tìm kiếm

2. Hãy thử những kết quả có thể



