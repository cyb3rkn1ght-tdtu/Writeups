# 1. Thông tin tổng quan
* Challenge: Invisible Editor
* Category: Misc
* Description
![Description](./images/image.png)

---

# 2. Kiến thức lý thuyết cốt lõi
Để giải quyết thử thách này, chúng ta cần hiểu bản chất cấu trúc của các định dạng tài liệu hiện đại:
* **Office Open XML (OOXML):** Kể từ phiên bản Office 2007, các file Word `.docx` (hoặc Excel `.xlsx`, PowerPoint `.pptx`) thực chất là một **file nén định dạng ZIP**. Bên trong nó chứa một cấu trúc thư mục gồm các file XML cấu hình, file văn bản thô, và các tệp đa phương tiện đi kèm.
* **Custom XML & Log thay đổi:** Khi một tài liệu được chỉnh sửa qua các trình soạn thảo (đặc biệt là các bản lưu vết trực tuyến hoặc tính năng Track Changes), các thay đổi này thường không hiển thị trực tiếp trên giao diện Word thông thường mà được ghi lại dưới dạng nhật ký (Log) trong các file XML tùy biến, tiêu biểu là tệp `item1.xml` nằm trong thư mục `customXml`. 

---

# 3. Quá trình giải quyết

### Bước 1: Khảo sát file Word ban đầu
Khi tải về và mở tệp tin `invisible_editor.docx`, tài liệu chỉ hiển thị duy nhất một dòng nội dung:
`Did you see the flag?`

Ngoài câu hỏi trên, không có bất kỳ thông tin hay manh mối ẩn nào xuất hiện trên giao diện Word thông thường. Từ đây, chúng ta đặt ra hai câu hỏi mang tính quyết định:
1. *Liệu tài liệu này có lưu trữ lịch sử chỉnh sửa (Revision Log) hay không?*
2. *Nội dung thực tế trước khi câu hỏi này được nhập vào là gì? Có khả năng đó chính là flag đã bị ghi đè?*

### Bước 2: Khám phá cấu trúc bên trong tệp .docx
Để kiểm tra giả thuyết trên, ta tiến hành đổi đuôi tệp từ `.docx` sang `.zip` và giải nén để phân tích cấu trúc mã nguồn bên trong. Kết quả giải nén cho thấy tài liệu được cấu thành từ 4 thư mục và 1 tệp tin XML:

![Cấu trúc thư mục](./images/image-1.png)

### Bước 3: Định vị manh mối trong các tệp cấu hình XML
Tiến hành rà soát các thư mục vừa giải nén:
* Các thư mục cấu hình mặc định của Microsoft Word không chứa thông tin nào bất thường.
* Tuy nhiên, khi kiểm tra thư mục `customXml`, chúng ta tìm thấy tệp tin `item1.xml`.

Bên trong tệp tin này xuất hiện cấu trúc `<revisionLog>` ghi lại lịch sử thay đổi của văn bản. Đặc biệt, giá trị khởi tạo ban đầu nằm trong thẻ `<initial>` là chuỗi `grodno`. Đây chính là manh mối then chốt xác nhận tài liệu này đã lưu lại toàn bộ vết chỉnh sửa, mở ra hướng đi phân tích chi tiết các bước thay đổi tiếp theo để khôi phục lại flag ban đầu.

---

# 4. Phân tích chi tiết từng bước

Để tìm ra flag, ta cần theo dõi sự biến đổi của chuỗi văn bản qua từng bước chỉnh sửa (Revisions) trong file `item1.xml`. Dưới đây là phân tích chi tiết thực tế của từng bước:

* **Giá trị khởi tạo ban đầu (Initial):** `grodno`

### Phân tích chi tiết từ Step 1 đến Step 20 (Quá trình dựng Flag):

#### **Step 1:**
```xml
<revision step="1" author="Invisible Editor" at="2026-02-19T10:01:00Z">
    <deleted>
        <chunk>gro</chunk>
        <chunk>dn</chunk>
        <chunk>o</chunk>
    </deleted>
    <inserted>
        <chunk>grod</chunk>
        <chunk>no{</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa `gro`, `dn`, `o` (toàn bộ chuỗi ban đầu `grodno`), sau đó được nhập `grod` và `no{`. Đây là khởi đầu của format flag được quy định trong CTF này, vậy xác nhận ta đã đi đúng hướng và chỉ cần phân tích các step tiếp theo.
* **Nội dung sau khi phân tích Step 1:** `grodno{`

---

#### **Step 2:**
```xml
<revision step="2" author="Invisible Editor" at="2026-02-19T10:02:00Z">
    <deleted>
        <chunk>gro</chunk>
        <chunk>dno{</chunk>
    </deleted>
    <inserted>
        <chunk>gr</chunk>
        <chunk>odn</chunk>
        <chunk>o</chunk>
        <chunk>{F</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa các chunk `gro`, `dno{` (tức xóa chuỗi `grodno{` từ Step 1) và chèn thêm các chunk ký tự mới là `gr`, `odn`, `o`, `{F`.
* **Nội dung sau khi phân tích Step 2:** `grodno{F`

---

#### **Step 3:**
```xml
<revision step="3" author="Invisible Editor" at="2026-02-19T10:03:00Z">
    <deleted>
        <chunk>grod</chunk>
        <chunk>n</chunk>
        <chunk>o{F</chunk>
    </deleted>
    <inserted>
        <chunk>grod</chunk>
        <chunk>no{F</chunk>
        <chunk>1</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa các chunk `grod`, `n`, `o{F` (chuỗi `grodno{F` cũ) và chèn thêm các chunk mới `grod`, `no{F`, `1`.
* **Nội dung sau khi phân tích Step 3:** `grodno{F1`

---

#### **Step 4:**
```xml
<revision step="4" author="Invisible Editor" at="2026-02-19T10:04:00Z">
    <deleted>
        <chunk>g</chunk>
        <chunk>rod</chunk>
        <chunk>n</chunk>
        <chunk>o{F1</chunk>
    </deleted>
    <inserted>
        <chunk>gr</chunk>
        <chunk>od</chunk>
        <chunk>no{</chunk>
        <chunk>F1@</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa các chunk `g`, `rod`, `n`, `o{F1` (chuỗi `grodno{F1` cũ) và chèn thêm các chunk mới `gr`, `od`, `no{`, `F1@`.
* **Nội dung sau khi phân tích Step 4:** `grodno{F1@`

---

#### **Step 5:**
```xml
<revision step="5" author="Invisible Editor" at="2026-02-19T10:05:00Z">
    <deleted>
        <chunk>gro</chunk>
        <chunk>dn</chunk>
        <chunk>o</chunk>
        <chunk>{</chunk>
        <chunk>F</chunk>
        <chunk>1@</chunk>
    </deleted>
    <inserted>
        <chunk>g</chunk>
        <chunk>r</chunk>
        <chunk>od</chunk>
        <chunk>no</chunk>
        <chunk>{</chunk>
        <chunk>F1@</chunk>
        <chunk>g</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa toàn bộ các chunk của chuỗi `grodno{F1@` cũ và chèn thêm chuỗi mới kết thúc bằng ký tự `g`.
* **Nội dung sau khi phân tích Step 5:** `grodno{F1@g`

---

#### **Step 6:**
```xml
<revision step="6" author="Invisible Editor" at="2026-02-19T10:06:00Z">
    <deleted>
        <chunk>grod</chunk>
        <chunk>no{</chunk>
        <chunk>F</chunk>
        <chunk>1@g</chunk>
    </deleted>
    <inserted>
        <chunk>grod</chunk>
        <chunk>no</chunk>
        <chunk>{</chunk>
        <chunk>F1@</chunk>
        <chunk>g_</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa cấu trúc cũ và chèn thêm dấu gạch dưới `_` sau chữ `g`.
* **Nội dung sau khi phân tích Step 6:** `grodno{F1@g_`

---

#### **Step 7:**
```xml
<revision step="7" author="Invisible Editor" at="2026-02-19T10:07:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>od</chunk>
        <chunk>n</chunk>
        <chunk>o{F1</chunk>
        <chunk>@g_</chunk>
    </deleted>
    <inserted>
        <chunk>g</chunk>
        <chunk>rodn</chunk>
        <chunk>o{F</chunk>
        <chunk>1@g</chunk>
        <chunk>_W</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm ký tự `W` vào cuối.
* **Nội dung sau khi phân tích Step 7:** `grodno{F1@g_W`

---

#### **Step 8:**
```xml
<revision step="8" author="Invisible Editor" at="2026-02-19T10:08:00Z">
    <deleted>
        <chunk>g</chunk>
        <chunk>ro</chunk>
        <chunk>d</chunk>
        <chunk>no</chunk>
        <chunk>{F1</chunk>
        <chunk>@</chunk>
        <chunk>g_</chunk>
        <chunk>W</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>d</chunk>
        <chunk>no</chunk>
        <chunk>{F1@</chunk>
        <chunk>g_W</chunk>
        <chunk>@</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm ký tự `@` sau chữ `W`.
* **Nội dung sau khi phân tích Step 8:** `grodno{F1@g_W@`

---

#### **Step 9:**
```xml
<revision step="9" author="Invisible Editor" at="2026-02-19T10:09:00Z">
    <deleted>
        <chunk>grod</chunk>
        <chunk>no{</chunk>
        <chunk>F1</chunk>
        <chunk>@</chunk>
        <chunk>g_W@</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>dno{</chunk>
        <chunk>F</chunk>
        <chunk>1@</chunk>
        <chunk>g_W</chunk>
        <chunk>@5</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm ký tự `5` ở cuối.
* **Nội dung sau khi phân tích Step 9:** `grodno{F1@g_W@5`

---

#### **Step 10:**
```xml
<revision step="10" author="Invisible Editor" at="2026-02-19T10:10:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>od</chunk>
        <chunk>no</chunk>
        <chunk>{F1@</chunk>
        <chunk>g_W@</chunk>
        <chunk>5</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>dn</chunk>
        <chunk>o{</chunk>
        <chunk>F1@</chunk>
        <chunk>g_W@</chunk>
        <chunk>5_</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm dấu gạch dưới `_` sau số `5`.
* **Nội dung sau khi phân tích Step 10:** `grodno{F1@g_W@5_`

---

#### **Step 11:**
```xml
<revision step="11" author="Invisible Editor" at="2026-02-19T10:11:00Z">
    <deleted>
        <chunk>grod</chunk>
        <chunk>no</chunk>
        <chunk>{F1@</chunk>
        <chunk>g_W</chunk>
        <chunk>@</chunk>
        <chunk>5</chunk>
        <chunk>_</chunk>
    </deleted>
    <inserted>
        <chunk>grod</chunk>
        <chunk>no{</chunk>
        <chunk>F1@</chunk>
        <chunk>g_W@</chunk>
        <chunk>5_H</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm chữ cái `H` viết hoa.
* **Nội dung sau khi phân tích Step 11:** `grodno{F1@g_W@5_H`

---

#### **Step 12:**
```xml
<revision step="12" author="Invisible Editor" at="2026-02-19T10:12:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>odn</chunk>
        <chunk>o{F1</chunk>
        <chunk>@g_W</chunk>
        <chunk>@5_H</chunk>
    </deleted>
    <inserted>
        <chunk>gr</chunk>
        <chunk>odn</chunk>
        <chunk>o{</chunk>
        <chunk>F1@g</chunk>
        <chunk>_</chunk>
        <chunk>W@5_</chunk>
        <chunk>H</chunk>
        <chunk>3</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm số `3` sau chữ `H`.
* **Nội dung sau khi phân tích Step 12:** `grodno{F1@g_W@5_H3`

---

#### **Step 13:**
```xml
<revision step="13" author="Invisible Editor" at="2026-02-19T10:13:00Z">
    <deleted>
        <chunk>g</chunk>
        <chunk>rod</chunk>
        <chunk>no{F</chunk>
        <chunk>1@g_</chunk>
        <chunk>W@</chunk>
        <chunk>5</chunk>
        <chunk>_H3</chunk>
    </deleted>
    <inserted>
        <chunk>gr</chunk>
        <chunk>odno</chunk>
        <chunk>{</chunk>
        <chunk>F1</chunk>
        <chunk>@g_</chunk>
        <chunk>W</chunk>
        <chunk>@5_H</chunk>
        <chunk>3r</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm ký tự `r` thường ở cuối.
* **Nội dung sau khi phân tích Step 13:** `grodno{F1@g_W@5_H3r`

---

#### **Step 14:**
```xml
<revision step="14" author="Invisible Editor" at="2026-02-19T10:14:00Z">
    <deleted>
        <chunk>gro</chunk>
        <chunk>dno</chunk>
        <chunk>{F1</chunk>
        <chunk>@</chunk>
        <chunk>g_</chunk>
        <chunk>W</chunk>
        <chunk>@5_H</chunk>
        <chunk>3r</chunk>
    </deleted>
    <inserted>
        <chunk>g</chunk>
        <chunk>ro</chunk>
        <chunk>dn</chunk>
        <chunk>o{F1</chunk>
        <chunk>@</chunk>
        <chunk>g_W@</chunk>
        <chunk>5_H3</chunk>
        <chunk>r</chunk>
        <chunk>3</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm số `3` sau ký tự `r`.
* **Nội dung sau khi phân tích Step 14:** `grodno{F1@g_W@5_H3r3`

---

#### **Step 15:**
```xml
<revision step="15" author="Invisible Editor" at="2026-02-19T10:15:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>od</chunk>
        <chunk>no</chunk>
        <chunk>{F</chunk>
        <chunk>1</chunk>
        <chunk>@g_W</chunk>
        <chunk>@5_H</chunk>
        <chunk>3r3</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>dno</chunk>
        <chunk>{</chunk>
        <chunk>F1@g</chunk>
        <chunk>_W@</chunk>
        <chunk>5</chunk>
        <chunk>_H</chunk>
        <chunk>3</chunk>
        <chunk>r</chunk>
        <chunk>3_</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm ký tự gạch dưới `_` ở cuối.
* **Nội dung sau khi phân tích Step 15:** `grodno{F1@g_W@5_H3r3_`

---

#### **Step 16:**
```xml
<revision step="16" author="Invisible Editor" at="2026-02-19T10:16:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>od</chunk>
        <chunk>no</chunk>
        <chunk>{</chunk>
        <chunk>F</chunk>
        <chunk>1@</chunk>
        <chunk>g_W@</chunk>
        <chunk>5_</chunk>
        <chunk>H</chunk>
        <chunk>3r3_</chunk>
    </deleted>
    <inserted>
        <chunk>gr</chunk>
        <chunk>odno</chunk>
        <chunk>{F1</chunk>
        <chunk>@g_W</chunk>
        <chunk>@5_H</chunk>
        <chunk>3r</chunk>
        <chunk>3</chunk>
        <chunk>_</chunk>
        <chunk>0</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm chữ số `0` ở cuối.
* **Nội dung sau khi phân tích Step 16:** `grodno{F1@g_W@5_H3r3_0`

---

#### **Step 17:**
```xml
<revision step="17" author="Invisible Editor" at="2026-02-19T10:17:00Z">
    <deleted>
        <chunk>gr</chunk>
        <chunk>odn</chunk>
        <chunk>o{F</chunk>
        <chunk>1@g_</chunk>
        <chunk>W</chunk>
        <chunk>@</chunk>
        <chunk>5_</chunk>
        <chunk>H</chunk>
        <chunk>3</chunk>
        <chunk>r3_0</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>dno</chunk>
        <chunk>{F</chunk>
        <chunk>1</chunk>
        <chunk>@g_W</chunk>
        <chunk>@5_</chunk>
        <chunk>H3r3</chunk>
        <chunk>_0n</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm chữ cái `n` thường sau số `0`.
* **Nội dung sau khi phân tích Step 17:** `grodno{F1@g_W@5_H3r3_0n`

---

#### **Step 18:**
```xml
<revision step="18" author="Invisible Editor" at="2026-02-19T10:18:00Z">
    <deleted>
        <chunk>g</chunk>
        <chunk>rod</chunk>
        <chunk>n</chunk>
        <chunk>o</chunk>
        <chunk>{</chunk>
        <chunk>F</chunk>
        <chunk>1@g</chunk>
        <chunk>_W@5</chunk>
        <chunk>_H3r</chunk>
        <chunk>3_0n</chunk>
    </deleted>
    <inserted>
        <chunk>grod</chunk>
        <chunk>no</chunk>
        <chunk>{</chunk>
        <chunk>F1@g</chunk>
        <chunk>_W</chunk>
        <chunk>@5</chunk>
        <chunk>_</chunk>
        <chunk>H3r3</chunk>
        <chunk>_0</chunk>
        <chunk>n</chunk>
        <chunk>c</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm chữ cái `c` sau chữ `n`.
* **Nội dung sau khi phân tích Step 18:** `grodno{F1@g_W@5_H3r3_0nc`

---

#### **Step 19:**
```xml
<revision step="19" author="Invisible Editor" at="2026-02-19T10:19:00Z">
    <deleted>
        <chunk>grod</chunk>
        <chunk>no</chunk>
        <chunk>{</chunk>
        <chunk>F1</chunk>
        <chunk>@g</chunk>
        <chunk>_W@5</chunk>
        <chunk>_</chunk>
        <chunk>H3r3</chunk>
        <chunk>_0n</chunk>
        <chunk>c</chunk>
    </deleted>
    <inserted>
        <chunk>gro</chunk>
        <chunk>dno</chunk>
        <chunk>{</chunk>
        <chunk>F1@g</chunk>
        <chunk>_W@</chunk>
        <chunk>5_H</chunk>
        <chunk>3</chunk>
        <chunk>r3_</chunk>
        <chunk>0nc</chunk>
        <chunk>3</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm chữ số `3` sau chữ `c`.
* **Nội dung sau khi phân tích Step 19:** `grodno{F1@g_W@5_H3r3_0nc3`

---

#### **Step 20:**
```xml
<revision step="20" author="Invisible Editor" at="2026-02-19T10:20:00Z">
    <deleted>
        <chunk>g</chunk>
        <chunk>r</chunk>
        <chunk>o</chunk>
        <chunk>dno{</chunk>
        <chunk>F1@g</chunk>
        <chunk>_</chunk>
        <chunk>W@5_</chunk>
        <chunk>H</chunk>
        <chunk>3</chunk>
        <chunk>r3_0</chunk>
        <chunk>nc3</chunk>
    </deleted>
    <inserted>
        <chunk>g</chunk>
        <chunk>rod</chunk>
        <chunk>no{F</chunk>
        <chunk>1@</chunk>
        <chunk>g</chunk>
        <chunk>_W@5</chunk>
        <chunk>_H3</chunk>
        <chunk>r3_</chunk>
        <chunk>0</chunk>
        <chunk>nc</chunk>
        <chunk>3}</chunk>
    </inserted>
</revision>
```
* **Phân tích:** Xóa chuỗi cũ và chèn thêm dấu đóng ngoặc nhọn `}` ở cuối để hoàn tất cấu trúc Flag.
* **Nội dung sau khi phân tích Step 20:** `grodno{F1@g_W@5_H3r3_0nc3}`

---

### Tóm tắt từ Step 21 đến Step 100 (Quá trình ẩn giấu Flag):

Kể từ Step 21, người biên soạn bắt đầu thay thế dần các ký tự của flag nhằm biến nó thành `Did you see the flag?`

---

# 5. Flag
`grodno{F1@g_W@5_H3r3_0nc3}`