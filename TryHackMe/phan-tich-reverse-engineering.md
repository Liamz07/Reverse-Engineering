# Phân tích Reverse Engineering: `Compiled-1688545393558.Compiled`

## Mục tiêu và phạm vi

Tài liệu này phân tích binary người dùng cung cấp, dựa trên mã giả C từ Ghidra và các ảnh kèm theo. Mục tiêu là hiểu chính xác đường đi dẫn tới `Correct!`, thay vì chỉ đoán chuỗi từ kết quả `strings`.

> Lưu ý: các chuỗi/ký hiệu như `_init` và `__dso_handle` trong cửa sổ decompiler có thể là tên symbol ELF do Ghidra tự gán. Khi chúng xuất hiện làm đối số cho `strcmp`, cần đọc chúng như **chuỗi hằng nằm tại địa chỉ đó** và xác minh bằng dữ liệu thô.

## 1. Recon tĩnh

Kiểm tra đầu file cho thấy magic `7F 45 4C 46`, tức là ELF; byte class `02` cho biết ELF 64-bit. File có kích thước 16.152 byte và SHA-256:

```text
32FD4208DC3EDB63579B3441BB7A4C9C07804AC6B8115FBC55EF10ACEBEF861F
```

Các chuỗi đáng chú ý hiện diện trong binary gồm:

```text
Password:
DoYouEven%sCTF
__dso_handle
_init
Correct!
Try again!
```

Không nên kết luận từ riêng `strings`: thử thách cố ý có thể đặt chuỗi nhiễu (decoy). Bằng chứng quyết định là các lời gọi `scanf` và `strcmp` trong `main`.

## 2. Mã giả decompile từ Ghidra

Đây là mã nguồn giả C do Ghidra sinh ra từ binary, theo nội dung được cung cấp. Nó không phải source C nguyên gốc: tên như `local_28`, `iVar1`, `undefined8`, cùng các hàm wrapper ở PLT là do công cụ suy luận/đặt lại tên.

```c
#include "out.h"

undefined main;
pointer __dso_handle;
undefined1 completed.0;
undefined8 stdout;

int _init(EVP_PKEY_CTX *ctx)
{
    int iVar1;
    iVar1 = **gmon_start();
    return iVar1;
}

void FUN_00101020(void)
{
    (*(code *)(undefined *)0x0)();
}

int printf(char *__format, ...)
{
    int iVar1;
    iVar1 = printf(__format);
    return iVar1;
}

int strcmp(char *__s1, char *__s2)
{
    int iVar1;
    iVar1 = strcmp(__s1, __s2);
    return iVar1;
}

void __isoc99_scanf(void)
{
    __isoc99_scanf();
}

size_t fwrite(void *__ptr, size_t __size, size_t __n, FILE *__s)
{
    size_t sVar1;
    sVar1 = fwrite(__ptr, __size, __n, __s);
    return sVar1;
}

void __cxa_finalize(void)
{
    __cxa_finalize();
}

void processEntry_start(undefined8 param_1, undefined8 param_2)
{
    undefined1 auStack_8[8];
    __libc_start_main(main, param_2, &stack0x00000008,
                      0, 0, param_1, auStack_8);
    do { } while (true);
}

void deregister_tm_clones(void) { return; }
void register_tm_clones(void) { return; }

void __do_global_dtors_aux(void)
{
    if (completed_0 != '\0') return;
    __cxa_finalize(__dso_handle);
    deregister_tm_clones();
    completed_0 = 1;
}

void frame_dummy(void)
{
    register_tm_clones();
}

undefined8 main(void)
{
    int iVar1;
    char local_28[32];

    fwrite("Password: ", 1, 10, stdout);
    __isoc99_scanf("DoYouEven%sCTF", local_28);

    iVar1 = strcmp(local_28, "__dso_handle");
    if ((-1 < iVar1) &&
        (iVar1 = strcmp(local_28, "__dso_handle"), iVar1 < 1)) {
        printf("Try again!");
        return 0;
    }

    iVar1 = strcmp(local_28, "_init");
    if (iVar1 == 0)
        printf("Correct!");
    else
        printf("Try again!");
    return 0;
}

void _fini(void)
{
    return;
}
```

Các khối khởi động/kết thúc ELF như `processEntry_start`, `frame_dummy`, `__do_global_dtors_aux`, `_init`, `_fini` và các wrapper import không tham gia kiểm tra mật khẩu. Phần cần lần theo nằm trong `main`.

## 3. Rút gọn hàm `main`

Phần logic quan trọng có thể viết lại dễ đọc như sau:

```c
char input[32];

fwrite("Password: ", 1, 10, stdout);
scanf("DoYouEven%sCTF", input);   // giá trị trả về bị bỏ qua

if (strcmp(input, "__dso_handle") == 0) {
    puts("Try again!");
    return 0;
}

if (strcmp(input, "_init") == 0)
    puts("Correct!");
else
    puts("Try again!");
```

Điều kiện đầu trong mã Ghidra:

```c
(-1 < strcmp(input, "__dso_handle")) && (strcmp(input, "__dso_handle") < 1)
```

tương đương chính xác với `strcmp(...) == 0`. Đây chỉ là một nhánh chặn chuỗi `__dso_handle`; nó không phải đáp án.

## 4. Phân tích chính xác `scanf("DoYouEven%sCTF", input)`

Định dạng gồm ba phần:

| Thành phần | Ý nghĩa |
|---|---|
| `DoYouEven` | Phải khớp nguyên văn ở đầu input; không được lưu vào `input`. |
| `%s` | Đọc chuỗi không có whitespace và lưu vào `input`. |
| `CTF` | Ba ký tự literal mà `scanf` cố khớp sau `%s`. |

Một điểm tinh tế: `%s` là tham lam (greedy), nên với input `DoYouEven_initCTF`, nó sẽ đọc **`_initCTF`** vào `input`, rồi không còn `CTF` để khớp. Vì vậy, không nên thêm hậu tố `CTF` nếu mục đích là đưa `_init` vào biến.

Điểm quan trọng hơn: chương trình **không kiểm tra giá trị trả về của `scanf`**. Khi nhập `DoYouEven_init` rồi nhấn Enter:

1. Literal `DoYouEven` khớp.
2. `%s` lưu `_init` vào `input` và một phép gán đã thành công.
3. Ký tự newline khiến phần literal `CTF` không khớp, nên `scanf` dừng.
4. `scanf` vẫn trả về `1` (một phép gán `%s` thành công), nhưng `main` bỏ qua kết quả này.
5. Do đó `input` vẫn là `_init`, rồi so sánh cuối trả về 0 và in `Correct!`.

## 5. Suy luận đáp án

Điều kiện thành công là:

```c
strcmp(input, "_init") == 0
```

Trong khi phần prefix literal của `scanf` buộc người dùng mở đầu bằng `DoYouEven`. Kết hợp hai yêu cầu, input cần nhập là:

```text
DoYouEven_init
```

Sau đó nhấn Enter. **Không** nhập `DoYouEven_initCTF`; biến `input` khi đó sẽ thành `_initCTF`, làm so sánh thất bại.

## 6. Cách kiểm chứng an toàn

Trên môi trường cô lập/CTF, có thể chạy binary và gửi đúng một dòng input:

```bash
printf 'DoYouEven_init\n' | ./Compiled-1688545393558.Compiled
```

Kết quả mong đợi là `Correct!`. Để đối chứng, thử `DoYouEven_initCTF`; kết quả phải là `Try again!` vì `%s` đã nuốt cả `CTF`.

## 7. Bẫy và bài học phân tích

1. **Đừng tin hoàn toàn tên biến/symbol do decompiler đặt.** `_init` và `__dso_handle` trông như cấu trúc ELF, nhưng ở ngữ cảnh `strcmp` chúng đại diện cho địa chỉ chứa chuỗi hằng.
2. **Theo dõi dữ liệu, không chỉ đọc format theo trực giác.** `input` chỉ nhận phần `%s`; prefix `DoYouEven` không nằm trong biến.
3. **Xét ngữ nghĩa đầy đủ của `scanf`.** Literal phía sau `%s` không tạo “delimiter” cho `%s`; `%s` không tự dừng trước `CTF`.
4. **Luôn xem giá trị trả về bị bỏ qua.** Chính việc không kiểm tra kết quả `scanf` biến một lần khớp format không hoàn chỉnh thành đường đi hợp lệ.
5. **Lưu ý an toàn bộ nhớ.** `input` chỉ có 32 byte nhưng format `%s` không có giới hạn độ rộng. Đây là lỗi tràn bộ đệm tiềm tàng, dù không cần khai thác để giải bài này.

## Kết luận

Đáp án/chuỗi nhập để chương trình in `Correct!` là **`DoYouEven_init`** (kèm Enter). Cơ chế cốt lõi không phải giải mã phức tạp mà là: trích `_init` qua `%s`, rồi tận dụng việc chương trình bỏ qua lỗi khớp `CTF` ở cuối định dạng.
