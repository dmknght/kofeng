# libkofantarc — plan

**Tệp tạm.** Xoá khi ba mục tiêu chính đã xong. Nó tồn tại để giữ ngữ cảnh
giữa các phiên làm việc, không phải để thành tài liệu.

Tên: Antarctica — Nam Cực, vì chim cánh cụt. Prefix `kofa_`.

---

## 0. Vị trí trong cây

```
libkofeng/      lấy bytes -> nói đó là gì
libkofgrille/   Windows: hoạt động của máy -> records   (kofw_)
libkofantarc/   Linux:   hoạt động của máy -> records   (kofa_)   <- ĐÂY
libkoforbit/    từ vựng chung (kofevt) + cache (koffridge)
```

Luật kế thừa nguyên vẹn từ kofgrille, **không được phá**:

- Không `#include` gì từ `libkofeng/` trong tầng thu thập. Thư viện này thu
  thập, nó không phán xét.
- Từ vựng lấy từ `libkoforbit/kofevt/kofevt.h`, **không định nghĩa lại**.
  `KOF_OS_LINUX`, `KOF_PLAT_LINUX` và cột Linux của `enum kof_evt_loc`
  (`systemd`, `cron`, `.bashrc`, `/etc/ld.so.preload`, `authorized_keys`,
  `/etc/shadow`, `/lib/modules`, `/var/www`, `/etc/hosts`) đã có sẵn.
  kofgrille đã từng mirror enum một buổi chiều rồi phải gộp lại — đừng lặp lại.
- Mọi thứ không kiểm tra được thì **báo cáo**, không im lặng. Cờ
  `KOFA_RGF_UNEXAMINED` và `kofa_health` tồn tại vì lý do đó.

---

## 1. Ba mục tiêu

| # | Mục tiêu | Trạng thái |
|---|---|---|
| 1 | Scan process (snapshot) | **ĐANG LÀM** |
| 2 | Real-time scan qua fanotify, **notify-only** | sau |
| 3 | Rootkit / boot fingerprint | optional, sau cùng |

Đã duyệt:
- fanotify **không block** ở v1. Phần block thiết kế riêng về sau.
- eBPF optional, chỉ cân nhắc khi làm rootkit detection (mục tiêu 3).

---

## 2. SỐ ĐO — căn cứ của mọi quyết định dưới đây

Đo ngày 2026-09-12, máy này, user thường (34 process đọc được, 10 182 VMA).
Đo lại khi chạy với quyền root sẽ ra nhiều process hơn nhưng **hình dạng**
không đổi.

### 2.0 PHÁT HIỆN BỔ SUNG: PROT_NONE là "reserved" của Linux

Tôi đã viết ở §5 rằng Linux không phân biệt reserved/committed. **Sai.** Nó có
phân biệt, và cách viết là map một dải **không quyền gì cả** (`---p`).

Đo: **7 vùng `---p`, mỗi vùng ~1.3 TB**, mỗi Chromium process một vùng, tổng
**9.1 TB** address space trên một desktop bình thường. Lượt quét đầu tiên cộng
cả chúng vào và báo **10.5 TB resident trên máy 16 GB**.

=> `KOFA_USE_UNKNOWN`, lọc bỏ mặc định (`KOFA_MW_RESERVED` để bật lại).

### 2.1 Phân bố vùng nhớ

| loại | VMA | ảo | **resident thật** |
|---|---:|---:|---:|
| exec file-backed (module) | 1 076 | 2 736 MB | quét FILE, cache |
| **exec ANON (unbacked code)** | **43** | **3 777 MB** | **≈ 12 MB** |
| rw anon (heap) | 2 478 | 19 346 MB | **1 867 MB** |
| mapping `(deleted)` | 94 | | |
| `memfd` | 8 | | |

`cat maps` = 1 ms (1343 VMA). `cat smaps` = 7 ms. `smaps_rollup` = 5 ms.

### 2.2 Ảo KHÁC resident tới hai bậc độ lớn

Vùng RWX 512 MB của V8 (Electron/VS Code/node), 5 process thật:

```
pid 748  code   512.0 MB ảo ->   4.76 MB thật (0.93%), 11 run
pid 575  code   512.0 MB ảo ->   0.15 MB thật (0.03%), 13 run
pid 383  code   512.0 MB ảo ->   1.92 MB thật (0.38%),  2 run
pid  22  code   512.0 MB ảo ->   3.52 MB thật (0.69%),  5 run
pid 660  claude  64.0 MB ảo ->   1.61 MB thật (2.51%), 30 run
```

### 2.3 pagemap thắng đọc mù 37x–887x

```
pid 748: pagemap 0.4 ms | readv mù 80.7 ms | readv có pagemap 0.5 ms -> 148x
pid 575: pagemap 0.5 ms | readv mù 80.8 ms | readv có pagemap 0.1 ms -> 887x
pid 383: pagemap 0.5 ms | readv mù 81.1 ms | readv có pagemap 0.3 ms -> 308x
pid  22: pagemap 0.5 ms | readv mù 78.8 ms | readv có pagemap 0.7 ms -> 120x
pid 660: pagemap 0.1 ms | readv mù  8.5 ms | readv có pagemap 0.2 ms ->  37x
```

### 2.4 Ba sự thật đã kiểm chứng bằng chương trình riêng

1. **`/proc/<pid>/pagemap` đọc được với user thường**; bit 63 = PRESENT đúng.
   PFN bị zero hoá khi không có `CAP_SYS_ADMIN` — ta không cần PFN.
2. ~~**`process_vm_readv` KHÔNG fault-in trang chưa tồn tại.**~~ **SAI — ĐÃ SỬA.**
   Kết luận cũ dựa trên RSS và chỉ đúng một nửa. Đo lại bằng pagemap:

   ```
   sau khi child GHI 4 trang trong 64MB :   512 present, RSS 2996 KB
   sau khi scanner ĐỌC MÙ 64 MB         : 16384 present, RSS 2996 KB
   ```

   Đọc một trang anon chưa chạm làm kernel map **SHARED ZERO PAGE**: PTE được
   tạo nên pagemap báo PRESENT vĩnh viễn, còn zero page không được tính vào
   RSS nên RSS đứng yên. Ba hệ quả:

   - **PRESENT không có nghĩa là CÓ NỘI DUNG.**
   - **`rss` không thể lấy từ pagemap.** Phải lấy từ `smaps` (`Rss:` loại trừ
     zero page). pagemap nói **Ở ĐÂU**, smaps nói **BAO NHIÊU**. Chi phí:
     maps 1 ms vs smaps 7 ms cho process 1343 vùng.
   - **Đọc mù một lần là phá hỏng pagemap vĩnh viễn** cho chính scanner và mọi
     công cụ khác. Xác nhận thực nghiệm: đúng 3 trong 5 process mà benchmark
     `real.c` từng đọc mù (575, 383, 660) sau đó báo 100% present; ba process
     chưa từng bị đọc (381, 151, 135) vẫn khớp smaps chính xác. Cờ
     `KOFA_RGF_ZERO_HEAVY` bắt đúng ba cái đầu, không bắt nhầm cái nào.

   => `KOFA_MW_PAGEMAP` bật mặc định, và tuỳ chọn tắt nó được ghi là **PHÁ
   HOẠI**, không phải chỉ "chậm hơn".
3. **THP làm pagemap thành CẬN TRÊN, không phải số chính xác.** Test: chạm 100
   trang rải rác trong 512 MB -> RSS 205 MB, `AnonHugePages: 204800 kB`, độ
   hạt 2 MB. Trên process thật (không rải rác nhân tạo) sai số này nhỏ.

### 2.5 Phân bố kích thước heap resident

| nhóm | VMA | MB | % bytes |
|---|---:|---:|---:|
| <64KB | 1 223 | 17.6 | 0.9% |
| 64–256KB | 267 | 41.1 | 2.2% |
| 256KB–1MB | 207 | 114.9 | 6.2% |
| 1–4MB | 92 | 188.6 | 10.1% |
| 4–16MB | 66 | 519.7 | 27.8% |
| 16–64MB | 18 | 461.3 | 24.7% |
| >64MB | 4 | 524.4 | 28.1% |

**90.4% số VMA nằm dưới 1 MB nhưng chỉ chiếm 9.3% số byte.**
Cap 1 MB/VMA: giữ 173.6 MB thay vì 1867.5 MB (10.8x rẻ hơn), giữ 1697/1877 vùng.

---

## 3. THUẬT TOÁN — 5 tầng

```
T0  LIỆT KÊ      /proc/<pid>/maps             1 ms/proc, 0 syscall mỗi vùng
T1  PHÂN LOẠI    (không đọc byte nào)         quyết định vùng nào đáng nhìn
T2  THU HẸP      /proc/<pid>/pagemap          chỉ vùng qua T1 và > ngưỡng
T3  ĐỌC          process_vm_readv theo run    chỉ trang PRESENT
T4  GIAO ENGINE  kof_scan_bytes + as_view     theo định dạng thật
```

### T1 — bảng quyết định (chi phí bằng không)

| vùng | hành động |
|---|---|
| file-backed, exec, path thường | **quét FILE**, dedup qua `koffridge` |
| file-backed, `(deleted)` | **đọc process** — file không còn để quét |
| file-backed, `/memfd:` | **đọc process** — fileless Linux, ưu tiên cao nhất |
| **anon + exec** | **đọc process** — lý do memory scan tồn tại |
| anon + rw, không exec | **heap — xem §4** |
| `[stack]` `[vdso]` `[vvar]` `[vsyscall]` | bỏ qua |

### T2/T3 — cận phải áp VÀ phải báo cáo khi chạm

```c
uint64_t max_region;       /* vùng lớn hơn -> KOFA_RGF_UNEXAMINED, không đọc */
uint64_t max_bytes_proc;   /* tổng byte đọc ra khỏi MỘT process              */
uint64_t max_bytes_sweep;  /* tổng byte cho cả lượt quét                     */
uint64_t pagemap_min;      /* vùng nhỏ hơn thì đọc thẳng, rẻ hơn 1 pread     */
```

`pagemap_min` đề xuất 1 MB — **CHƯA ĐO điểm hoà vốn thật**, cần đo.

### Ước tính một lượt quét đầy đủ  [Inference — suy từ §2, chưa chạy cả lượt]

34 proc x 1 ms maps + 43 x 0.5 ms pagemap + 12 MB readv ≈ **<100 ms thu thập**.
Cách làm mù: 3 777 MB và hàng chục giây.

---

## 4. HEAP — quyết định và lý do

### 4.1 Tắt hoàn toàn có đúng không? — KHÔNG, nhưng "bật hết" còn sai hơn

Chi phí: heap resident 1 867 MB so với code set 12 MB. **Gấp 155 lần.**
Chỉ riêng con số này đã đủ để heap không thể bật mặc định trong một lượt quét
định kỳ.

### 4.2 Các case bị MISS khi tắt heap — thật, và phải ghi lại

| # | Case | Có thật không |
|---|---|---|
| 1 | Payload đã giải mã, **chưa** `mprotect(RX)` | Miss chỉ trong cửa sổ đua. Sau mprotect -> `KOFA_USE_CODE`, bắt được. Không phải miss thật với lượt quét. |
| 2 | **Config/C2 đã giải mã** — domain list, key, campaign id | **MISS THẬT.** Trên đĩa đã mã hoá; bản rõ chỉ tồn tại trong heap. Đây là thứ commodity bot Linux (Mirai và họ hàng) luôn giữ. |
| 3 | **Payload thông dịch** — python/perl/php nhận qua socket rồi `exec()` | **MISS THẬT.** Không bao giờ exec ở tầng trang, không bao giờ chạm đĩa. |
| 4 | LD_PRELOAD `.so` | Không miss — file-backed, bắt được. |

Case 2 và 3 đều là **dữ liệu, không phải mã**. Đúng trực giác "Linux map data
vào memory hơi đặc biệt" — vì trên Linux, fileless thường là *dữ liệu được
thông dịch*, không phải *mã được map*.

### 4.3 Signature file có dùng được cho memory không?

Có, cho các case trên. Config và script là **chuỗi phẳng** — không có
relocation, không có loader layout, nên chữ ký viết cho file khớp nguyên vẹn.
Vấn đề của heap **không phải là khớp được hay không, mà là quy trách nhiệm**:
một match trong heap nói rằng process đã *chạm* vào bytes đó, không nói rằng
process *là* thứ đó.

Khác với module đã map: ở đó signature file có thể trượt vì loader đã sửa
bytes (relocation, IAT) — đó là lý do `pe_unmap.h` tồn tại bên Windows. Với
heap thì không có vấn đề đó.

### 4.4 Quyết định: KHÔNG phải công tắc on/off, mà bốn tầng

```
T1  CAP THEO KÍCH THƯỚC, không phải tắt hẳn.
    Cap 1 MB/VMA: giữ 90.4% số vùng, trả 173 MB thay vì 1867 MB.
    Config đã giải mã có kích thước KB -> nằm trong tập được giữ.
    JS heap của trình duyệt (nguồn của cả chi phí lẫn phần lớn FP) bị loại.
    -> Lấy lại case 2 và 3 với 9.3% chi phí.

T2  CHỈ QUÉT KHI CÓ TRIGGER, không bao giờ theo timer.
    wproc.h: "a scan is worth far more when something triggered it than
    when a timer did." Trigger tự sinh trong cùng lượt quét: quét heap của
    process mà tầng code ĐÃ tìm thấy gì đó, hoặc process mang cờ cấu trúc
    (UNBACKED / DELETED / MEMFD). Khi fanotify chạy thì có thêm trigger ngoài.

T3  KHỬ TIẾNG VỌNG HAI LƯỢT  <- giải quyết ĐÚNG case YARA đã gặp
    Lượt 1: quét thứ CÓ ĐỊNH DANH ỔN ĐỊNH (file sau module, vùng exec)
            -> thu tập origins = { tên finding -> pid gốc }
    Lượt 2: quét heap
            finding X trong heap pid P:
              X thuoc origins va origins[X] != P  -> TIẾNG VỌNG
                 -> hạ cấp, ghi nguồn, KHÔNG báo là phát hiện riêng
              nguoc lai -> giữ nguyên

    Case đã gặp: CLI cha chạy tool test có string; tool khớp X ở file/image
    (lượt 1); heap của CLI cha cũng khớp X (lượt 2) -> origins[X] = pid tool
    != pid cha -> đánh dấu KOFA_FF_ECHO, báo "đã chạm X, nguồn pid N", không
    báo "cha nhiễm X".

    Giới hạn  [Inference]: nếu malware giữ payload trong heap của chính nó VÀ
    cùng payload đó cũng nằm hợp pháp trên đĩa chỗ khác, tầng này hạ cấp một
    phát hiện thật. Nên nó phải là HẠ CẤP CÓ GHI NGUỒN, không phải LOẠI BỎ.

T4  MATCH TRONG HEAP KHÔNG BAO GIỜ TỰ NÓ THÀNH VERDICT.
    Tối đa KOF_LEVEL_SUSPECT kèm cờ provenance, kể cả khi origins rỗng.
    Lý do: một MISS trong heap không phải bằng chứng gì (buffer đã free trước
    khi ta nhìn), nên một HIT cũng không được mang sức nặng tương xứng.
```

**QUYẾT ĐỊNH 2026-09-12: TẮT HEAP HOÀN TOÀN Ở v1.** Rủi ro nhiều, công sức
nhiều, giá trị ít. `KOFA_MW_HEAP` đã tắt mặc định và `max_heap_region` đã có
sẵn — để nguyên làm **room cải tiến về sau**, không phát triển thêm bây giờ.

T1 (cap) và T4 (không thành verdict) đã nằm trong libkofantarc. **T2 và T3 cần
kofmemscan chạy hai lượt** -> đụng file dùng chung, để sau, và chỉ khi heap
được bật lại.

---

## 5. Khác biệt so với `kofw_region` và lý do

| | Windows | Linux |
|---|---|---|
| `kind` (kernel nói) | `MEM_PRIVATE/MAPPED/IMAGE` | **KHÔNG TỒN TẠI.** Chỉ bỏ đi, không giả vờ có thẩm quyền kernel. |
| `alloc_base` | có | **KHÔNG TỒN TẠI.** Gom run bằng inode + liền kề, trong .c. |
| `size` | = committed | **là lời nói dối 100x.** Phải thêm `rss`. |
| đọc bộ nhớ | `ReadProcessMemory` | `process_vm_readv` |
| định danh proc | `(pid, create_time)` | `(pid, starttime)` = `/proc/pid/stat` trường 22 |

Cờ riêng của Linux, giá trị ngang `KOFW_RGF_UNBACKED`:
`KOFA_RGF_DELETED`, `KOFA_RGF_MEMFD`, `KOFA_RGF_VOLATILE`, `KOFA_RGF_SPARSE`.

`KOFA_RGF_WX` (rwxp) **tự nó không phải finding** — V8 dùng nó trên mọi máy có
Electron. 7 vùng rwxp 512 MB trên máy này đều là node.

---

## 6. Tránh xung đột với phiên đang sửa libkofgrille

| Làm ngay — không đụng file nào của phiên kia | |
|---|---|
| `libkofantarc/kofantarc.h` | từ vựng + API công khai |
| `libkofantarc/aproc.c` | `/proc` walk, phân loại |
| `libkofantarc/apagemap.c` | T2 tách riêng để test độc lập |
| `libkofantarc/atest.c` | tool tạm, chạy được mà không cần kofmemscan |
| `tests/unit/antarc_*.c` | test với process tự sinh |

| Phải đợi | Lý do |
|---|---|
| `kofwatcher/kofmemscan.c` | cần `#ifdef` chọn `kofw_pmem` vs `kofa_pmem` |
| `Makefile` | thêm target, dễ conflict, để cuối |
| `wchan.c` -> backend POSIX | phiên kia có thể đang sửa |

---

## 7. Thứ tự

- [x] 1. `kofantarc.h` + `aproc.h` — từ vựng, số đo §2 làm căn cứ
- [x] 2. `apagemap.c` — T2, test độc lập được
- [x] 3. `aproc.c` — T0/T1/T3, plist + pmem
- [x] 4. `atest.c` — chạy thật, **đã tìm ra 3 lỗi thật**
- [x] 4b. `atest_unit.c` — 10 case, sạch dưới `-Wpedantic -Wshadow` và
        ASan/UBSan/LeakSan trên cả lượt quét có heap
- [ ] 5. Đo điểm hoà vốn `pagemap_min` (đang để 1 MB, chưa có căn cứ)
- [ ] 6. Ghép `kofmemscan` + Makefile  — **sau khi phiên kia xong**
- [ ] 7. Heap T2/T3 (trigger + khử tiếng vọng)
- [ ] 8. Mục tiêu 2: fanotify notify-only
- [ ] 9. Mục tiêu 3: rootkit/boot (optional)

---

## 7b. KẾT QUẢ CHẠY THẬT (2026-09-12, sau khi sửa 3 lỗi)

```
processes walked   : 34  (3 refused)
regions reported   : 6280  (4060 filtered, 0 unexamined)
  virtual          : 7519.5 MB
  RESIDENT         : 1185.0 MB  over 6280 measured regions
unbacked code      : 11 regions, 2753.1 MB virt -> 45.35 MB res
deleted / memfd    : 86 / 8
rwx / sparse       : 15 / 157
walk took 74 ms
```

**11 vùng code thật, không phải 43.** Con số 43 đo bằng awk ban đầu đếm cả
`[vdso]` (inode 0, r-xp) của mọi process. Trình phân loại xử lý `[...]` trước
nên không mắc — đây là lý do thứ tự các phép thử trong `a_classify` là cả hàm.

**2753 MB ảo -> 45 MB thật**, tỉ lệ 60x, đúng tinh thần §2.2.

Bật heap: +2511 vùng, +2380 MB resident, 241 vùng chạm cap 1 MB. Heap đắt hơn
code **53 lần** — cùng kết luận §4.1 dù con số khác (đo lúc khác, tải khác).

Chi phí: mặc định 74 ms, `--exec` 72 ms, `--heap` 87 ms (34 process).

### Ba lỗi mà việc CHẠY THẬT tìm ra (không lỗi nào lộ ra lúc đọc code)

1. `rss = size` cho vùng không đo pagemap, rồi **cộng dồn** -> báo 10.5 TB
   resident. Sửa: `KOFA_RGF_RSS_MEASURED` + hai cột thống kê tách biệt.
2. `---p` 1.3 TB không bị lọc (§2.0).
3. `rss` lấy từ pagemap bị nhiễm zero page (§2.4 mục 2).

Lỗi 1 và 3 cùng một hình dạng: **một cận trên bị dùng như một phép đo.**

### Một cái bẫy API đã lộ ra

`kofa_pmem_option.want == 0` mới lấy `KOFA_MW_DEFAULT`. Caller đặt **một** cờ
sẽ âm thầm **mất hết** cờ mặc định còn lại — chính atest dính, và triệu chứng
là `rss` sai chứ không phải lỗi biên dịch. Giữ nguyên vì kofgrille cũng vậy,
nhưng cần cân nhắc.

## 7c. SIGNATURE REUSE — ĐO 2026-09-12

### Câu hỏi: chữ ký file dùng lại được cho memory không?

**Được, 100%, và không cần viết `elf_unmap`.**

So byte vùng file-backed trong memory với chính file (`mem[base+k]` vs
`file[file_off+k]` — ELF map tuyến tính trong một PT_LOAD nên quan hệ này đúng
theo định nghĩa):

```
pid 22  (Chromium, 592 vùng): EXEC  42 852 352 B ->       0 khác  (0.0000%)
                              RO    68 917 994 B -> 3 751 346 khác (5.44%)
                              WRITE  2 864 096 B ->   399 511 khác (13.95%)
pid bash (57 vùng)          : EXEC   3 067 904 B ->       0 khác  (0.0000%)
```

**Vùng EXEC khác 0 byte.** Vì x86-64 PIE dùng RIP-relative: không relocation
động nào rơi vào `.text`, tất cả rơi vào `.got`, `.got.plt`, `.data.rel.ro`.
Đó chính là lý do trang text chia sẻ được giữa các process.

Ngược hẳn với PE: base relocation ghi đè `.text`, nên `pe_unmap.h` **bắt buộc
phải có**. Ở Linux **không có việc gì cho nó làm**.

### Còn region partition (rule scoped CODE/DATA)?

`kof_elf_rebuild` trong `libkofeng/kofunpack/elf_rebuild.h` **đã có sẵn** và
nhận đúng interface ta có: read callback theo địa chỉ ảo — tức `kofa_pmem_read`.
Chạy thật trên process sống, không sửa dòng nào:

```
/usr/bin/sleep : dựng 49 312 B  (file 54 456 B),  1.04% khác, đầu tiên 0x28
/usr/bin/bash  : dựng 1 117 888 B (file 1 117 888 B), 3.40% khác, đầu tiên 0x103951
```

- bash: **độ dài dựng lại BẰNG ĐÚNG file gốc**
- `sleep` khác đầu tiên tại `0x28` = `e_shoff` trong `Elf64_Ehdr` — section
  header table không nằm trong PT_LOAD nào nên không dựng lại được
- 5 144 byte thiếu của `sleep` = section headers + `.symtab`/`.strtab`
- 3.4% của bash nằm hết trong segment ghi được (0x103951 đã qua text)

| phần | so với file |
|---|---|
| `.text` / segment exec | **giống hệt 100%** |
| ELF header | khác `e_shoff` |
| `.data`, `.got` | khác — relocation + ghi lúc chạy |
| section headers, `.symtab` | **không có** (không thuộc PT_LOAD) |

=> Rule scoped **CODE chạy hoàn hảo**. Rule cần **tên section** thì không
(không có section table). Partition theo program header
(HEADERS/CODE/DATA/NOLOAD) chạy được.

### Phái sinh miễn phí: KOFA_RGF_DIRTY_CODE

Vì code giống hệt file, **bất kỳ** trang exec nào private-dirty đều là có người
ghi vào code. `Private_Dirty` đã nằm trong smaps ta đang đọc -> **chi phí bằng 0**.

Baseline đo toàn máy: **0 kB trên 1079 vùng exec file-backed.** 0 FP.
Test xác nhận nó bắn đúng khi child tự vá 1 byte `.text` của mình, và không
bắn ở vùng nào khác. Đây là `KOFW_RGF_DIRTY_IMAGE` của Linux, rẻ hơn nhiều.

### Packed ELF lúc chạy

Từ phần reverse UPX đã có trong cây (`libkofemu/kofemu.c:1394`,
`kofemu.h:182`): stub UPX gọi `readlink("/proc/self/exe")`, mở và **map file**
chứ không mang dữ liệu trong memory, rồi giải nén vào vùng nó tự `mmap`.
`elf_rebuild.h` ghi kết quả đo: *"sáu vùng nhớ riêng biệt quay về... segment
nằm ở địa chỉ ảo của chúng, rải rác theo những gì stub tình cờ map"*.

Nên một ELF đã pack lúc chạy cho ra:
- mapping file-backed của file **đã pack** (khớp file pack, không khớp payload)
- **vùng anon exec chứa payload ĐÃ GIẢI NÉN** -> `KOFA_USE_CODE` + `UNBACKED`

Khác Windows: packer Windows hay giải nén **tại chỗ** vào memory của image gốc
(file-backed, hiện ra dạng dirty page). Packer Linux thường mmap vùng anon mới.
Tức payload giải nén rơi **đúng vào tập mà walk đang nhắm**, và
`kof_elf_rebuild` biến nó thành file cho cả engine parse.

**[Unverified]** Chưa chạy được binary packed thật: máy không có `upx`,
`woody-woodpacker` cần `clang` (chưa cài). Trên đây suy từ phần reverse stub
UPX của chính cây này, không phải từ một lần chạy trực tiếp. Cần xác minh khi
có packer build được.

## 7d. Ý mới 2026-09-12 — đã làm và chưa làm

### Đã làm (nằm gọn trong libkofantarc)

| cờ | ý nghĩa | chi phí |
|---|---|---|
| `KOFA_PF_EXE_UNLINKED` | exe `(deleted)` **và** path không còn -> tự xoá sau khi chạy | 1 `access()`, chỉ cho process có cờ deleted |
| `KOFA_PF_FAKE_KTHREAD` | comm dạng `[x]`, **không** có `PF_KTHREAD`, **và** exe resolve ra path tuyệt đối | 0 — đã đọc `stat` rồi |
| `KOFA_PF_STDIO_SOCKET` | fd 0/1/2 là socket | 3 `readlink` |
| `cmdline` | `/proc/pid/cmdline`, NUL -> space | 1 open + 1 read |
| `n_fd` / `n_socket` | đếm fd và fd socket | 1 readdir + n readlinkat |

Chi phí toàn lượt: 74 ms -> **83 ms** (34 process).

**`FAKE_KTHREAD` phát hiện được MIỄN PHÍ và chính xác theo cấu trúc**, vì walk
này phân loại kernel thread bằng `PF_KTHREAD` (trường 9 của `stat` — bit của
chính kernel) chứ **không bao giờ** bằng tên. Nên bất đồng giữa tên process tự
đặt và điều kernel nói là rơi ra sẵn, và không có cách viết tên nào né được.

### Reverse shell — CÙNG MỘT SOCKET, không phải "cả hai đều là socket"

Phiên bản đầu của tôi ("fd 0/1/2 bất kỳ cái nào là socket") có **8 FP** trên
desktop sạch. Sai. Điều kiện đúng là stdin và stdout trỏ tới **CÙNG một
socket**, so bằng inode kernel ghi trong link.

Đo trên máy này:

```
8 cái hợp lệ (LSP, extension host, agent):
   stdin socket:[14376315]  stdout socket:[14376317]
   stdin socket:[14382089]  stdout socket:[14382091]
   stdin socket:[14362326]  stdout socket:[14362328]   ... luôn là CẶP KHÁC NHAU

reverse shell `bash -i >& /dev/tcp/...`:
   stdin socket:[14899490]  stdout socket:[14899490]   <- CÙNG INODE
```

`>&` dup **một** socket sang cả hai đầu vì chỉ có **một** kết nối. Process được
spawn bình thường có **socketpair** — hai object, hai inode, mỗi chiều một cái.

Quét toàn máy `stdin == stdout == socket`: **đúng 1 process, là reverse shell.**
8 FP -> **0**, đổi lấy một phép so chuỗi.

| cờ | ý nghĩa | FP trên desktop sạch |
|---|---|---|
| `KOFA_PF_STDIO_SOCKET` | bất kỳ fd 0/1/2 là socket | **8** — gần như vô dụng |
| `KOFA_PF_STDIO_SAME_SOCKET` | **fd 0 và fd 1** cùng một socket | **0** |
| `KOFA_PF_STDIO_ONLY` | **mọi** fd đều là cùng object với fd 0 | **0** |
| `KOFA_PF_SHELL` | exe là sh/bash/dash/zsh/ksh/ash/busybox/fish/csh/tcsh/mksh | nhiều, chỉ là nửa thứ hai |

### KHÔNG ĐƯỢC nới ra cả bảng fd — đo được 4 FP ngay

Cám dỗ hiển nhiên là "hai fd bất kỳ dùng chung socket". Sai trên phần mềm
thường, đo trên desktop này, không có gì độc đang chạy:

```
claude  fd 1 va fd 7 cung mot socket; fd 2 va fd 8 cung mot socket  (x3 process)
code    fd 10 va fd 30 cung mot socket
```

Đó là chương trình giữ thêm handle cho stdout/stderr của chính nó — bình thường.
Cũng không được dùng fd 1 vs fd 2: đó là hình dạng của mọi `2>&1` trong mọi script.
**Neo vào đúng fd 0 và fd 1.**

### "Chỉ 3 fd" — đúng ý, sai con số

`bash -i >& /dev/tcp/...` có **4 fd, không phải 3**:

```
fd 0 -> socket:[14908548]
fd 1 -> socket:[14908548]
fd 2 -> socket:[14908548]
fd 255 -> socket:[14908548]     <- ban sao terminal cho job control cua bash
```

dash/sh có 3, bash có 4, shell khác có thể 5 — một con số ở đây là mã hoá "rule
này viết cho shell nào". `KOFA_PF_STDIO_ONLY` viết thành **thuộc tính**: *mọi*
fd đều trỏ tới cùng object với fd 0. Đúng với tất cả, và tự động **không** bắt
netcat/ncat/socat vì relay giữ ít nhất listening socket + accepted socket — fd
của nó không phải một object. Đó là chủ ý: tool relay là hình dạng khác, cần
luật khác.

`fd_stdin` / `fd_stdout` / `fd_stderr` được trả về **nguyên văn** bên cạnh cờ,
theo cùng lý do `kofa_region` giữ `path` cạnh phân loại: cờ là quyết định có
thể sai, chuỗi thô là thứ duy nhất cho phép kiểm chứng.

### Heur này chỉ cover COMMON CASE, không phải coverage

Ghi rõ trong header: không bắt shell được nối bằng dup2 sang fd rời; không bắt
netcat/ncat/socat (relay, fd không phải một object); không bắt cái đã nâng lên
pty; không bắt payload re-exec rồi sắp xếp lại fd; không bắt socket nhận qua
SCM_RIGHTS. **Một lượt quét im lặng nghĩa là hình dạng này vắng mặt, không có
nghĩa là sạch.**

Và kể cả khi bắn cũng không phải verdict: service kiểu inetd được đưa một socket
làm stdio có đúng hình dạng này và đang làm đúng việc của nó.

### `KOFA_PF_STDIO_SAME_TTY` — đã thu, nhưng CẨN THẬN

Clause thứ hai trong rule cũ (`fd 0 == fd 1 == fd 2 == /dev/pts/N`) đã được thu
thành cờ riêng, **nhưng một mình nó không phải tín hiệu**: đó chính xác là hình
dạng của **mọi** interactive shell trong **mọi** cửa sổ terminal — đó là định
nghĩa của terminal.

Nó bắt reverse shell **đã được nâng lên pty** (`python -c 'import pty;
pty.spawn("/bin/bash")'`). Thứ phân biệt hai trường hợp **không nằm ở fd**: đó
là **AI GIỮ ĐẦU KIA**. Login thật thì terminal emulator hoặc sshd giữ master
side; shell đã nâng cấp thì là thứ attacker chạy. Muốn dùng clause này phải đi
duyệt fd của process khác — việc của caller, không phải của cờ này.

**Cần bạn xác nhận**: rule cũ có thêm điều kiện nào cho nhánh pts không (parent
process? không có controlling terminal?), hay nó vốn chỉ dùng khi đã có tín
hiệu khác?

### Chưa làm — heur so runtime với file trên đĩa (packed?)

Ý: vùng anon exec chứa payload đã giải nén -> so với file trên đĩa xem file có
dấu hiệu packed không. Đây là heur **hai nguồn**, cần cả snapshot lẫn engine,
nên nó KHÔNG thuộc libkofantarc (thư viện này không được include `kofeng.h`).

Chỗ đúng là **kofmemscan / kofmontrace**, nơi đã có cả hai. Hình dạng:

```
vùng anon exec, ELF hợp lệ, kích thước đáng kể
  + file sau /proc/pid/exe quét ra "packed" (entropy cao / unpacker nhận ra)
  + nội dung vùng KHÁC nội dung file
  -> "chương trình này giải nén chính nó vào memory"
```

Windows cần cùng heur này nhưng ngược chiều: packer Windows hay giải nén **tại
chỗ**, nên dấu hiệu là `KOFW_RGF_DIRTY_IMAGE` trên vùng image, không phải vùng
anon. Cùng một câu hỏi, hai hình dạng, và đó là lý do nó phải là hai luật.

## 8. Câu hỏi còn mở

1. `pagemap_min` = 1 MB là phỏng đoán. Cần đo điểm hoà vốn giữa
   `pread(pagemap)` và đọc mù.
2. Cap heap 1 MB/VMA — có nên cho chỉnh theo process không (browser vs daemon)?
3. THP làm pagemap thành cận trên. Có cần lọc trang zero sau khi đọc không,
   hay để engine tự bỏ qua?
4. Khi chạy root, số process tăng ~10x. Cần đo lại §2 với root trước khi
   chốt `max_bytes_sweep`.
