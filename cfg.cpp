#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <cmath>
#include <string>
#include <vector>
#include <array>
#include <bitset>
#include <optional>
#include <algorithm>
#include <random>
#include <chrono>
#include <functional>
#include <unordered_map>

#if defined(_WIN32) || defined(_WIN64)
    #define CFG_TOOLKIT_WINDOWS 1
    #include <windows.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#else
    #define CFG_TOOLKIT_WINDOWS 0
#endif

namespace cfg {
using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;
using addr_t = std::uintptr_t;

struct CFGConstants {
    static constexpr u32 PageShift = 12;
    static constexpr u32 ByteShift = 15;
    static constexpr u32 BitMask   = 0x7;
    static constexpr u64 PageSize  = 0x1000;
    static constexpr u64 PageMask  = 0xFFF;
    static constexpr u64 BytesPerBitmapByte = 1ull << ByteShift;
    static constexpr u64 BytesPerBitmapPage = PageSize * BytesPerBitmapByte;
    static_assert(BytesPerBitmapByte == 32768, "32 KB per byte");
    static_assert(BytesPerBitmapPage == 128ull * 1024 * 1024, "128 MB per page");
};

static std::string to_hex(u64 v, int width = 0) {
    char buf[32];
    if (width > 0) std::snprintf(buf, sizeof(buf), "0x%0*" PRIx64, width, v);
    else           std::snprintf(buf, sizeof(buf), "0x%" PRIx64, v);
    return std::string(buf);
}

static std::optional<u64> parse_hex(const std::string& s) {
    if (s.empty()) return std::nullopt;
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    char* end = nullptr;
    errno = 0;
    u64 v = std::strtoull(p, &end, 16);
    if (errno || end == p || *end != '\0') return std::nullopt;
    return v;
}


class Bitmap {
public:
    Bitmap() = default;
    explicit Bitmap(addr_t base, size_t bytes, u8 fill = 0)
        : base_(base), data_(bytes, fill) {}
    addr_t base() const { return base_; }
    size_t size() const { return data_.size(); }
    u8*    raw()        { return data_.data(); }
    const u8* raw() const { return data_.data(); }
    void resize(size_t bytes, u8 fill = 0) { data_.assign(bytes, fill); }
    static u64 page_index(addr_t a) { return (a >> CFGConstants::PageShift); }
    static u64 bit_index (addr_t a) { return (a >> CFGConstants::ByteShift) & CFGConstants::BitMask; }
    static u64 bitmap_byte_offset(addr_t a) { return page_index(a); }
    static addr_t bitmap_byte_address(addr_t image_base, addr_t bitmap_rva, addr_t target) {
        return image_base + bitmap_rva + bitmap_byte_offset(target);
    }

    bool test(addr_t a) const {
        u64 off = bitmap_byte_offset(a);
        if (off >= data_.size()) return false;
        u8 b = data_[off];
        return (b >> bit_index(a)) & 1u;
    }

    void set(addr_t a, bool v = true) {
        u64 off = bitmap_byte_offset(a);
        if (off >= data_.size()) return;
        u8 mask = u8(1u << bit_index(a));
        if (v) data_[off] |=  mask;
        else   data_[off] &= ~mask;
    }

    size_t count_set() const {
        size_t n = 0;
        for (u8 b : data_) n += (size_t)std::bitset<8>(b).count();
        return n;
    }

    double sparsity() const {
        size_t total = data_.size() * 8;
        if (!total) return 0.0;
        return 1.0 - double(count_set()) / double(total);
    }

    double entropy() const {
        if (data_.empty()) return 0.0;
        std::array<size_t, 256> hist{};
        for (u8 b : data_) hist[b]++;
        double H = 0.0, N = double(data_.size());
        for (size_t c : hist) {
            if (!c) continue;
            double p = double(c) / N;
            H -= p * std::log2(p);
        }
        return H;
    }

    struct RunStats { size_t runs; size_t longest_bits; addr_t longest_addr; };
    RunStats run_stats() const {
        RunStats s{0, 0, 0};
        size_t cur = 0;
        addr_t cur_start = 0;
        for (size_t i = 0; i < data_.size(); ++i) {
            u8 b = data_[i];
            for (int bit = 0; bit < 8; ++bit) {
                bool v = (b >> bit) & 1u;
                addr_t a = addr_t(i) << CFGConstants::PageShift;
                a += addr_t(bit) << CFGConstants::ByteShift;
                if (v) {
                    if (cur == 0) cur_start = a;
                    ++cur;
                } else if (cur) {
                    ++s.runs;
                    if (cur > s.longest_bits) { s.longest_bits = cur; s.longest_addr = cur_start; }
                    cur = 0;
                }
            }
        }
        if (cur) {
            ++s.runs;
            if (cur > s.longest_bits) { s.longest_bits = cur; s.longest_addr = cur_start; }
        }
        return s;
    }

private:
    addr_t base_ = 0;
    std::vector<u8> data_;
};

class ControlFlowGuard {
public:
    static constexpr addr_t DefaultBitmapRva = 0x1ff760;
    static constexpr addr_t DefaultImageBase = 0x140000000ull;
    ControlFlowGuard() = default;
    ControlFlowGuard(addr_t image_base, addr_t bitmap_rva, Bitmap* bitmap)
        : image_base_(image_base), bitmap_rva_(bitmap_rva), bitmap_(bitmap) {}
    addr_t image_base() const { return image_base_; }
    addr_t bitmap_rva() const { return bitmap_rva_; }
    addr_t bitmap_abs() const { return image_base_ + bitmap_rva_; }
    void set_image_base(addr_t b) { image_base_ = b; }
    void set_bitmap_rva(addr_t r) { bitmap_rva_ = r; }
    void set_bitmap(Bitmap* b)    { bitmap_ = b; }
    addr_t byte_address(addr_t target) const {
        return image_base_ + bitmap_rva_ + Bitmap::bitmap_byte_offset(target);
    }

    bool is_valid_target(addr_t target) const {
        if (!bitmap_) return false;
        return bitmap_->test(target);
    }

    bool is_valid_rva(addr_t rva) const {
        return is_valid_target(image_base_ + rva);
    }

    std::vector<addr_t> enumerate_targets(addr_t start, addr_t end) const {
        std::vector<addr_t> out;
        if (!bitmap_ || end <= start) return out;
        for (addr_t a = start; a < end; a += CFGConstants::BytesPerBitmapByte) {
            if (is_valid_target(a)) out.push_back(a);
        }
        return out;
    }

private:
    addr_t  image_base_ = DefaultImageBase;
    addr_t  bitmap_rva_ = DefaultBitmapRva;
    Bitmap* bitmap_     = nullptr;
};

namespace pe {

#pragma pack(push, 1)
struct DOSHeader {
    u16 e_magic;
    u8  _pad[58];
    u32 e_lfanew;
};
struct FileHeader {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
};
struct DataDirectory {
    u32 VirtualAddress;
    u32 Size;
};
struct OptionalHeader64 {
    u16 Magic;
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u64 SizeOfStackReserve;
    u64 SizeOfStackCommit;
    u64 SizeOfHeapReserve;
    u64 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};
struct OptionalHeader32 {
    u16 Magic;
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u32 BaseOfData;
    u32 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u32 SizeOfStackReserve;
    u32 SizeOfStackCommit;
    u32 SizeOfHeapReserve;
    u32 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};
struct SectionHeader {
    char Name[8];
    u32 VirtualSize;
    u32 VirtualAddress;
    u32 SizeOfRawData;
    u32 PointerToRawData;
    u32 PointerToRelocations;
    u32 PointerToLinenumbers;
    u16 NumberOfRelocations;
    u16 NumberOfLinenumbers;
    u32 Characteristics;
};
#pragma pack(pop)

struct LoadConfigInfo {
    bool     present = false;
    bool     cfg_enabled = false;
    u32      size = 0;
    u32      rva = 0;
    u64      guard_cf_check_ptr = 0;
    u64      guard_cf_dispatch_ptr = 0;
    u64      guard_cf_function_table = 0;
    u64      guard_cf_function_count = 0;
    u32      guard_flags = 0;

    bool has_cf_instrumentation() const { return (guard_flags & 0x100) != 0; }
    bool has_cf_function_table() const { return (guard_flags & 0x400) != 0; }
};

struct ParsedPE {
    bool     ok = false;
    bool     is64 = false;
    u64      image_base = 0;
    u32      size_of_image = 0;
    u32      entry_point = 0;
    u32      num_sections = 0;
    std::vector<u8> raw;
    DataDirectory load_config{};
    LoadConfigInfo load{};
    std::vector<SectionHeader> sections;
    u64      bitmap_rva = 0;
    bool     bitmap_rva_valid = false;
};

static u32 rva_to_offset(const std::vector<SectionHeader>& secs, u32 rva) {
    for (const auto& s : secs) {
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + std::max(s.VirtualSize, s.SizeOfRawData)) {
            return rva - s.VirtualAddress + s.PointerToRawData;
        }
    }
    return 0;
}

static bool parse_file(const std::string& path, ParsedPE& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n <= 0) { std::fclose(f); return false; }
    out.raw.resize(size_t(n));
    size_t got = std::fread(out.raw.data(), 1, out.raw.size(), f);
    std::fclose(f);
    if (got != out.raw.size()) return false;
    if (out.raw.size() < sizeof(DOSHeader)) return false;
    const auto* dos = reinterpret_cast<const DOSHeader*>(out.raw.data());
    if (dos->e_magic != 0x5A4D) return false;
    if (dos->e_lfanew + 4 + sizeof(FileHeader) > out.raw.size()) return false;
    const u8* nt = out.raw.data() + dos->e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) return false;
    const auto* fh = reinterpret_cast<const FileHeader*>(nt + 4);
    if (dos->e_lfanew + 4 + sizeof(FileHeader) + fh->SizeOfOptionalHeader > out.raw.size()) return false;
    const u8* opt = nt + 4 + sizeof(FileHeader);
    u16 magic = *reinterpret_cast<const u16*>(opt);
    out.is64 = (magic == 0x20b);
    out.num_sections = fh->NumberOfSections;
    const DataDirectory* dd = nullptr;
    u32 num_dd = 0;
    if (out.is64) {
        if (fh->SizeOfOptionalHeader < sizeof(OptionalHeader64)) return false;
        const auto* oh = reinterpret_cast<const OptionalHeader64*>(opt);
        out.image_base = oh->ImageBase;
        out.size_of_image = oh->SizeOfImage;
        out.entry_point = oh->AddressOfEntryPoint;
        num_dd = oh->NumberOfRvaAndSizes;
        dd = oh->DataDirectory;
    } else {
        if (fh->SizeOfOptionalHeader < sizeof(OptionalHeader32)) return false;
        const auto* oh = reinterpret_cast<const OptionalHeader32*>(opt);
        out.image_base = oh->ImageBase;
        out.size_of_image = oh->SizeOfImage;
        out.entry_point = oh->AddressOfEntryPoint;
        num_dd = oh->NumberOfRvaAndSizes;
        dd = oh->DataDirectory;
    }

    if (num_dd > 10) out.load_config = dd[10];

    const u8* sec_start = opt + fh->SizeOfOptionalHeader;
    if (sec_start + fh->NumberOfSections * sizeof(SectionHeader) > out.raw.data() + out.raw.size())
        return false;

    out.sections.resize(fh->NumberOfSections);
    std::memcpy(out.sections.data(), sec_start, fh->NumberOfSections * sizeof(SectionHeader));

    if (out.load_config.VirtualAddress && out.load_config.Size >= 0x70) {
        u32 off = rva_to_offset(out.sections, out.load_config.VirtualAddress);
        if (off && off + out.load_config.Size <= out.raw.size()) {
            const u8* lc = out.raw.data() + off;
            out.load.present = true;
            out.load.size = out.load_config.Size;
            out.load.rva = out.load_config.VirtualAddress;
            if (out.load_config.Size >= 0x90 + 4) {
                std::memcpy(&out.load.guard_cf_check_ptr,      lc + 0x70, 8);
                std::memcpy(&out.load.guard_cf_dispatch_ptr,   lc + 0x78, 8);
                std::memcpy(&out.load.guard_cf_function_table, lc + 0x80, 8);
                std::memcpy(&out.load.guard_cf_function_count, lc + 0x88, 8);
                std::memcpy(&out.load.guard_flags,             lc + 0x90, 4);
            }
            out.load.cfg_enabled = (out.load.guard_flags & 0x100) != 0 ||
                                   (out.load.guard_flags & 0x400) != 0;
        }
    }

    out.bitmap_rva_valid = false;
    out.bitmap_rva = 0x1ff760;
    out.bitmap_rva_valid = out.load.present;
    out.ok = true;
    return true;
}

}

#if CFG_TOOLKIT_WINDOWS
namespace live {

struct ModuleInfo {
    std::string name;
    addr_t base = 0;
    size_t size = 0;
};

static std::optional<DWORD> find_pid_by_name(const std::string& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::nullopt;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    std::optional<DWORD> found;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name.c_str()) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static std::vector<ModuleInfo> enum_modules(DWORD pid) {
    std::vector<ModuleInfo> mods;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return mods;
    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.name = me.szModule;
            mi.base = reinterpret_cast<addr_t>(me.modBaseAddr);
            mi.size = me.modBaseSize;
            mods.push_back(std::move(mi));
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

static bool read_remote(HANDLE h, addr_t addr, void* buf, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf, n, &got) && got == n;
}

static std::optional<Bitmap> snapshot_bitmap(DWORD pid, addr_t bitmap_addr, size_t bitmap_size) {
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return std::nullopt;
    Bitmap bm(bitmap_addr, bitmap_size);
    bool ok = read_remote(h, bitmap_addr, bm.raw(), bitmap_size);
    CloseHandle(h);
    if (!ok) return std::nullopt;
    return bm;
}

}
#endif

namespace analysis {

struct TargetStats {
    size_t count = 0;
    addr_t min_addr = 0;
    addr_t max_addr = 0;
    double density = 0.0;
    addr_t longest_run_start = 0;
    size_t longest_run_bits = 0;
    size_t longest_run_bytes = 0;
};

static TargetStats compute(const ControlFlowGuard& cfg, addr_t start, addr_t end) {
    TargetStats s{};
    if (end <= start) return s;
    s.min_addr = start;
    s.max_addr = end;
    addr_t first = 0, last = 0;
    size_t run = 0;
    for (addr_t a = start; a < end; a += CFGConstants::BytesPerBitmapByte) {
        if (cfg.is_valid_target(a)) {
            if (s.count == 0) first = a;
            last = a;
            ++s.count;
            ++run;
            if (run > s.longest_run_bits) {
                s.longest_run_bits = run;
                s.longest_run_bytes = run * CFGConstants::BytesPerBitmapByte;
                s.longest_run_start = a - (run - 1) * CFGConstants::BytesPerBitmapByte;
            }
        } else {
            run = 0;
        }
    }
    if (s.count) {
        s.min_addr = first;
        s.max_addr = last;
        double span = double(last - first) + CFGConstants::BytesPerBitmapByte;
        s.density = double(s.count) / span;
    }
    return s;
}

struct GadgetRun {
    addr_t start;
    addr_t end;
    size_t targets;
};

static std::vector<GadgetRun> find_runs(const ControlFlowGuard& cfg,
                                        addr_t start, addr_t end,
                                        size_t min_run_bytes) {
    std::vector<GadgetRun> out;
    addr_t run_start = 0;
    size_t run_targets = 0;
    auto flush = [&](addr_t stop) {
        if (run_targets && (stop - run_start) >= min_run_bytes) {
            out.push_back({run_start, stop, run_targets});
        }
        run_start = 0;
        run_targets = 0;
    };
    for (addr_t a = start; a < end; a += CFGConstants::BytesPerBitmapByte) {
        if (cfg.is_valid_target(a)) {
            if (!run_targets) run_start = a;
            ++run_targets;
        } else {
            flush(a);
        }
    }
    flush(end);
    return out;
}

static std::array<size_t, 256> byte_histogram(const Bitmap& bm) {
    std::array<size_t, 256> h{};
    for (u8 b : std::vector<u8>(bm.raw(), bm.raw() + bm.size())) h[b]++;
    return h;
}

}

namespace synth {

static Bitmap generate(addr_t base, size_t bytes, double rate,
                       std::mt19937_64& rng, size_t cluster_count = 0,
                       size_t cluster_size = 32) {
    Bitmap bm(base, bytes, 0);
    std::uniform_real_distribution<double> ur(0.0, 1.0);
    for (size_t i = 0; i < bytes; ++i) {
        u8 v = 0;
        for (int bit = 0; bit < 8; ++bit) {
            if (ur(rng) < rate) v |= u8(1u << bit);
        }
        bm.raw()[i] = v;
    }
    std::uniform_int_distribution<size_t> pick(0, bytes ? bytes - 1 : 0);
    for (size_t c = 0; c < cluster_count && bytes; ++c) {
        size_t start = pick(rng);
        for (size_t k = 0; k < cluster_size && start + k < bytes; ++k) {
            bm.raw()[start + k] = 0xFF;
        }
    }
    return bm;
}

}

static void print_banner() {
    std::puts("cfg_toolkit - Control Flow Guard analysis\n"
              "  models Windows CFG bitmap lookup + PE load config\n"
              "  type 'help' for commands\n");
}

static void cmd_help() {
    std::puts(
        "commands:\n"
        "  help                                - this text\n"
        "  consts                              - print CFG constants\n"
        "  lookup <image_base> <bitmap_rva> <addr>\n"
        "                                      - compute page/bit/byte for addr\n"
        "  synth [bytes] [rate] [clusters]     - generate & analyze a synthetic bitmap\n"
        "  pe <path>                           - parse PE, dump load config\n"
        "  pe_bitmap <path>                    - parse PE, report bitmap heuristics\n"
        "  runs <bytes> <rate> <min_run_bytes> - find valid-target runs in synthetic bitmap\n"
        "  entropy <bytes> <rate>              - bitmap entropy / sparsity\n"
        "  fuzz [iters]                        - randomized self-test\n"
        "  live <pid> <bitmap_addr> <bytes>    - (Windows) snapshot bitmap from live process\n"
        "  live_name <name> <bytes>            - (Windows) find pid by name, try bitmap at default rva\n"
        "  quit / exit\n");
}

static void cmd_consts() {
    using C = CFGConstants;
    std::printf("PageShift            = %u\n", C::PageShift);
    std::printf("ByteShift            = %u\n", C::ByteShift);
    std::printf("BitMask              = 0x%x\n", C::BitMask);
    std::printf("PageSize             = 0x%" PRIx64 "\n", C::PageSize);
    std::printf("BytesPerBitmapByte   = 0x%" PRIx64 " (%llu bytes)\n",
                C::BytesPerBitmapByte, (unsigned long long)C::BytesPerBitmapByte);
    std::printf("BytesPerBitmapPage   = 0x%" PRIx64 " (%llu bytes)\n",
                C::BytesPerBitmapPage, (unsigned long long)C::BytesPerBitmapPage);
    std::printf("DefaultBitmapRva     = 0x%llx\n",
                (unsigned long long)ControlFlowGuard::DefaultBitmapRva);
    std::printf("DefaultImageBase     = 0x%llx\n",
                (unsigned long long)ControlFlowGuard::DefaultImageBase);
}

static void cmd_lookup(const std::vector<std::string>& args) {
    if (args.size() < 4) { std::puts("usage: lookup <image_base> <bitmap_rva> <addr>"); return; }
    auto ib  = parse_hex(args[1]);
    auto br  = parse_hex(args[2]);
    auto ad  = parse_hex(args[3]);
    if (!ib || !br || !ad) { std::puts("bad hex"); return; }
    addr_t page = Bitmap::page_index(*ad);
    addr_t bit  = Bitmap::bit_index(*ad);
    addr_t byte_off = Bitmap::bitmap_byte_offset(*ad);
    addr_t byte_abs = ControlFlowGuard(*ib, *br, nullptr).byte_address(*ad);
    std::printf("target           = %s\n", to_hex(*ad).c_str());
    std::printf("page index       = %s  (>> %u)\n", to_hex(page).c_str(), CFGConstants::PageShift);
    std::printf("bit index        = %u   (>> %u & 0x%x)\n",
                (unsigned)bit, CFGConstants::ByteShift, CFGConstants::BitMask);
    std::printf("bitmap byte off  = %s\n", to_hex(byte_off).c_str());
    std::printf("bitmap byte abs  = %s  (image_base + bitmap_rva + byte_off)\n",
                to_hex(byte_abs).c_str());
    std::printf("coverage of byte = [%s, %s)\n",
                to_hex(*ad & ~(CFGConstants::BytesPerBitmapByte - 1)).c_str(),
                to_hex(((*ad & ~(CFGConstants::BytesPerBitmapByte - 1)) +
                        CFGConstants::BytesPerBitmapByte)).c_str());
}

static void cmd_synth(const std::vector<std::string>& args) {
    size_t bytes = 1 << 16;
    double rate = 0.25;
    size_t clusters = 4;
    if (args.size() >= 2) bytes    = (size_t)std::strtoull(args[1].c_str(), nullptr, 0);
    if (args.size() >= 3) rate     = std::atof(args[2].c_str());
    if (args.size() >= 4) clusters = (size_t)std::strtoull(args[3].c_str(), nullptr, 0);
    std::mt19937_64 rng(std::random_device{}());
    Bitmap bm = synth::generate(0, bytes, rate, rng, clusters, 64);
    auto rs = bm.run_stats();
    std::printf("synthetic bitmap: %zu bytes, %zu bits, %zu set (%.2f%%)\n",
                bm.size(), bm.size() * 8, bm.count_set(),
                100.0 * double(bm.count_set()) / double(bm.size() * 8));
    std::printf("  entropy            = %.4f bits/byte\n", bm.entropy());
    std::printf("  sparsity           = %.4f\n", bm.sparsity());
    std::printf("  runs               = %zu\n", rs.runs);
    std::printf("  longest run        = %zu bits (%zu bytes), starting at %s\n",
                rs.longest_bits,
                rs.longest_bits * (size_t)CFGConstants::BytesPerBitmapByte,
                to_hex(rs.longest_addr).c_str());
}

static void cmd_pe(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::puts("usage: pe <path>"); return; }
    pe::ParsedPE p;
    if (!pe::parse_file(args[1], p)) { std::printf("failed to parse '%s'\n", args[1].c_str()); return; }
    std::printf("PE file: %s\n", args[1].c_str());
    std::printf("  arch             = %s\n", p.is64 ? "x64" : "x86");
    std::printf("  image base       = %s\n", to_hex(p.image_base).c_str());
    std::printf("  size of image    = %s (%u bytes)\n", to_hex(p.size_of_image).c_str(), p.size_of_image);
    std::printf("  entry point RVA  = %s\n", to_hex(p.entry_point).c_str());
    std::printf("  sections         = %u\n", p.num_sections);
    if (!p.load.present) {
        std::puts("  load config      = <not present>");
        return;
    }
    std::printf("  load config RVA  = %s (size 0x%x)\n",
                to_hex(p.load.rva).c_str(), p.load.size);
    std::printf("  GuardFlags       = 0x%08x\n", p.load.guard_flags);
    std::printf("    CF instrumented= %s\n", p.load.has_cf_instrumentation() ? "yes" : "no");
    std::printf("    CF function tbl= %s\n", p.load.has_cf_function_table() ? "yes" : "no");
    std::printf("  GuardCFCheckFn   = %s\n", to_hex(p.load.guard_cf_check_ptr).c_str());
    std::printf("  GuardCFDispatch  = %s\n", to_hex(p.load.guard_cf_dispatch_ptr).c_str());
    std::printf("  GuardCFFnTable   = %s (count=%llu)\n",
                to_hex(p.load.guard_cf_function_table).c_str(),
                (unsigned long long)p.load.guard_cf_function_count);
    std::printf("  sections:\n");
    for (const auto& s : p.sections) {
        char name[9] = {0};
        std::memcpy(name, s.Name, 8);
        std::printf("    %-8s VA=%s VS=%s RAW=%s\n",
                    name,
                    to_hex(s.VirtualAddress).c_str(),
                    to_hex(s.VirtualSize).c_str(),
                    to_hex(s.SizeOfRawData).c_str());
    }
}

static void cmd_pe_bitmap(const std::vector<std::string>& args) {
    if (args.size() < 2) { std::puts("usage: pe_bitmap <path>"); return; }
    pe::ParsedPE p;
    if (!pe::parse_file(args[1], p)) { std::printf("failed to parse '%s'\n", args[1].c_str()); return; }
    std::puts("bitmap heuristics:");
    std::printf("  image base        = %s\n", to_hex(p.image_base).c_str());
    std::printf("  default bitmap rva= %s\n", to_hex(p.bitmap_rva).c_str());
    std::printf("  bitmap abs (est)  = %s\n", to_hex(p.image_base + p.bitmap_rva).c_str());
    std::printf("  bitmap rva valid? = %s\n", p.bitmap_rva_valid ? "yes (load config present)" : "unknown");
    if (p.load.present) {
        std::printf("  GuardCFFnTable    = %s (symbol table, not bitmap)\n",
                    to_hex(p.load.guard_cf_function_table).c_str());
        std::printf("  GuardCFFnCount    = %llu\n",
                    (unsigned long long)p.load.guard_cf_function_count);
    }
    std::puts("  NOTE: the actual bitmap is allocated by the loader at runtime;");
    std::puts("        the RVA is not stored in the PE file. Use 'live' on a");
    std::puts("        running process to read the real bitmap.");
}

static void cmd_runs(const std::vector<std::string>& args) {
    if (args.size() < 4) { std::puts("usage: runs <bytes> <rate> <min_run_bytes>"); return; }
    size_t bytes = (size_t)std::strtoull(args[1].c_str(), nullptr, 0);
    double rate  = std::atof(args[2].c_str());
    size_t minr  = (size_t)std::strtoull(args[3].c_str(), nullptr, 0);
    std::mt19937_64 rng(1234);
    Bitmap bm = synth::generate(0, bytes, rate, rng, 8, 64);
    ControlFlowGuard cfg(0, 0, &bm);
    addr_t start = 0;
    addr_t end   = addr_t(bytes) << CFGConstants::PageShift;
    auto runs = analysis::find_runs(cfg, start, end, minr);
    std::printf("found %zu runs >= %zu bytes\n", runs.size(), minr);
    for (size_t i = 0; i < runs.size() && i < 40; ++i) {
        const auto& r = runs[i];
        std::printf("  [%2zu] %s .. %s  (%zu targets, %zu bytes)\n",
                    i, to_hex(r.start).c_str(), to_hex(r.end).c_str(),
                    r.targets, (size_t)(r.end - r.start));
    }
    if (runs.size() > 40) std::printf("  ... (%zu more)\n", runs.size() - 40);
}

static void cmd_entropy(const std::vector<std::string>& args) {
    size_t bytes = 1 << 20;
    double rate  = 0.25;
    if (args.size() >= 2) bytes = (size_t)std::strtoull(args[1].c_str(), nullptr, 0);
    if (args.size() >= 3) rate  = std::atof(args[2].c_str());
    std::mt19937_64 rng(42);
    Bitmap bm = synth::generate(0, bytes, rate, rng, 0, 0);
    auto hist = analysis::byte_histogram(bm);
    std::printf("bitmap: %zu bytes, entropy %.4f bits/byte, sparsity %.4f\n",
                bm.size(), bm.entropy(), bm.sparsity());
    std::printf("top byte values:\n");
    std::vector<std::pair<size_t, int>> v;
    for (int i = 0; i < 256; ++i) v.emplace_back(hist[i], i);
    std::sort(v.rbegin(), v.rend());
    for (int i = 0; i < 8 && i < (int)v.size(); ++i) {
        std::printf("  0x%02x : %zu\n", v[i].second, v[i].first);
    }
}

static int run_selftest(int iters) {
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<u64> addr_dist(0, 0x7fffffffffffull);
    std::uniform_int_distribution<size_t> size_dist(64, 4096);
    int failures = 0;
    for (int i = 0; i < iters; ++i) {
        addr_t base = addr_dist(rng) & ~addr_t(0xFFF);
        size_t bytes = size_dist(rng);
        Bitmap bm(base, bytes, 0);
        std::uniform_int_distribution<size_t> byte_dist(0, bytes - 1);
        int nset = (int)(rng() % (bytes * 4 + 1));
        for (int k = 0; k < nset; ++k) {
            u8& b = bm.raw()[byte_dist(rng)];
            b |= u8(1u << (rng() & 7));
        }

        for (size_t k = 0; k < 64; ++k) {
            addr_t a = base + (addr_t)(rng() % (bytes * CFGConstants::BytesPerBitmapByte));
            bool v = bm.test(a);
            u64 off = Bitmap::bitmap_byte_offset(a - base);
            if (off >= bm.size()) continue;
            u8 byte = bm.raw()[off];
            bool expected = (byte >> Bitmap::bit_index(a - base)) & 1u;
            if (v != expected) {
                ++failures;
                std::printf("  MISMATCH at iter %d addr %s: test=%d expected=%d\n",
                            i, to_hex(a).c_str(), (int)v, (int)expected);
            }
        }

        auto rs = bm.run_stats();
        if (rs.runs == 0 && bm.count_set() != 0) {
            ++failures;
            std::printf("  RUN_STATS mismatch at iter %d\n", i);
        }
    }
    std::printf("fuzz: %d iterations, %d failures\n", iters, failures);
    return failures;
}

#if CFG_TOOLKIT_WINDOWS
static void cmd_live(const std::vector<std::string>& args) {
    if (args.size() < 4) { std::puts("usage: live <pid> <bitmap_addr> <bytes>"); return; }
    DWORD pid = (DWORD)std::strtoul(args[1].c_str(), nullptr, 0);
    auto ba   = parse_hex(args[2]);
    size_t nb = (size_t)std::strtoull(args[3].c_str(), nullptr, 0);
    if (!ba) { std::puts("bad bitmap address"); return; }
    auto bm = live::snapshot_bitmap(pid, *ba, nb);
    if (!bm) { std::printf("failed to read bitmap from pid %u\n", pid); return; }
    std::printf("snapshot from pid %u: %zu bytes at %s\n",
                pid, bm->size(), to_hex(*ba).c_str());
    std::printf("  set bits   = %zu\n", bm->count_set());
    std::printf("  entropy    = %.4f bits/byte\n", bm->entropy());
    std::printf("  sparsity   = %.4f\n", bm->sparsity());
    auto rs = bm->run_stats();
    std::printf("  runs       = %zu\n", rs.runs);
    std::printf("  longest    = %zu bits starting at %s\n",
                rs.longest_bits, to_hex(rs.longest_addr).c_str());
}

static void cmd_live_name(const std::vector<std::string>& args) {
    if (args.size() < 3) { std::puts("usage: live_name <name> <bytes>"); return; }
    auto pid = live::find_pid_by_name(args[1]);
    if (!pid) { std::printf("process '%s' not found\n", args[1].c_str()); return; }
    size_t nb = (size_t)std::strtoull(args[2].c_str(), nullptr, 0);
    auto mods = live::enum_modules(*pid);
    if (mods.empty()) { std::puts("no modules"); return; }
    std::printf("pid %u modules:\n", *pid);
    for (auto& m : mods) {
        std::printf("  %-16s base=%s size=%s\n",
                    m.name.c_str(), to_hex(m.base).c_str(), to_hex(m.size).c_str());
    }
    const auto& main = mods[0];
    addr_t guess = main.base + ControlFlowGuard::DefaultBitmapRva;
    std::printf("trying bitmap at %s (main base + 0x%llx)\n",
                to_hex(guess).c_str(),
                (unsigned long long)ControlFlowGuard::DefaultBitmapRva);
    auto bm = live::snapshot_bitmap(*pid, guess, nb);
    if (!bm) { std::puts("read failed (bitmap rva likely differs for this binary)"); return; }
    std::printf("  set bits = %zu, entropy = %.4f\n",
                bm->count_set(), bm->entropy());
}
#else
static void cmd_live(const std::vector<std::string>&) {
    std::puts("live commands are only available on Windows builds.");
}
static void cmd_live_name(const std::vector<std::string>&) {
    std::puts("live commands are only available on Windows builds.");
}
#endif

static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quote = false;
    for (char c : line) {
        if (c == '"') { in_quote = !in_quote; continue; }
        if (!in_quote && (c == ' ' || c == '\t')) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
        const std::string& cmd = args[0];
        if (cmd == "lookup")       cmd_lookup(args);
        else if (cmd == "consts")  cmd_consts();
        else if (cmd == "synth")   cmd_synth(args);
        else if (cmd == "pe")      cmd_pe(args);
        else if (cmd == "pe_bitmap") cmd_pe_bitmap(args);
        else if (cmd == "runs")    cmd_runs(args);
        else if (cmd == "entropy") cmd_entropy(args);
        else if (cmd == "fuzz") {
            int it = (args.size() >= 2) ? std::atoi(args[1].c_str()) : 1000;
            return run_selftest(it) ? 1 : 0;
        }
        else if (cmd == "live")      cmd_live(args);
        else if (cmd == "live_name") cmd_live_name(args);
        else if (cmd == "help" || cmd == "-h" || cmd == "--help") cmd_help();
        else { std::printf("unknown command: %s\n", cmd.c_str()); return 2; }
        return 0;
    }

    print_banner();
    std::string line;
    while (true) {
        std::fputs("cfg> ", stdout);
        std::fflush(stdout);
        if (!std::getline(std::cin, line)) break;
        auto args = tokenize(line);
        if (args.empty()) continue;
        const std::string& cmd = args[0];
        if (cmd == "quit" || cmd == "exit" || cmd == "q") break;
        else if (cmd == "help")     cmd_help();
        else if (cmd == "consts")   cmd_consts();
        else if (cmd == "lookup")   cmd_lookup(args);
        else if (cmd == "synth")    cmd_synth(args);
        else if (cmd == "pe")       cmd_pe(args);
        else if (cmd == "pe_bitmap")cmd_pe_bitmap(args);
        else if (cmd == "runs")     cmd_runs(args);
        else if (cmd == "entropy")  cmd_entropy(args);
        else if (cmd == "fuzz") {
            int it = (args.size() >= 2) ? std::atoi(args[1].c_str()) : 1000;
            run_selftest(it);
        }
        else if (cmd == "live")      cmd_live(args);
        else if (cmd == "live_name") cmd_live_name(args);
        else std::printf("unknown command: %s\n", cmd.c_str());
    }
    return 0;
}

}

int main(int argc, char** argv) {
    return cfg::main(argc, argv);
}
