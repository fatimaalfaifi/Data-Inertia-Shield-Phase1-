#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory> // ✅ added for unique_ptr

namespace fs = std::filesystem;

// ===================== Settings =====================
// Paths
static const std::wstring HIGH_DIR = L"C:\\DIS\\High";
static const std::wstring MEDIUM_DIR = L"C:\\DIS\\Medium";
static const std::wstring LOW_DIR = L"C:\\DIS\\Low";

// Burst rule (High delete burst)
static const int      DELETE_THRESHOLD = 2;      // allow 2, trigger on 3rd within window
static const ULONGLONG WINDOW_MS = 1000;

// Freeze behavior
static const bool FREEZE_ON_ALERT = true; // set High files Read-Only

// Optional PID attribution via Sysmon (no kernel code, but requires Sysmon installed)
// If false -> PID will be "N/A"
static const bool USE_SYSMON_PID = false;
// =====================================================

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}
static bool StartsWithI(const std::wstring& s, const std::wstring& prefix) {
    auto ls = ToLower(s);
    auto lp = ToLower(prefix);
    return ls.rfind(lp, 0) == 0;
}
static std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (a.back() == L'\\') return a + b;
    return a + L"\\" + b;
}

// ----------------------------- Domain Types -----------------------------
enum class Tier { High, Medium, Low, Unknown };
static const wchar_t* TierName(Tier t) {
    switch (t) {
    case Tier::High: return L"High";
    case Tier::Medium: return L"Medium";
    case Tier::Low: return L"Low";
    default: return L"Unknown";
    }
}
enum class FileAction { Added, Removed, Modified, RenamedOld, RenamedNew, Unknown };
static const wchar_t* ActionName(FileAction a) {
    switch (a) {
    case FileAction::Added: return L"Added";
    case FileAction::Removed: return L"Removed";
    case FileAction::Modified: return L"Modified";
    case FileAction::RenamedOld: return L"RenamedOld";
    case FileAction::RenamedNew: return L"RenamedNew";
    default: return L"Unknown";
    }
}
struct FileEvent {
    FileAction action{ FileAction::Unknown };
    std::wstring directory;     // watched root
    std::wstring relativePath;  // from ReadDirectoryChangesW
    std::wstring fullPath;      // directory + relativePath
    Tier tier{ Tier::Unknown };
    ULONGLONG tsMs{ 0 };        // ms since boot
};

// ----------------------------- Thread-safe Queue -----------------------------
template <typename T>
class BlockingQueue {
public:
    void Push(T item) {
        { std::lock_guard<std::mutex> lk(m_); q_.push(std::move(item)); }
        cv_.notify_one();
    }
    bool Pop(T& out) {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&] { return stop_ || !q_.empty(); });
        if (stop_ && q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop();
        return true;
    }
    void Stop() {
        { std::lock_guard<std::mutex> lk(m_); stop_ = true; }
        cv_.notify_all();
    }
private:
    std::mutex m_;
    std::condition_variable cv_;
    std::queue<T> q_;
    bool stop_{ false };
};

// ----------------------------- Tier Mapper -----------------------------
struct TierRule { Tier tier; std::wstring rootDir; };
class TierMapper {
public:
    explicit TierMapper(std::vector<TierRule> rules) : rules_(std::move(rules)) {}
    Tier MapPathToTier(const std::wstring& fullPath) const {
        Tier best = Tier::Unknown;
        size_t bestLen = 0;
        for (const auto& r : rules_) {
            if (r.rootDir.empty()) continue;
            if (StartsWithI(fullPath, r.rootDir) && r.rootDir.size() > bestLen) {
                bestLen = r.rootDir.size();
                best = r.tier;
            }
        }
        return best;
    }
private:
    std::vector<TierRule> rules_;
};

// ----------------------------- Event Filter -----------------------------
class EventFilter {
public:
    bool Allow(const FileEvent& ev) const {
        if (ev.action == FileAction::Unknown) return false;
        if (ev.relativePath.empty()) return false;

        // reduce noise
        const auto p = ToLower(ev.fullPath);
        if (EndsWith(p, L".tmp") || EndsWith(p, L".temp") || EndsWith(p, L".log")) return false;
        if (Contains(p, L"\\appdata\\local\\temp\\")) return false;
        if (Contains(p, L"\\windows\\temp\\")) return false;
        if (Contains(p, L"\\$recycle.bin\\")) return false;
        if (ContainsFileNamePrefix(p, L"~$")) return false;

        // keep key actions
        return (ev.action == FileAction::Removed ||
            ev.action == FileAction::Modified ||
            ev.action == FileAction::RenamedOld ||
            ev.action == FileAction::RenamedNew);
    }
private:
    static bool EndsWith(const std::wstring& s, const std::wstring& suf) {
        if (s.size() < suf.size()) return false;
        return s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
    }
    static bool Contains(const std::wstring& s, const std::wstring& sub) {
        return s.find(sub) != std::wstring::npos;
    }
    static bool ContainsFileNamePrefix(const std::wstring& full, const std::wstring& prefix) {
        auto pos = full.find_last_of(L"\\/");
        std::wstring name = (pos == std::wstring::npos) ? full : full.substr(pos + 1);
        return name.rfind(prefix, 0) == 0;
    }
};

// ----------------------------- Freeze (Read-Only) -----------------------------
static void FreezeHighReadOnly(const std::wstring& highRoot) {
    try {
        for (auto& p : fs::recursive_directory_iterator(highRoot)) {
            if (!p.is_regular_file()) continue;
            std::wstring fp = p.path().wstring();
            DWORD attrs = GetFileAttributesW(fp.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) continue;
            if ((attrs & FILE_ATTRIBUTE_READONLY) == 0) {
                SetFileAttributesW(fp.c_str(), attrs | FILE_ATTRIBUTE_READONLY);
            }
        }
    }
    catch (...) {
        // best-effort
    }
}

// ✅ ADDED: Unfreeze (remove Read-Only)
static void UnfreezeHigh(const std::wstring& highRoot) {
    try {
        for (auto& p : fs::recursive_directory_iterator(highRoot)) {
            if (!p.is_regular_file()) continue;
            std::wstring fp = p.path().wstring();
            DWORD attrs = GetFileAttributesW(fp.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) continue;

            if (attrs & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesW(fp.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
            }
        }
    }
    catch (...) {
        // best-effort
    }
}

// ----------------------------- PID attribution (Sysmon OPTIONAL) -----------------------------
struct Attribution {
    DWORD pid{ 0 };
    std::wstring image;
    std::wstring user;
    bool ok{ false };
};
static Attribution GetAttributionFromSysmonBestEffort(const std::wstring& /*targetPath*/) {
    return {};
}

// ----------------------------- Directory Watcher -----------------------------
class DirectoryWatcher {
public:
    DirectoryWatcher(std::wstring dir, bool recursive, BlockingQueue<FileEvent>& outQ, const TierMapper& mapper)
        : dir_(std::move(dir)), recursive_(recursive), outQ_(outQ), mapper_(mapper) {
    }

    bool Start() {
        stop_ = false;
        hDir_ = CreateFileW(
            dir_.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );
        if (hDir_ == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[Watcher] Failed CreateFileW for " << dir_ << L", err=" << GetLastError() << L"\n";
            return false;
        }
        th_ = std::thread([this] { Run(); });
        return true;
    }

    void Stop() {
        stop_ = true;
        if (hDir_ != INVALID_HANDLE_VALUE) CancelIoEx(hDir_, nullptr);
        if (th_.joinable()) th_.join();
        if (hDir_ != INVALID_HANDLE_VALUE) CloseHandle(hDir_);
        hDir_ = INVALID_HANDLE_VALUE;
    }
    ~DirectoryWatcher() { Stop(); }

private:
    void Run() {
        std::vector<BYTE> buffer(64 * 1024);
        while (!stop_) {
            DWORD bytesReturned = 0;
            BOOL ok = ReadDirectoryChangesW(
                hDir_,
                buffer.data(),
                (DWORD)buffer.size(),
                recursive_ ? TRUE : FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                nullptr, nullptr
            );
            if (!ok) {
                DWORD err = GetLastError();
                if (stop_) break;
                std::wcerr << L"[Watcher] ReadDirectoryChangesW failed for " << dir_ << L", err=" << err << L"\n";
                Sleep(200);
                continue;
            }
            if (bytesReturned == 0) continue;
            ParseAndEmit(buffer.data());
        }
    }

    void ParseAndEmit(const BYTE* data) {
        const BYTE* ptr = data;
        while (true) {
            auto info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(ptr);
            std::wstring rel(info->FileName, info->FileNameLength / sizeof(WCHAR));
            FileAction act = TranslateAction(info->Action);

            FileEvent ev;
            ev.action = act;
            ev.directory = dir_;
            ev.relativePath = rel;
            ev.fullPath = JoinPath(dir_, rel);
            ev.tier = mapper_.MapPathToTier(ev.fullPath);
            ev.tsMs = GetTickCount64();

            outQ_.Push(std::move(ev));

            if (info->NextEntryOffset == 0) break;
            ptr += info->NextEntryOffset;
        }
    }

    static FileAction TranslateAction(DWORD a) {
        switch (a) {
        case FILE_ACTION_ADDED: return FileAction::Added;
        case FILE_ACTION_REMOVED: return FileAction::Removed;
        case FILE_ACTION_MODIFIED: return FileAction::Modified;
        case FILE_ACTION_RENAMED_OLD_NAME: return FileAction::RenamedOld;
        case FILE_ACTION_RENAMED_NEW_NAME: return FileAction::RenamedNew;
        default: return FileAction::Unknown;
        }
    }

private:
    std::wstring dir_;
    bool recursive_{ true };
    BlockingQueue<FileEvent>& outQ_;
    const TierMapper& mapper_;
    std::atomic<bool> stop_{ false };
    HANDLE hDir_{ INVALID_HANDLE_VALUE };
    std::thread th_;
};

// ----------------------------- Main -----------------------------
int wmain() {
    std::wcout << L"=== DIS User-Mode Containment (No Kernel) ===\n";

    // Ensure folders exist (optional)
    fs::create_directories(HIGH_DIR);
    fs::create_directories(MEDIUM_DIR);
    fs::create_directories(LOW_DIR);

    std::vector<TierRule> rules = {
        { Tier::High,   HIGH_DIR },
        { Tier::Medium, MEDIUM_DIR },
        { Tier::Low,    LOW_DIR }
    };

    TierMapper mapper(rules);
    EventFilter filter;
    BlockingQueue<FileEvent> q;

    std::vector<std::unique_ptr<DirectoryWatcher>> watchers;
    for (const auto& r : rules) {
        auto w = std::make_unique<DirectoryWatcher>(r.rootDir, true, q, mapper);
        if (!w->Start()) return 1;
        watchers.push_back(std::move(w));
        std::wcout << L"[OK] Watching: " << r.rootDir << L"\n";
    }

    // Burst tracking for High deletes
    ULONGLONG windowStart = GetTickCount64();
    int highDeleteCount = 0;
    std::vector<std::wstring> lastDeleted; // keep last N deleted paths
    const size_t MAX_EVIDENCE = 25;

    std::wcout << L"\nMonitoring... (Ctrl+C to stop)\n\n";

    while (true) {
        FileEvent ev;
        if (!q.Pop(ev)) break;
        if (!filter.Allow(ev)) continue;

        // Keep evidence for deleted paths
        if (ev.action == FileAction::Removed && ev.tier == Tier::High) {
            lastDeleted.push_back(ev.fullPath);
            if (lastDeleted.size() > MAX_EVIDENCE) lastDeleted.erase(lastDeleted.begin());
        }

        // Print normal events (optional)
        std::wcout << L"[" << TierName(ev.tier) << L"] " << ActionName(ev.action)
            << L" | " << ev.fullPath << L"\n";

        // Rolling window
        ULONGLONG now = GetTickCount64();
        if (now - windowStart > WINDOW_MS) {
            windowStart = now;
            highDeleteCount = 0;
        }

        // Burst rule: High delete
        if (ev.tier == Tier::High && ev.action == FileAction::Removed) {
            highDeleteCount++;

            if (highDeleteCount > DELETE_THRESHOLD) {
                // Attribution (PID) - optional via Sysmon
                Attribution a;
                if (USE_SYSMON_PID) a = GetAttributionFromSysmonBestEffort(ev.fullPath);

                // ALERT
                std::wcout << L"\n==============================\n";
                std::wcout << L"[ALERT] Possible Wiper/Delete Burst!\n";
                std::wcout << L"Tier: High\n";
                std::wcout << L"Deletes within " << WINDOW_MS << L"ms: " << highDeleteCount << L"\n";
                std::wcout << L"Time (ms since boot): " << now << L"\n";

                if (a.ok) {
                    std::wcout << L"PID: " << a.pid << L"\n";
                    std::wcout << L"Image: " << a.image << L"\n";
                    if (!a.user.empty()) std::wcout << L"User: " << a.user << L"\n";
                }
                else {
                    std::wcout << L"PID: N/A (ReadDirectoryChangesW has no PID; enable Sysmon attribution)\n";
                }

                std::wcout << L"Evidence (last deleted files):\n";
                for (const auto& p : lastDeleted) std::wcout << L"  - " << p << L"\n";
                std::wcout << L"Action: " << (FREEZE_ON_ALERT ? L"Freeze High (Read-Only)" : L"Alert only") << L"\n";
                std::wcout << L"==============================\n\n";

                // Freeze High (best effort)
                if (FREEZE_ON_ALERT) {
                    FreezeHighReadOnly(HIGH_DIR);
                }

                // Also write JSON incident (simple)
                try {
                    std::ofstream jf("incident.json", std::ios::trunc);
                    jf << "{\n";
                    jf << "  \"alert\": \"Possible Wiper/Delete Burst\",\n";
                    jf << "  \"tier\": \"High\",\n";
                    jf << "  \"window_ms\": " << (unsigned long long)WINDOW_MS << ",\n";
                    jf << "  \"delete_count\": " << highDeleteCount << ",\n";
                    jf << "  \"pid\": " << (a.ok ? std::to_string(a.pid) : std::string("null")) << ",\n";
                    jf << "  \"action\": \"" << (FREEZE_ON_ALERT ? "freeze_readonly" : "alert_only") << "\",\n";
                    jf << "  \"evidence\": [\n";
                    for (size_t i = 0; i < lastDeleted.size(); i++) {
                        std::wstring wp = lastDeleted[i];
                        std::string sp(wp.begin(), wp.end());
                        jf << "    \"" << sp << "\"" << (i + 1 < lastDeleted.size() ? "," : "") << "\n";
                    }
                    jf << "  ]\n";
                    jf << "}\n";
                }
                catch (...) {}

                // ✅ ADDED: Ask admin if they want to restore/unfreeze
                std::wcout << L"\nSystem is in PROTECTION mode.\n";
                std::wcout << L"Do you want to restore High tier to NORMAL mode? (y/n): ";

                wchar_t choice;
                std::wcin >> choice;

                if (choice == L'y' || choice == L'Y') {
                    std::wcout << L"\nRestoring High tier...\n";
                    UnfreezeHigh(HIGH_DIR);
                    std::wcout << L"[OK] High tier restored to NORMAL mode.\n\n";
                }
                else {
                    std::wcout << L"High tier remains PROTECTED.\n\n";
                }

                // Reset counter after alert to avoid spamming
                highDeleteCount = 0;
                lastDeleted.clear();
                windowStart = GetTickCount64(); // ✅ restart window after decision
            }
        }
    }

    q.Stop();
    watchers.clear();
    return 0;
}
