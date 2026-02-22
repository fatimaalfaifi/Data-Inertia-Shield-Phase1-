#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>
#include <tlhelp32.h>

using namespace std;

// ===== Directories =====
const string HIGH_DIR = "C:\\DIS_High";
const string MEDIUM_DIR = "C:\\DIS_Medium";
const string LOW_DIR = "C:\\DIS_Low";

// ===== Weights =====
const int HIGH_WEIGHT = 5;
const int MEDIUM_WEIGHT = 3;
const int LOW_WEIGHT = 1;

// ===== Thresholds =====
const int SUSPICIOUS_THRESHOLD = 50;
const int DESTRUCTIVE_THRESHOLD = 150;

// ===== Atomic Counters =====
atomic<int> highDeletes(0);
atomic<int> medDeletes(0);
atomic<int> lowDeletes(0);

// ===== Open Directory =====
HANDLE OpenDir(const string& path) {
    return CreateFileA(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
}

// ===== Monitor Thread =====
void MonitorDeletes(HANDLE hDir, atomic<int>& counter) {

    char buffer[4096];
    DWORD bytesReturned;

    while (true) {

        if (ReadDirectoryChangesW(
            hDir,
            &buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME,
            &bytesReturned,
            NULL,
            NULL
        )) {

            FILE_NOTIFY_INFORMATION* fni =
                (FILE_NOTIFY_INFORMATION*)buffer;

            do {
                if (fni->Action == FILE_ACTION_REMOVED) {
                    counter++;
                }

                if (fni->NextEntryOffset == 0)
                    break;

                fni = (FILE_NOTIFY_INFORMATION*)
                    ((BYTE*)fni + fni->NextEntryOffset);

            } while (true);
        }
    }
}

// ===== Get Most Recently Created Process (Heuristic Attribution) =====
DWORD GetLatestProcess() {

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD latestPID = 0;
    FILETIME latestTime = { 0 };

    if (Process32First(snap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                FILETIME createTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(hProc, &createTime, &exitTime, &kernelTime, &userTime)) {
                    if (CompareFileTime(&createTime, &latestTime) > 0) {
                        latestTime = createTime;
                        latestPID = pe.th32ProcessID;
                    }
                }
                CloseHandle(hProc);
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return latestPID;
}

int main() {

    HANDLE hHigh = OpenDir(HIGH_DIR);
    HANDLE hMed = OpenDir(MEDIUM_DIR);
    HANDLE hLow = OpenDir(LOW_DIR);

    if (hHigh == INVALID_HANDLE_VALUE ||
        hMed == INVALID_HANDLE_VALUE ||
        hLow == INVALID_HANDLE_VALUE) {

        cout << "Failed to open directories.\n";
        return 1;
    }

    cout << "Monitoring started...\n";

    // Launch threads
    thread tHigh(MonitorDeletes, hHigh, ref(highDeletes));
    thread tMed(MonitorDeletes, hMed, ref(medDeletes));
    thread tLow(MonitorDeletes, hLow, ref(lowDeletes));

    tHigh.detach();
    tMed.detach();
    tLow.detach();

    // ===== Aggregation Loop =====
    while (true) {

        this_thread::sleep_for(chrono::seconds(1));

        int h = highDeletes.exchange(0);
        int m = medDeletes.exchange(0);
        int l = lowDeletes.exchange(0);

        int Fd =
            (h * HIGH_WEIGHT) +
            (m * MEDIUM_WEIGHT) +
            (l * LOW_WEIGHT);

        string state = "Normal";

        if (Fd >= DESTRUCTIVE_THRESHOLD)
            state = "Destructive";
        else if (Fd >= SUSPICIOUS_THRESHOLD)
            state = "Suspicious";

        // Timestamp
        auto nowTime = chrono::system_clock::now();
        time_t tt = chrono::system_clock::to_time_t(nowTime);
        tm local_tm;
        localtime_s(&local_tm, &tt);

        char timeStr[9];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &local_tm);

        double riskPercent =
            min(100.0, (Fd / (double)DESTRUCTIVE_THRESHOLD) * 100.0);

        cout << "[" << timeStr << "] "
            << "H=" << h
            << " M=" << m
            << " L=" << l
            << " | Fd=" << Fd
            << " | Risk=" << (int)riskPercent << "%"
            << " | State=" << state;

        if (Fd >= SUSPICIOUS_THRESHOLD) {
            DWORD suspectPID = GetLatestProcess();
            if (suspectPID != 0)
                cout << " | Suspect PID=" << suspectPID;
        }

        cout << endl;
    }

    return 0;
}
