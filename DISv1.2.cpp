#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>

using namespace std;

// ===== Directories (Tier Mapping - hardcoded) =====
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
atomic<int> highDeletes(0), medDeletes(0), lowDeletes(0);
atomic<int> highWrites(0), medWrites(0), lowWrites(0);
atomic<int> highRenames(0), medRenames(0), lowRenames(0);

// ===== Phase 2 Logical Trigger =====
atomic<bool> phase2Trigger(false);
bool phase2Printed = false;

// ===== Rapid High Delete Detection Settings =====
const int RAPID_DELETE_THRESHOLD = 3;      // عدد الحذف السريع
const int RAPID_DELETE_WINDOW_MS = 500;    // الزمن بالمللي ثانية

atomic<int> rapidHighDeleteCount(0);
atomic<long long> firstDeleteTime(0);

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

// ===== TierCounters =====
struct TierCounters {
    atomic<int>& deletes;
    atomic<int>& writes;
    atomic<int>& renames;
};

// ===== Monitor Thread =====
void MonitorEvents(HANDLE hDir, TierCounters ctrs) {

    char buffer[4096];
    DWORD bytesReturned = 0;

    while (true) {
        BOOL ok = ReadDirectoryChangesW(
            hDir,
            &buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL
        );

        if (!ok) continue;

        auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);

        while (true) {
            switch (fni->Action) {
            case FILE_ACTION_REMOVED:
                ctrs.deletes++;
                // ===== Rapid High Delete Detection =====
                if (&ctrs.deletes == &highDeletes)
                {
                    long long nowMs = chrono::duration_cast<chrono::milliseconds>(
                        chrono::steady_clock::now().time_since_epoch()).count();

                    if (rapidHighDeleteCount == 0)
                        firstDeleteTime = nowMs;

                    rapidHighDeleteCount++;

                    long long diff = nowMs - firstDeleteTime;

                    if (rapidHighDeleteCount >= RAPID_DELETE_THRESHOLD &&
                        diff <= RAPID_DELETE_WINDOW_MS)
                    {
                        cout << "\nRAPID HIGH DELETE DETECTED!\n";
                        cout << "Deletes: " << rapidHighDeleteCount
                            << " within " << diff << " ms\n\n";

                        rapidHighDeleteCount = 0;
                        firstDeleteTime = 0;
                    }

                    if (diff > RAPID_DELETE_WINDOW_MS)
                    {
                        rapidHighDeleteCount = 1;
                        firstDeleteTime = nowMs;
                    }
                }

                break;

            case FILE_ACTION_MODIFIED:
                ctrs.writes++;
                break;

            case FILE_ACTION_RENAMED_OLD_NAME:
            case FILE_ACTION_RENAMED_NEW_NAME:
                ctrs.renames++;
                break;

            default:
                break;
            }

            if (fni->NextEntryOffset == 0) break;

            fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset
                );
        }
    }
}

int main() {

    HANDLE hHigh = OpenDir(HIGH_DIR);
    HANDLE hMed = OpenDir(MEDIUM_DIR);
    HANDLE hLow = OpenDir(LOW_DIR);

    if (hHigh == INVALID_HANDLE_VALUE ||
        hMed == INVALID_HANDLE_VALUE ||
        hLow == INVALID_HANDLE_VALUE) {
        cout << "Failed to open directories. Create:\n"
            << HIGH_DIR << "\n" << MEDIUM_DIR << "\n" << LOW_DIR << "\n";
        return 1;
    }

    cout << "Monitoring started...\n";

    thread tHigh(MonitorEvents, hHigh, TierCounters{ highDeletes, highWrites, highRenames });
    thread tMed(MonitorEvents, hMed, TierCounters{ medDeletes,  medWrites,  medRenames });
    thread tLow(MonitorEvents, hLow, TierCounters{ lowDeletes,  lowWrites,  lowRenames });

    tHigh.detach();
    tMed.detach();
    tLow.detach();

    // ===== (8) Alert memory (anti-spam) + (11) Alert ID =====
    bool alertActive = false;
    string lastAlertLevel = "NONE";
    int alertCounter = 0;

    // ===== (10) Files Lost cumulative =====
    long long filesLostTotal = 0;

    while (true) {

        // (5) 1-second time window aggregation
        this_thread::sleep_for(chrono::seconds(1));

        // Read + reset counters per window
        int hd = highDeletes.exchange(0);
        int hw = highWrites.exchange(0);
        int hr = highRenames.exchange(0);

        int md = medDeletes.exchange(0);
        int mw = medWrites.exchange(0);
        int mr = medRenames.exchange(0);

        int ld = lowDeletes.exchange(0);
        int lw = lowWrites.exchange(0);
        int lr = lowRenames.exchange(0);

        // Totals per tier
        int hTotal = hd + hw + hr;
        int mTotal = md + mw + mr;
        int lTotal = ld + lw + lr;

        // (9) Tiers touched tracking (count + names)
        bool touchedHigh = (hTotal > 0);
        bool touchedMed = (mTotal > 0);
        bool touchedLow = (lTotal > 0);

        int tiersTouchedCount =
            (touchedHigh ? 1 : 0) +
            (touchedMed ? 1 : 0) +
            (touchedLow ? 1 : 0);

        string tiersTouched = "";
        if (touchedHigh) tiersTouched += "High ";
        if (touchedMed)  tiersTouched += "Medium ";
        if (touchedLow)  tiersTouched += "Low ";
        if (tiersTouched.empty()) tiersTouched = "None";

        // (10) Files lost counter (this window + cumulative)
        int filesLostThisWindow = hd + md + ld;      // deletes only
        filesLostTotal += filesLostThisWindow;

        // (6) Weighted scoring (Fd)
        int Fd =
            (hTotal * HIGH_WEIGHT) +
            (mTotal * MEDIUM_WEIGHT) +
            (lTotal * LOW_WEIGHT);

        // Cross-tier spread amplification (optional but recommended)
        if (tiersTouchedCount >= 2)
            Fd = (int)(Fd * 1.2);

        // (7) Threshold classification
        string state = "Normal";
        if (Fd >= DESTRUCTIVE_THRESHOLD) state = "Destructive";
        else if (Fd >= SUSPICIOUS_THRESHOLD) state = "Suspicious";

        // ===== Phase 2 Trigger Logic =====
        if (state == "Destructive")
        {
            phase2Trigger = true;
        }

        if (phase2Trigger && !phase2Printed)
        {
            cout << ">>> Phase 2 Trigger ACTIVATED <<<" << endl;
            phase2Printed = true;
        }

        // (8) Alert Trigger Mechanism
        bool alertRaised = false;
        string alertLevel = "NONE";

        if (state == "Suspicious" || state == "Destructive") {
            alertRaised = true;
            alertLevel = (state == "Destructive") ? "DESTRUCTIVE" : "SUSPICIOUS";
        }

        // Fire only when alert starts or escalates
        bool newAlertEvent = false;
        if (alertRaised) {
            if (!alertActive || alertLevel != lastAlertLevel) {
                newAlertEvent = true;
                alertActive = true;
                lastAlertLevel = alertLevel;
            }
        }
        else {
            alertActive = false;
            lastAlertLevel = "NONE";
            phase2Printed = false;
            phase2Trigger = false;
        }

        // Print ONLY when a new alert event happens (no telemetry spam)
        if (newAlertEvent) {
            alertCounter++;

            cout << "\n=========== ALERT EVENT ===========" << endl;
            cout << "Alert ID: " << alertCounter << endl;
            cout << "Level: " << alertLevel << endl;
            cout << "Fd: " << Fd << endl;
            cout << "State: " << state << endl;
            cout << "TiersTouchedCount: " << tiersTouchedCount << endl;
            cout << "TiersTouched: " << tiersTouched << endl;
            cout << "DeletesThisWindow: " << filesLostThisWindow << endl;
            cout << "FilesLostTotal: " << filesLostTotal << endl;
            cout << "===================================\n" << endl;
        }
    }

    return 0;
}