#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <ctime>
#include <chrono>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winevt.h>
#include <psapi.h>
#include <wininet.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")


#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define WHITE   "\x1b[37m"
#define RESET   "\x1b[0m"
#define BOLD    "\x1b[1m"

// Yapılar
struct MitreEntry { std::string id, name; int risk; };
struct LogEntry { std::string id, mitre, lastSeen; int count, risk; };
struct NetConn { DWORD pid; std::string process, remoteIP, geo, state; };
struct HostRiskProfile {
    long long totalRisk = 0;
    int bruteForce = 0;
    int aiDetections = 0;
};


HostRiskProfile globalRisk;
std::vector<LogEntry> logs;
std::vector<NetConn> netMap;
std::mutex logMtx, netMtx, riskMtx;
std::unordered_map<std::string, std::string> geoCache;
bool running = true;

// Mitre DB
std::unordered_map<std::string, MitreEntry> MitreDB = {
    // --- INITIAL ACCESS & BRUTE FORCE ---
{"4624", {"T1078", "Valid Account Usage", 10}},
{"4625", {"T1110", "Brute Force Attempt", 80}},
{"4768", {"T1558", "Kerberos TGT Request (AS-REP Roasting)", 80}},

// --- EXECUTION & PERSISTENCE ---
{"4688", {"T1059", "Process Creation", 50}},
{"1",    {"T1059", "Sysmon: Process Create (Command Line)", 30}},
{"4698", {"T1053", "Scheduled Task Created", 50}},
{"13",   {"T1112", "Sysmon: Registry Event (Run Keys Persistence)", 60}},
{"4697", {"T1543", "Service Created (Remote Execution/Persistence)", 85}},

// --- PRIVILEGE ESCALATION & DEFENSE EVASION ---
{"4732", {"T1098", "Privileged Group Add", 90}},
{"4673", {"T1003", "Sensitive Privilege Use (SeDebugPrivilege)", 76}},
{"1102", {"T1562", "Security Log Cleared", 100}},
{"7",    {"T1140", "Sysmon: Image Loaded (Suspicious DLL)", 85}},
{"4657", {"T1562", "Registry Value Modified (AV Disable Attempt)", 95}},

// --- CREDENTIAL ACCESS (LSASS, SAM & AD) ---
{"10",   {"T1003", "Sysmon: Process Access (LSASS Dumping)", 85}},
{"8",    {"T1055", "Sysmon: CreateRemoteThread (LSASS Injection)", 95}},
{"4661", {"T1003", "SAM / Domain Policy Handle Request", 85}},
{"4662", {"T1003", "AD Object Access (Potential DCSync Attack)", 90}},

// --- DISCOVERY & LATERAL MOVEMENT ---
{"4799", {"T1087", "Local Group Enumeration (Discovery)", 70}},
{"5140", {"T1021", "Network Share Access (Lateral Movement)", 100}},
{"4648", {"T1550", "Logon using explicit credentials", 75}},
{"20",   {"T1047", "Sysmon: WMI Event (Remote Command Execution)", 80}},

// --- C2, EXFILTRATION & IMPACT ---
{"3",    {"T1071", "Sysmon: Network Conn (C2 Communication)", 90}},
{"22",   {"T1071", "Sysmon: DNS Query (Exfiltration/C2)", 75}},
{"11",   {"T1083", "Sysmon: File Created (Sensitive Data/Dump)", 75}},
{"23",   {"T1485", "Sysmon: File Delete (Mass Deletion/Ransomware)", 85}}
};

std::string Now() {
    time_t t = time(0); tm tmv; localtime_s(&tmv, &t);
    char buf[15]; strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    return buf;
}

void GoToXY(int x, int y) {
    COORD pos = { (SHORT)x, (SHORT)y };
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), pos);
}

std::string GetProcessName(DWORD pid) {
    if (pid == 0) return "[Idle]";
    char path[MAX_PATH] = "";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(h, 0, path, &size)) {
            std::string full = path; CloseHandle(h);
            return full.substr(full.find_last_of("\\") + 1);
        }
        CloseHandle(h);
    }
    return "Unknown";
}

// ============================
// CORE LOGIC (GEO, AI, EVENT)
// ============================

std::string FetchCountry(std::string ip) {
    if (ip.find("192.168.") == 0 || ip.find("10.") == 0 || ip.find("127.") == 0) return "LOCAL";
    if (geoCache.count(ip)) return geoCache[ip];

    HINTERNET hSession = InternetOpenA("SOC_Engine", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hSession) {
        std::string url = "http://ip-api.com/line/" + ip + "?fields=status,countryCode";
        HINTERNET hUrl = InternetOpenUrlA(hSession, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hUrl) {
            char buffer[128]; DWORD read;
            if (InternetReadFile(hUrl, buffer, sizeof(buffer), &read)) {
                std::string res(buffer, read);
                if (res.find("success") != std::string::npos) {
                    size_t pos = res.find_last_of('\n', res.length() - 2);
                    std::string code = res.substr(pos + 1, 2);
                    geoCache[ip] = code;
                    InternetCloseHandle(hUrl); InternetCloseHandle(hSession);
                    return code;
                }
            }
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hSession);
    }
    return "??";
}

void AICheck(int currentRisk, std::string id) {
    std::lock_guard<std::mutex> lock(riskMtx);
    static int chainCount = 0;
    if (currentRisk >= 80) chainCount++;

    if (chainCount >= 3) {
        globalRisk.totalRisk += (currentRisk * 5);
        globalRisk.aiDetections++;
        chainCount = 0;
    }
    else {
        globalRisk.totalRisk += currentRisk;
    }
}

void ProcessEvent(const std::string& xml) {
    
    if (xml.find("msedgewebview2.exe") != std::string::npos ||
        xml.find("SearchApp.exe") != std::string::npos ||
        xml.find("OneDrive.exe") != std::string::npos) return;

    size_t start = xml.find("<EventID");
    if (start == std::string::npos) return;
    start = xml.find(">", start) + 1;
    size_t end = xml.find("</EventID>", start);
    std::string id = xml.substr(start, end - start);
    id.erase(std::remove_if(id.begin(), id.end(), ::isspace), id.end());

    auto it_db = MitreDB.find(id);
    if (it_db != MitreDB.end()) {
        std::lock_guard<std::mutex> lock(logMtx);

        // --- SMART STACKING: Logu tüm listede ara ---
        auto it_log = std::find_if(logs.begin(), logs.end(), [&](const LogEntry& le) {
            return le.id == id;
            });

        if (it_log != logs.end()) {
            it_log->count++;
            it_log->lastSeen = Now();

            
            LogEntry updated = *it_log;
            logs.erase(it_log);
            logs.insert(logs.begin(), updated);
        }
        else {
            
            logs.insert(logs.begin(), { id, it_db->second.id + " | " + it_db->second.name, Now(), 1, it_db->second.risk });
            if (logs.size() > 12) logs.pop_back();
        }

        
        AICheck(it_db->second.risk, id);
        if (id == "4625") globalRisk.bruteForce++;
    }
}

// ============================
// THREADS (NET & RENDER)
// ============================

void NetScanner() {
    while (running) {
        ULONG size = 0;
        GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(size);
        PMIB_TCPTABLE_OWNER_PID tcp = (PMIB_TCPTABLE_OWNER_PID)buf.data();
        if (GetExtendedTcpTable(tcp, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            std::vector<NetConn> tmp;
            for (DWORD i = 0; i < (std::min)(tcp->dwNumEntries, (DWORD)20); i++) {
                if (tcp->table[i].dwRemoteAddr == 0) continue;
                in_addr addr; addr.S_un.S_addr = tcp->table[i].dwRemoteAddr;
                char ip[20]; inet_ntop(AF_INET, &addr, ip, 20);
                std::string currentIp(ip);
                tmp.push_back({ tcp->table[i].dwOwningPid, GetProcessName(tcp->table[i].dwOwningPid),
                               currentIp, FetchCountry(currentIp), (tcp->table[i].dwState == MIB_TCP_STATE_ESTAB ? "ESTABLISHED" : "WAIT") });
            }
            std::lock_guard<std::mutex> lock(netMtx);
            netMap = tmp;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
}

void Renderer() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci = { 100, FALSE }; SetConsoleCursorInfo(hOut, &ci);
    auto startTime = std::chrono::steady_clock::now();

    while (running) {
        GoToXY(0, 0);

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        int hrs = elapsed / 3600; int mins = (elapsed % 3600) / 60; int secs = elapsed % 60;

        // --- HEADER ---
        std::cout << BOLD << WHITE << " SOC ENGINE v3.9 " << RESET << " | "
            << "UPTIME: " << YELLOW << std::setfill('0') << std::setw(2) << hrs << ":"
            << std::setw(2) << mins << ":" << std::setw(2) << secs << RESET
            << " | STATUS: " << GREEN << "ACTIVE SCANNING" << RESET << "          \n";

        // --- RISK SCORE PANEL ---
        
        std::string sCol = (globalRisk.totalRisk > 1000) ? RED : (globalRisk.totalRisk > 400 ? YELLOW : GREEN);
        std::cout << WHITE << " " << std::string(72, '=') << " \n";
        std::cout << "  CORE RISK INDEX >> " << BOLD << sCol << std::setfill(' ') << std::setw(10) << globalRisk.totalRisk << RESET
            << WHITE << "  [ AI:" << YELLOW << globalRisk.aiDetections << WHITE << " | BRUTE:" << RED << globalRisk.bruteForce << RESET << WHITE << " ] \n";
        std::cout << WHITE << " " << std::string(72, '=') << " \n\n";

        // --- LIVE ATTACK STREAM ---
        std::cout << BOLD << WHITE << " [ LIVE ATTACK SCREEN ]" << RESET << "\n";
        {
            std::lock_guard<std::mutex> lock(logMtx);
            for (int i = 0; i < 10; i++) {
                if (i < logs.size()) {
                    auto& l = logs[i];

                    // --- SMART COLOR LOGIC ---
                    std::string color = WHITE;
                    if (l.id == "4625" && l.count > 5) color = RED;
                    else if (l.risk >= 75 || l.id == "10" || l.id == "1102") color = RED;
                    else if (l.risk >= 40) color = YELLOW;
                    else color = "\x1b[90m"; 

                    std::cout << color << BOLD << "  " << (color == RED ? ">> " : "-- ")
                        << "[" << l.lastSeen << "] "
                        << "(x" << std::left << std::setfill(' ') << std::setw(3) << l.count << ") "
                        << "ID:" << std::left << std::setw(6) << l.id
                        << "-> " << std::setw(40) << l.mitre.substr(0, 38) << RESET << " \n";
                }
                else std::cout << std::string(82, ' ') << "\n";
            }
        }

        // --- NETWORK ANALYSIS ---
        std::cout << BOLD << WHITE << "\n [ NETWORK INTELLIGENCE & THREAT MAP ]" << RESET << "\n";
        {
            std::lock_guard<std::mutex> lock(netMtx);
            for (int i = 0; i < 6; i++) {
                if (i < netMap.size()) {
                    auto& n = netMap[i];
                    std::string nCol = (n.geo != "LOCAL" && n.geo != "??") ? RED : GREEN;
                    std::cout << "  " << nCol << std::left << std::setw(8) << n.pid
                        << std::setw(18) << n.process.substr(0, 16)
                        << std::setw(18) << n.remoteIP << "[" << n.geo << "] " << n.state << RESET << "     \n";
                }
                else std::cout << std::string(82, ' ') << "\n";
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

// ============================
// CALLBACK & MAIN
// ============================

DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION act, PVOID, EVT_HANDLE evt) {
    if (act != EvtSubscribeActionDeliver) return 0;
    DWORD req = 0, pcc = 0;
    EvtRender(NULL, evt, EvtRenderEventXml, 0, NULL, &req, &pcc);
    std::vector<wchar_t> buf(req / sizeof(wchar_t) + 1);
    if (EvtRender(NULL, evt, EvtRenderEventXml, req, buf.data(), &req, &pcc)) {
        std::wstring w(buf.data());
        std::string xml(w.begin(), w.end());
        ProcessEvent(xml);
    }
    return 0;
}

int main() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
    SetConsoleTitleA("TRS4R3N Sentinal AI SOC Behavior");

    // 1. Security Kanalı
    EVT_HANDLE hSecurity = EvtSubscribe(NULL, NULL, L"Security", L"*", NULL, NULL,
        (EVT_SUBSCRIBE_CALLBACK)EventCallback,
        EvtSubscribeToFutureEvents);

    // 2. Sysmon Kanalı
    EVT_HANDLE hSysmon = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational", L"*", NULL, NULL,
        (EVT_SUBSCRIBE_CALLBACK)EventCallback,
        EvtSubscribeToFutureEvents);

    if (!hSecurity || !hSysmon) {
        std::cout << RED << BOLD << "! CRITICAL Error : Not Subscribed channels" << RESET << std::endl;
        std::cout << YELLOW << "-> Security: " << (hSecurity ? "OK" : "FAIL") << RESET << std::endl;
        std::cout << YELLOW << "-> Sysmon:   " << (hSysmon ? "OK" : "FAIL") << RESET << std::endl;
        std::cout << WHITE << "Not: Yonetici (Admin) haklari gerekiyor." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return 1;
    }

    std::cout << GREEN << BOLD << "[+] Radar Baslatildi..." << RESET << std::endl;

    std::thread tNet(NetScanner);
    std::thread tUI(Renderer);

    tNet.detach();
    tUI.join(); // UI kapandığında program biter

    EvtClose(hSecurity);
    EvtClose(hSysmon);
    return 0;
}
#endif