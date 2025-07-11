#define _WIN32_DCOM
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <fstream>
#include <thread>
#include <mutex>
#include <algorithm> // Needed for std::transform
#include <comdef.h>
#include <wbemidl.h>
#include <powrprof.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <initguid.h> // Include this header to define GUIDs

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "comsuppw.lib")

// Manually define the GUID if it's not in the SDK.
DEFINE_GUID(GUID_PROCESSOR_FREQUENCY_MAXIMUM, 0x75b0ae3f, 0xbce0, 0x45a7, 0x8c, 0x89, 0xc9, 0x61, 0x1c, 0x25, 0xe1, 0x00);


// --- Globals ---
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

std::wstring g_logFilePath;
std::wstring g_configPath;
std::set<std::wstring> g_gameList;
std::set<std::wstring> g_backgroundList;
std::set<DWORD> g_managedGamePIDs;
std::map<DWORD, DWORD_PTR> g_originalAffinities;
std::mutex g_pidMutex;
std::mutex g_affinityMutex;

DWORD_PTR g_pCoreMask = 0;
DWORD_PTR g_eCoreMask = 0;
int g_activeGameCount = 0;
DWORD g_originalMaxFreqAC = 0;
DWORD g_originalMaxFreqDC = 0;
bool g_freqChanged = false;

// --- Forward Declarations ---
void LogMessage(const std::wstring& message);
void WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD CtrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);
void ApplyAffinity(DWORD processId, std::wstring processName); // Changed to take by value
void SetMaxFrequency(DWORD freqMhz);
void RevertAllChanges();
void DetectCoreMasks();
void LoadProcessLists();
void SetAffinityForExistingProcesses();
bool EnableDebugPrivilege();
void MonitorProcessEvents();
HRESULT InitializeWMI(IWbemServices** pSvc, IWbemLocator** pLoc);
DWORD WINAPI AffinityWatcherThread(LPVOID lpParam);

// --- Helper Function ---
// Converts a wstring to lowercase
void ToLower(std::wstring& str) {
    std::transform(str.begin(), str.end(), str.begin(),
                   [](wchar_t c){ return std::tolower(c); });
}

// --- Logging ---
void LogMessage(const std::wstring& message) {
    std::wofstream logFile(g_logFilePath.c_str(), std::ios_base::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t buffer[100];
        wsprintfW(buffer, L"%04d-%02d-%02d %02d:%02d:%02d - ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        logFile << buffer << message << std::endl;
    }
}

void LogEvent(const std::wstring& message, WORD eventType) {
    HANDLE hEventSource = RegisterEventSourceW(NULL, L"AffinityManager");
    if (hEventSource) {
        LPCWSTR messages[] = { message.c_str() };
        ReportEventW(hEventSource, eventType, 0, 0, NULL, 1, 0, messages, NULL);
        DeregisterEventSource(hEventSource);
    }
}

// --- Privilege & Core Management ---
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return true;
}

void DetectCoreMasks() {
    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buffer(length);
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buffer.data();
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &length)) return;

    g_pCoreMask = 0;
    g_eCoreMask = 0;
    for (DWORD i = 0; i < length; ) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX current = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)&buffer[i];
        if (current->Relationship == RelationProcessorCore) {
            if (current->Processor.EfficiencyClass == 0) {
                g_eCoreMask |= current->Processor.GroupMask[0].Mask;
            } else {
                g_pCoreMask |= current->Processor.GroupMask[0].Mask;
            }
        }
        i += current->Size;
    }
    LogMessage(L"Detected P-Core Mask: " + std::to_wstring(g_pCoreMask));
    LogMessage(L"Detected E-Core Mask: " + std::to_wstring(g_eCoreMask));
}

// --- Process List & Affinity ---
void LoadProcessLists() {
    g_gameList.clear();
    g_backgroundList.clear();
    std::wifstream gameFile((g_configPath + L"\\games.txt").c_str());
    std::wstring line;
    if (gameFile.is_open()) {
        while (std::getline(gameFile, line)) {
            if (!line.empty() && line.back() == L'\r') line.pop_back();
            if (!line.empty()) {
                ToLower(line); // Convert to lowercase
                g_gameList.insert(line);
            }
        }
        gameFile.close();
    }
    
    std::wifstream bgFile((g_configPath + L"\\background.txt").c_str());
    if (bgFile.is_open()) {
        while (std::getline(bgFile, line)) {
             if (!line.empty() && line.back() == L'\r') line.pop_back();
             if (!line.empty()) {
                ToLower(line); // Convert to lowercase
                g_backgroundList.insert(line);
             }
        }
        bgFile.close();
    }
    LogMessage(L"Loaded " + std::to_wstring(g_gameList.size()) + L" games and " + std::to_wstring(g_backgroundList.size()) + L" background processes.");
}

void ApplyAffinity(DWORD processId, std::wstring processName) { // Take by value to modify
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return;

    std::wstring originalName = processName;
    ToLower(processName); // Convert process name to lowercase for comparison

    DWORD_PTR targetMask = 0;
    if (g_gameList.count(processName)) {
        targetMask = g_pCoreMask;
    } else if (g_backgroundList.count(processName)) {
        targetMask = g_eCoreMask;
    }

    if (targetMask != 0) {
        DWORD_PTR processAffinity, systemAffinity;
        if (GetProcessAffinityMask(hProcess, &processAffinity, &systemAffinity)) {
            std::lock_guard<std::mutex> lock(g_affinityMutex);
            if (g_originalAffinities.find(processId) == g_originalAffinities.end()) {
                g_originalAffinities[processId] = processAffinity;
                LogMessage(L"Stored original affinity for " + originalName);
            }
        }
        
        if (SetProcessAffinityMask(hProcess, targetMask)) {
             LogMessage(L"Set affinity for " + originalName + L" to mask " + std::to_wstring(targetMask));
        }
    }
    CloseHandle(hProcess);
}

void SetAffinityForExistingProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            ApplyAffinity(pe.th32ProcessID, pe.szExeFile);
            
            std::wstring processNameLower = pe.szExeFile;
            ToLower(processNameLower);
            if (g_gameList.count(processNameLower)) {
                std::lock_guard<std::mutex> lock(g_pidMutex);
                g_managedGamePIDs.insert(pe.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

// --- Frequency Management ---
void SetMaxFrequency(DWORD freqMhz) {
    GUID* activePolicyGuid;
    if (PowerGetActiveScheme(NULL, &activePolicyGuid) != ERROR_SUCCESS) return;

    if (freqMhz > 0) {
        if (!g_freqChanged) {
            PowerReadACValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, &g_originalMaxFreqAC);
            PowerReadDCValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, &g_originalMaxFreqDC);
            g_freqChanged = true;
        }
        LogMessage(L"Setting max frequency to " + std::to_wstring(freqMhz) + L" MHz.");
        PowerWriteACValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, freqMhz);
        PowerWriteDCValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, freqMhz);
    } else {
        if (g_freqChanged) {
            LogMessage(L"Restoring original max frequency.");
            PowerWriteACValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, g_originalMaxFreqAC);
            PowerWriteDCValueIndex(NULL, activePolicyGuid, &GUID_PROCESSOR_SETTINGS_SUBGROUP, &GUID_PROCESSOR_FREQUENCY_MAXIMUM, g_originalMaxFreqDC);
            g_freqChanged = false;
        }
    }
    
    PowerSetActiveScheme(NULL, activePolicyGuid);
    LocalFree(activePolicyGuid);
}

// --- Cleanup ---
void RevertAllChanges() {
    LogMessage(L"Service stopping. Reverting all changes...");
    
    if (g_freqChanged) {
        SetMaxFrequency(0);
    }

    std::lock_guard<std::mutex> lock(g_affinityMutex);
    for (auto const& [pid, originalAffinity] : g_originalAffinities) {
        HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
        if (hProcess) {
            if (SetProcessAffinityMask(hProcess, originalAffinity)) {
                LogMessage(L"Restored original affinity for PID " + std::to_wstring(pid));
            }
            CloseHandle(hProcess);
        }
    }
    g_originalAffinities.clear();
    LogMessage(L"Cleanup complete.");
}


// --- WMI Event Monitoring ---
class EventSink : public IWbemObjectSink {
    LONG m_lRef;
public:
    EventSink() : m_lRef(0) {}
    ULONG STDMETHODCALLTYPE AddRef() { return InterlockedIncrement(&m_lRef); }
    ULONG STDMETHODCALLTYPE Release() {
        LONG lRef = InterlockedDecrement(&m_lRef);
        if (lRef == 0) delete this;
        return lRef;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = (IWbemObjectSink *)this;
            AddRef();
            return WBEM_S_NO_ERROR;
        }
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount, IWbemClassObject **apObjArray) {
        for (long i = 0; i < lObjectCount; i++) {
            VARIANT vtProp;
            apObjArray[i]->Get(L"TargetInstance", 0, &vtProp, 0, 0);
            IUnknown* pUnk = vtProp.punkVal;
            IWbemClassObject* pTargetInstance = nullptr;
            pUnk->QueryInterface(IID_IWbemClassObject, (void**)&pTargetInstance);
            VariantClear(&vtProp);

            if (pTargetInstance) {
                VARIANT vtProcessName, vtProcessId;
                if (SUCCEEDED(pTargetInstance->Get(L"Name", 0, &vtProcessName, 0, 0)) &&
                    SUCCEEDED(pTargetInstance->Get(L"ProcessId", 0, &vtProcessId, 0, 0))) {
                    
                    std::wstring processName = vtProcessName.bstrVal;
                    DWORD processId = vtProcessId.uintVal;

                    VARIANT vtClass;
                    apObjArray[i]->Get(L"__CLASS", 0, &vtClass, 0, 0);
                    std::wstring className = vtClass.bstrVal;
                    VariantClear(&vtClass);
                    
                    std::wstring processNameLower = processName;
                    ToLower(processNameLower);

                    if (className == L"__InstanceCreationEvent") {
                        LogMessage(L"Process Created: " + processName + L" (ID: " + std::to_wstring(processId) + L")");
                        ApplyAffinity(processId, processName);

                        if (g_gameList.count(processNameLower)) {
                            if (g_activeGameCount == 0) SetMaxFrequency(100);
                            g_activeGameCount++;
                            std::lock_guard<std::mutex> lock(g_pidMutex);
                            g_managedGamePIDs.insert(processId);
                        }
                    } else if (className == L"__InstanceDeletionEvent") {
                        LogMessage(L"Process Terminated: " + processName + L" (ID: " + std::to_wstring(processId) + L")");
                        if (g_gameList.count(processNameLower)) {
                            g_activeGameCount--;
                            if (g_activeGameCount <= 0) {
                                g_activeGameCount = 0;
                                SetMaxFrequency(0);
                            }
                        }
                        std::lock_guard<std::mutex> lock(g_pidMutex);
                        g_managedGamePIDs.erase(processId);
                        std::lock_guard<std::mutex> affinityLock(g_affinityMutex);
                        g_originalAffinities.erase(processId);
                    }
                    VariantClear(&vtProcessName);
                    VariantClear(&vtProcessId);
                }
                pTargetInstance->Release();
            }
        }
        return WBEM_S_NO_ERROR;
    }
    HRESULT STDMETHODCALLTYPE SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject *pObjParam) {
        return WBEM_S_NO_ERROR;
    }
};

HRESULT InitializeWMI(IWbemServices** pSvc, IWbemLocator** pLoc) {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return hres;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) { CoUninitialize(); return hres; }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)pLoc);
    if (FAILED(hres)) { CoUninitialize(); return hres; }

    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hres = (*pLoc)->ConnectServer(bstrNamespace, NULL, NULL, NULL, 0, NULL, NULL, pSvc);
    SysFreeString(bstrNamespace);
    if (FAILED(hres)) { (*pLoc)->Release(); CoUninitialize(); return hres; }
    
    hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) { (*pSvc)->Release(); (*pLoc)->Release(); CoUninitialize(); return hres; }

    return S_OK;
}

void MonitorProcessEvents() {
    IWbemServices* pSvc = nullptr;
    IWbemLocator* pLoc = nullptr;

    HRESULT hres = InitializeWMI(&pSvc, &pLoc);
    if (FAILED(hres)) return;

    EventSink* pSink = new EventSink();
    pSink->AddRef();
    
    BSTR bstrQueryLang = SysAllocString(L"WQL");
    BSTR bstrQuery = SysAllocString(L"SELECT * FROM __InstanceOperationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
    
    hres = pSvc->ExecNotificationQueryAsync(bstrQueryLang, bstrQuery, WBEM_FLAG_SEND_STATUS, NULL, pSink);
    
    SysFreeString(bstrQueryLang);
    SysFreeString(bstrQuery);

    if (FAILED(hres)) {
        // Handle error
    } else {
        WaitForSingleObject(g_ServiceStopEvent, INFINITE);
    }
    
    pSvc->CancelAsyncCall(pSink);
    pSvc->Release();
    pLoc->Release();
    pSink->Release();
    CoUninitialize();
}

// --- Service Main Logic ---
int wmain(int argc, wchar_t **argv) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"AffinityManager", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"AffinityManager", ServiceCtrlHandler);
    if (g_StatusHandle == NULL) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    wchar_t path[MAX_PATH];
    GetEnvironmentVariableW(L"ProgramData", path, MAX_PATH);
    g_configPath = std::wstring(path) + L"\\AffinityManager";
    g_logFilePath = g_configPath + L"\\affinitymanager.log";

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    LogMessage(L"--- Service Starting ---");
    
    if (!EnableDebugPrivilege()) {
        LogMessage(L"Could not enable SeDebugPrivilege. The service may not be able to manage all processes.");
    } else {
        LogMessage(L"SeDebugPrivilege enabled successfully.");
    }
    
    DetectCoreMasks();
    if(g_eCoreMask > 0) SetProcessAffinityMask(GetCurrentProcess(), g_eCoreMask);
    LoadProcessLists();
    SetAffinityForExistingProcesses();

    HANDLE hWatcherThread = CreateThread(NULL, 0, AffinityWatcherThread, NULL, 0, NULL);

    MonitorProcessEvents();

    // --- CLEANUP ON EXIT ---
    RevertAllChanges();
    // --- END CLEANUP ---

    if (hWatcherThread != NULL) {
        WaitForSingleObject(hWatcherThread, 1000);
        CloseHandle(hWatcherThread);
    }
    
    LogEvent(L"AffinityManager Service stopped.", EVENTLOG_INFORMATION_TYPE);
    return ERROR_SUCCESS;
}

DWORD WINAPI AffinityWatcherThread(LPVOID lpParam) {
    LogMessage(L"Affinity watcher thread started.");
    while (WaitForSingleObject(g_ServiceStopEvent, 5000) == WAIT_TIMEOUT) {
        std::lock_guard<std::mutex> lock(g_pidMutex);
        if (g_managedGamePIDs.empty()) continue;

        for (auto it = g_managedGamePIDs.begin(); it != g_managedGamePIDs.end(); ) {
            DWORD pid = *it;
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid);

            if (hProcess) {
                DWORD_PTR processAffinity, systemAffinity;
                if (GetProcessAffinityMask(hProcess, &processAffinity, &systemAffinity)) {
                    if (processAffinity != g_pCoreMask) {
                        LogMessage(L"Affinity for PID " + std::to_wstring(pid) + L" has changed. Re-applying P-Core mask.");
                        SetProcessAffinityMask(hProcess, g_pCoreMask);
                    }
                }
                CloseHandle(hProcess);
                ++it;
            } else {
                it = g_managedGamePIDs.erase(it);
            }
        }
    }
    LogMessage(L"Affinity watcher thread stopped.");
    return 0;
}
