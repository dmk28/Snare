#include <Winsock2.h>
#include <Shlwapi.h>
#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <fstream>
#include <objbase.h>
#include <oleauto.h>
#include <olectl.h>
#include <Psapi.h>
#include <ocidl.h>
#include <ws2tcpip.h>
#include <aclapi.h>
#include <sddl.h>
#include <sstream>
#pragma comment(lib, "Ws2_32.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define IDC_PROCESS_NAME_EDIT 1001
#define IDC_DLL_PATH_EDIT 1002
#define IDC_INJECT_BUTTON 1003
#define IDC_ATTACHMENTS_LIST_EDIT 1004
#define IDC_BROWSE_BUTTON 1005
#define ID_PROCESS_DROPDOWN 1006









typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef NTSTATUS(NTAPI* NT_CREATE_THREAD_EX_FN)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


volatile bool bTerminateThread = false;
//const int portNumber = 4445;
const TCHAR* saveFolder = _T("C:\\SavedAttachments\\");
std::wstring receivedFileName;



LRESULT CALLBACK WindowsProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool InjectDLL(DWORD processID, const TCHAR* dllPath);
DWORD WINAPI ListenForAttachments(LPVOID lpParam);
//SOCKET CreateSocketServer(int port);
void PopulateProcessDropdown(HWND hProcessDropdown);
DWORD find_process_by_name(const TCHAR* processName);
LRESULT CALLBACK WindowsProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);




int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCommandLine, int nCommandShow) {
    const TCHAR CLASS_NAME[] = _T("Snare");
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowsProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, _T("SNARE"), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 600, 350, NULL, NULL, hInstance, (LPVOID)hInstance);
    DWORD threadID;
    HANDLE hListenForAttachmentsThread = CreateThread(NULL, 0, ListenForAttachments, (LPVOID)hwnd, 0, &threadID);

    if (hwnd == NULL) {
        return 0;
    }

    ShowWindow(hwnd, nCommandShow);
    UpdateWindow(hwnd);

    MSG msg = {};

    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_QUIT) {
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

      

    return 0;
}



bool CheckDllLoaded(DWORD processID, const TCHAR* dllPath) {
    MODULEENTRY32 moduleEntry;
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hModuleSnap, &moduleEntry)) {
        do {
            if (_tcsicmp(moduleEntry.szExePath, dllPath) == 0) {
                CloseHandle(hModuleSnap);
                return true;
            }
        } while (Module32Next(hModuleSnap, &moduleEntry));
    }
    CloseHandle(hModuleSnap);
    return false;
}



// Save the file to the specified folder
void SaveFile(const std::string& folderPath, const std::string& fileName, const std::vector<BYTE>& byteArray) {
    std::string filePath = folderPath + "\\" + fileName;
    std::ofstream outputFile(filePath, std::ios::binary);
    outputFile.write(reinterpret_cast<const char*>(byteArray.data()), byteArray.size());
    outputFile.close();
}

SOCKET CreateSocketServer(int port) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << std::endl;
        return INVALID_SOCKET;
    }

    addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* addrResult = nullptr;
    std::stringstream ss;
    ss << port;
    std::string portStr = ss.str();
    result = getaddrinfo(NULL, portStr.c_str(), &hints, &addrResult);
    if (result != 0) {
        std::cerr << "getaddrinfo failed with error: " << result << std::endl;
        WSACleanup();
        return INVALID_SOCKET;
    }

    SOCKET listenSocket = socket(addrResult->ai_family, addrResult->ai_socktype, addrResult->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "socket failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(addrResult);
        WSACleanup();
        return INVALID_SOCKET;
    }

    result = bind(listenSocket, addrResult->ai_addr, (int)addrResult->ai_addrlen);
    if (result == SOCKET_ERROR) {
        std::cerr << "bind failed with error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(addrResult);
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    freeaddrinfo(addrResult);

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return listenSocket;
}
DWORD WINAPI ListenForAttachments(LPVOID lpParam) {
    int injectionAttempts = 0;
    int maxInjectionAttempts = 15;
    bool dllInjected = false;
    const int portNumber = 9000;

    SOCKET listenSocket = CreateSocketServer(portNumber);
    if (listenSocket == INVALID_SOCKET) {
        return 0;
    }

    TCHAR* buffer = new TCHAR[MAX_PATH + 1];
    DWORD bytesRead;

    while (!dllInjected && injectionAttempts < maxInjectionAttempts) {
        TCHAR processName[MAX_PATH] = { 0 };
        GetWindowText(GetDlgItem((HWND)lpParam, IDC_PROCESS_NAME_EDIT), processName, MAX_PATH);

        DWORD processID = find_process_by_name(processName);
        if (processID != 0) {
            TCHAR dllPath[MAX_PATH] = { 0 };
            GetCurrentDirectory(MAX_PATH, dllPath);
            PathAppend(dllPath, _T("Dll3.dll"));

            dllInjected = InjectDLL(processID, dllPath);
            if (dllInjected) {
                MessageBox((HWND)lpParam, _T("DLL injected successfully."), _T("Success"), MB_ICONINFORMATION | MB_OK);
            }
            else {
                MessageBox((HWND)lpParam, _T("DLL injection failed in ListenForAttachments."), _T("Error"), MB_ICONERROR | MB_OK);
                std::cerr << "Error code" << std::endl;
                
            }
        }

        Sleep(200); // Sleep for 200ms before checking again
        injectionAttempts++;
    }

    SOCKET clientSocket = INVALID_SOCKET;

    while (!bTerminateThread) {
        clientSocket = accept(listenSocket, (sockaddr*)NULL, (int*)NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "accept failed with error: " << WSAGetLastError() << std::endl;
            continue;
        }
        std::cout << "Client connected" << std::endl;

        while (TRUE) {
            bytesRead = recv(clientSocket, (char*)buffer, MAX_PATH * sizeof(TCHAR), 0);
            if (bytesRead == 0) {
                std::cout << "Client disconnected" << std::endl;
                break;
            }

            // Echo the received message back to the client
            send(clientSocket, (char*)buffer, bytesRead, 0);
        }

        // Close the client socket
        closesocket(clientSocket);
    }

    delete[] buffer;

    // Cleanup
    WSACleanup();

    return 0;
}




bool InjectDLL(DWORD targetProcessID, const TCHAR* dllPath) {
    std::wcout << L"Injecting DLL: " << dllPath << L" into process ID: " << targetProcessID << std::endl;
    DWORD processID = targetProcessID;
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        
        TCHAR errorMessage[256];
        _stprintf_s(errorMessage, _countof(errorMessage), _T("Failed to open process. Error code: %d"), GetLastError());
        MessageBox(NULL, errorMessage, _T("Error"), MB_ICONERROR | MB_OK);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
    if (!pLoadLibrary) {
        std::cout << "Failed to get LoadLibraryW address. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"LoadLibraryW address: " << pLoadLibrary << std::endl;
    size_t dllPathSize = (_tcslen(dllPath) + 1) * sizeof(TCHAR);
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, (dllPathSize + 1) * sizeof(TCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
        if (!pDllPath) {
            TCHAR errorMessage[256];
            _stprintf_s(errorMessage, _countof(errorMessage), _T("Failed to allocate memory in the target process. Error code: %d"), GetLastError());
            MessageBox(NULL, errorMessage, _T("Error"), MB_ICONERROR | MB_OK);
            CloseHandle(hProcess);
            return false;
        }
        std::wcout << L"Allocated memory in target process at address: " << pDllPath << std::endl;
    }
    else {
        std::cout << "Invalid process handle." << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, (LPVOID)dllPath, (dllPathSize + 1) * sizeof(TCHAR), NULL)) {
        TCHAR errorMessage[256];
        _stprintf_s(errorMessage, _countof(errorMessage), _T("Failed to allocate memory in the target process. Error code: %d"), GetLastError());
        MessageBox(NULL, errorMessage, _T("Error"), MB_ICONERROR | MB_OK);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread;
    HMODULE hNtDll = GetModuleHandle(TEXT("ntdll.dll"));
    NT_CREATE_THREAD_EX_FN NtCreateThreadEx = (NT_CREATE_THREAD_EX_FN)GetProcAddress(hNtDll, "NtCreateThreadEx");
    NTSTATUS ntStatus = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(ntStatus)) {
        TCHAR errorMessage[256];
        _stprintf_s(errorMessage, _countof(errorMessage), _T("Failed to allocate memory in the target process. Error code: %d"), GetLastError());
        MessageBox(NULL, errorMessage, _T("Error"), MB_ICONERROR | MB_OK);
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"Remote thread created with ID: " << hThread << std::endl;
    DWORD exitCode;
    if (GetExitCodeThread(hThread, &exitCode) && exitCode == 0) {
        TCHAR errorMessage[256];
        _stprintf_s(errorMessage, _countof(errorMessage), _T("Failed to allocate memory in the target process. Error code: %d"), GetLastError());
        MessageBox(NULL, errorMessage, _T("Error"), MB_ICONERROR | MB_OK);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

  

    std::cout << "DLL injected successfully." << std::endl;
    return true;
}






DWORD find_process_by_name(const TCHAR* processName) {
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry)) {
            do {
                if (_tcsicmp(processEntry.szExeFile, processName) == 0) {
                    processID = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
    }

    CloseHandle(snapshot);
    return processID;
}

void PopulateProcessDropdown(HWND hProcessDropdown) {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

            if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                }
            }

            SendMessage(hProcessDropdown, CB_ADDSTRING, 0, (LPARAM)szProcessName);
            CloseHandle(hProcess);
        }
    }
}

LRESULT CALLBACK WindowsProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

    switch (uMsg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_CREATE:
    {
        HWND hDllPathLabel = CreateWindow(TEXT("STATIC"), TEXT("DLL Path:"), WS_VISIBLE | WS_CHILD, 10, 10, 80, 20, hwnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        HWND hProcessLabel = CreateWindow(TEXT("STATIC"), TEXT("Process:"), WS_VISIBLE | WS_CHILD, 10, 40, 80, 20, hwnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);

        HWND hDllPathEdit = CreateWindow(_T("EDIT"), NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 10, 280, 20, hwnd, (HMENU)IDC_DLL_PATH_EDIT, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        HWND hBrowseButton = CreateWindow(TEXT("BUTTON"), TEXT("Browse"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 390, 10, 100, 20, hwnd, (HMENU)IDC_BROWSE_BUTTON, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        HWND hInjectButton = CreateWindow(TEXT("BUTTON"), TEXT("Inject"), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 390, 40, 100, 20, hwnd, (HMENU)IDC_INJECT_BUTTON, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        HWND hProcessDropdown = CreateWindow(TEXT("COMBOBOX"), NULL, WS_VISIBLE | WS_CHILD | CBS_DROPDOWN | WS_VSCROLL, 100, 40, 280, 200, hwnd, (HMENU)ID_PROCESS_DROPDOWN, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        PopulateProcessDropdown(hProcessDropdown);

        return 0;
    }
    break;

    case WM_CLOSE: {
        bTerminateThread = true;
        DestroyWindow(hwnd);
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BROWSE_BUTTON) {
            //For the Browse button that will pull the DLL.
            OPENFILENAME ofn;
            TCHAR szFile[MAX_PATH];

            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = szFile;
            ofn.lpstrFile[0] = '\0';
            ofn.nMaxFile = sizeof(szFile);
            ofn.lpstrFilter = _T("DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0");
            ofn.nFilterIndex = 1;
            ofn.lpstrFileTitle = NULL;
            ofn.nMaxFileTitle = 0;
            ofn.lpstrInitialDir = NULL;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (GetOpenFileName(&ofn) == TRUE) {
                SetWindowText(GetDlgItem(hwnd, IDC_DLL_PATH_EDIT), ofn.lpstrFile);
            }

        }
        else if (LOWORD(wParam) == IDC_INJECT_BUTTON) {
            TCHAR dllPath[MAX_PATH];
            GetWindowText(GetDlgItem(hwnd, IDC_DLL_PATH_EDIT), dllPath, MAX_PATH);

            TCHAR processName[MAX_PATH];
            HWND hProcessDropdown = GetDlgItem(hwnd, ID_PROCESS_DROPDOWN);
            int selectedIndex = SendMessage(hProcessDropdown, CB_GETCURSEL, 0, 0);
            if (selectedIndex != CB_ERR) {
                SendMessage(hProcessDropdown, CB_GETLBTEXT, selectedIndex, (LPARAM)processName);
            }

            DWORD processID = find_process_by_name(processName);
            if (processID != 0) {
                TCHAR message[256];
                swprintf_s(message, _countof(message), L"Attempting to inject DLL into process with ID: %u", processID);
                MessageBox(hwnd, message, _T("Process ID"), MB_ICONINFORMATION | MB_OK);
                if (InjectDLL(processID, dllPath)) {
                    if (CheckDllLoaded(processID, dllPath)) {
                        MessageBox(hwnd, _T("DLL injected successfully."), _T("Success"), MB_ICONINFORMATION | MB_OK);
                    }
                    else {
                        MessageBox(hwnd, _T("DLL injected, but failed to load."), _T("Error"), MB_ICONERROR | MB_OK);
                    }
                }
                else {
                    MessageBox(hwnd, _T("DLL injection failed in WindowsProc."), _T("Error"), MB_ICONERROR | MB_OK);
                }

                
            }
            else {
                MessageBox(hwnd, _T("Process not found."), _T("Error"), MB_ICONERROR | MB_OK);
            }
        }
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
