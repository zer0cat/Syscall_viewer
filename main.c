#define WIN32_LEAN_AND_MEAN
#define NOCRYPT 
#define NOSERVICE
#define NOMCX
#define NOIME

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <tchar.h>
#include "main.h"

#define NELEMS(a)  (sizeof(a) / sizeof((a)[0]))

/** Prototypes **************************************************************/

static INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
LPBYTE OpenPEFileW(LPCWSTR);
void ClosePEFile(LPBYTE);
int ParseFromMem(LPCSTR,HWND);
int ParseFromDisk(LPWSTR,HWND);
DWORD Rva2Raw(LPVOID, DWORD_PTR);
void Err(char *);
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
BOOL IsWow64(void);

extern int Syscall32(int a,int b);
extern int Syscall48(int a,int b);
/** Global variables ********************************************************/

static HANDLE ghInstance;
LPFN_ISWOW64PROCESS fnIsWow64Process;
BOOL isWoW = FALSE;

int PASCAL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdLine, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc;
    WNDCLASSEX wcx;

    ghInstance = hInstance;

    /* Initialize common controls. Also needed for MANIFEST's */
    /*
     * TODO: set the ICC_???_CLASSES that you need.
     */
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES /*|ICC_COOL_CLASSES|ICC_DATE_CLASSES|ICC_PAGESCROLLER_CLASS|ICC_USEREX_CLASSES|... */;
    InitCommonControlsEx(&icc);

    /* Load Rich Edit control support */
    /*
     * TODO: uncomment one of the lines below, if you are using a Rich Edit control.
     */
    // LoadLibrary(_T("riched32.dll"));  // Rich Edit v1.0
    // LoadLibrary(_T("riched20.dll"));  // Rich Edit v2.0, v3.0

    /*
     * TODO: uncomment line below, if you are using the Network Address control (Windows Vista+).
     */
    // InitNetworkAddressControl();

    /* Get system dialog information */
    wcx.cbSize = sizeof(wcx);
    if (!GetClassInfoEx(NULL, MAKEINTRESOURCE(32770), &wcx))
        return 0;

    /* Add our own stuff */
    wcx.hInstance = hInstance;
    wcx.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDR_ICO_MAIN));
    wcx.lpszClassName = _T("SysCallVClass");
    if (!RegisterClassEx(&wcx))
        return 0;

    /* The user interface is a modal dialog box */
    return DialogBox(hInstance, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)MainDlgProc);
}

static INT_PTR CALLBACK MainDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
HWND hList = GetDlgItem(hwndDlg,IDLIST1);
OPENFILENAMEW OpenFileName;
static WCHAR lpstrFile[MAX_PATH] = L"";
LPVOID mem;
UINT sys_num = 0;

    switch (uMsg)
    {
        case WM_INITDIALOG:
			isWoW = IsWow64();
            /*
             * TODO: Add code to initialize the dialog.
             */
            return TRUE;

        case WM_SIZE:
            /*
             * TODO: Add code to process resizing, when needed.
             */
            return TRUE;

        case WM_COMMAND:
            switch (GET_WM_COMMAND_ID(wParam, lParam))
            {
				case IDPSYS: //parse from sysdir
					SendMessage(hList, LB_RESETCONTENT, 0, 0);
					ParseFromDisk(NULL,hList);
					break;

				case IDPMEM: //parse from memory
					SendMessage(hList, LB_RESETCONTENT, 0, 0);
					ParseFromMem(NULL,hList);
					break;


				case IDPCUSTOM: //open custom ntdll file in disk
					//открытие файла, проверка на РЕ32, потом парсе_фром_диск
				OpenFileName.lStructSize = sizeof(OPENFILENAMEW);
				OpenFileName.hwndOwner = hwndDlg;
				//OpenFileName.hInstance = hInst;
				OpenFileName.lpstrFilter = L"ntdll.dll\0ntdll.dll\0All Files\0*.*\0\0";
				OpenFileName.lpstrCustomFilter = NULL;
				OpenFileName.nFilterIndex = 0;
				OpenFileName.lpstrFile = lpstrFile;
				OpenFileName.nMaxFile = MAX_PATH;
				OpenFileName.lpstrFileTitle = NULL;
				OpenFileName.lpstrInitialDir = NULL;
				OpenFileName.lpstrTitle = L"Open some custom ntdll";
				OpenFileName.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_LONGNAMES | 	OFN_PATHMUSTEXIST;
				OpenFileName.lpstrDefExt = NULL;

			if(!GetOpenFileNameW(&OpenFileName))
				MessageBoxW(hwndDlg, L"Cant open file",L"ERR", MB_OK); 
			else
				ParseFromDisk(OpenFileName.lpstrFile,hList);
					break;

				case IDFTEST:
					sys_num = ParseFromMem("NtCreateFile",hList);
					//mem = VirtualAlloc(NULL,4096,MEM_RESERVE | MEM_COMMIT,PAGE_READONLY);
					if(isWoW)
						Syscall48((int)mem,sys_num);
					else
						Syscall32((int)mem,sys_num);
                	break;

                case IDEXIT:
                    EndDialog(hwndDlg, TRUE);
                    return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwndDlg, 0);
            return TRUE;

        /*
         * TODO: Add more messages, when needed.
         */
    }

    return FALSE;
}


LPBYTE OpenPEFileW(LPCWSTR lpszFileName)
{
  HANDLE hMapping,hFile;
  LPBYTE pBase = NULL;
  hFile = CreateFileW(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    Err("Cannot open file (CreateFile)");
    return NULL;
  }

  hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  CloseHandle(hFile);

  if (hMapping != NULL)
    {
    pBase = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    }
  return pBase;
}

void ClosePEFile(LPBYTE pBase)
{
  if (pBase != NULL)
    UnmapViewOfFile(pBase);
}

int ParseFromMem(LPCSTR lpApiName,HWND hList)
{
LPBYTE PE = NULL;
IMAGE_DOS_HEADER* pDosHeader;
IMAGE_NT_HEADERS* pNtHeader;
char list2[512];

PE = (LPBYTE)GetModuleHandleW(L"ntdll.dll");
	if(!PE) return 1;

pDosHeader = (IMAGE_DOS_HEADER*)PE;
pNtHeader = (IMAGE_NT_HEADERS*)(PE +  pDosHeader->e_lfanew);

DWORD va = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)(PE + va);

PDWORD functions,names;
PWORD ordinals;
unsigned char *name;

functions = (PDWORD)(PE + pIED->AddressOfFunctions);
ordinals = (PWORD)(PE + pIED->AddressOfNameOrdinals);
names = (PDWORD)(PE + pIED->AddressOfNames);

for (unsigned long int i = 0; i < pIED->NumberOfNames; i++)
    {
	name = (char*)PE + names[i];

		if((name[0] != 'N') || (name[1] != 't'))
			{
			continue;
			}
	DWORD ordinalIndex = ordinals[i];
	DWORD fnVa = functions[ordinalIndex];

	unsigned char isMov = *(PE + fnVa);

	if(isMov != 0xB8) // skip, this is not syscall
			{
			continue;
			}

	if(lpApiName != NULL)
		{
		if(lstrcmpA(lpApiName,name) == 0)
				return (int)MAKEWORD(*(PE + fnVa+ 1),*(PE + fnVa+ 2));
		}

	wsprintfA(list2,"%x %s = 0x%hx",fnVa,name,MAKEWORD(*(PE + fnVa+ 1),*(PE + fnVa+ 2)));
	SendMessageA(hList,LB_ADDSTRING ,0,(LPARAM)list2);
	}	

return 1;
}

int ParseFromDisk(LPWSTR DllPath,HWND hList)
{
LPBYTE PE = NULL;
IMAGE_DOS_HEADER* pDosHeader;
IMAGE_NT_HEADERS* pNtHeader;

WCHAR dll_path[MAX_PATH+1];
char list2[512];
/*Terminal Services:   If the application is running in a Terminal Services environment, 
each user has a private Windows directory. There is also a shared Windows directory for the system. 
If the application is Terminal-Services-aware (has the IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE flag set 
in the image header), this function returns the path of the system Windows directory, 
just as the GetSystemWindowsDirectory function does.
Otherwise, it retrieves the path of the private Windows directory for the user. */ 

if (DllPath != NULL) //manually select file
	{
	PE = OpenPEFileW(DllPath);
	}
else
{
	if(isWoW)
		{
		if (!GetWindowsDirectoryW(dll_path,MAX_PATH)) return 1; //врядли такое будет,но мало ли
		lstrcatW(dll_path,L"\\Syswow64");
		}
	else
		{
		GetSystemDirectoryW(dll_path,MAX_PATH);
		}
	lstrcatW(dll_path,L"\\ntdll.dll");

	PE = OpenPEFileW(dll_path);
}
if(!PE) return 2;

pDosHeader = (IMAGE_DOS_HEADER*)PE;
pNtHeader = (IMAGE_NT_HEADERS*)(PE +  pDosHeader->e_lfanew);

if(pNtHeader->FileHeader.Machine != 0x014C)
	{
	MessageBoxW(0,L"Only 32-bit dll supported!",L"Error",MB_ICONERROR);
	ClosePEFile(PE);
	return 1;
	}

DWORD dwRva = Rva2Raw(PE,pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)(PE + dwRva);

PDWORD functions,names;
PWORD ordinals;
unsigned char *name;


functions = (PDWORD)(PE + Rva2Raw(PE,pIED->AddressOfFunctions));
ordinals = (PWORD)(PE + Rva2Raw(PE,pIED->AddressOfNameOrdinals));
names = (PDWORD)(PE + Rva2Raw(PE,pIED->AddressOfNames));

for (int i = 0; i < pIED->NumberOfNames; i++)
    {
	name = (char*)PE + (DWORD)Rva2Raw(PE,names[i]);

		if((name[0] != 'N') || (name[1] != 't')) //пропускаем то, что не начинается с Nt (можно Zw)
			{
			continue;
			}

	DWORD ordinalIndex = ordinals[i];
	DWORD dwRVA = functions[ordinalIndex];

	DWORD_PTR nSys = Rva2Raw(PE,dwRVA);
	
	unsigned char isMov = *(PE + nSys);

	if(isMov != 0xB8)
			{
			continue;
			}
	
    wsprintfA(list2,"%x %s = 0x%hx",dwRVA,name,MAKEWORD(*(PE + nSys+ 1),*(PE + nSys+ 2)));
	SendMessageA(hList,LB_ADDSTRING ,0,(LPARAM)list2);


    }
ClosePEFile(PE);
	return 0;
}

DWORD Rva2Raw(LPVOID pe, DWORD_PTR dwRVA)
{
	DWORD dwRawRvaAddr = 0;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	dos = (PIMAGE_DOS_HEADER)pe;
	nt = (PIMAGE_NT_HEADERS)(((DWORD_PTR)pe) + dos->e_lfanew);
	PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(nt);

	if (!pSections)
	{
		return dwRawRvaAddr;
	}

	while (pSections->VirtualAddress != 0)
	{
		if (dwRVA >= pSections->VirtualAddress && dwRVA < pSections->VirtualAddress + pSections->SizeOfRawData)
		{
			dwRawRvaAddr = (dwRVA - pSections->VirtualAddress) + pSections->PointerToRawData;
			break;
		}
		pSections++;
	}

	return dwRawRvaAddr;
}


void Err(char *err)
{
    //printf("%s\n",err);
	MessageBoxA(0,err,"Error",MB_ICONERROR);
}

BOOL IsWow64(void)
{
	BOOL bIsWow64 = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandleW(L"kernel32"),"IsWow64Process");

	if(NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
		{
			OutputDebugStringA("Error IsWoW");
		}
	}
	return bIsWow64;
}
