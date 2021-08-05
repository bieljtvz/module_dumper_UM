#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <string>

using namespace std;


DWORD_PTR GetModuleBase(DWORD ProcessId, const wchar_t* ModuleName, PMODULEENTRY32 ModuleEntry1)
{
 
    MODULEENTRY32 ModuleEntry = { 0 };

    HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    if (!SnapShot)
        return NULL;
  
    ModuleEntry.dwSize = sizeof(ModuleEntry);
 
    if (!Module32First(SnapShot, &ModuleEntry))
        return NULL;

    do {
       
        if (!wcscmp(ModuleEntry.szModule, ModuleName)) {
          
            CloseHandle(SnapShot);
            *ModuleEntry1 = ModuleEntry;
            return (DWORD)ModuleEntry.modBaseAddr;

        }
        
    } while (Module32Next(SnapShot, &ModuleEntry));

    printf("[-] Modulo Incorreto...");
  
    CloseHandle(SnapShot);
    return NULL;
}


void dump_user_module(DWORD process_id, const char* name,  DWORD_PTR StartAddress, DWORD Size)
{
    printf("[-] Abrindo processo...\n");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!hProc)
    {
        printf("[-] Invalid PID\n\n");
        return;
    }

    // Alocar um buffer suficientemente grande para o módulo
    //
    auto buf = new char[Size];

    if (!buf)
        return;

    // Copiar o módulo da memória para o nosso buffer recém-alocado
    //
    SIZE_T bytes_read = 0;
    printf("[-] Lendo Memoria...\n");
    ReadProcessMemory(hProc, (PVOID)StartAddress, buf, Size, &bytes_read);

    if (!bytes_read)
    {
        printf("[-] Erro ao ler bytes...\n");
        delete[] buf;
        return;
    }

    // Obter as informações a partir dos cabeçalos no PE (se não foram apagados como uma forma de anti-dumping)
    //
    auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
    auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buf + pimage_dos_header->e_lfanew);

    // Este é um PE 64. Utilizar a versão em 64 bits dos nt headers
    //
    if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        // Obter o ponteiro para o primeiro section header
        //
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);

        for (WORD i = 0; i < pimage_nt_headers->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as seções deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o binário de maneira limpa em ferramentas para análise estática
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }

        // Arrumar o image base para a base do módulo que será dumpado
        //
        pimage_nt_headers->OptionalHeader.ImageBase = (DWORD_PTR)StartAddress;
    }

    // Este é um PE 32. Utilizar a versão em 32 bits dos nt headers
    //
    else if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto pimage_nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pimage_nt_headers);
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers32 + 1);

        for (WORD i = 0; i < pimage_nt_headers32->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as seções deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o binário de maneira limpa em ferramentas para análise estática
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }

        // Arrumar o image base para a base do módulo que será dumpado
        //
        pimage_nt_headers32->OptionalHeader.ImageBase = (DWORD_PTR)(StartAddress);
    }

    // Não suportado
    //
    else
    {
        delete[] buf;
        return;
    }

    // Montar o nome do módulo dumpado. Exemplo: "dump_kernel32.dll"
    //
    char bufName[MAX_PATH] = { 0 };
    strcpy(bufName, "dump_");
    strcat(bufName, name); 

    // Criar o arquivo no diretório atual (você pode mudar para outro diretório se quiser)
    //

    printf("[-] iniciando create file\n");

    HANDLE hFile = CreateFileA(bufName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);  

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] falha ao criar handle\n");
        return;
    }

    DWORD Ip1, Ip2;
    WriteFile(hFile, buf, (DWORD_PTR)bytes_read, &Ip1, nullptr);
        
    CloseHandle(hFile);
    CloseHandle(hProc);
    printf("[+] Modulo dumpado com sucesso...\n\n ");    

   
    delete[] buf;
}

int main()
{
    char sPID[99];
    char Name_c[99];
    wchar_t Name_w[99];
    int modo;


    printf("[+] Digito o PID(dec) do processo: ");
    scanf("%s", sPID);

    int PID = atoi(sPID);
    
    printf("[+] 1 = modulo || 2 = memoria \n");
    scanf("%i", &modo);

    if (modo == 1)
    {
        //Module
        printf("[+] Digito o modulo que deseja: ");
        scanf("%ws", Name_w);

        MODULEENTRY32 Modulo;
        GetModuleBase(PID, Name_w, &Modulo);

        printf("Base: %p Size: %X\n", Modulo.modBaseAddr, Modulo.modBaseSize);
        sprintf(Name_c,"%ws",Name_w);

        dump_user_module(PID, Name_c, (DWORD_PTR)Modulo.modBaseAddr, Modulo.modBaseSize);
    }
    else if (modo == 2)
    {

        DWORD_PTR BaseAddress = NULL;
        DWORD Size = NULL;

        //memoria
        printf("[=] digite a baseaddress\n");
        scanf("%p", &BaseAddress);

        printf("[=] digite o Size\n");
        scanf("%X", &Size);

        dump_user_module(PID, Name_c, BaseAddress,Size);
    
    }


    
   

    printf("Obrigado iPower,lucas,GuidedHacking e todos outros que ajudaram\n\n");
    printf("Deseja dumpar outro modulo?(1/0): ");

    int status = 0;
    scanf("%i", status);

    if (status == 1)
        main();
    else
        ExitProcess(0);

    system("pause");
}