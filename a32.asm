.model flat,c

;thanks four-f for structs
UNICODE_STRING STRUCT
	woLength		WORD	?		; len of string in bytes (not chars)
	MaximumLength	WORD	?		; len of Buffer in bytes (not chars)
	Buffer			DWORD	?		; pointer to string
UNICODE_STRING ENDS
PUNICODE_STRING	typedef	PTR UNICODE_STRING

OBJECT_ATTRIBUTES STRUCT		; sizeof = 18h
	dwLength					DWORD			? ; original name Length
	RootDirectory				DWORD			?
	ObjectName					PUNICODE_STRING	?
	Attributes					DWORD			?
	SecurityDescriptor			DWORD			? ; Points to type SECURITY_DESCRIPTOR
	SecurityQualityOfService	DWORD			? ; Points to type SECURITY_QUALITY_OF_SERVICE
OBJECT_ATTRIBUTES ENDS
POBJECT_ATTRIBUTES typedef OBJECT_ATTRIBUTES

NTSTATUS	typedef		DWORD

.const
PAGE_EXECUTE_READWRITE equ 40h
FILE_NON_DIRECTORY_FILE equ 40h
FILE_SYNCHRONOUS_IO_NONALERT equ 20h
FILE_CREATE equ 2h
FILE_ATTRIBUTE_NORMAL equ 80h

.data
oa       OBJECT_ATTRIBUTES <0>
us       UNICODE_STRING <>
iosb     dd  0,0,0 
fName    db  "\??\D:\Sysenter.txt",0    ;// имя создаваемого файла
fLen    SIZESTR "\??\D:\Sysenter.txt"                  ;// его длина
align    4                              ;// выравнивание на 4-байт границу
buff     db  256 dup (0)               ;// здесь будет UNICODE-строк
dwNum dd 0
oldProtect dd 0
pMem dd 0
sNum dd 0

.data?
fHndl dd ?

.code
SysDataInit proc
mov     esi,offset fName     ;// ESI = адрсе строки с именем файла
mov     edi,offset buff      ;// EDI = адрес приёмного буфера
mov     ecx,fLen      ;// ECX = длина строки
xor     eax,eax       ;//
@unicode:                     ;// конвертируем в UNICODE..
        lodsb                 ;// берём очередной байт из ESI
        stosw                 ;// записываем его как слово в EDI
        loop    @unicode      ;// повторить ECX-раз..

        mov     ecx,fLen      ;// ECX = длина строки
        shl     ecx,1         ;// умножить длину на 2

mov word ptr [us.woLength],cx       ;// отправляем длину в структуру UNICODE_STRING
mov dword ptr [us.Buffer],offset buff     ;// туда-же адрес буфера со-строкой

mov dword ptr [oa.ObjectName],offset us   ;// определяем struct.Unicode как имя в OBJECT_ATTRIBUTES
mov [oa.dwLength],sizeof OBJECT_ATTRIBUTES
mov [oa.Attributes],40h

ret
SysDataInit endp




Syscall32 proc; pMem:dword,sNum:dword
push ebp
mov ebp,esp

mov eax,[ebp+8]                     ; first param
mov pMem,eax
mov eax,[ebp+12]                    ;  second
mov sNum,eax

call SysDataInit

xor eax,eax
push eax ;EaLength
push eax ;EaBuffer
push FILE_NON_DIRECTORY_FILE + FILE_SYNCHRONOUS_IO_NONALERT
push FILE_CREATE
push eax;FILE_SHARE_READ+FILE_SHARE_WRITE
push FILE_ATTRIBUTE_NORMAL
push eax ;Allocation size 
push offset iosb          ;// IoStatusBlock
push offset oa            ;// ObjectAttributes
push 1F01ffh;GENERIC_WRITE  ;// Desired Access     = R/W тут ошибка, а какая хз
push offset fHndl         ;// Handle

push offset @f
push offset @f


mov eax,sNum
mov edx,esp
sysenter
@@:
add esp,11*4 ; тут параметры
add esp,4

pop ebp
ret
Syscall32 endp

Syscall48 proc;wow64 syscall
push ebp
mov ebp,esp

mov eax,[ebp+8]                     ; first param
mov pMem,eax
mov eax,[ebp+12]                    ;  second
mov sNum,eax

call SysDataInit

xor eax,eax
push eax ;EaLength
push eax ;EaBuffer
push FILE_NON_DIRECTORY_FILE + FILE_SYNCHRONOUS_IO_NONALERT
push FILE_CREATE
push eax;FILE_SHARE_READ+FILE_SHARE_WRITE
push FILE_ATTRIBUTE_NORMAL
push eax ;Allocation size 
push offset iosb          ;// IoStatusBlock
push offset oa            ;// ObjectAttributes
push 1F01ffh;GENERIC_WRITE  ;// Desired Access     = R/W тут ошибка, а какая хз
push offset fHndl         ;// Handle

call @f
@@:

mov eax,sNum
lea edx,[esp+4]
xor ecx,ecx

;assume fs:nothing
call dword ptr fs:[0C0h]

add esp,11*4 ; тут параметры
add esp,4

pop ebp
ret
Syscall48 endp
end 
