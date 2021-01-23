.model flat,c

.const
PAGE_EXECUTE_READWRITE equ 40h

.data
dwNum dd 0
oldProtect dd 0
pMem dd 0
sNum dd 0

.code
Syscall32 proc; pMem:dword,sNum:dword
push ebp
mov ebp,esp

mov eax,[ebp+8]                     ; first param
mov pMem,eax
mov eax,[ebp+12]                    ;  second
mov sNum,eax


push offset oldProtect
push PAGE_EXECUTE_READWRITE
	mov dwNum,4096
push offset dwNum
push offset pMem
push 0FFFFFFFFh

push offset @f
push offset @f


mov eax,sNum
mov edx,esp
sysenter
@@:
add esp,5*4
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

push offset oldProtect
push PAGE_EXECUTE_READWRITE
mov dwNum,4096
push offset dwNum
push offset pMem
push 0FFFFFFFFh

call @f
@@:

mov eax,sNum
lea edx,[esp+4]
xor ecx,ecx ;тут не всегда так

;assume fs:nothing
call dword ptr fs:[0C0h]

add esp,5*4 ; тут параметры
add esp,4 

pop ebp
ret
Syscall48 endp
end 
