from pwn import *
import string

cool_string = ""

def main():
	global cool_string
	for cool_new_char in string.printable:
		p = process("timeout 0.05s ltrace ./vm chall.o", shell=True)
	
		i = 0
		p.sendline(cool_string + cool_new_char)
		getchar_found = False
		while True:
			try:
				l = p.recvline()
			except:
				break
        
			if "getchar" in l:
				i += 1
				getchar_found = True
			if(l[-4:-1] == " 10"):
				break
			if not "getchar" in l and getchar_found:
				break
	
		if (i > len(cool_string) + 1):
			cool_string += cool_new_char
			break
		print cool_string + cool_new_char
		p.close()
	
if __name__ == "__main__":
	while True:
		main()