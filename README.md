# Capcom.sys : The driver that disables SMEP.

- I tried my best to make the poc as simple as possible, it's no more than 40 lines. Could be found here.
- I am still a student, mistakes are possible.
- This blog was made possible through this video : https://www.youtube.com/watch?v=pJZjWXxUEl4&t=6844s for OJ Reeves. Consider taking a look over there. Fuzz Security also has a great article about it providing 1 more video as a part 2 of the original video. I will try my best here to include everything to make understanding it easier and less time consuming, because OJ Reeve's video was 2 hours (which again, i recommend watching).

----

## Before we start

A quick background story about this driver. It was first introduced in 2016 when Street Figter 5 was released, and part of the download was this driver, Capcom.sys. This driver disabled SMEP through it's IOCTL (Input/Output Control) codes, Which is the method to communicate with the driver. SMEP is Supervisor Execution prevention, and try to disable may cause some pain, since the to disable SMEP, you need to filp the bit in the CR4 register (more on that here https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/) Which is in a nutshell, flipping the 20th Bit in the CR4 Register, which is responsible for the flags that enable processor feathers and indicate feature capabilities of the processor. Explaining it in more details is not in the scope of the blog.

Here is what an SMEP BSOD (Blue screen of death) looks like :

<img width="523" height="390" alt="image" src="https://github.com/user-attachments/assets/39d38393-4ff9-41f5-9f64-18daee2d57e0" />


**The tweet the blew up :**


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

Scrolling down, we see that there is an IoCreateSymbolicLink call, which is creating the "\\\\.\\DeviceName" part, this means that right after that function, the real DeviceName is now officially stored in a register, looking more into it, we see that the register `rdx` holds the full name for the driver, this will be important for us to remember when we come back to the DeviceName in windbg :

<img width="612" height="586" alt="image" src="https://github.com/user-attachments/assets/a1c77d45-64d1-422e-9c72-3a88cd248711" />

The offset of the last call of the driver is at 0x707 :

<img width="1112" height="458" alt="image" src="https://github.com/user-attachments/assets/0e3667c7-bbfe-46ba-8c03-816640503ca5" />

Now that we are done with the first part, we see that we have an if condition here :

<img width="864" height="427" alt="image" src="https://github.com/user-attachments/assets/12a23626-bf64-42b0-a8b5-e741097f2616" />

We can also convert to pseudo-code using the button "TAB" :

<img width="699" height="251" alt="image" src="https://github.com/user-attachments/assets/78d7812d-cb90-45e6-bdcf-402b9ef39aef" />

Obviously in our case, we will not close the device handle in our exploit just yet, we will go with the second option, being the funcitons mentioned :

<img width="920" height="425" alt="image" src="https://github.com/user-attachments/assets/74a46fd8-8e52-46ea-881b-07fd23fba253" />



