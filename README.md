# uSBS
uSBS: Static Binary Sanitization of Bare-metal Embedded Devices

## Required packages

* capstone (for linear disassembling)
* keystone (for assembling)
* pyelftools (for reading elf binaries)
* LIEF (for modifying elf sections and segments)

## Executing uSBS

In order to execute uSBS just fo binary translation, you can run uSBS.py with the binary firmware as an argument. Furthermore, for instrumenting the binary, you need to run asan.py with firmware binary as an argument. 

**Note** The asan.py can be modified for any instrumentation policy (i.e. other sanitization policies).

## Flashing the STM32 device and running the application

Connect to the OpenOCD server and upload the program with the following commands:

* telnet localhost 4444
* init
* reset init
* halt
* flash write_image erase (application_name).elf
* exit




