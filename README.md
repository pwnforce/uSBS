# μSBS
μSBS: Static Binary Sanitization of Bare-metal Embedded Devices

## Required packages

μSBS is built on several opensource tools.

* capstone (for linear disassembling)
* keystone (for assembling)
* pyelftools (for reading elf binaries)
* LIEF (for modifying elf sections and segments)

## Executing μSBS

In order to execute μSBS just fo binary translation, you can run uSBS.py with the binary firmware as an argument. Furthermore, for instrumenting the binary, you need to run asan.py with firmware binary as an argument. 

**Note 1:** The asan.py can be modified for any instrumentation policy (i.e. other sanitization policies).

**Note 2** This project has been tested on Ubuntu 18.04 and with STM32 NUCLEO-F401RE and STM32479I-Eval boards.

## Flashing the STM32 device and running the application

Connect to the OpenOCD server and upload the program with the following commands:

* telnet localhost 4444
* init
* reset init
* halt
* flash write_image erase (application_name).elf
* exit

## Citing
The following publication cover technical parts of μSBS project:

```
@inproceedings{μSBS:RAID2020,
  author    = {Majid Salehi and Danny Hughes and Bruno Crispo},
  title     = {μSBS: Static Binary Sanitization of Bare-metal Embedded Devices for Fault Observability},
  booktitle = {Proceedings of the 23rd International Symposium on Research in Attacks, Intrusions and Defenses (RAID'20)},
  address = {San Sebastian},
  pages = {381--395},
  url = {https://www.usenix.org/conference/raid2020/presentation/salehi},
  publisher = {{USENIX} Association},
  year      = {2020},
  month     = {OCTOBER}

}
```
