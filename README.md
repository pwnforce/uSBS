# μSBS (Discovery and Identification of Memory Corruption Vulnerabilities on Bare-metal Embedded Devices)

μSBS: Static Binary Sanitization of Bare-metal Embedded Devices

## Required packages

μSBS requires *Python2* and is built on several open-source tools.

* capstone (for linear disassembling)
* keystone (for assembling)
* pyelftools (for reading elf binaries)
* LIEF (for modifying elf sections and segments)

To simplify the setup, we provide a Dockerfile with which you can enjoy an already setup environment.

## Starting the container

1. Clone and `cd` into this repo.
2. Build the docker image:

    ```bash
    docker build -t usbs .
    ```

3. Once the image has been built, run it. Make sure to pass the path of the folder containing the elf firmware you want to instrument through the `-v` flag.

    ```bash
    docker run -it -v $(realpath <path_to_elf_folder>):/elf --rm usbs:latest
    ```

## Executing μSBS

In order to execute μSBS just for binary translation, you can run `uSBS.py` with the binary firmware as an argument. Furthermore, for instrumenting the binary, you need to run `asan.py` with firmware binary as an argument.

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

```bibtex
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
