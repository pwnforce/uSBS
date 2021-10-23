# Discovery and Identification of Memory Corruption Vulnerabilities on Bare-metal Embedded Devices

This repository contains the code of the `Discovery and Identification of Memory Corruption Vulnerabilities on Bare-metal Embedded Devices` paper, including the firmware used in the benchmarking section (with P2IM fuzzing scripts), code of the injected vulnerabilities and some CBMC tests to evaluate callback support.

## Contents

- `cbmc_callback_tests/` contains two tests that illustrate what to add to the source code to run CBMC on and construct the inputs through symbolic execution. `callback.c` demonstrates that CBMC can also follow callbacks.

- `fw/` contains some firmware with their P2IM fuzzing scripts and inputs. As an example, `udp_echo_server_bof/` constains also an input (`crash/UDP_Echo_Server_Client_first_char.pcapng.input`) that triggers a bof vulnerability in the attached firmware.

- `injected_snippets/` contains the code of the vulnerabilities injected (bof, off-by-one, double-free and use-after-free).

## How to instantiate the benchmark

A benchmark is made of a set of vulnerable firmware *(a)*, vulnerabilities *(b)* and inputs *(c)* that triggers the vulnerabilities injected. You need to provide *(a)* and *(b)*. `fw/` contains examples of compiled vulnerable firmware *(a)*. Some  *(b)* are provided in `injected_snippets/`.

To construct *(c)*, you can use [angr](https://github.com/angr/angr) with Z3 or CBMC if the source code is available.

CBMC allows input construction automatically in most scenarios. To construct an input that reaches a specific line of the code, you just have to add the following before the target line:

```C
__CPROVER_assert(0, "postcondition");
```

Then you run CBMC: `cbmc <filename>.c --trace` and the last state traced should give you an input that satisfies the conditions to reach the target.

To construct *(a)*, repeatedly you pick some reachable locations in each firmware and inject a vulnerability from *(b)* and compile it.

Now you can start benchmarking your fuzzer.

---  

If you are using our work, please cite:

```bibtex
TODO
```
