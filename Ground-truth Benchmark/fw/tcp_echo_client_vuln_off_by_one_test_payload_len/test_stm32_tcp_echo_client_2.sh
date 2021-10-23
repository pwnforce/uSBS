#!/bin/bash

BINARY=./test/stm32_tcp_echo_client.yml
INPUTS=./test/inputs
OUTPUTS=./test/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
#/home/halfuzz/hal-fuzz/afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/TCP_Echo_Server_ICMP.pcapng.input
