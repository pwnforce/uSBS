#!/bin/bash

BINARY=./test/stm32_udp_echo_server.yml
INPUTS=./test/inputs
OUTPUTS=./test/output/
HARNESS="python3 -m hal_fuzz.harness -d -t -c $BINARY"
#/home/halfuzz/hal-fuzz/afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/UDP_Echo_Server_Client.pcapng.input
$HARNESS $INPUTS/crash/UDP_Echo_Server_Client_first_char.pcapng.input

