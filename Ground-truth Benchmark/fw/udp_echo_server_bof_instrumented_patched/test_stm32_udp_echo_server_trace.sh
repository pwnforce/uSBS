#!/bin/bash

BINARY=./test/stm32_udp_echo_server.yml
INPUTS=./test/inputs
OUTPUTS=./test/output/
HARNESS="python3 -m hal_fuzz.harness -d -t -M -c $BINARY"
#/home/halfuzz/hal-fuzz/afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/UDP_Echo_Server_Client.pcapng.input
