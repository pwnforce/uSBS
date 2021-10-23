#!/bin/bash

BINARY=./test/stm32_tcp_echo_client.yml
INPUTS=./test/inputs
OUTPUTS=./test/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
#/home/halfuzz/hal-fuzz/afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#HARNESS $INPUTS/TCP_Echo_Server_Client.pcapng.input
nprocs=11
for i in `seq 2 $nprocs`; do
    /home/halfuzz/hal-fuzz/afl-fuzz -t 2000 -S slave$i -U -m none -i $INPUTS -o ./test/sync -- $HARNESS @@ >/dev/null 2>&1 &
done
/home/halfuzz/hal-fuzz/afl-fuzz -t 1000+ -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz
