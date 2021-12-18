#!/bin/sh

#run all tests

#set to number of active CPUS
NUM_CPUS=64

#extra options, e.g. for setting affinity on even CPUs :
EXTRA_OPTS=$(for a in $(seq 0 2 127); do echo -n "-a ${a} "; done)

#ppc64 striding, use with NUM_CPUS=8

#stride 1
#EXTRA_OPTS=$(for a in $(seq 0 2 15); do echo -n "-a ${a} "; done)
#stride 2
#EXTRA_OPTS=$(for a in $(seq 0 4 31); do echo -n "-a ${a} "; done)
#stride 4
#EXTRA_OPTS=$(for a in $(seq 0 8 63); do echo -n "-a ${a} "; done)
#stride 8
#EXTRA_OPTS=$(for a in $(seq 0 16 127); do echo -n "-a ${a} "; done)

#Vary update fraction
#x: vary update fraction from 0 to 0.0001
  #fix number of readers and reader C.S. length, vary delay between updates
#y: ops/s

rm -f runall.log
rm -fr runall.detail.log

#setting gc each 32768. ** UPDATE FOR YOUR ARCHITECTURE BASED ON PHASE 1 RESULT **
EXTRA_OPTS="${EXTRA_OPTS} -b 32768"

echo Executing update fraction test

DURATION=10
WDELAY_ARRAY="0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768
              65536 131072 262144 524288 1048576 2097152 4194304 8388608
              16777216 33554432 67108864 134217728"
NR_WRITERS=$((${NUM_CPUS} / 2))

rm -f update-fraction.log

NR_READERS=$((${NUM_CPUS} - ${NR_WRITERS}))
for WDELAY in ${WDELAY_ARRAY}; do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d ${WDELAY} ${EXTRA_OPTS} | tee -a update-fraction.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d ${WDELAY} ${EXTRA_OPTS} | tee -a update-fraction.log
done
