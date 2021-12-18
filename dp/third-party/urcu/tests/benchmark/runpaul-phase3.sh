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

#Test scalability :
# x: vary number of readers from 0 to num cpus
# y: ops/s
# 0 writer.

echo Executing scalability test

NR_WRITERS=0
DURATION=10

rm -f scalability.log

for NR_READERS in $(seq 1 ${NUM_CPUS}); do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS}| tee -a scalability.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS}| tee -a scalability.log
done


