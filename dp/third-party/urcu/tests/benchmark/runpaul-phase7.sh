#!/bin/sh

#run all tests

#set to number of active CPUS
export NUM_CPUS=64
#export NUM_CPUS=8

#extra options, e.g. for setting affinity on even CPUs :
EXTRA_OPTS=$(for a in $(seq 0 2 127); do echo -n "-a ${a} "; done)
#EXTRA_OPTS=$(for a in $(seq 0 1 7); do echo -n "-a ${a} "; done)

rm -f *.log

# x: Vary writer C.S. length from 0 to 100 us
# y: reads/s
# 4 readers
# 4 writers

echo Executing writer C.S. length test

NR_READERS=$((${NUM_CPUS} / 2))
NR_WRITERS=$((${NUM_CPUS} / 2))
DURATION=10
WDELAY=10
#in loops.
WRITERCSLEN_ARRAY="0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152"

rm -f writercslen.log

for WRITERCSLEN in ${WRITERCSLEN_ARRAY}; do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS} -d ${WDELAY} -e ${WRITERCSLEN} | tee -a writercslen.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS} -d ${WDELAY} -e ${WRITERCSLEN} | tee -a writercslen.log
done



mkdir ppc64-writercslen
mv *.log ppc64-writercslen/
#mkdir xeon-writercslen
#mv *.log xeon-writercslen/
