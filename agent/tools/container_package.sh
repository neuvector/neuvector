#!/bin/sh
#if which uname >/dev/null 2>&1; then
#	uname -r|awk '{printf("linux (%s)\n",$1);}'
#fi
#
#if which agetty >/dev/null 2>&1; then
#	agetty --version|awk '{printf("%s (%s)\n",$3,$4);}'
#fi
if which curl >/dev/null 2>&1; then
	curl --version|head -n 1|awk '{printf("%s (%s)\n", $1,$2);}'
fi

if which dhcpcd >/dev/null 2>&1; then
	dhcpcd --version|grep dhcpcd |awk '{printf("%s (%s)\n",$1,$2);}'
fi

if which sssd >/dev/null 2>&1; then
	sssd --version|awk '{printf("sssd (%s)\n",$1,$2);}'
fi

if which openssl >/dev/null 2>&1; then
	openssl version|awk '{printf("%s (%s)\n",$1,$2);}'
fi

if which sudo >/dev/null 2>&1; then
	sudo --version|head -n 1|awk '{printf("%s (%s)\n",$1,$3);}'
fi

if which rsync >/dev/null 2>&1; then
	rsync --version|head -n 1|awk '{printf("%s (%s)\n",$1,$3);}'
fi

if which git >/dev/null 2>&1; then
	git --version|awk '{printf("%s (%s)\n",$1,$3);}'
fi

if which tar  >/dev/null 2>&1; then
	tar --version|head -n 1|grep -v busybox|sed "s/tar.* \([0-9\.]*\)/tar (\1)/g"
fi

if which sqlite3 >/dev/null 2>&1; then
	sqlite3 --version|awk '{printf("sqlite3 (%s)\n",$1);}'
fi

if which jq  >/dev/null 2>&1; then
	jq --version|sed "s/jq-\([0-9\.a-z\-]*\)/jq (\1)/g"
fi

if which bash  >/dev/null 2>&1; then
	bash --version|head -n 1|sed "s/.*version \([0-9\.]*\).*/bash (\1)/g"
fi

if which wget >/dev/null 2>&1; then
	wget --version|head -n 1|sed "s/.*Wget \([0-9\.]*\).*/wget (\1)/g"
fi

if which runc >/dev/null 2>&1; then
	runc --version|head -n 1|sed "s/.* \([0-9\.a-z\-]*\)/runc (\1)/g"
fi

if which python3.5 >/dev/null 2>&1; then
	python3.5 --version |awk '{printf("%s (%s)\n",$1,$2);}'
fi

if which busybox >/dev/null 2>&1; then
	busybox --help|head -n 1|sed "s/BusyBox v\([0-9\.a-z\-]*\).*/busybox (\1)/g"
fi

ldconfig -v | sed "s/\t\(lib[a-z0-9\-\_]*\)\.so.* -> \(lib[a-z0-9\-\_]*\)\.so\.\([0-9\.]*\)/\2 (\3)/g"|grep "(" 
#err output
if which nginx >/dev/null 2>&1; then
	stderr="$(nginx -V 2>&1)"
	echo $stderr |sed "s/.*nginx\/\([0-9\.]*\).*/nginx (\1)/g"
fi
if which python >/dev/null 2>&1; then
	stderr="$(python --version 2>&1)"
	echo $stderr |awk '{printf("%s (%s)\n",$1,$2);}'
fi

if which python2.7 >/dev/null 2>&1; then
	stderr="$(python2.7 --version 2>&1)"
	echo $stderr |awk '{printf("%s (%s)\n",$1,$2);}'
fi

#multiline 
IFS='
'
stderr="$(tcpdump --version 2>&1)"
count=0
for item in $stderr
do
	if [ $count = 2 ]; then
		echo $item|awk '{printf("%s (%s)\n",$1,$2);}'
	else
		echo $item|awk '{printf("%s (%s)\n",$1,$3);}'
	fi
	count=$((count+1))
done
