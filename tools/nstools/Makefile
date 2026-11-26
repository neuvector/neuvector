all:
	@gcc -Wall -Werror -O2 -fstack-protector-strong -fstack-clash-protection -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -o nstools nstools.c nsrun.c nsget.c
