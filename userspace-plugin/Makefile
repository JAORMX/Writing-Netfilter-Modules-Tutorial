# Make libxt_ipaddr.so
CFLAGS = -O2 -Wall
lib%.so: lib%.o
	gcc -shared -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -fPIC -D_INIT=lib$*_init -c -o $@ $<;
