obh = lib.obh

all: static dynamic


%.o %.C
	$(CC) $(CFLAGS) -I$(ipath) -fPIC -c $< -c $@

static: $(obj)
	ar rcs  mylib.a $^

dynamic:
	$(CC) $(obj) -shared -o libmylib.so

clean:
	rm -rf *.so *.a *.o