obj = mylib.o

all: static dynamic
%.o: %.c
	$(CC) $(CFLAGS) -I$(ipath) -fPIC -c $< -o $@

static: $(obj)
	ar rcs mylib.a $^

dynamic: $(obj)
	$(CC) $(obj) -shared -o libmylib.so

clean:
	rm -rf *.so *.a *.o
