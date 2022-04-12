obj = mylib.o

all: static dynamic
%.o: %.c
	$(CC) $(CFLAGS) -I$(ipath) -fPIC -lcrypto -lssl -c $< -o $@

static: $(obj)
	ar rcs mylib.a $^ 

dynamic: $(obj)
	$(CC) $(obj) -lcrypto -lssl -shared -o libmylib.so

clean:
	rm -rf *.so *.a *.o
