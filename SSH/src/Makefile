obj = server.o
obj_1 = client.o


flags = $(slib)
ifeq ($(LIBTYPE), DYNAMIC)
	flags = -lmylib -L$(lpath)
endif

all: build
	
%.o: %.c
	$(CC) $(CFLAGS) -I$(ipath) $< -c -o $@


build: $(obj) $(obj_1)
	$(CC) $(obj) $(flags) $(CFLAGS) -o server -lpam -lpam_misc
	$(CC) $(obj_1) $(flags) $(CFLAGS) -o client
	

clean:
	rm -rf ./*.o client server
