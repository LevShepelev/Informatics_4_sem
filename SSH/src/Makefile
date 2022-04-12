obj = server.o
obj_1 = client.o
obj_2 = server_keys_config.o


flags = $(slib)
ifeq ($(LIBTYPE), DYNAMIC)
	flags = -lmylib -L$(lpath)
endif

all: build
	
%.o: %.c
	$(CC) $(CFLAGS) -I$(ipath) $< -c -o $@


build: $(obj) $(obj_1) $(obj_2)
	$(CC) $(obj) $(flags) $(CFLAGS) -o server -lpam -lpam_misc -lcrypto -lssl
	$(CC) $(obj_1) $(flags) $(CFLAGS) -o client -lcrypto -lssl
	$(CC) $(obj_2) $(flags) $(CFLAGS) -o keys_config -lcrypto -lssl
	

clean:
	rm -rf ./*.o client server
