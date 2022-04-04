
flags = $(if $(DO_DYNAMIC), -lmylib -L$(lpath)!, $(slib)!)

ALL_C_FILES = $(wildcard *.c)
ALL_O_FILES = $(ALL_C_FILES:%.c=%.o)

all: $(ALL_O_FILES) build

%.o: %.c
	$(CC) $(CFLAGS) -I$(ipath) $< -c -o $@

echoes: $(ALL_C_FILES)
	echo $?

build: 
	$(CC) $(ALL_C_FILES) $(CFLAGS) -o task
clean:
	rm -rf task ./*.o 
