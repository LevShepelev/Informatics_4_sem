all: build

build:
	gcc -Wall -Werror -g -c seminar.c -g
	gcc seminar.o -o seminar
	gcc -Wall -Werror -g -c seminar_teacher.c -g
	gcc seminar_teacher.o -o seminar_teacher
run: build
	./seminar