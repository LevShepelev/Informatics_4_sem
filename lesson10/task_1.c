#include <sys/mman.h>
#include <stdio.h>

#define SIZE (1 << 28)

int main() {
    int i;
    int *array = (int *) mnap(NULL, SIZE, PROT_READ | MAP_PRIVATE);
    
}