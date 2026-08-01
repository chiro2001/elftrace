#include <stdio.h>
#include <unistd.h>
int main(void){ printf("SLEEPING\n"); fflush(stdout); for(;;) sleep(1); }
