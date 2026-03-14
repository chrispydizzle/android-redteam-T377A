#include <stdio.h>
#include <fcntl.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
static long get_slab(const char *n) {
    FILE *f = fopen("/proc/slabinfo","r"); if (!f) return -1;
    char l[256]; long a=-1;
    while(fgets(l,sizeof(l),f)){char nm[64]; long ac,to;
        if(sscanf(l,"%63s %ld %ld",nm,&ac,&to)>=2 && !strcmp(nm,n)){a=ac;break;}}
    fclose(f); return a;
}
int main(void){
    long b128=get_slab("kmalloc-128"),b192=get_slab("kmalloc-192"),b256=get_slab("kmalloc-256");
    printf("before: 128=%ld 192=%ld 256=%ld\n",b128,b192,b256);
    int fds[100]; int n=0;
    for(int i=0;i<100;i++){fds[i]=timerfd_create(CLOCK_REALTIME,TFD_NONBLOCK);if(fds[i]>=0)n++;}
    long a128=get_slab("kmalloc-128"),a192=get_slab("kmalloc-192"),a256=get_slab("kmalloc-256");
    printf("after:  128=%ld 192=%ld 256=%ld\n",a128,a192,a256);
    printf("delta:  128=%+ld 192=%+ld 256=%+ld n=%d\n",a128-b128,a192-b192,a256-b256,n);
    for(int i=0;i<n;i++) close(fds[i]);
    return 0;
}