#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <semaphore.h>


struct thread_info
{
    pthread_t thread_id;
	unsigned int size;
	unsigned int num;
	int addr;
    
};

void *trng_thread(void *args)
{
	
	struct timeval start_tval, end_tval;
	int fd = -1;
	int fd_w = -1;
	int tem;
	int i = 0;
	int j = 0;
	int ret;
        unsigned int input;
	char c;
	int f = 0;	
	int byte_num;
	int remain_byte = input%4;
	struct thread_info *tinfo = args;
	input = tinfo->size;
	unsigned int *data = (unsigned int*)malloc(sizeof(unsigned int) * input);
	if(!data)
		return -1;
	
	byte_num = input/4;
	if (tinfo->addr == 0){
		
//		printf("Now try to get %d bytes random number from /dev/hwrng.\n", input * 4);
		fd = open ("/dev/hwrng", O_RDONLY);
	}
	else if (tinfo->addr == 1){
//		printf("Now try to get %d bytes random number from /dev/random.\n", input * 4);
		fd = open ("/dev/random", O_RDONLY);
	}
	
	if (fd <0 ) {
		printf("can not open\n");
 		return fd;
	}

	fd_w = open ("/root/trng_file", O_WRONLY|O_CREAT|O_APPEND,0777);
	if (fd_w <0 ) {
		printf("can not open trng_file\n");
 		return fd_w;
	}
	memset(data, 0, sizeof(int) * input);
//	for (i = 0; i < input; j++) {
	//printf("get number for %dtimes.\n",i);
 	ret = read(fd, data, input);
	if (ret < 0) {
        	printf("read error %d\n", ret);
        	return ret;
    }
	write(fd_w,data,input);
	//for (j; j < byte_num; j++) {
	//		printf("read data num= %x\n",*(data+j));
	//}

	//if (remain_byte){
  	//	printf("read data num= %x\n",*(data+j));
	//}
	
//}
  
  	close(fd);
	close(fd_w);

  return 0;
}


void trng_test(int addr,int num,unsigned int si,int thread_num)
{
		
	int i;
	void *ret = NULL;
	struct thread_info *tinfo;
	tinfo = calloc(thread_num, sizeof(struct thread_info));
    if(tinfo == NULL)
    {
        printf("calloc fail...\n");
        return -1;
    }
	for(i = 0; i<thread_num; ++i)
    {
		tinfo[i].thread_id = i;
		tinfo[i].addr = addr;
		tinfo[i].num = num;
		tinfo[i].size = si;
		
        if((pthread_create(&tinfo[i].thread_id,NULL,trng_thread, (void *)&tinfo[i])) != 0)
        {
            return -1;
        }
    }

    for(i=0; i<thread_num; ++i)
    {
        if(pthread_join(tinfo[i].thread_id, &ret) != 0)
        {
            printf("thread is not exit....\n");
            return -1;
        }
  //      printf("thread exit coid %d\n", (int *)ret);
		free(ret);
    }
	free(tinfo);
}




int main (int argc, char* argv[]) {
	
	int opt;
	cpu_set_t mask;
	int cpuid = 0;
	int addr,num,thread_num;
	int show_help = 0;
	unsigned int si;
	
	while ((opt = getopt(argc, argv, "hri:p:s:")) != -1) {
		switch (opt) {
		case 'h':
			addr = 0;
			break;
		case 'r':
			addr = 1;
			break;
		case 'i':
			num = atoi(optarg);
			if (num <= 0)
				show_help = 1;
			break;
		case 'p':
			thread_num = atoi(optarg);
			break;
		case 's':
			si = (unsigned int)atoi(optarg);
			break;
		default:
			show_help = 1;
			break;
		}
	}

	trng_test(addr,num,si,thread_num);

	return 0;
}
