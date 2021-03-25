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
	
	int fd = -1;
	int fd_w = -1;
	int ret;
        unsigned int input;
	struct thread_info *tinfo = args;
	input = tinfo->size;
	unsigned int *data = (unsigned int*)malloc(sizeof(unsigned int) * input);

	if(!data)
		return NULL;
	
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
 		return NULL;
	}

	fd_w = open ("/root/trng_file", O_WRONLY|O_CREAT|O_APPEND,0777);
	if (fd_w <0 ) {
		printf("can not open trng_file\n");
 		return NULL;
	}
	memset(data, 0, sizeof(int) * input);
 	ret = read(fd, data, input);
	if (ret < 0) {
        	printf("read error %d\n", ret);
        	return NULL;
	}
	ret =write(fd_w,data,input);
	if (ret < 0) {
		printf("write error %d\n", ret);
		return NULL;
	}
  
  	close(fd);
	close(fd_w);

	return NULL;
}


void trng_test(int addr,int num,unsigned int si,int thread_num)
{
		
	int i;
	void *ret = NULL;
	struct thread_info *tinfo;
	tinfo = calloc(thread_num, sizeof(struct thread_info));

	if (tinfo == NULL)
	{
		printf("calloc fail...\n");
		return;
	}

	for (i = 0; i<thread_num; ++i)
	{
		tinfo[i].thread_id = i;
		tinfo[i].addr = addr;
		tinfo[i].num = num;
		tinfo[i].size = si;

		if ((pthread_create(&tinfo[i].thread_id,NULL,trng_thread, (void *)&tinfo[i])) != 0)
		{
			return;
		}
	}

	for (i=0; i<thread_num; ++i)
	{
		if (pthread_join(tinfo[i].thread_id, &ret) != 0)
		{
			printf("thread is not exit....\n");
			return;
		}
		//printf("thread exit coid %d\n", (int *)ret);
		free(ret);
	}
	free(tinfo);
}




int main (int argc, char* argv[]) {
	
	int opt;
	int addr = 0, num = 0, thread_num = 0;
	unsigned int si = 0;
	
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
			break;
		case 'p':
			thread_num = atoi(optarg);
			break;
		case 's':
			si = (unsigned int)atoi(optarg);
			break;
		default:
			break;
		}
	}

	trng_test(addr,num,si,thread_num);

	return 0;
}
