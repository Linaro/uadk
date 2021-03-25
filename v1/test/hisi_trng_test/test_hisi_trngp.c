#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

static int input;
static int thread_num;
struct thread_info
{
	pthread_t thread_id;
	unsigned int size;
	int num;
};

void *trng_thread(void *args)
{
	int j;
	int fd = -1;
	int data;
	int ret;
	struct thread_info *tinfo = args;
	int  si;
	int num;
	int size;
	int fd_w = -1;
	si = tinfo->size;
	num = tinfo->num;
	size=si/num;
	printf("Now try to get  bytes random number from /dev/random.\n");
	fd = open("/dev/random", O_RDONLY);
	if (fd <0 ) {
		printf("can not open\n");
		return NULL;
	}
	for (j = 0; j< size; j++) {
		ret = read(fd, &data, 1);
		if (ret < 0) {
			printf("read error %d\n", ret);
			return NULL;
		}
//		else if (ret < 1)
//		goto rd_ag;
// 		if (!data) {
//   			printf("read data error!\n");
//   			return data;
//		}
		printf("the read num:%x\n",data);
	}
	fd_w = open ("/root/trng_file", O_RDWR | O_CREAT |O_APPEND , 0777);
	if (fd_w <0 ) {
		printf("can not open trng_file\n");
		return NULL;
	}
	ret = write(fd_w,&data,size);
	if (ret < 0) {
		printf("write error %d\n", ret);
		return NULL;
	}
	close(fd);
	close(fd_w);
	return NULL;
}

void trng_test(int input,int thread_num)
{
	int i;
	void *ret = NULL;
	struct thread_info *tinfo;
	tinfo = calloc(thread_num, sizeof(struct thread_info));
	if(tinfo == NULL)
	{
		printf("calloc fail...\n");
		return;
	}
	for(i = 0; i<thread_num; ++i)
	{
		tinfo[i].thread_id = i;
		tinfo[i].num=thread_num;
//		tinfo[i].addr = addr;
//		tinfo[i].num = num;
		tinfo[i].size = input;
		if((pthread_create(&tinfo[i].thread_id,NULL,trng_thread, (void *)&tinfo[i])) != 0)
		{
			return;
		}
	}

	for(i=0; i<thread_num; ++i)
	{
		if(pthread_join(tinfo[i].thread_id, &ret) != 0)
		{
			printf("thread is not exit....\n");
			return;
		}
//      	printf("thread exit coid %d\n", (int *)ret);
		free(ret);
	}
	free(tinfo);
}

int main (int argc, char* argv[])
{
	struct timeval start_tval, end_tval;
	float time,speed;
	int fd_f=-1;
	fd_f = open ("/root/trng_file", O_RDWR | O_CREAT |O_TRUNC, 0777);
	if (fd_f <0 ) {
		printf("can not open trng_file\n");
		return fd_f;
	}
	input = strtoul(argv[1], NULL, 10);
	if (input <= 0){
		printf("input error!\n");
		return -1;
	}
	thread_num = strtoul((char *)argv[2], NULL, 10);
	if (thread_num <= 0 || thread_num > 128) {
		printf("Invalid threads num:%d!\n",thread_num);
		printf("Now set threads num as 2\n");
		thread_num = 2;
	}
	gettimeofday(&start_tval, NULL);
	trng_test(input,thread_num);
	gettimeofday(&end_tval, NULL);
	time = (float)((end_tval.tv_sec - start_tval.tv_sec) * 1000000 +
				(end_tval.tv_usec - start_tval.tv_usec));
	speed = input/(time / 1000000);
	printf("read random speed: %0.0f time\n", time);
	printf("read random speed: %0.0f bytes/s\n", speed);
	close(fd_f);
	return 0;
}
