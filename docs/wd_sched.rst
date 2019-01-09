wd_sched
========

*Wd_sched* is a *WarpDrive* API warpper. It provides multi *WarpDrive* queue
scheduling support to the *WarpDrive* applications.

The core data structure for *wd_sched* is the *wd_scheduler*, or sched for
short. The user initialize it with the following fields:

* qs and q_num: wd_queue array and its size. You don't need to get the queues.
  Just init the data structure and *wd_sched* will get them for you.
* ss_region_size: size of ss_region, which will be shared by all queues. set to
  0 to let sched to make the decision.
* msg_cache_num: size of input buffer. Sched will send until all cache entries
  are used or no data for input.
* msg_data_size: size of the data buffer in cache. Every cache a msg_data_size
        data for input and another for output.
        They can be different in future version.
* init_cache: call back function to init the cache entry
* input: call back function to send data to the cache entry
* output: call back function to receive data from the cache entry

The general code style will be: ::
	ret = wd_sched_init(&sched);

	while(data_remained || !wd_sched_empty(sched)) {
		ret = wd_sched_work(&sched, input_num);
	}

	wd_sched_fini(&sched);

The wd_sched_work() work one step (send or receive) to one of the queue
according to the schedule algorithm.
