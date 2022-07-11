
# UADK Architecture Design


| Version | Author | Changes |
| --- | :---- | :---- |
|  0.91   | Haojian Zhuang |1) Remove the content of 3rd party memory  |
|         | Zhou Wang      |   allocation. |
|         |                |2) Remove "ss_va" and "ss_dma" from struct wd_chan.|
|         |                |3) Change to user app polling async interface.  |
|         |                |4) Add examples.  |
|  0.92   |                |1) Reorganize the document. |
|         |                |2) Remove some structures that are unused in apps. |
|  0.93   |                |1) Avoid to discuss whether IOMMU disabled in NOSVA |
|         |                |   scenario since it's not important. |
|         |                |2) Remove multiple queue since it's transparent to |
|         |                |   user application. |
|  0.94   |                |1) Split UADK into UACCE, libwd, algorithm |
|         |                |   libraries and libaffinity. Change doc according |
|         |                |   to this notion. |
|         |                |2) Illustrate how to select hardware accelerator. |
|         |                |3) Illustrate how libaffinity working. |
|  0.95   |                |1) Remove libaffinity extension for unclear logic. |
|         |                |2) Add API to identify NOSVA in libwd. |
|  0.96   |                |1) Fix on asynchronous operation. |
|  0.97   |                |1) Fix the missing hook of async poll. |
|         |                |2) Illustrate more on binding driver. |
|  0.98   |                |1) Do not expose context to user application. Use |
|         |                |   handler instead. |
|         |                |2) Illustrate each parameter or field in table. |
|         |                |3) Adjust the layout. |
|  0.99   |                |1) Fix the parameters in wd_alg_compress() and |
|         |                |   wd_alg_decompress(). |
|  0.100  |                |1) Remove wd_get_domain_affinity() for no benefit. |
|         |                |2) Remove dev_list from struct wd_alg_comp_ctx |
|         |                |   since only one device is meaningful. |
|         |                |3) Rename context to session. Rename channel to |
|         |                |   context. |
|         |                |4) Remove tag_id for not used. |
|         |                |5) Fix in struct wd_comp_arg. |
|         |                |6) Add compression interface for stream mode. |
|         |                |7) Simplify the parameters in wd_drv_unmap_qfr(). |
|         |                |8) Append a new image for asynchronous mode. |
|  0.101  |                |1) Make libwd used by application directly. |
|         |                |   Application could either use algorithm library |
|         |                |   or libwd. |
|         |                |2) Change affinity to accel. |
|         |                |3) Adjust the layout. |
|         |                |4) Drop the concept of session. |
|  0.102  |                |1) Make libwd used by vendor driver only. |
|         |                |2) Add session back for algorithm libraries. |
|  0.103  |                |1) Remove the device list in compression algorithm |
|         |                |   library since it's just an interim state. |
|         |                |2) Fix typo error. |
|         |                |3) Add context as parameter of wd_is_nosva(). |
|         |                |4) Adjust the layout. |
|  0.104  |                |1) Merge libaccel into libwd. |
|  0.105  |                |1) Add parameter in callback for async mode. |
|         |                |2) Fix minor issues. |
|  0.106  |                |1) Update *struct wd_comp_arg*. |
|         |                |2) Update wd_alg_comp_alloc_sess(). |
|         |                |3) Update *struct wd_alg_comp*. |
|         |                |4) Update *struct wd_comp_sess*. |
|         |                |5) Update *struct wd_ctx*. |
|  0.107  |                |1) Remove patchset information. |
|         |                |2) Fix typo error. |
|         |                |3) Mention libwd and algorithm libraries are built |
|         |                |   as different libraries. |
|  0.108  |                |1) Add more descriptions. |
|  0.109  |                |1) Hide *struct wd_ctx*. Only expose context |
|         |                |   handle to user space Apps. |
|         |                |2) Update on mask and session. |
|  0.110  |                |1) Remove fini() callback in *struct wd_alg_comp*. |
|  0.111  |                |1) Change the meaning of *arg->src_len*. |
|  1.0    |                |1) Update with the latest interface. |
|  1.1    |                |1) Rename *wd_drv_mmap_qfr()/wd_drv_unmap_qfr()* |
|         |                |   to *wd_mmap_qfr()/wd_unmap_qfr()*. |
|  1.2    |                |1) Rename *wd_mmap_qfr()/wd_unmap_qfr()* to |
|         |                |   *wd_ctx_mmap_qfr()/wd_ctx_unmap_qfr()*. |
|  1.3    |                |1) Add environment variable. |
|         |                |2) Change *user* layer to *sched* layer since |
|         |                |   sample_sched is moved from user space into UADK |
|         |                |   framework. |


## Terminology

| Term | Illustration |
| :-- | :-- |
| SVA             | Shared Virtual Addressing |
| NUMA            | Non Uniform Memory Access |
| Context         | A dual directional hardware communication resource between |
|                 | CPU and hardware accelerator. |
| IOMMU           | Input Output Memory Management Unit |


## Overview

UADK is a framework for user application to access hardware accelerator
in a unified, secure, and efficient way. UADK is comprised of UACCE,
libwd and many other algorithm libraries for different applications.

![overview](./wd_overview.png)

Libwd provides a wrapper of basic UACCE user space interfaces, they are a set
of helper functions.

Algorithm libraries offer a set of APIs to users, who could use this set of
APIs to do specific task without accessing low level implementations. Algorithm
libraries also offer a register interface to let hardware vendors to register
their own user space driver, which could use above helper functions to do UACCE
related work.

So two mechanisms are provided to user application. User application could
either access libwd or algorithm libraries. And all of these are compiled as
libraries. User application could pick up appropriate libraries to link.

This document focuses on the design of libwd and algorithm libraries.


## Based Technology

UADK relies on SVA (Shared Virtual Address) that needs to be supported
by IOMMU.

In UADK framework, virtual address could be used by vendor driver and
application directly. And it's actually the same virtual address, memory copy
could be avoided between vendor driver and application with SVA.


### UACCE user space API

As the kernel driver of UADK, UACCE offers a set of APIs between kernel
and user space. UACCE is introduced in "uacce.rst" and "sysfs-driver-uacce"
in kernel documents.

Hardware accelerator registers in UACCE as a char dev. At the same time,
hardware information of accelerators are also exported in sysfs node. For
example, the file path of char dev is */dev/[Accel]* and hardware information
are in */sys/class/uacce/[Accel]/*. The same name is shared in both devfs and
sysfs. The *Accel* is comprised of name, dash and id.

After opening this char device once, vendor driver will get a context to access
the resource of this accelerator device. Vendor driver can configure above
context by ioctl of this opened fd, and mmap hardware resource, like MMIO or
context to user space.


## Libwd Helper Functions

Hardware accelerator communicates with CPU by MMIO and contexts. Libwd helper
functions provide the interface that vendor driver could access memory from
UADK. And libwd is only accessed by vendor driver.


### Context

Context is a dual directional hardware communication resource between hardware
accelerator and CPU. When a vendor driver wants to access resources of an
accelerator, a context is the requisite resource.

UACCE creates a char dev for each registered hardware device. Once the char dev
is opened by UADK, a handle of context is created. Vendor driver or
application could refer to the context by the handle.

```
typedef unsigned long long int    handle_t;
```

Libwd defines APIs to allocate contexts.

***handle_t \*wd_request_ctx(struct uacce_dev \*dev);***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| libwd | *dev* | IN | A device in sysfs. All attrs information in sysfs |
|       |       |    | are recorded in this *struct uacce_dev*. |

Return the context handle if it succeeds. Return 0 if it fails.

***void wd_release_ctx(handle_t h_ctx);***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| libwd | *h_ctx* | IN | The handle indicates the working context. |


### mmap

With a context, resources on hardware accelerator could be shared to CPU.
When vendor driver or application wants to access the resource, it needs to map
the context.

Libwd provides API to create the mapping between virtual address and physical
address. The mapping could cover three different types. They are MMIO (device
MMIO region), DUS (device user share region) and SS (static share memory
region).

*wd_ctx_mmap_qfr()* and *wd_ctx_unmap_qfr()* are a pair of APIs to create and
destroy the mapping.

***void *wd_ctx_mmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| libwd | *h_ctx* | IN | The handle indicate the working context. |
|       | *qfrt*  | IN | Indicate the queue file region type. It could be  |
|       |         |    | MMIO (device MMIO region), DUS (device user share |
|       |         |    | region) or SS (static share memory region for |
|       |         |    | user). |

Return virtual address if it succeeds. Return NULL if it fails.

*wd_ctx_mmap_qfr()* maps qfile region to user space.

***void wd_ctx_unmap_qfr(handle_t h_ctx, enum uacce_qfrt qfrt);***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| libwd | *h_ctx* | IN | The handle indicate the working context. |
|       | *qfrt*  | IN | Indicate the queue file region type. |

*wd_ctx_unmap_qfr()* unmaps qfile region from user space.

qfrt means queue file region type. The details could be found in UACCE kernel
driver.


## Algorithm Libraries

Libwd is a fundamental layer what user relies on to access hardware. UADK also
provides algorithm interfaces that user could get out of the hardware details,
such as contexts. With the algorithm interface, the user application could be
executed on multiple vendor's hardware.


### Compression Algorithm

In compression algorithm, the contexts won't be accessed by user any more.
Instead, user only need to focus on compressing and decompressing.

In libwd, everything is based on context resource. In compression algorithm,
everything is based on session. Session is a superset of context, since vendor
driver may apply multiple contexts for performance. With compression algorithm
layer, user doesn't care how the multiple contexts are used.


#### Session in Compression Algorithm

The session in compression algorithm records working algorithm, accelerator,
working mode, working context, and so on. It helps to gather more information
and encapsulates them together. Application only needs to record the handle of
session.

Whatever user wants to compress or decompress, a session is always necessary.
Each session could only support either compression or decompression. And there
are also some configurations of the compression/decompression. They are defined
in the *struct wd_comp_sess_setup*.

```
struct wd_comp_sess_setup {
    enum wd_comp_alg_type   alg_type;   // zlib or gzip
    enum wd_comp_level      comp_lv;    // compression level
    enum wd_comp_winsz_type win_sz;     // compression window size
    enum wd_comp_op_type    op_type;    // compress or decompress
    enum wd_ctx_mode        mode;       // synchronous or asynchronous
};
```

With *struct wd_comp_sess_setup*, a session could be created. The details of
the session is encapsuled. Only a handle is exported to user.

***handle_t wd_comp_alloc_sess(struct wd_comp_sess_setup \*setup)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *setup* | IN | The structure describes the configurations of |
| algorithm |         |    | compression or decompression. |

If a session is created successfully, a non-zero handle value is returned.
If fails to create a session, just return 0.


***void wd_comp_free_sess(handle_t h_sess)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *h_sess* | IN | A 64-bit handle value indicates working |
| algorithm |          |    | session. |

With the handle, a related session could be destroyed.


#### Compression & Decompression

Compression & decompression always submit data buffer to hardware accelerator
and collect the output. These buffer information could be encapsulated into a
structure, *struct wd_comp_req*.

```
    typedef void *wd_alg_comp_cb_t(void *cb_param);
    struct wd_comp_req {
        void              *src;
        __u32             src_len;
        void              *dst;
        __u32             dst_len;
        wd_alg_comp_cb_t  *cb;
        void              *cb_param;
        __u8              op_type;
        __u32             last;
        __u32             status;
    };
```

| Field | Direction | Comments |
| :-- | :-- | :-- |
| *src*      | IN   | Input the virtual address of source buffer that is |
|            |      | prepared by user application. |
| *src_len*  | IN & | Input the length of source buffer. |
|            | OUT  | When the operation is done, *src_len* is updated. |
|            |      | It could indicate the length consumed by hardware. |
| *dst*      | IN   | Input the virtual address of destination buffer that |
|            |      | is prepared by user application. |
| *dst_len*  | IN & | Input the length of destination buffer. |
|            | OUT  | When the operation is done, *dst_len* is updated. |
|            |      | It indicates the real length of output data. |
| *cb*       | IN   | Indicate the user application callback that is used |
|            |      | in asynchronous mode. |
| *cb_param* | IN   | Indicate the parameter that is used by callback in |
|            |      | asynchronous mode. |
| *op_type*  | IN   | Indicate compression or decompression. |
| *last*     | IN   | Indicate whether it's the last data frame. |
| *status*   | OUT  | Indicate the result. 0 means successful, and others |
|            |      | are error code. |

When an application gets a session, it could request hardware accelerator to
work in synchronous mode or asynchronous mode. *cb* is the callback function
of user application that is only used in asynchronous mode. *cb_param* is the
parameter of the asynchronous callback function.

Since synchronous or asynchronous mode is specified in *struct wd_comp_req*,
the compression or decompression could be treated that user submits requests to
a session.

There're two kinds of compression interface. One is block mode that the data
in the request is not related to the previous or later data. And the other is
stream mode that the data in the request is related to the data in the previous
or later request. If user wants to compress/decompress large data buffer, it's
suggested to use stream mode.


***int wd_do_comp_sync(handle_t h_sess, struct wd_comp_req \*req)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *h_sess* | IN   | Indicate the session. User application doesn't |
| algorithm |          |      | know the details in context. |
|           | *req*    | IN & | Indicate the source and destination buffer. |
|           |          | OUT  | |

*wd_do_comp_sync()* sends a synchronous compression/decompression request for
block mode.

Return 0 if it succeeds. Return negative value if it fails. Parameter *req*
contains the buffer information.


***int wd_do_comp_strm(handle_t h_sess, struct wd_comp_req \*req)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *h_sess* | IN   | Indicate the session. User application doesn't |
| algorithm |          |      | know the details in context. |
|           | *req*    | IN & | Indicate the source and destination buffer. |
|           |          | OUT  | |

Return 0 if it succeeds. Return negative value if it fails. Parameter *req*
contains the buffer information.

*wd_do_comp_strm()* sends a synchronous compression/decompression request for
stream mode. *wd_do_comp_strm()* just likes *wd_do_comp_sync()*, user only
sends one request that the data buffer should be processed at one time.


***int wd_do_comp_sync2(handle_t h_sess, struct wd_comp_req \*req)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *h_sess* | IN   | Indicate the session. User application doesn't |
| algorithm |          |      | know the details in context. |
|           | *req*    | IN & | Indicate the source and destination buffer. |
|           |          | OUT  | |

Return 0 if it succeeds. Return negative value if it fails. Parameter *req*
contains the buffer information.

*wd_do_comp_sync2()* sends a synchronous compression/decompression request for
stream mode. *wd_do_comp_sync2()* is the superset of *wd_do_comp_strm()*. If
the data buffer of one request is too large to hardware accelerator, it could
split it into several requests until all data handled by hardware.



#### Asynchronous Mode

In synchronous mode, user application is blocked until the submitted request
is finished by hardware accelerator. Then a new request could be submitted.
In hardware accelerator, multiple requests are always processed in a stream
line. If a process needs to submit multiple requests to hardware, it can't
get good performance in synchronous mode. Since the stream line isn't fully
used. In this case, asynchronous mode could help user application to gain
better performance.

In asynchronous mode, user application gets return immediately while a request
is submitted.

***int wd_do_comp_async(handle_t h_sess, struct wd_comp_req \*req)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *h_sess* | IN   | Indicate the session. User application doesn't |
| algorithm |          |      | know the details in context. |
|           | *req*    | IN & | Indicate the source and destination buffer. |
|           |          | OUT  | |

Return 0 if it succeeds. Return negative value if it fails. Parameter *req*
contains the buffer information.

When hardware accelerator finishes the request, the callback that
is provided by user will be invoked. Because the compression library isn't
driven by interrupt, a polling function is necessary to check result.

***int wd_comp_poll(__u32 expt, __u32 \*count)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *expt*  | IN  | Indicate the expected receiving requests from |
| algorithm |         |     | hardware accelerator. |
|           | *count* | OUT | Indicate the real receiving requests from |
|           |         |     | hardware accelerator. |

Return 0 if all expected requests are received. Return error number if fails.

Usually *wd_comp_poll()* could be invoked in a user defined polling thread.


#### Bind Accelerator and Driver

Compression algorithm library requires each vendor driver providing an
instance, *struct wd_comp_driver*. This instance represents a vendor driver.
Compression algorithm library binds an vendor driver by the instance.

```
    struct wd_comp_driver {
        const char *drv_name;
        const char *algo_name;
        __u32 drv_ctx_size;
        int  (*init)(struct wd_ctx_config_internal *config, void *priv);
        void (*exit)(void *priv);
        int (*comp_send)(handle_t ctx, struct wd_comp_msg *msg);
        int (*comp_recv)(handle_t ctx, struct wd_comp_msg *msg);
    };
```

| Field | Comments |
| :-- | :-- |
| *drv_name* | Driver name that is matched with device name. |
| *alg_name* | Algorithm name |
| *init*     | Hook to do hardware initialization that implemented in vendor |
|            | driver. |
| *exit*     | Hook to finish all hardware operation that implemented in |
|            | vendor driver. |


A matched vendor driver is bound to compression algorithm library in a global
instance, *struct wd_comp_setting*. The binding process is finished by
macro *WD_COMP_SET_DRIVER()*.


*struct wd_comp_setting* binds context resources, user scheduler and vendor
driver together. At first, user application needs to allocate contexts and to
create scheduler instance. Then use *wd_comp_init()* to initialize vendor
device.

***int wd_comp_init(struct wd_ctx_config \*config, struct wd_sched \*sched)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *config* | IN | Indicate a context set. |
| algorithm | *sched*  | IN | Indicate a user scheduler that is used to |
|           |          |    | arrange context resource to a session. |

Return 0 if it succeeds. And return error number if it fails.

In *wd_comp_init()*, context resources, user scheduler and vendor driver are
initialized.


***void wd_comp_uninit(void)***

In *wd_comp_uninit()*, all configurations on resources are cleared.



### Scheduler

When algorithm layer is used, context resource is not exposed to user any more.
So user could define a scheduler that allocate context resources, arrange
proper resources to sessions and free context resources.

For user convenient, a sample scheduler is provided in UADK for reference.

***struct wd_sched \*sample_sched_alloc(__u8 sched_type, __u8 type_num,
__u8 numa_num, user_poll_func func)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| sched | *sched_type* | Input | The scheduler policy type that is supported |
|       |              |       | in current scheduler. |
|       | *type_num*   | Input | The service type number of user's service |
|       |              |       | that is defined by user. |
|       | *numa_num*   | Input | The NUMA number is used by user. |
|       | *func*       | Input | User provided polling function to poll events |
|       |              |       | on contexts. |

Return a scheduler instance if it succeeds. And return NULL if it fails.


***void sample_sched_release(struct wd_sched \*sched)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| sched | *sched* | Input | The user defined scheduler. |

*sample_sched_release()* is used to release a scheduler instance.


***int sample_sched_fill_data(const struct wd_sched \*sched, int numa_id,
__u8 mode, __u8 type, __u32 begin, __u32 end)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| sched | *sched*   | Input | The user defined scheduler |
|       | *numa_id* | Input | The ID of NUMA node |
|       | *mode*    | Input | Specify operation mode. |
|       |           |       | 0 -- sync mode, 1 -- async mode. |
|       | *type*    | Input | Service type that is defined by user. |
|       | *begin*   | Input | The index of first context in the region. |
|       | *end*     | Input | The index of last context in the region. |

After context resources allocated by *wd_request_ctx()*, user could specify
which context resources are working in the specified mode or type by
*sample_sched_fill_data()*.


### Environment Variable

According to above document, user need to care NUMA node and context number
to make use of UADK. The configuration process is a little boring. The idea
of Environment Variable is to make those parameters configured in user's
environment variable. It could help user to configure those parameters.


***wd_comp_env_init(void)***

Create a registered table for algorithm that could parse different environment
variables. With those parameters from user environment variables, allocate
related hardware resources.


***wd_comp_env_uninit(void)***

Free allocated hardware resources.


***wd_comp_ctx_num_init(__u32 node, __u32 type, __u32 num, __u8 mode)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *node* | Input | The ID of NUMA node. |
| algorithm | *type* | Input | Service type that is defined by user. |
|           | *num*  | Input | Context number. |
|           | *mode* | Input | Specify operation mode. |
|           |        |       | 0 -- sync mode, 1 -- async mode. |

Specify the parameters and create a pseudo environment variable. By this
pseduo environment table, allocate related hardware resource.


***wd_comp_ctx_num_uninit(void)***

Free allocated hardware resources like ***wd_comp_env_uninit()***.


***wd_comp_get_env_param(__u32 node, __u32 type, __u32 mode,
                         __u32 \*num, __u8 \*is_enable)***

| Layer | Parameter | Direction | Comments |
| :-- | :-- | :-- | :-- |
| compress  | *node*      | Input  | The ID of NUMA node. |
| algorithm | *type*      | Input  | Service type that is defined by user. |
|           | *mode*      | Input  | Specify operation mode. |
|           |             |        | 0 -- sync mode, 1 -- async mode. |
|           | *num*       | Output | Context number. |
|           | *is_enable* | Output | Indicate whether asynchronous polling |
|           |             |        | mode is enabled or not. |

Query context number that is defined in environment variable by specified
NUMA node, type and operation mode. At the same time, asynchronous polling
mode is queried.



## Vendor Driver

A vendor driver is the counterpart of a hardware accelerator. Without the
vendor driver, the accelerator can't work. *Context* could store the
information from the both accelerator and vendor driver.

If an accelerator is a bit special and not be generalized, application could
access the vendor driver directly. The interface to application is defined
by vendor driver itself.

Before accessing hardware accelerator, vendor driver needs to allocate
*context* first. In the *struct wd_ctx*, the node path of accelerator is also
recorded. If there're multiple accelerators share a same vendor driver, vendor
driver should decide to choose which accelerator by itself.

Application may want to track *context*. It's not good to share *context* to
application directly. It's better to transfer *context* to handle for security.



## Example

### Example in user application

Here's an example of compression in user application. User application just
needs a few APIs to complete synchronous compression.

![comp_sync](./wd_comp_sync.png)

Synchoronous operation means polling hardware accelerator status of each
operation. It costs too much CPU resources on polling and causes performance
down. User application could divide the job into multiple parts. Then it
could make use of asynchronous mechanism to save time on polling.

![comp_async2](./wd_comp_async2.png)

There's also a limitation on asynchronous operation in SVA scenario. Let's
assume there're two output frames generated by accelerator, A frame and B
frame. If the output is in fixed-length, then we can calculate the address of
A and B frame in the output buffer of application. If the length of hardware
accelerator output isn't fixed, we have to setup the temperary buffer to store
A and B frame. Then a memory copy operation is required between temperary
buffer and application buffer. So we use compression as a demo to explain
asynchronous operation. It doesn't mean that we recommend to use asynchronous
compression.


### Vendor Driver Exposed to User Application

Here's an example of implementing vendor driver that is exposed to application
direcly.

When user application needs to access hardware accelerator, it calls the
interface in vendor driver. The interface is defined by vendor driver. Then
vendor driver requests a context by *wd_request_ctx()*.

With the context, vendor driver could access hardware accelerator by libwd,
such as MMIO, memory mapping, and so on. And application has to use the
interface that is defined by vendor driver.

When application doesn't want to access hardware accelerator, vendor driver
could invokes *wd_release_ctx()* to release the hardware.
