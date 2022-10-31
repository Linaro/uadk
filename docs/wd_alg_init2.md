# wd_alg_init2

## Preface

The current uadk initialization process is:
1.Call wd_request_ctx() to request ctxs from devices.
2.Call wd_sched_rr_alloc() to create a sched(or some other scheduler alloc function if exits).
3.Initialize the sched.
4.Call wd_alg_init() with ctx_config and sched.

```flow
st=>start: Start
o1=>operation: request ctxs
o2=>operation: create uadk_sched and instance ctxs to sched region
o3=>operation: call wd_alg_init
e=>end
st->o1->o2->o3->e
```

Logic is reasonable. But in practice, the step of wd_request_ctx()
and wd_sched_rr_alloc() are very tedious. This makes it difficult
for users to use the interface. One of the main reasons for this is
that uadk has made a lot of configurations in the scheduler in order
to provide users with better performance. Based on this consideration,
the current uadk requires the user to arrange the division of hardware
resources according to the device topology during initialization.
Therefore, as a high-level interface, this scheme can provide customized
scheme configuration for users with deep needs.

## wd_alg_init2

### Design

Is there any way to simplify these steps? Not currently. Because the
architecture model designed by uadk is to manage hardware resources
through a scheduler, users can no longer perceive after specifying
hardware resources, and all subsequent tasks are handled by the scheduler.
The original intention of this design is to make the scenarios supported
by uadk more flexible. Because the resource requirements of different
business scenarios are different from the task model of the business
itself, the best performance experience can be obtained through the
scheduler to match.

But we can try to provide a layer of encapsulation. The original design
intention of this layer of encapsulation is that users only need to
specify available resources and requirements, and the configuration of
resources is completed internally by the interface. Because the previous
interface complexity mainly lies in the parameter configuration of CTX
and scheduler, it is easy for users to make configuration errors and
generate bugs because of their misunderstanding of parameters.

All algorithms have the same input parameters and initialization logic.

```c
struct wd_ctx_config {
	__u32 ctx_num;
	struct wd_ctx *ctxs;
	void *priv;
};

struct wd_sched {
	const char *name;
	int sched_policy;
	handle_t (*sched_init)(handle_t h_sched_ctx, void *sched_param);
	__u32 (*pick_next_ctx)(handle_t h_sched_ctx, void *sched_key,
			       const int sched_mode);
	int (*poll_policy)(handle_t h_sched_ctx, __u32 expect, __u32 *count);
	handle_t h_sched_ctx;
};

int wd_alg_init(struct wd_ctx_config *config, struct wd_sched *sched);
```

`wd_ctx_config` is the requested ctxs descriptor, and the attributes
of ctxs are contained in their own structure. The attributes will be
used in scheduler for picking ctx according to request type. The main
difficulty in this step is that users need to apply for CTXs from the
appropriate device nodes according to their own business distribution.
If the user does not consider the appropriate device distribution,
it may lead to cross chip or cross numa node which will affect
performance.

`wd_sched` is the scheduler descriptor of the request. It will create
the scheduling domain based parameters passed by the users. User needs
to allocate the ctxs applied to the scheduling domain that meets the
attribute, so that uadk can select the appropriate ctxs according to
the issued business. The main difficulty in this step is that the user
needs to initialize the correct scheduling domain according to the ctxs
attributes previously applied. However, there are many attributes of
ctxs here, which should be divided by multiple dimensions. If the
parameters are not understood enough, it is easy to make queue
allocation errors, resulting in the scheduling of the wrong ctxs when
the task is finally issued, and cause unexpected errors.

Therefore, the next thing to be done is to use limited and easy-to-use
input parameters to describe users' requirements on the two input
parameters, ensuring that the functions of the new interface init2
are the same as those of init. For ease of description, v1 is used
to refer to the existing interface, and v2 is used to refer to the
layer of encapsulation.

Let's clarify the following logic first: all uacce devices under a
numa node can be regarded as the same. So although we request for
ctxs from the device, we manage ctxs according to numa nodes.
That means if users want to get the same performance for all cpu,
the uadk configure should be same for all numa node.

At present, at least 4 parameters are required to meet the user
configuration requirements with the V1 interface function remains
unchanged.

@alg: The algorithm users wanted.

@sched_type: Scheduling type the user wants to use.

@task_tp: Reserved.

@wd_ctx_params: op_type_num and ctx_set_num means the requested ctx
number for each numa node. Due to users may have different requirements
for different types of ctx numbers, needs a two-dimensional array as
input. The bitmask provided by libnuma. Users can use this parameter
to control requesting ctxs devices in the bind NUMA scenario.
This parameter is mainly convenient for users to use in the binding
cpu scenario. It can avoid resource waste or initialization failure
caused by insufficient resources. Libnuma provides a complete operation
interface which can be found in numa.h.

To sum up, the wd_alg_init2_() is as follows

```c
struct wd_ctx_nums {
	__u32 sync_ctx_num;
	__u32 async_ctx_num;
};

struct wd_ctx_params {
	__u32 op_type_num;
	struct wd_ctx_nums *ctx_set_num;
	struct bitmask *bmp;
};

init wd_alg_init2_(char *alg, __u32 sched_type, int task_tp,
                   struct wd_ctx_params *ctx_params);
```

Somebody may say that the wd_alg_init2_() is still complex for three
input parameters are structure. So the interface support default value
for some parameters. The @bmp can be set as NULL, and then it will be
initialized according to device list. The @cparams can be set as NULL,
and it has a default value in wd_alg.c. So there is a simpler interface
wd_alg_init2().

```c
#define wd_alg_init2(alg, sched_type, task_tp) \
	wd_alg_init2_(alg, sched_type, task_tp, NULL)
```

Please do not use this interface with wd_comp_init() together,
or some resources may be leak.
