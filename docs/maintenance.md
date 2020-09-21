
# Contributor's Guide

## Getting Started

Make sure you have registered in the mailing list "linux-accelerators@lists.ozlabs.org".

Clone UADK from [Github](https://github.com/Linaro/uadk).

## Lincense

libwd is adopting Apache License 2.0.

## Coding Style

### Include statement ording

All header files that are included by a source file must use the following,
grouped ordering. This is to improve readability (by making it easier to
quickly read through the list of headers) and maintainability.

**System** includes: Head files from the standard *C* library, such as
		     *stddef.h* and *string.h*.

**Library** includes: Head files under the *include/* directory within
		      UADK.

**Internal** includes: Head files relating to an internal component within
		       UADK.

Within each group, **\#include** statements must be in alphabetical order,
taking both the file and directory names into account.

Groups must be separated by a single blank line for clarity.

### Avoid anonymous typedefs of structs/enums in headers

```
    typedef struct {
        int arg1;
        int arg2;
    } my_struct_t;
```
is better written as:
```
    struct {
        int arg1;
        int arg2;
    };
```

This allows function declarations in other header files that depend on the
struct/enum to forward declare the struct/enum instead of including the entire
header:

```
    #include <my_struct.h>
    void my_func(my_struct_t *arg);
```
instead of:
```
    struct my_struct;
    void my_func(struct my_struct *arg);
```

## Making Changes

Keep the commits on topic.
Please test your changes.

## Submitting Changes

Ensure that each commit in the series has at least one **Signed-off-by:** line,
using your real name and email address. The names in the **Signed-off-by:**
and **Author:** lines must match. If anyone else contributes to the commit,
they must also add their own **Signed-off-by:** line.

Submit your changes for review at the mailing list
"linux-accelerators@lists.ozlabs.org" targeting the **master** branch.

When the changes are accepted, the maintainers will integrate them.

## Working Branch

### Kernel Branch

Clone kernel from [Github](https://github.com/Linaro/linux-kernel-warpdrive).

 Current working branch: uacce-devel

   This branch is based on current mainline kernel Linux X.X-rcX. Patches which
   are under reviewed in community will be added into this branch.

 Release branch: uacce-devel-X.X

   Current working branch will be changed to Release branch once the mainline
   kernel which current working branch is based on is released.

### UADK Branch

 Current working branch: master

   tags like wd-X.X will be added to match with kernel release branch
   uacce-devel-X.X. However, UADK should be alway compatible with
   former kernel versions.

## Main maintainers

Haojian Zhuang <haojian.zhuang@linaro.org>
Wei Xu <xuwei5@hisilicon.com>
Zhou Wang <wangzhou1@hisilicon.com>
