************************************************************************

*功能描述:
	使用dpdk环境作为第三方内存平台，链接wd库用于运行wd 用户态业务，
	链接openssl库用于运行软算业务，从而验证wd 用户态对第三方内存的支持。
	
	demo 展示了“dpdk内存 + wd 块内存”使用场景
	1. 从dpdk 申请大页内存
	2. 基于dpdk大页内存创建wd 块内存
	3. 从wd 块内存池申请内存运行wd 算法业务

*版本说明:
		commit:863643f87808962a0dbab3630b8aa13a46d69e0f
		Author: Chengchang Tang <tangchengchang@hisilicon.com>
		Date:   Mon Nov 4 08:59:17 2019 +0800

		基于以上commit版本制作的patch与源文件		
	
*文件说明:

	third_part_mem_test.patch:
		app/dpdk/下生成的patch文件。

	Makefile:
		基于app/dpdk/app/test-pmd/Makefile修改，修改内容见patch文件
	
	testpmd.c:
		基于app/dpdk/app/test-pmd/testpmd.c文件修改，修改内容见patch文件
	

*环境配置

	1.关闭smmu
	2.预留大页内存
		修改/boot/efi/EFI/centos/grub.cfg文件，内核启动命令行中添加如下字段
			default_hugepagesz=2M hugepagesz=2M hugepages=1000
			备注：预留的页大小与个数根据内存实际使用情况
	3.单板启动之后，执行
		mkdir -p /mnt/huge
		mount -t hugetlbfs nodev /mnt/huge
	
*编译可执行文件:
	
	1. 按照patch 修改app/dpdk/app/test-pmd/Makefile
	2. 按照patch 修改app/dpdk/app/test-pmd/testpmd.c
	3. 编译warpdrive, “make product=plinth warpdrive”，
	   将libwd.a、libcrypto_wd.so复制到app/dpdk/app/test-pmd目录下
	4. 编译dpdk
	   命令：“make -j64 product=plinth app-dpdk-1811 KERNEL_SOURCE=kernel”
	   输出可执行文件“testpmd”
	   位于out\plinth\app-dpdk-1811\home\root\app
	5. 单板上执行testpmd

************************************************************************