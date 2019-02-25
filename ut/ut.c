/**
 * unit testing helper file, use only under linux with glibc
 */
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <stdarg.h>
#include <setjmp.h>

/**** ut_assert ****/
#define ut_assert(cond) ut_assert_func(__FILE__, __LINE__, !!(cond), "")
#define ut_assert_str(cond, fmt, ...) ut_assert_func(__FILE__, __LINE__, !!(cond), fmt, ##__VA_ARGS__)

#ifdef UT_DUMPSTACK
#define ut_dumpstack() dumpstack()
#ifndef DUMP_DEEP
#define DUMP_DEEP 10
#endif
void dumpstack(void) {
	void * arr[DUMP_DEEP];
	int l, i;
	l = backtrace(arr, DUMP_DEEP);
	fprintf(stderr, "dump stack: \n");
	for(i=0; i<l; i++) {
		fprintf(stderr, "0x%lx\n", (unsigned long)arr[i]);
	}
}
#else
#define ut_dumpstack()
#endif

void ut_assert_func(char * f, int line, int cond, const char *fmt, ...) {
	va_list args;
	
	va_start(args, fmt);
	if(!cond) {
		printf("testfail at %s:%i: ", f, line);
		vprintf(fmt, args);
		printf("\n");
		ut_dumpstack();
		abort();
	}
	va_end(args);
}

/**** testcase and broken jump ****/
void default_broken(int val) {
	printf("broken from test (val=%d)\n", val);
}

int testcase = 0;
jmp_buf jmpenv;
void (*broken)(int val) = default_broken;

static inline void testj(void (*test_func)(void)) {
	if(setjmp(jmpenv)) {
		broken(-1);
	}else {
		test_func();
	}
}
#define ut_break(val) longjmp(jmpenv, val)

#define test(tc, test_func) \
	testcase = tc; \
	printf("test %s(%d)...", #test_func, tc); \
	testj(test_func); \
	printf("done\n");

#define in_test(from, to) (testcase >= (from) && testcase < (to))
#define ret_in_test(from, to) if(in_test(from, to)) return


/**** pair counter ****/
#define ut_cnt_val_range(tcid1, tcid2, cls) utcnt_##tcid1##_##tcid2##cls
#define ut_cnt_def_range(tcid1, tcid2, cls) int ut_cnt_val_range(tcid1, tcid2, cls) = 0
#define ut_cnt_add_range(tcid1, tcid2, cls) if(testcase>=tcid1&&testcase<=tcid2) ut_cnt_val_range(tcid1, tcid2, cls)++
#define ut_cnt_sub_range(tcid1, tcid2, cls) if(testcase>=tcid1&&testcase<=tcid2) ut_cnt_val_range(tcid1, tcid2, cls)--
#define ut_check_cnt_var_range(tcid1, tcid2, cls, var) \
	ut_assert_str(ut_cnt_val_range(tcid1, tcid2, cls)==var, \
	"testcase %d-%d fail on pair check for %s: %d\n", \
	tcid1, tcid2, #cls, ut_cnt_val_range(tcid1, tcid2, cls))
#define ut_check_cnt_range(tcid1, tcid2, cls) ut_check_cnt_var_range(tcid1, tcid2, cls, 0)

#define ut_cnt_def(tcid, cls) ut_cnt_def_range(tcid, tcid, cls)
#define ut_cnt_add(tcid, cls) ut_cnt_add_range(tcid, tcid, cls)
#define ut_cnt_sub(tcid, cls) ut_cnt_sub_range(tcid, tcid, cls)
#define ut_check_cnt_var(tcid, cls, var) ut_check_cnt_var_range(tcid, tcid, cls, var)
#define ut_check_cnt(tcid, cls) ut_check_cnt_range(tcid, tcid, cls)

