
# Sanity Test Guide

## Sanity Test Overview

The sanity test focuses on functional validation of compression and encryption
features, utilizing UADK (User-space Accelerator Development Kit) to verify correct
behavior when hardware acceleration is available. To build this test suite, OpenSSL
must be installed, as it is a core dependency.

**Usage**

Users can execute the tests directly by running the script:
```
$./test/sanity_test.sh
```

This provides a simple, one-command method to verify functionally.


## Add Test Case into Sanity Test

The sanity test suite includes multiple test cases, and each result must be clearly
logged to identify any failures. To maintain consistency, developers must adhere to
the following guidelines when adding new test cases:

### Test Execution and Logging

The run_cmd() function will execute test commands with structured logging and result
tracking. For example:
```
run_cmd "HW compress for gzip format in block mode" \
	uadk_tool test --m zip --alg 2 --in origin --out /tmp/ori.gz
```

**Command Structure Requirements**

1. Function Prefix
All commands must begin with **run_cmd** to trigger the execution framework.

2. Descriptive Comment
A quoted description explaining the test purpose (e.g., "Hw compress...").

3. Original Command
The actual command/arguments follow the description.

**Logging and Tracking**

Test Case ID: Automatically generated and displayed in logs.
Result Recording: Explicit pass/fail status.
Output Format:
```
Command [5]: uadk_tool test --m zip --alg 2 --inf --in /tmp/ori.gz --out origin
	Command passed (CMD: HW decompress for gzip format in block mode).
```

**Test Command Execution Control**

The test framework provides two execution modes to accommodate different debugging
needs:

1. Verbose Mode (run_cmd)

Display full command output for debugging.
Example:

```
run_cmd "HW compress for gzip format in block mode" \
	uadk_tool test --m zip --alg 2 --in origin --out /tmp/ori.gz
```

2. Quiet Mode (run_cmd_quiet)

Suppress command output.
Example:
```
run_cmd_quiet "HW compress for gzip format in block mode" \
	uadk_tool test --m zip --alg 2 --in origin --out /tmp/ori.gz
```

**Test Summary Report**

A test summary report is generated.
```
Passed 46 test. Failed 0 test.
```
