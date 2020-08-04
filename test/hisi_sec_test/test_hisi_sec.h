// SPDX-License-Identifier: GPL-2.0+
#ifndef TEST_HISI_SEC_H_
#define TEST_HISI_SEC_H
enum cipher_op_type {
	ENCRYPTION,
	DECRYPTION,
};
enum cipher_alg {
	CIPHER_SM4,
	CIPHER_AES,
	CIPHER_DES,
	CIPHER_3DES,
};

enum cipher_mode {
	ECB,
	CBC,
	CTR,
	XTS,
};

struct cipher_testvec {
	const char *key;
	int klen;
	const char *iv;
	int ivlen;
	const char *iv_out;
	const char *ptext;
	const char *ctext;
	int len;
};

struct cipher_testvec aes_ecb_tv_template_128[] = {
	{
		.key = "\x00\x01\x02\x03\x04\x05\x06\x07"
			"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		.klen = 16,
		.ptext = "\x00\x11\x22\x33\x44\x55\x66\x77"
			"x88\x99\xaa\xbb\xcc\xdd\xee\xff",
		.len = 16,
	}	
};
#endif /* TEST_HISI_SEC_H_ */
