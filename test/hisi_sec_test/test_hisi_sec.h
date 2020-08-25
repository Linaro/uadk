// SPDX-License-Identifier: GPL-2.0+
#ifndef __TEST_HISI_SEC_H
#define __TEST_HISI_SEC_H

enum alg_class {
	CIPHER_CLASS,
	AEAD_CLASS,
	DIGEST_CLASS,
};

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

struct hash_testvec {
	const char *key;
	const char *plaintext;
	const char *digest;
	unsigned int psize;
	unsigned short ksize;
	unsigned int dsize;
};

struct hash_testvec sha256_tv_template[] = {
	{
		.plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
		.psize	= 64,
		.digest = "\xb5\xfe\xad\x56\x7d\xff\xcb\xa4"
			"\x2c\x32\x29\x32\x19\xbb\xfb\xfa"
			"\xd6\xff\x94\xa3\x72\x91\x85\x66"
			"\x3b\xa7\x87\x77\x58\xa3\x40\x3a",
		.dsize	= 32,
	}
};

struct cipher_testvec aes_ecb_tv_template_128[] = {
	{
		.key = "\x00\x01\x02\x03\x04\x05\x06\x07"
			"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		.klen = 16,
		.ptext = "\x00\x11\x22\x33\x44\x55\x66\x77"
			"\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
		.ctext	= "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30"
		  	"\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a",
		.len = 16,
	}	
};

/* 128bit */
struct cipher_testvec aes_cbc_tv_template_128[] = {
	{
		.key    = "\x06\xa9\x21\x40\x36\xb8\xa1\x5b"
			  "\x51\x2e\x03\xd5\x34\x12\x00\x06",
		.klen   = 16,
		.iv	= "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30"
			  "\xb4\x22\xda\x80\x2c\x9f\xac\x41",
		.iv_out	= "\xe3\x53\x77\x9c\x10\x79\xae\xb8"
			  "\x27\x08\x94\x2d\xbe\x77\x18\x1a",
		.ptext	= "Single block msg",
		.ctext	= "\xe3\x53\x77\x9c\x10\x79\xae\xb8"
			  "\x27\x08\x94\x2d\xbe\x77\x18\x1a",
		.len	= 16,
	}
};

#endif /* __TEST_HISI_SEC_H */
