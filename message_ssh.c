//
// Reference https://github.com/majek/openssl/blob/master/demos/evp/aesgcm.c
//

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Key = c96d6da9f5af4f67fa61a7bfce7b23fe
// IV = 5d9d77a12c40b962e9e0dace
// PT = 3d5e6534d036caf26ca3739acbfe8b684e780bc6fdf37b3db76b71cba0df105f039b738bd0cd4ada8ee6a27b46f4090e15b289
// AAD = 4f91837486d058d0f77bcadea96974b9a467c2d06350d49fec7ae15e6e45ea337d32a90143c1102fb7c611b1a044da68
// CT = cac4d0653eefa565c437483157bc3fc897c1d0de23248db4c47e88fd4ee1a3924010ad952547090c80d5acdcb3a6b7b8b0e503
// Tag = 1cc022ab2cea606862c08a095f16


// Key = cipher key 128 bits
static const unsigned char gcm_key[] = {

	0xc9, 0x6d, 0x6d, 0xa9, 0xf5, 0xaf, 0x4f, 0x67,
	0xfa, 0x61, 0xa7, 0xbf, 0xce, 0x7b, 0x23, 0xfe
};

// IV = Initialization Vector
static const unsigned char gcm_iv[] = {
	0x5d, 0x9d, 0x77, 0xa1, 0x2c, 0x40, 0xb9, 0x62,
	0xe9, 0xe0, 0xda, 0xce
};

// PT = Plain TextPT = Plain Text
static const unsigned char gcm_pt[] = {
	0x3d, 0x5e, 0x65, 0x34, 0xd0, 0x36, 0xca, 0xf2, 0x6c, 0xa3, 0x73, 0x9a,
	0xcb, 0xfe, 0x8b, 0x68, 0x4e, 0x78, 0x0b, 0xc6, 0xfd, 0xf3, 0x7b, 0x3d,
	0xb7, 0x6b, 0x71, 0xcb, 0xa0, 0xdf, 0x10, 0x5f, 0x03, 0x9b, 0x73, 0x8b,
	0xd0, 0xcd, 0x4a, 0xda, 0x8e, 0xe6, 0xa2, 0x7b, 0x46, 0xf4, 0x09, 0x0e,
	0x15, 0xb2, 0x89

};

// AAD = Additional Authentication Data
static const unsigned char gcm_aad[] = {
	0x4f, 0x91, 0x83, 0x74, 0x86, 0xd0, 0x58, 0xd0, 0xf7, 0x7b, 0xca, 0xde, 
	0xa9, 0x69, 0x74, 0xb9, 0xa4, 0x67, 0xc2, 0xd0, 0x63, 0x50, 0xd4, 0x9f, 
	0xec, 0x7a, 0xe1, 0x5e, 0x6e, 0x45, 0xea, 0x33, 0x7d, 0x32, 0xa9, 0x01,
	0x43, 0xc1, 0x10, 0x2f, 0xb7, 0xc6, 0x11, 0xb1, 0xa0, 0x44, 0xda, 0x68
};

// CT = Cipher Text
static const unsigned char gcm_ct[] = {
	0xca, 0xc4, 0xd0, 0x65, 0x3e, 0xef, 0xa5, 0x65, 0xc4, 0x37, 0x48, 0x31,
	0x57, 0xbc, 0x3f, 0xc8, 0x97, 0xc1, 0xd0, 0xde, 0x23, 0x24, 0x8d, 0xb4,
	0xc4, 0x7e, 0x88, 0xfd, 0x4e, 0xe1, 0xa3, 0x92, 0x40, 0x10, 0xad, 0x95,
	0x25, 0x47, 0x09, 0x0c, 0x80, 0xd5, 0xac, 0xdc, 0xb3, 0xa6, 0xb7, 0xb8,
	0xb0, 0xe5, 0x03
};

//Tag = ICV or Tag 
static const unsigned char gcm_tag[] = {
	0x1c, 0xc0, 0x22, 0xab, 0x2c, 0xea, 
	0x60, 0x68, 0x62, 0xc0, 0x8a, 0x09,
	0x5f, 0x16
};

void aes_gcm_encrypt(void);
void aes_gcm_decrypt(void);

int main(int argc, char **argv)
	{
	aes_gcm_encrypt();
	aes_gcm_decrypt();
	}

void aes_gcm_encrypt(void)
	{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;
	unsigned char outbuf[1024];
	printf("AES GCM Encrypt:\n");
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));
	ctx = EVP_CIPHER_CTX_new();
	
	/* Set cipher type and mode */
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
	
	/* Initialise key and IV */
	EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
	
	/* Zero or more calls to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
	
	/* Encrypt plaintext */
	EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
	
	/* Output encrypted block */
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, outbuf, outlen);
	
	/* Finalise: note get no output for GCM */
	EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
	
	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
	
	/* Output tag */
	printf("Tag:\n");
	BIO_dump_fp(stdout, outbuf, 16);
	EVP_CIPHER_CTX_free(ctx);
	}

void aes_gcm_decrypt(void)
	{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen, rv;
	unsigned char outbuf[1024];
	printf("AES GCM Derypt:\n");
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
	ctx = EVP_CIPHER_CTX_new();
	
	/* Select cipher */
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);

	/* Zero or more calls to specify any AAD */
	EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
	
	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
	
	/* Output decrypted block */
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, outbuf, outlen);
	
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag), gcm_tag);
	
	/* Finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
	
	printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
	EVP_CIPHER_CTX_free(ctx);
	}


	
