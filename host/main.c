/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypted_key[2] = {0,};
	int len=64;

	FILE *fp = 0;

	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if(strcmp(argv[0],"TEEencrypt") == 0)
	{
		if(strcmp(argv[1],"-e") == 0)
		{
			printf("========================Encryption========================\n");

			if(fp=fopen(argv[2], "r"))
			{
				fgets(plaintext, sizeof(plaintext), fp);
				memcpy(op.params[0].tmpref.buffer, plaintext, len);
				printf("Plaintext : %s", op.params[0].tmpref.buffer);
				fclose(fp);
			}

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);

			if(fp = fopen("ciphertext.txt", "w"))
			{
				fprintf(fp,op.params[0].tmpref.buffer);
				printf("Ciphertext : %s", op.params[0].tmpref.buffer);
				fclose(fp);
			}
			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
				 &err_origin);

			if(fp = fopen("encryptedkey.txt", "w"))
			{
				fprintf(fp,op.params[0].tmpref.buffer);
				printf("Encryptedkey : %s\n", op.params[0].tmpref.buffer);
				fclose(fp);
			}
		}
		else if(strcmp(argv[1],"-d") == 0)
		{
			printf("========================Decryption========================\n");

			if(fp=fopen(argv[2], "r"))
			{
				fgets(ciphertext, sizeof(ciphertext), fp);
				printf("Ciphertext : %s", ciphertext);
				fclose(fp);
			}
			
			if(fp=fopen(argv[3], "r"))
			{
				fgets(encrypted_key, sizeof(encrypted_key), fp);
				printf("Encryptedkey : %s\n", encrypted_key);
				fclose(fp);
			}
			
			memcpy(op.params[0].tmpref.buffer, encrypted_key, len);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
				 &err_origin);

			if(fp = fopen("Randomkey.txt", "w"))
			{
				fprintf(fp,op.params[0].tmpref.buffer);
				printf("Randomkey : %s\n", op.params[0].tmpref.buffer);
				fclose(fp);
			}

			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
			if(fp = fopen("Decryptedtext.txt", "w"))
			{
				fprintf(fp,op.params[0].tmpref.buffer);
				printf("Plaintext : %s\n", op.params[0].tmpref.buffer);
				fclose(fp);
			}

		}
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

