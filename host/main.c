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

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct ta_attrs
{
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ta->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
    TEEC_CloseSession(&ta->sess);
    TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz)
{
    memset(op, 0, sizeof(*op));

    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_NONE, TEEC_NONE);
    op->params[0].tmpref.buffer = in;
    op->params[0].tmpref.size = in_sz;
    op->params[1].tmpref.buffer = out;
    op->params[1].tmpref.size = out_sz;
}

void rsa_gen_keys(struct ta_attrs *ta)
{
    TEEC_Result res;

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
    printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    printf("\n============ RSA ENCRYPT CA SIDE ============\n");
    prepare_op(&op, in, in_sz, out, out_sz);

    res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
                             &op, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
             res, origin);
    printf("\nThe text sent was encrypted: %s\n", out);
}

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t err_origin;

    char plaintext[1024] = {
        0,
    };
    char ciphertext[1024] = {
        0,
    };
    char encrypted_key[2] = {
        0,
    };
    int len = 1024;

    FILE *fp = 0;

    res = TEEC_InitializeContext(NULL, &ctx);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = plaintext;
    op.params[0].tmpref.size = len;

    if (strcmp(argv[0], "TEEencrypt") == 0)
    {
        if (strcmp(argv[1], "-e") == 0)
        {
            printf("========================Encryption========================\n");

            if (fp = fopen(argv[2], "r"))
            {
                fgets(plaintext, sizeof(plaintext), fp);
                memcpy(op.params[0].tmpref.buffer, plaintext, len);
                printf("Plaintext : %s", op.params[0].tmpref.buffer);
                fclose(fp);
            }

            if (strcmp(argv[3], "Caesar") == 0)
            {
                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
                                         &err_origin);

                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
                                         &err_origin);

                if (fp = fopen("ciphertext.txt", "w"))
                {
                    fprintf(fp, op.params[0].tmpref.buffer);
                    printf("Ciphertext : %s", op.params[0].tmpref.buffer);
                    fclose(fp);
                }

                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
                                         &err_origin);

                if (fp = fopen("encryptedkey.txt", "w"))
                {
                    fprintf(fp, op.params[0].tmpref.buffer);
                    printf("Encryptedkey : %s\n", op.params[0].tmpref.buffer);
                    fclose(fp);
                }
            }
            else if (strcmp(argv[3], "RSA") == 0)
            {
                struct ta_attrs ta;

                prepare_ta_session(&ta);

                rsa_gen_keys(&ta);
                rsa_encrypt(&ta, plaintext, RSA_MAX_PLAIN_LEN_1024, ciphertext, RSA_CIPHER_LEN_1024);
                if (fp = fopen("ciphertext.txt", "w"))
                {
                    fprintf(fp, ciphertext);
                    fclose(fp);
                }

                terminate_tee_session(&ta);
            }
        }
        else if (strcmp(argv[1], "-d") == 0)
        {
            printf("========================Decryption========================\n");

            if (fp = fopen(argv[2], "r"))
            {
                fgets(ciphertext, sizeof(ciphertext), fp);
                printf("Ciphertext : %s", ciphertext);
                fclose(fp);
            }

            if (fp = fopen(argv[3], "r"))
            {
                fgets(encrypted_key, sizeof(encrypted_key), fp);
                printf("Encryptedkey : %s\n", encrypted_key);
                fclose(fp);
            }

            memcpy(op.params[0].tmpref.buffer, encrypted_key, len);
            res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
                                     &err_origin);

            if (fp = fopen("Randomkey.txt", "w"))
            {
                fprintf(fp, op.params[0].tmpref.buffer);
                printf("Randomkey : %s\n", op.params[0].tmpref.buffer);
                fclose(fp);
            }

            memcpy(op.params[0].tmpref.buffer, ciphertext, len);
            res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
                                     &err_origin);
            if (fp = fopen("Decryptedtext.txt", "w"))
            {
                fprintf(fp, op.params[0].tmpref.buffer);
                printf("Plaintext : %s\n", op.params[0].tmpref.buffer);
                fclose(fp);
            }
        }
    }

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}

