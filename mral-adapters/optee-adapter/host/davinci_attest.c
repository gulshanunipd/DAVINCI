// SPDX-License-Identifier: BSD-2-Clause
/*
 * davinci-attest — normal-world collector for the OP-TEE Root of Trust.
 *
 *   davinci-attest pubkey          -> {"e":..,"n":..,"alg":..}
 *   davinci-attest attest <nonce>  -> signed TEE-core / TA-memory / TA-header
 *                                     evidence bound to <nonce> (hex)
 *   davinci-attest work <hex>      -> run the workload (HMAC) on <hex>
 *
 * Output is JSON on stdout; the guest serves it over HTTP (cgi-bin/attest) to
 * the MRAL in the Attestation Manager, which verifies every signature.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <davinci_ta.h>

#define OUT_SZ 1024

static TEEC_Context ctx;
static TEEC_Session sess;

static void die(const char *what, TEEC_Result res, uint32_t origin)
{
	printf("{\"error\":\"%s\",\"code\":\"0x%08x\",\"origin\":%u}\n", what,
	       res, origin);
	exit(1);
}

static void print_hex(const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++)
		printf("%02x", b[i]);
}

static size_t parse_hex(const char *s, uint8_t *out, size_t max)
{
	size_t n = strlen(s) / 2;

	if (n > max || strlen(s) % 2)
		return 0;
	for (size_t i = 0; i < n; i++) {
		unsigned int v = 0;

		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			return 0;
		out[i] = v;
	}
	return n;
}

static void open_ta(void)
{
	TEEC_UUID uuid = DAVINCI_TA_UUID;
	uint32_t origin = 0;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		die("TEEC_InitializeContext", res, 0);
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &origin);
	if (res != TEEC_SUCCESS)
		die("TEEC_OpenSession", res, origin);
}

static void cmd_pubkey(void)
{
	uint8_t e[16] = { }, n[OUT_SZ] = { };
	TEEC_Operation op = { };
	uint32_t origin = 0;
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = e;
	op.params[0].tmpref.size = sizeof(e);
	op.params[1].tmpref.buffer = n;
	op.params[1].tmpref.size = sizeof(n);
	res = TEEC_InvokeCommand(&sess, DAVINCI_CMD_GET_PUBKEY, &op, &origin);
	if (res != TEEC_SUCCESS)
		die("GET_PUBKEY", res, origin);

	printf("{\"rot\":\"optee\",\"e\":\"");
	print_hex(e, op.params[0].tmpref.size);
	printf("\",\"n\":\"");
	print_hex(n, op.params[1].tmpref.size);
	printf("\",\"alg\":\"0x%08x\"}\n", op.params[2].value.a);
}

static void print_signed(const char *name, const uint8_t *b, size_t n,
			 int last)
{
	printf("\"%s\":{\"hash\":\"", name);
	print_hex(b, 32);
	printf("\",\"sig\":\"");
	print_hex(b + 32, n - 32);
	printf("\"}%s", last ? "" : ",");
}

static void cmd_attest(const char *nonce_hex)
{
	uint8_t nonce[64] = { };
	uint8_t tee[OUT_SZ] = { }, ta[OUT_SZ] = { }, shdr[OUT_SZ] = { };
	TEEC_Operation op = { };
	uint32_t origin = 0;
	TEEC_Result res;
	size_t nonce_sz = parse_hex(nonce_hex, nonce, sizeof(nonce));

	if (!nonce_sz)
		die("bad nonce", 0, 0);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = nonce_sz;
	op.params[1].tmpref.buffer = tee;
	op.params[1].tmpref.size = sizeof(tee);
	op.params[2].tmpref.buffer = ta;
	op.params[2].tmpref.size = sizeof(ta);
	op.params[3].tmpref.buffer = shdr;
	op.params[3].tmpref.size = sizeof(shdr);
	res = TEEC_InvokeCommand(&sess, DAVINCI_CMD_ATTEST, &op, &origin);
	if (res != TEEC_SUCCESS)
		die("ATTEST", res, origin);

	printf("{\"rot\":\"optee\",\"ta_uuid\":"
	       "\"3ef86ac2-55b2-4243-810a-33347fcd1d5d\",\"nonce\":\"%s\",",
	       nonce_hex);
	print_signed("tee_core", tee, op.params[1].tmpref.size, 0);
	print_signed("ta_memory", ta, op.params[2].tmpref.size, 0);
	print_signed("ta_shdr", shdr, op.params[3].tmpref.size, 1);
	printf("}\n");
}

static void cmd_work(const char *in_hex)
{
	uint8_t in[256] = { }, out[64] = { };
	TEEC_Operation op = { };
	uint32_t origin = 0;
	TEEC_Result res;
	size_t in_sz = parse_hex(in_hex, in, sizeof(in));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = in_sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sizeof(out);
	res = TEEC_InvokeCommand(&sess, DAVINCI_CMD_WORK, &op, &origin);
	if (res != TEEC_SUCCESS)
		die("WORK", res, origin);
	printf("{\"out\":\"");
	print_hex(out, op.params[1].tmpref.size);
	printf("\"}\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s pubkey | attest <nonce-hex> | work <hex>\n",
			argv[0]);
		return 2;
	}
	open_ta();
	if (!strcmp(argv[1], "pubkey"))
		cmd_pubkey();
	else if (!strcmp(argv[1], "attest") && argc > 2)
		cmd_attest(argv[2]);
	else if (!strcmp(argv[1], "work") && argc > 2)
		cmd_work(argv[2]);
	else
		die("unknown command", 0, 0);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
