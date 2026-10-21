// SPDX-License-Identifier: BSD-2-Clause
/*
 * DAVINCI workload Trusted Application.
 *
 * Two roles:
 *  1. Attestation proxy: the OP-TEE attestation PTA only signs a TA-memory
 *     hash for the TA that calls it, so this TA calls the PTA on behalf of the
 *     normal-world collector and returns the signed TEE-core hash, its own
 *     runtime memory hash and its signed-header digest.
 *  2. Workload: a small keyed service (HMAC under a TA-held secret). Building
 *     with -DDAVINCI_BACKDOOR yields a "compromised" variant that also leaks
 *     the secret; it is signed with the same key and has the same UUID, so
 *     OP-TEE loads it, but its code differs and the runtime memory hash no
 *     longer matches the reference value.
 */
#include <string.h>
#include <tee_internal_api.h>
#include <pta_attestation.h>
#include <davinci_ta.h>

static const uint8_t workload_secret[32] = "davinci-workload-secret-000000";

static TEE_Result open_pta(TEE_TASessionHandle *sess)
{
	const TEE_UUID pta = PTA_ATTESTATION_UUID;
	uint32_t origin = 0;

	return TEE_OpenTASession(&pta, TEE_TIMEOUT_INFINITE, 0, NULL, sess,
				 &origin);
}

static TEE_Result get_pubkey(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_VALUE_OUTPUT,
					     TEE_PARAM_TYPE_NONE);
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param p[TEE_NUM_PARAMS] = { };
	uint32_t origin = 0;
	TEE_Result res = TEE_SUCCESS;

	if (pt != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	res = open_pta(&sess);
	if (res)
		return res;

	p[0].memref.buffer = params[0].memref.buffer;
	p[0].memref.size = params[0].memref.size;
	p[1].memref.buffer = params[1].memref.buffer;
	p[1].memref.size = params[1].memref.size;
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_ATTESTATION_GET_PUBKEY, exp, p, &origin);
	params[0].memref.size = p[0].memref.size;
	params[1].memref.size = p[1].memref.size;
	params[2].value.a = p[2].value.a;
	TEE_CloseTASession(sess);
	return res;
}

static TEE_Result pta_hash(TEE_TASessionHandle sess, uint32_t cmd,
			   void *nonce, size_t nonce_sz, TEE_Param *out)
{
	const uint32_t pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_OUTPUT,
					    TEE_PARAM_TYPE_NONE,
					    TEE_PARAM_TYPE_NONE);
	TEE_Param p[TEE_NUM_PARAMS] = { };
	uint32_t origin = 0;
	TEE_Result res = TEE_SUCCESS;

	p[0].memref.buffer = nonce;
	p[0].memref.size = nonce_sz;
	p[1].memref.buffer = out->memref.buffer;
	p[1].memref.size = out->memref.size;
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd, pt, p,
				  &origin);
	out->memref.size = p[1].memref.size;
	return res;
}

static TEE_Result pta_shdr_digest(TEE_TASessionHandle sess, void *nonce,
				  size_t nonce_sz, TEE_Param *out)
{
	const uint32_t pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_MEMREF_OUTPUT,
					    TEE_PARAM_TYPE_NONE);
	TEE_Param p[TEE_NUM_PARAMS] = { };
	TEE_UUID self = { };
	uint32_t origin = 0;
	TEE_Result res = TEE_SUCCESS;

	res = TEE_GetPropertyAsUUID(TEE_PROPSET_CURRENT_TA, "gpd.ta.appID",
				    &self);
	if (res)
		return res;

	p[0].memref.buffer = &self;
	p[0].memref.size = sizeof(self);
	p[1].memref.buffer = nonce;
	p[1].memref.size = nonce_sz;
	p[2].memref.buffer = out->memref.buffer;
	p[2].memref.size = out->memref.size;
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_ATTESTATION_GET_TA_SHDR_DIGEST, pt, p,
				  &origin);
	out->memref.size = p[2].memref.size;
	return res;
}

static TEE_Result attest(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT);
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	void *nonce = NULL;
	size_t nonce_sz = 0;

	if (pt != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	/* The PTA rejects buffers shared with the normal world; copy the nonce. */
	nonce_sz = params[0].memref.size;
	if (!nonce_sz || nonce_sz > 64)
		return TEE_ERROR_BAD_PARAMETERS;
	nonce = TEE_Malloc(nonce_sz, 0);
	if (!nonce)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(nonce, params[0].memref.buffer, nonce_sz);

	res = open_pta(&sess);
	if (res)
		goto out;

	res = pta_hash(sess, PTA_ATTESTATION_HASH_TEE_MEMORY, nonce, nonce_sz,
		       &params[1]);
	if (!res)
		res = pta_hash(sess, PTA_ATTESTATION_HASH_TA_MEMORY, nonce,
			       nonce_sz, &params[2]);
	if (!res)
		res = pta_shdr_digest(sess, nonce, nonce_sz, &params[3]);

	TEE_CloseTASession(sess);
out:
	TEE_Free(nonce);
	return res;
}

static TEE_Result work(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_Attribute attr = { };
	TEE_Result res = TEE_SUCCESS;
	size_t out_sz = 0;

	if (pt != exp)
		return TEE_ERROR_BAD_PARAMETERS;

#ifdef DAVINCI_BACKDOOR
	/* Compromised build: exfiltrates the workload secret. */
	if (params[1].memref.size >= sizeof(workload_secret)) {
		TEE_MemMove(params[1].memref.buffer, workload_secret,
			    sizeof(workload_secret));
		params[1].memref.size = sizeof(workload_secret);
		return TEE_SUCCESS;
	}
#endif

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256, &key);
	if (res)
		return res;
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, workload_secret,
			     sizeof(workload_secret));
	res = TEE_PopulateTransientObject(key, &attr, 1);
	if (res)
		goto out;
	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
				    256);
	if (res)
		goto out;
	res = TEE_SetOperationKey(op, key);
	if (res)
		goto out;
	TEE_MACInit(op, NULL, 0);
	out_sz = params[1].memref.size;
	res = TEE_MACComputeFinal(op, params[0].memref.buffer,
				  params[0].memref.size,
				  params[1].memref.buffer, &out_sz);
	params[1].memref.size = out_sz;
out:
	if (op)
		TEE_FreeOperation(op);
	TEE_FreeTransientObject(key);
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[TEE_NUM_PARAMS] __unused,
				    void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused, uint32_t cmd,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case DAVINCI_CMD_GET_PUBKEY:
		return get_pubkey(pt, params);
	case DAVINCI_CMD_ATTEST:
		return attest(pt, params);
	case DAVINCI_CMD_WORK:
		return work(pt, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
