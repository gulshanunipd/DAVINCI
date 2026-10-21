/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DAVINCI workload Trusted Application — shared definitions (TA <-> CA).
 *
 * The TA is the TEE-resident workload attested by the OP-TEE Root of Trust.
 * It forwards attestation requests to the OP-TEE attestation PTA, which signs
 * runtime hashes of the TEE core and of this TA's own memory with the device
 * attestation key (RSASSA-PSS / SHA-256, key kept in OP-TEE secure storage).
 */
#ifndef DAVINCI_TA_H
#define DAVINCI_TA_H

/* 3ef86ac2-55b2-4243-810a-33347fcd1d5d */
#define DAVINCI_TA_UUID \
	{ 0x3ef86ac2, 0x55b2, 0x4243, \
		{ 0x81, 0x0a, 0x33, 0x34, 0x7f, 0xcd, 0x1d, 0x5d } }

/*
 * Return the PTA attestation public key.
 * [out] memref[0] exponent (big endian)
 * [out] memref[1] modulus (big endian)
 * [out] value[2].a signature algorithm (TEE_ALG_*)
 */
#define DAVINCI_CMD_GET_PUBKEY		0

/*
 * Produce signed runtime evidence bound to a caller nonce.
 * [in]  memref[0] nonce
 * [out] memref[1] TEE core memory: SHA-256 hash || signature
 * [out] memref[2] this TA's memory: SHA-256 hash || signature
 * [out] memref[3] this TA's signed-header digest || signature
 * Each signature is RSASSA-PSS(SHA-256(nonce || hash)), salt length 32.
 */
#define DAVINCI_CMD_ATTEST		1

/* Workload operation: HMAC-SHA256 of the input under a TA-held secret. */
#define DAVINCI_CMD_WORK		2

#endif /* DAVINCI_TA_H */
