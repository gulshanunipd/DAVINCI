# Build with the OP-TEE TA dev kit:
#   make TA_DEV_KIT_DIR=<optee_os out>/export-ta_arm64 CROSS_COMPILE=aarch64-linux-gnu-
# Add EXTRA_CFLAGS=-DDAVINCI_BACKDOOR for the compromised variant.
BINARY = 3ef86ac2-55b2-4243-810a-33347fcd1d5d
CFLAGS += $(EXTRA_CFLAGS)
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
