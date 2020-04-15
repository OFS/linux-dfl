/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for Intel FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#ifndef _LINUX_IFPGA_SEC_MGR_H
#define _LINUX_IFPGA_SEC_MGR_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/mutex.h>

struct ifpga_sec_mgr;

/**
 * typedef sysfs_reh_hndlr_t - Function pointer to sysfs file handler
 *			       for root entry hashes
 * @imgr:      pointer to security manager structure
 * @hash:      pointer to a pointer to an array of bytes comprising the hash
 * @hash_size: pointer to the number of bytes in the root entry hash
 *
 * This datatype is used to define a sysfs file handler function to
 * return root entry hash data to be displayed via sysfs.
 *
 * Context: No locking requirements are imposed by the security manager.
 *          The function is expected to vmalloc the hash array on success.
 *	    The security manager is responsible for calling vfree.
 * Return:  0 on success, negative errno on failure
 */
typedef int (*sysfs_reh_hndlr_t)(struct ifpga_sec_mgr *imgr,
				 u8 **hash, unsigned int *hash_size);

/**
 * typedef sysfs_cnt_hndlr_t - Function pointer to sysfs file handler
 *			       for flash counts
 * @imgr: pointer to security manager structure
 *
 * This datatype is used to define a sysfs file handler function to
 * return a flash count to be displayed via sysfs.
 *
 * Context: No locking requirements are imposed by the security manager
 * Return: flash count or negative errno
 */
typedef int (*sysfs_cnt_hndlr_t)(struct ifpga_sec_mgr *imgr);

/**
 * typedef sysfs_csk_hndlr_t - Function pointer to sysfs file handler
 *			       bit vector of canceled keys
 *
 * @imgr:    pointer to security manager structure
 * @csk_map: pointer to a pointer of a cancellation key bitmap
 * @nbits:   number of bits in cancellation key bitmap
 *
 * This datatype is used to define a sysfs file handler function to
 * return a bitmap of canceled keys to be displayed via sysfs.
 *
 * Context: No locking requirements are imposed by the security manager.
 *          The function is expected to vmalloc the cancellation key bitmap
 *	    on success. The security manager is responsible for calling
 *	    vfree.
 * Return:  0 on success, negative errno on failure
 */
typedef int (*sysfs_csk_hndlr_t)(struct ifpga_sec_mgr *imgr,
				 unsigned long **csk_map, unsigned int *nbits);

/**
 * struct ifpga_sec_mgr_ops - device specific operations
 * @user_flash_count:	 Optional: Return sysfs string output for FPGA
 *			 image flash count
 * @bmc_flash_count:	 Optional: Return sysfs string output for BMC
 *			 image flash count
 * @sr_root_entry_hash:	 Optional: Return sysfs string output for static
 *			 region root entry hash
 * @pr_root_entry_hash:	 Optional: Return sysfs string output for partial
 *			 reconfiguration root entry hash
 * @bmc_root_entry_hash: Optional: Return sysfs string output for BMC
 *			 root entry hash
 * @sr_canceled_csks:	 Optional: Return sysfs string output for static
 *			 region canceled keys
 * @pr_canceled_csks:	 Optional: Return sysfs string output for partial
 *			 reconfiguration canceled keys
 * @bmc_canceled_csks:	 Optional: Return sysfs string output for bmc
 *			 canceled keys
 * @prepare:		 Required: Prepare secure update
 * @write_blk:		 Required: Write a block of data
 * @poll_complete:	 Required: Check for the completion of the
 *			 HW authentication/programming function
 * @cancel:		 Required: Signal HW to cancel update
 * @cleanup:		 Optional: Complements the prepare()
 *			 function and is called at the completion
 *			 of the update, whether success or failure,
 *			 iff the prepare function succeeded.
 */
struct ifpga_sec_mgr_ops {
	sysfs_cnt_hndlr_t user_flash_count;
	sysfs_cnt_hndlr_t bmc_flash_count;
	sysfs_cnt_hndlr_t smbus_flash_count;
	sysfs_reh_hndlr_t sr_root_entry_hash;
	sysfs_reh_hndlr_t pr_root_entry_hash;
	sysfs_reh_hndlr_t bmc_root_entry_hash;
	sysfs_csk_hndlr_t sr_canceled_csks;
	sysfs_csk_hndlr_t pr_canceled_csks;
	sysfs_csk_hndlr_t bmc_canceled_csks;
	int (*prepare)(struct ifpga_sec_mgr *imgr);
	int (*write_blk)(struct ifpga_sec_mgr *imgr, u32 offset, u32 size);
	int (*poll_complete)(struct ifpga_sec_mgr *imgr);
	void (*cleanup)(struct ifpga_sec_mgr *imgr);
	int (*cancel)(struct ifpga_sec_mgr *imgr);
};

/* Update progress codes */
#define IFPGA_SEC_PROG_IDLE			0x0
#define IFPGA_SEC_PROG_READ_FILE		0x1
#define IFPGA_SEC_PROG_PREPARING		0x2
#define IFPGA_SEC_PROG_WRITING			0x3
#define IFPGA_SEC_PROG_PROGRAMMING		0x4
#define IFPGA_SEC_PROG_MAX			0x5

struct ifpga_sec_mgr {
	const char *name;
	struct device dev;
	const struct ifpga_sec_mgr_ops *iops;
	struct mutex lock;	/* protect data structure contents */
	struct work_struct work;
	char *filename;
	const u8 *data;		/* pointer to update data */
	u32 remaining_size;	/* size remaining to transfer */
	u32 progress;
	int err_state;		/* progress state at time of failure */
	int err_code;		/* negative errno value on failure */
	bool request_cancel;
	bool driver_unload;
	void *priv;
};

int ifpga_sec_mgr_register(struct ifpga_sec_mgr *imgr);
void ifpga_sec_mgr_unregister(struct ifpga_sec_mgr *imgr);
struct ifpga_sec_mgr *
ifpga_sec_mgr_create(struct device *dev, const char *name,
		     const struct ifpga_sec_mgr_ops *iops, void *priv);
void ifpga_sec_mgr_free(struct ifpga_sec_mgr *imgr);

#endif
