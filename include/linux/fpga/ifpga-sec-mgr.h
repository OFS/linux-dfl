/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for Intel FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#ifndef _LINUX_IFPGA_SEC_MGR_H
#define _LINUX_IFPGA_SEC_MGR_H

#include <linux/completion.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct ifpga_sec_mgr;

/**
 * typedef sysfs_reh_size_t - Function to return byte size of root entry hash
 *
 * @imgr:      pointer to security manager structure
 *
 * This datatype is used to define a function that returns the byte size of a
 * root entry hash.
 *
 * Context: No locking requirements are imposed by the security manager.
 * Return:  Byte count on success, negative errno on failure
 */
typedef int (*sysfs_reh_size_t)(struct ifpga_sec_mgr *imgr);

/**
 * typedef sysfs_reh_hndlr_t - Function pointer to sysfs file handler
 *			       for root entry hashes
 * @imgr:      pointer to security manager structure
 * @hash:      pointer to an array of bytes in which to store the hash
 * @size:      byte size of root entry hash
 *
 * This datatype is used to define a sysfs file handler function to
 * return root entry hash data to be displayed via sysfs.
 *
 * Context: No locking requirements are imposed by the security manager.
 * Return:  0 on success, negative errno on failure
 */
typedef int (*sysfs_reh_hndlr_t)(struct ifpga_sec_mgr *imgr, u8 *hash,
				 unsigned int size);

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
 * typedef sysfs_csk_nbits_t - Function to return the number of bits in
 *				      a Code Signing Key cancellation vector
 *
 * @imgr:      pointer to security manager structure
 *
 * This datatype is used to define a function that returns the number of bits
 * in a Code Signing Key cancellation vector.
 *
 * Context: No locking requirements are imposed by the security manager.
 * Return:  Number of bits on success, negative errno on failure
 */
typedef int (*sysfs_csk_nbits_t)(struct ifpga_sec_mgr *imgr);

/**
 * typedef sysfs_csk_hndlr_t - Function pointer to sysfs file handler
 *			       bit vector of canceled keys
 *
 * @imgr:    pointer to security manager structure
 * @csk_map: pointer to a bitmap to contain cancellation key vector
 * @nbits:   number of bits in CSK vector
 *
 * This datatype is used to define a sysfs file handler function to
 * return a bitmap of canceled keys to be displayed via sysfs.
 *
 * Context: No locking requirements are imposed by the security manager.
 * Return:  0 on success, negative errno on failure
 */
typedef int (*sysfs_csk_hndlr_t)(struct ifpga_sec_mgr *imgr,
				 unsigned long *csk_map, unsigned int nbits);

enum ifpga_sec_err {
	IFPGA_SEC_ERR_NONE	   = 0x0,
	IFPGA_SEC_ERR_HW_ERROR	   = 0x1,
	IFPGA_SEC_ERR_TIMEOUT	   = 0x2,
	IFPGA_SEC_ERR_CANCELED	   = 0x3,
	IFPGA_SEC_ERR_BUSY	   = 0x4,
	IFPGA_SEC_ERR_INVALID_SIZE = 0x5,
	IFPGA_SEC_ERR_RW_ERROR	   = 0x6,
	IFPGA_SEC_ERR_WEAROUT	   = 0x7,
	IFPGA_SEC_ERR_FILE_READ	   = 0x8,
	IFPGA_SEC_ERR_MAX	   = 0x9
};

/**
 * struct image_load - device specific image-load triggers
 * @name:	    Required: keyword used to enable the trigger
 * @load_image:	    Required: pointer to the trigger callback function
 */
struct image_load {
	const char *name;
	int (*load_image)(struct ifpga_sec_mgr *imgr);
};

/**
 * struct ifpga_sec_mgr_ops - device specific operations
 * @user_flash_count:	    Optional: Return sysfs string output for FPGA
 *			    image flash count
 * @bmc_flash_count:	    Optional: Return sysfs string output for BMC
 *			    image flash count
 * @sr_root_entry_hash:	    Optional: Return sysfs string output for static
 *			    region root entry hash
 * @pr_root_entry_hash:	    Optional: Return sysfs string output for partial
 *			    reconfiguration root entry hash
 * @bmc_root_entry_hash:    Optional: Return sysfs string output for BMC
 *			    root entry hash
 * @sr_canceled_csks:	    Optional: Return sysfs string output for static
 *			    region canceled keys
 * @pr_canceled_csks:	    Optional: Return sysfs string output for partial
 *			    reconfiguration canceled keys
 * @bmc_canceled_csks:	    Optional: Return sysfs string output for bmc
 *			    canceled keys
 * @bmc_canceled_csk_nbits: Optional: Return BMC canceled csk vector bit count
 * @sr_canceled_csk_nbits:  Optional: Return SR canceled csk vector bit count
 * @pr_canceled_csk_nbits:  Optional: Return PR canceled csk vector bit count
 * @bmc_reh_size:	    Optional: Return byte size for BMC root entry hash
 * @sr_reh_size:	    Optional: Return byte size for SR root entry hash
 * @pr_reh_size:	    Optional: Return byte size for PR root entry hash
 * @prepare:		    Required: Prepare secure update
 * @write_blk:		    Required: Write a block of data
 * @poll_complete:	    Required: Check for the completion of the
 *			    HW authentication/programming process. This
 *			    function should check for imgr->driver_unload
 *			    and abort with IFPGA_SEC_ERR_CANCELED when true.
 * @cancel:		    Required: Signal HW to cancel update
 * @cleanup:		    Optional: Complements the prepare()
 *			    function and is called at the completion
 *			    of the update, whether success or failure,
 *			    if the prepare function succeeded.
 * @get_hw_errinfo:	    Optional: Return u64 hw specific error info.
 *			    The software err_code may used to determine
 *			    whether the hw error info is applicable.
 * @image_load:		    pointer to array of image_load structures,
 *			    { } member terminated. These structures describe
 *			    image load triggers for BMC, FPGA, or firmware
 *			    images.
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
	sysfs_reh_size_t bmc_reh_size;
	sysfs_reh_size_t sr_reh_size;
	sysfs_reh_size_t pr_reh_size;
	sysfs_csk_nbits_t bmc_canceled_csk_nbits;
	sysfs_csk_nbits_t sr_canceled_csk_nbits;
	sysfs_csk_nbits_t pr_canceled_csk_nbits;
	enum ifpga_sec_err (*prepare)(struct ifpga_sec_mgr *imgr);
	enum ifpga_sec_err (*write_blk)(struct ifpga_sec_mgr *imgr,
					u32 offset, u32 size);
	enum ifpga_sec_err (*poll_complete)(struct ifpga_sec_mgr *imgr);
	void (*cleanup)(struct ifpga_sec_mgr *imgr);
	enum ifpga_sec_err (*cancel)(struct ifpga_sec_mgr *imgr);
	u64 (*get_hw_errinfo)(struct ifpga_sec_mgr *imgr);
	struct image_load *image_load;	/* terminated with { } member */
};

/* Update progress codes */
enum ifpga_sec_prog {
	IFPGA_SEC_PROG_IDLE	   = 0x0,
	IFPGA_SEC_PROG_READ_FILE   = 0x1,
	IFPGA_SEC_PROG_PREPARING   = 0x2,
	IFPGA_SEC_PROG_WRITING	   = 0x3,
	IFPGA_SEC_PROG_PROGRAMMING = 0x4,
	IFPGA_SEC_PROG_MAX	   = 0x5
};

struct ifpga_sec_mgr {
	const char *name;
	struct device dev;
	const struct ifpga_sec_mgr_ops *iops;
	struct mutex lock;		/* protect data structure contents */
	struct work_struct work;
	struct completion update_done;
	char *filename;
	const u8 *data;			/* pointer to update data */
	u32 remaining_size;		/* size remaining to transfer */
	enum ifpga_sec_prog progress;
	enum ifpga_sec_prog err_state;	/* progress state at time of failure */
	enum ifpga_sec_err err_code;	/* security manager error code */
	u64 hw_errinfo;			/* 64 bits of HW specific error info */
	bool request_cancel;
	bool driver_unload;
	void *priv;
};

struct ifpga_sec_mgr *
ifpga_sec_mgr_register(struct device *dev, const char *name,
		       const struct ifpga_sec_mgr_ops *iops, void *priv);
void ifpga_sec_mgr_unregister(struct ifpga_sec_mgr *imgr);

#endif
