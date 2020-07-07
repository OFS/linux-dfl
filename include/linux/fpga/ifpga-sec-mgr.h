/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for Intel FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#ifndef _LINUX_IFPGA_SEC_MGR_H
#define _LINUX_IFPGA_SEC_MGR_H

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
};

struct ifpga_sec_mgr {
	const char *name;
	struct device dev;
	const struct ifpga_sec_mgr_ops *iops;
	struct mutex lock;		/* protect data structure contents */
	void *priv;
};

struct ifpga_sec_mgr *
ifpga_sec_mgr_register(struct device *dev, const char *name,
		       const struct ifpga_sec_mgr_ops *iops, void *priv);
void ifpga_sec_mgr_unregister(struct ifpga_sec_mgr *imgr);

#endif
