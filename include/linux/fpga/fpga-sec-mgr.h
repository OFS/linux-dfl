/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#ifndef _LINUX_FPGA_SEC_MGR_H
#define _LINUX_FPGA_SEC_MGR_H

#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct fpga_sec_mgr;

/**
 * struct fpga_sec_mgr_ops - device specific operations
 * @user_flash_count:	    Optional: Return sysfs string output for FPGA
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
struct fpga_sec_mgr_ops {
	int (*user_flash_count)(struct fpga_sec_mgr *smgr);
	int (*bmc_root_entry_hash)(struct fpga_sec_mgr *smgr, u8 *hash,
				   unsigned int size);
	int (*sr_root_entry_hash)(struct fpga_sec_mgr *smgr, u8 *hash,
				  unsigned int size);
	int (*pr_root_entry_hash)(struct fpga_sec_mgr *smgr, u8 *hash,
				  unsigned int size);
	int (*bmc_canceled_csks)(struct fpga_sec_mgr *smgr,
				 unsigned long *csk_map, unsigned int nbits);
	int (*sr_canceled_csks)(struct fpga_sec_mgr *smgr,
				unsigned long *csk_map, unsigned int nbits);
	int (*pr_canceled_csks)(struct fpga_sec_mgr *smgr,
				unsigned long *csk_map, unsigned int nbits);
	int (*bmc_reh_size)(struct fpga_sec_mgr *smgr);
	int (*sr_reh_size)(struct fpga_sec_mgr *smgr);
	int (*pr_reh_size)(struct fpga_sec_mgr *smgr);
	int (*bmc_canceled_csk_nbits)(struct fpga_sec_mgr *smgr);
	int (*sr_canceled_csk_nbits)(struct fpga_sec_mgr *smgr);
	int (*pr_canceled_csk_nbits)(struct fpga_sec_mgr *smgr);
};

struct fpga_sec_mgr {
	const char *name;
	struct device dev;
	const struct fpga_sec_mgr_ops *sops;
	struct mutex lock;		/* protect data structure contents */
	void *priv;
};

struct fpga_sec_mgr *
fpga_sec_mgr_create(struct device *dev, const char *name,
		    const struct fpga_sec_mgr_ops *sops, void *priv);

struct fpga_sec_mgr *
devm_fpga_sec_mgr_create(struct device *dev, const char *name,
			 const struct fpga_sec_mgr_ops *sops, void *priv);

int fpga_sec_mgr_register(struct fpga_sec_mgr *smgr);
int devm_fpga_sec_mgr_register(struct device *dev,
			       struct fpga_sec_mgr *smgr);
void fpga_sec_mgr_unregister(struct fpga_sec_mgr *smgr);
void fpga_sec_mgr_free(struct fpga_sec_mgr *smgr);

#endif
