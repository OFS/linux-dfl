/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#ifndef _LINUX_FPGA_SEC_MGR_H
#define _LINUX_FPGA_SEC_MGR_H

#include <linux/completion.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct fpga_sec_mgr;

enum fpga_sec_err {
	FPGA_SEC_ERR_NONE,
	FPGA_SEC_ERR_HW_ERROR,
	FPGA_SEC_ERR_TIMEOUT,
	FPGA_SEC_ERR_CANCELED,
	FPGA_SEC_ERR_BUSY,
	FPGA_SEC_ERR_INVALID_SIZE,
	FPGA_SEC_ERR_RW_ERROR,
	FPGA_SEC_ERR_WEAROUT,
	FPGA_SEC_ERR_FILE_READ,
	FPGA_SEC_ERR_MAX
};

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
 * @prepare:		    Required: Prepare secure update
 * @write_blk:		    Required: Write a block of data
 * @poll_complete:	    Required: Check for the completion of the
 *			    HW authentication/programming process. This
 *			    function should check for smgr->driver_unload
 *			    and abort with FPGA_SEC_ERR_CANCELED when true.
 * @cancel:		    Required: Signal HW to cancel update
 * @cleanup:		    Optional: Complements the prepare()
 *			    function and is called at the completion
 *			    of the update, whether success or failure,
 *			    if the prepare function succeeded.
 * @get_hw_errinfo:	    Optional: Return u64 hw specific error info.
 *			    The software err_code may used to determine
 *			    whether the hw error info is applicable.
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
	enum fpga_sec_err (*prepare)(struct fpga_sec_mgr *smgr);
	enum fpga_sec_err (*write_blk)(struct fpga_sec_mgr *smgr,
				       u32 offset, u32 size);
	enum fpga_sec_err (*poll_complete)(struct fpga_sec_mgr *smgr);
	void (*cleanup)(struct fpga_sec_mgr *smgr);
	enum fpga_sec_err (*cancel)(struct fpga_sec_mgr *smgr);
	u64 (*get_hw_errinfo)(struct fpga_sec_mgr *smgr);
};

/* Update progress codes */
enum fpga_sec_prog {
	FPGA_SEC_PROG_IDLE,
	FPGA_SEC_PROG_READING,
	FPGA_SEC_PROG_PREPARING,
	FPGA_SEC_PROG_WRITING,
	FPGA_SEC_PROG_PROGRAMMING,
	FPGA_SEC_PROG_MAX
};

struct fpga_sec_mgr {
	const char *name;
	struct device dev;
	const struct fpga_sec_mgr_ops *sops;
	struct mutex lock;		/* protect data structure contents */
	struct work_struct work;
	struct completion update_done;
	char *filename;
	const u8 *data;			/* pointer to update data */
	u32 remaining_size;		/* size remaining to transfer */
	enum fpga_sec_prog progress;
	enum fpga_sec_prog err_state;	/* progress state at time of failure */
	enum fpga_sec_err err_code;	/* security manager error code */
	u64 hw_errinfo;			/* 64 bits of HW specific error info */
	bool request_cancel;
	bool driver_unload;
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
