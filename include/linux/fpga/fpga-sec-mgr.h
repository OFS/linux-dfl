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
 * struct image_load - device specific image-load triggers
 * @name:	    Required: keyword used to enable the trigger
 * @load_image:	    Required: pointer to the trigger callback function
 */
struct image_load {
	const char *name;
	int (*load_image)(struct fpga_sec_mgr *smgr);
};

/**
 * struct fpga_sec_mgr_ops - device specific operations
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
 * @image_load:		    pointer to array of image_load structures,
 *			    { } member terminated. These structures describe
 *			    image load triggers for BMC, FPGA, or firmware
 *			    images.
 */
struct fpga_sec_mgr_ops {
	enum fpga_sec_err (*prepare)(struct fpga_sec_mgr *smgr);
	enum fpga_sec_err (*write_blk)(struct fpga_sec_mgr *smgr,
				       u32 offset, u32 size);
	enum fpga_sec_err (*poll_complete)(struct fpga_sec_mgr *smgr);
	enum fpga_sec_err (*cancel)(struct fpga_sec_mgr *smgr);
	void (*cleanup)(struct fpga_sec_mgr *smgr);
	u64 (*get_hw_errinfo)(struct fpga_sec_mgr *smgr);
	struct image_load *image_load;	/* terminated with { } member */
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
