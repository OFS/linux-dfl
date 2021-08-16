/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for FPGA Image Load Framework
 *
 * Copyright (C) 2019-2021 Intel Corporation, Inc.
 */
#ifndef _LINUX_FPGA_IMAGE_LOAD_H
#define _LINUX_FPGA_IMAGE_LOAD_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <uapi/linux/fpga-image-load.h>

struct fpga_image_load;

/**
 * struct fpga_image_load_ops - device specific operations
 * @prepare:		    Required: Prepare secure update
 * @write:		    Required: The write() op receives the remaining
 *			    size to be written and must return the actual
 *			    size written or a negative error code. The write()
 *			    op will be called repeatedly until all data is
 *			    written.
 * @poll_complete:	    Required: Check for the completion of the
 *			    HW authentication/programming process.
 * @cleanup:		    Optional: Complements the prepare()
 *			    function and is called at the completion
 *			    of the update, whether success or failure,
 *			    if the prepare function succeeded.
 */
struct fpga_image_load_ops {
	u32 (*prepare)(struct fpga_image_load *imgld, const u8 *data, u32 size);
	s32 (*write)(struct fpga_image_load *imgld, const u8 *data,
		     u32 offset, u32 size);
	u32 (*poll_complete)(struct fpga_image_load *imgld);
	void (*cleanup)(struct fpga_image_load *imgld);
};

struct fpga_image_load {
	struct device dev;
	struct cdev cdev;
	const struct fpga_image_load_ops *ops;
	struct mutex lock;		/* protect data structure contents */
	atomic_t opened;
	struct work_struct work;
	const u8 *data;			/* pointer to update data */
	u32 remaining_size;		/* size remaining to transfer */
	u32 progress;
	u32 err_code;			/* image load error code */
	bool driver_unload;
	struct eventfd_ctx *finished;
	void *priv;
};

struct fpga_image_load *
fpga_image_load_register(struct device *dev,
			 const struct fpga_image_load_ops *ops, void *priv);

void fpga_image_load_unregister(struct fpga_image_load *imgld);

#endif
