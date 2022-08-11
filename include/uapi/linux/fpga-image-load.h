/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Header File for FPGA Image Load User API
 *
 * Copyright (C) 2019-2021 Intel Corporation, Inc.
 *
 */

#ifndef _UAPI_LINUX_FPGA_IMAGE_LOAD_H
#define _UAPI_LINUX_FPGA_IMAGE_LOAD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define FPGA_IMAGE_LOAD_MAGIC 0xB9

/* Image load progress codes */
#define FPGA_IMAGE_PROG_IDLE		0
#define FPGA_IMAGE_PROG_STARTING	1
#define FPGA_IMAGE_PROG_PREPARING	2
#define FPGA_IMAGE_PROG_WRITING		3
#define FPGA_IMAGE_PROG_PROGRAMMING	4
#define FPGA_IMAGE_PROG_MAX		5

/* Image error progress codes */
#define FPGA_IMAGE_ERR_HW_ERROR		1
#define FPGA_IMAGE_ERR_TIMEOUT		2
#define FPGA_IMAGE_ERR_CANCELED		3
#define FPGA_IMAGE_ERR_BUSY		4
#define FPGA_IMAGE_ERR_INVALID_SIZE	5
#define FPGA_IMAGE_ERR_RW_ERROR		6
#define FPGA_IMAGE_ERR_WEAROUT		7
#define FPGA_IMAGE_ERR_MAX		8

/**
 * FPGA_IMAGE_LOAD_WRITE - _IOW(FPGA_IMAGE_LOAD_MAGIC, 0,
 *				struct fpga_image_write)
 *
 * Upload a data buffer to the target device. The user must provide the
 * data buffer, size, and an eventfd file descriptor.
 *
 * Return: 0 on success, -errno on failure.
 */
struct fpga_image_write {
	/* Input */
	__u32 flags;		/* Zero for now */
	__u32 size;		/* Data size (in bytes) to be written */
	__s32 evtfd;		/* File descriptor for completion signal */
	__u64 buf;		/* User space address of source data */
};

#define FPGA_IMAGE_LOAD_WRITE	_IOW(FPGA_IMAGE_LOAD_MAGIC, 0, struct fpga_image_write)

#endif /* _UAPI_LINUX_FPGA_IMAGE_LOAD_H */
