/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for DFL driver and device API
 *
 * Copyright (C) 2020-2022 Intel Corporation, Inc.
 */

#ifndef __LINUX_DFL_H
#define __LINUX_DFL_H

#include <linux/device.h>
#include <linux/mod_devicetable.h>

/*
 * Device Feature Header Register Set
 *
 * For FIUs, they all have DFH + GUID + NEXT_AFU as common header registers.
 * For AFUs, they have DFH + GUID as common header registers.
 * For private features, they only have DFH register as common header.
 */
#define DFH			0x0
#define GUID_L			0x8
#define GUID_H			0x10
#define NEXT_AFU		0x18

/*
 * DFHv1 Register Offset definitons
 * In DHFv1, DFH + GUID + CSR_START + CSR_SIZE_GROUP + PARAM_HDR + PARAM_DATA
 * as common header registers
 */
#define DFHv1_CSR_ADDR		0x18  /* CSR Register start address */
#define DFHv1_CSR_SIZE_GRP	0x20  /* Size of Reg Block and Group/tag */
#define DFHv1_PARAM_HDR		0x28  /* Optional First Param header */
#define DFHv1_PARAM_DATA	0x8   /* Offset of Param data from Param header */

#define DFH_SIZE		0x8

/* Device Feature Header Register Bitfield */
#define DFH_ID			GENMASK_ULL(11, 0)	/* Feature ID */
#define DFH_REVISION		GENMASK_ULL(15, 12)	/* Feature revision */
#define DFH_NEXT_HDR_OFST	GENMASK_ULL(39, 16)	/* Offset to next DFH */
#define DFH_EOL			BIT_ULL(40)		/* End of list */
#define DFH_VERSION		GENMASK_ULL(59, 52)	/* DFH version */
#define DFH_TYPE		GENMASK_ULL(63, 60)	/* Feature type */

/*
 *  CSR Rel Bit, 1'b0 = relative (offset from feature DFH start),
 * 1'b1 = absolute (ARM or other non-PCIe use)
 */
#define DFHv1_CSR_ADDR_REL	BIT_ULL(0)

/*
 * CSR Header Register Bit Definitions
 */
#define DFHv1_CSR_ADDR_MASK       GENMASK_ULL(63, 1)  /* 63:1 of CSR address */

/*
 * CSR SIZE Goup Register Bit Definitions
 */
#define DFHv1_CSR_SIZE_GRP_INSTANCE_ID	GENMASK_ULL(15, 0)	/* Enumeration instantiated IP */
#define DFHv1_CSR_SIZE_GRP_GROUPING_ID	GENMASK_ULL(30, 16)	/* Group Features/interfaces */
#define DFHv1_CSR_SIZE_GRP_HAS_PARAMS	BIT_ULL(31)		/* Presence of Parameters */
#define DFHv1_CSR_SIZE_GRP_SIZE		GENMASK_ULL(63, 32)	/* Size of CSR Block in bytes */

/*
 * PARAM Header Register Bit Definitions
 */
#define DFHv1_PARAM_HDR_ID		GENMASK_ULL(15, 0) /* Id of this Param  */
#define DFHv1_PARAM_HDR_VERSION		GENMASK_ULL(31, 16) /* Version Param */
#define DFHv1_PARAM_HDR_NEXT_OFFSET	GENMASK_ULL(63, 32) /* Offset of next Param */

#define DFHv1_PARAM_ID_MSIX	0x1
#define DFHv1_PARAM_MSIX_STARTV	0x8
#define DFHv1_PARAM_MSIX_NUMV	0xc

#define DFHv1_PARAM_ID_CLK_FRQ    0x2
#define DFHv1_PARAM_ID_FIFO_LEN   0x3

#define DFHv1_PARAM_ID_REG_LAYOUT 0x4
#define DFHv1_PARAM_ID_REG_WIDTH  GENMASK_ULL(63, 32)
#define DFHv1_PARAM_ID_REG_SHIFT  GENMASK_ULL(31, 0)

/**
 * enum dfl_id_type - define the DFL FIU types
 */
enum dfl_id_type {
	FME_ID = 0,
	PORT_ID = 1,
	DFL_ID_MAX,
};

/**
 * struct dfl_device - represent an dfl device on dfl bus
 *
 * @dev: generic device interface.
 * @id: id of the dfl device.
 * @type: type of DFL FIU of the device. See enum dfl_id_type.
 * @feature_id: feature identifier local to its DFL FIU type.
 * @dfh_version: device feature header version.
 * @guid: feature GUID of the dfl device.
 * @mmio_res: mmio resource of this dfl device.
 * @irqs: list of Linux IRQ numbers of this dfl device.
 * @num_irqs: number of IRQs supported by this dfl device.
 * @cdev: pointer to DFL FPGA container device this dfl device belongs to.
 * @id_entry: matched id entry in dfl driver's id table.
 */
struct dfl_device {
	struct device dev;
	int id;
	u16 type;
	u16 feature_id;
	u8 revision;
	u8 dfh_version;
	guid_t guid;
	struct resource mmio_res;
	int *irqs;
	unsigned int num_irqs;
	struct dfl_fpga_cdev *cdev;
	const struct dfl_device_id *id_entry;
};

/**
 * struct dfl_driver - represent an dfl device driver
 *
 * @drv: driver model structure.
 * @id_table: pointer to table of device IDs the driver is interested in.
 *	      { } member terminated.
 * @probe: mandatory callback for device binding.
 * @remove: callback for device unbinding.
 */
struct dfl_driver {
	struct device_driver drv;
	const struct dfl_device_id *id_table;

	int (*probe)(struct dfl_device *dfl_dev);
	void (*remove)(struct dfl_device *dfl_dev);
};

#define to_dfl_dev(d) container_of(d, struct dfl_device, dev)
#define to_dfl_drv(d) container_of(d, struct dfl_driver, drv)

struct device *dfl_dev_get_base_dev(struct dfl_device *dfl_dev);

/*
 * use a macro to avoid include chaining to get THIS_MODULE.
 */
#define dfl_driver_register(drv) \
	__dfl_driver_register(drv, THIS_MODULE)
int __dfl_driver_register(struct dfl_driver *dfl_drv, struct module *owner);
void dfl_driver_unregister(struct dfl_driver *dfl_drv);

/*
 * module_dfl_driver() - Helper macro for drivers that don't do
 * anything special in module init/exit.  This eliminates a lot of
 * boilerplate.  Each module may only use this macro once, and
 * calling it replaces module_init() and module_exit().
 */
#define module_dfl_driver(__dfl_driver) \
	module_driver(__dfl_driver, dfl_driver_register, \
		      dfl_driver_unregister)

/*
 * dfl_find_param() - find the offset of the given parameter
 * @base: base pointer to start of dfl parameters in DFH
 * @max: maximum offset to search
 * @param: id of dfl parameter
 *
 * Return: positive offset on success, negative error code otherwise.
 */
int dfl_find_param(void __iomem *base, resource_size_t max, int param);
#endif /* __LINUX_DFL_H */
