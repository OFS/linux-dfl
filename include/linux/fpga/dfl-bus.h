/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header File for DFL driver and device API
 *
 * Copyright (C) 2020 Intel Corporation, Inc.
 */

#ifndef __FPGA_DFL_BUS_H
#define __FPGA_DFL_BUS_H

#include <linux/device.h>
#include <linux/mod_devicetable.h>

/**
 * enum dfl_id_type - define the DFL FIU types
 */
enum dfl_id_type {
	FME_ID,
	PORT_ID,
	DFL_ID_MAX,
};

/**
 * struct dfl_device - represent an dfl device on dfl bus
 *
 * @dev: Generic device interface.
 * @type: Type of DFL FIU of the device. See enum dfl_id_type.
 * @feature_id: 64 bits feature identifier local to its DFL FIU type.
 * @mmio_res: MMIO resource of this dfl device.
 * @irqs: List of Linux IRQ numbers of this dfl device.
 * @num_irqs: number of IRQs supported by this dfl device.
 * @cdev: pointer to DFL FPGA container device this dfl device belongs to.
 * @id_entry: matched id entry in dfl driver's id table.
 */
struct dfl_device {
	struct device dev;
	unsigned int type;
	unsigned long long feature_id;
	struct resource mmio_res;
	int *irqs;
	unsigned int num_irqs;
	struct dfl_fpga_cdev *cdev;
	const struct dfl_device_id *id_entry;
};

/**
 * struct dfl_driver - represent an dfl device driver
 *
 * @drv: Driver model structure.
 * @id_table: Pointer to table of device IDs the driver is interested in.
 * @probe: Callback for device binding.
 * @remove: Callback for device unbinding.
 */
struct dfl_driver {
	struct device_driver drv;
	const struct dfl_device_id *id_table;

	int (*probe)(struct dfl_device *dfl_dev);
	int (*remove)(struct dfl_device *dfl_dev);
};

#define to_dfl_dev(d) container_of(d, struct dfl_device, dev)
#define to_dfl_drv(d) container_of(d, struct dfl_driver, drv)

/*
 * use a macro to avoid include chaining to get THIS_MODULE
 */
#define dfl_driver_register(drv) \
	__dfl_driver_register(drv, THIS_MODULE)
int __dfl_driver_register(struct dfl_driver *dfl_drv, struct module *owner);
void dfl_driver_unregister(struct dfl_driver *dfl_drv);

/* module_dfl_driver() - Helper macro for drivers that don't do
 * anything special in module init/exit.  This eliminates a lot of
 * boilerplate.  Each module may only use this macro once, and
 * calling it replaces module_init() and module_exit()
 */
#define module_dfl_driver(__dfl_driver) \
	module_driver(__dfl_driver, dfl_driver_register, \
		      dfl_driver_unregister)

#endif /* __FPGA_DFL_BUS_H */
