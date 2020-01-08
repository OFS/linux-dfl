/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header File for Altera SPI Driver.
 */
#ifndef __LINUX_SPI_ALTERA_H
#define __LINUX_SPI_ALTERA_H

#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/types.h>

/**
 * struct altera_spi_platform_data - Platform data of the Altera SPI driver
 * @mode_bits:		Mode bits of SPI master.
 * @num_chipselect:	Number of chipselects.
 * @bits_per_word_mask:	bitmask of supported bits_per_word for transfers.
 * @num_devices:	Number of devices that shall be added when the driver
 *			is probed.
 * @devices:		The devices to add.
 * @use_parent_regmap:	If true, device uses parent regmap to access its
 *			registers. Otherwise try map platform mmio resources.
 * @regoff:		Offset of the device register base in parent regmap.
 *			This field is ignored when use_parent_regmap == false.
 */
struct altera_spi_platform_data {
	u16				mode_bits;
	u16				num_chipselect;
	u32				bits_per_word_mask;
	u16				num_devices;
	struct spi_board_info		*devices;
	bool				use_parent_regmap;
	u32				regoff;
};

#endif /* __LINUX_SPI_ALTERA_H */
