/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver Header File for Intel SPI Slave to AVMM Bus Bridge
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */

#ifndef __INTEL_SPI_AVMM_H
#define __INTEL_SPI_AVMM_H

#include <linux/spi/spi.h>
#include <linux/regmap.h>

#define TRANS_CODE_WRITE	0x0
#define TRANS_CODE_SEQ_WRITE	0x4
#define TRANS_CODE_READ		0x10
#define TRANS_CODE_SEQ_READ	0x14
#define TRANS_CODE_NO_TRANS	0x7f

struct trans_header {
	u8 trans_code;
	u8 rsvd;
	__be16 size;
	__be32 addr;
};

struct trans_response {
	u8 r_trans_code;
	u8 rsvd;
	__be16 size;
};

/* slave's register addr is 32 bits */
#define REG_SIZE		4UL

/* slave's register value is 32 bits */
#define VAL_SIZE		4UL

/*
 * max rx size could be larger. But considering the buffer consuming,
 * it is proper that we limit 1KB xfer at max.
 */
#define MAX_RX_CNT   256UL
#define MAX_TX_CNT   1UL

#define TRANS_HEAD_SIZE		(sizeof(struct trans_header))
#define TRANS_RESP_SIZE		(sizeof(struct trans_response))

#define WR_TRANS_TX_SIZE(n)	(TRANS_HEAD_SIZE + VAL_SIZE * (n))
#define RD_TRANS_TX_SIZE	TRANS_HEAD_SIZE

#define TRANS_TX_MAX		WR_TRANS_TX_SIZE(MAX_TX_CNT)
/*
 * The worst case, all chars are escaped, plus 4 special chars (SOP, CHANNEL,
 * CHANNEL_NUM, EOP). Finally make sure the length is aligned to SPI BPW.
 */
#define PHY_TX_MAX		ALIGN(2 * TRANS_TX_MAX + 4, 4)

/* No additional chars in transaction layer RX, just read out data */
#define TRANS_RX_MAX		(VAL_SIZE * MAX_RX_CNT)
/*
 * Unlike tx, phy rx is bothered by possible PHY_IDLE bytes from slave,
 * Driver will read the word one by one and filter out pure IDLE words.
 * The rest of words may still contain IDLE chars. A worse case could be
 * receiving word 0x7a7a7a7a in 4 BPW transfer mode. The 4 bytes word may
 * consume up to 12 bytes in rx buffer, like:
 * |4a|4a|4a|7d| |5a|7d|5a|7d| |5a|7d|5a|4a|
 * Besides, the packet layer header may consume up to 8 bytes, like:
 * |4a|4a|4a|7a| |7c|00|4a|4a|
 * So the PHY_RX_MAX is calculated as following.
 */
#define PHY_RX_MAX		(TRANS_RX_MAX * 3 + 8)

/**
 * struct spi_avmm_bridge - SPI slave to AVMM bus master bridge
 *
 * @spi: spi slave associated with this bridge.
 * @word_len: bytes of word for spi transfer.
 * @phy_tx_len: length of valid data in phy_tx_buf which will be sent by spi.
 * @phy_rx_len: length of valid data in phy_rx_buf which received from spi.
 *
 * As device's registers are implemented on the AVMM bus address space, it
 * requires driver to issue formatted requests to spi slave to AVMM bus master
 * bridge to perform register access.
 */
struct spi_avmm_bridge {
	struct spi_device *spi;
	unsigned int word_len;
	unsigned int phy_tx_len;
	unsigned int phy_rx_len;
	/* bridge buffer used in translation between protocol layers */
	char trans_tx_buf[TRANS_TX_MAX];
	char trans_rx_buf[TRANS_RX_MAX];
	char phy_tx_buf[PHY_TX_MAX];
	char phy_rx_buf[PHY_RX_MAX];
};

struct regmap *__devm_regmap_init_spi_avmm(struct spi_device *spi,
					   const struct regmap_config *config,
					   struct lock_class_key *lock_key,
					   const char *lock_name);

/**
 * devm_regmap_init_spi_avmm() - Initialise register map for Intel SPI Slave
 * to AVMM Bus Bridge
 *
 * @spi: Device that will be interacted with
 * @config: Configuration for register map
 *
 * The return value will be an ERR_PTR() on error or a valid pointer
 * to a struct regmap.  The map will be automatically freed by the
 * device management code.
 */
#define devm_regmap_init_spi_avmm(spi, config)				\
	__regmap_lockdep_wrapper(__devm_regmap_init_spi_avmm, #config,	\
				 spi, config)

#endif /* __INTEL_SPI_AVMM_H */
