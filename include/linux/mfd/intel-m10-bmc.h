/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intel MAX 10 Board Management Controller chip.
 *
 * Copyright (C) 2018-2020 Intel Corporation, Inc.
 */
#ifndef __MFD_INTEL_M10_BMC_H
#define __MFD_INTEL_M10_BMC_H

#include <linux/dev_printk.h>
#include <linux/regmap.h>
#include <linux/rwsem.h>

struct intel_m10bmc;

/* Supported MAX10 BMC types */
enum m10bmc_type {
	M10_N3000,
	M10_D5005,
	M10_N5010,
	M10_N6000,
	M10_C6100,
	M10_N5014,
};

#define M10BMC_LEGACY_BUILD_VER		0x300468
#define M10BMC_SYS_BASE			0x300800
#define M10BMC_SYS_END			0x300fff
#define M10BMC_FLASH_BASE		0x10000000
#define M10BMC_FLASH_END		0x1fffffff
#define M10BMC_MEM_END			M10BMC_FLASH_END

#define M10BMC_STAGING_BASE		0x18000000
#define M10BMC_STAGING_SIZE		0x3800000

/* Register offset of system registers */
#define NIOS2_FW_VERSION		0x0
#define M10BMC_MAC_LOW			0x10
#define M10BMC_MAC_BYTE4		GENMASK(7, 0)
#define M10BMC_MAC_BYTE3		GENMASK(15, 8)
#define M10BMC_MAC_BYTE2		GENMASK(23, 16)
#define M10BMC_MAC_BYTE1		GENMASK(31, 24)
#define M10BMC_MAC_HIGH			0x14
#define M10BMC_MAC_BYTE6		GENMASK(7, 0)
#define M10BMC_MAC_BYTE5		GENMASK(15, 8)
#define M10BMC_MAC_COUNT		GENMASK(23, 16)
#define M10BMC_TEST_REG			0x3c
#define M10BMC_BUILD_VER		0x68
#define M10BMC_VER_MAJOR_MSK		GENMASK(23, 16)
#define M10BMC_VER_PCB_INFO_MSK		GENMASK(31, 24)
#define M10BMC_VER_LEGACY_INVALID	0xffffffff

/* Retimer related registers, in system register region */
#define M10BMC_PKVL_POLL_CTRL		0x80
#define M10BMC_PKVL_A_PRELOAD		BIT(16)
#define M10BMC_PKVL_A_PRELOAD_TO	BIT(17)
#define M10BMC_PKVL_A_DATA_TOO_BIG	BIT(18)
#define M10BMC_PKVL_A_HDR_CKSUM	BIT(20)
#define M10BMC_PKVL_B_PRELOAD		BIT(24)
#define M10BMC_PKVL_B_PRELOAD_TO	BIT(25)
#define M10BMC_PKVL_B_DATA_TOO_BIG	BIT(26)
#define M10BMC_PKVL_B_HDR_CKSUM	BIT(28)

#define M10BMC_PKVL_PRELOAD		(M10BMC_PKVL_A_PRELOAD | M10BMC_PKVL_B_PRELOAD)
#define M10BMC_PKVL_PRELOAD_TIMEOUT	(M10BMC_PKVL_A_PRELOAD_TO | \
					 M10BMC_PKVL_B_PRELOAD_TO)
#define M10BMC_PKVL_DATA_TOO_BIG	(M10BMC_PKVL_A_DATA_TOO_BIG | \
					 M10BMC_PKVL_B_DATA_TOO_BIG)
#define M10BMC_PKVL_HDR_CHECKSUM	(M10BMC_PKVL_A_HDR_CKSUM | \
					 M10BMC_PKVL_B_HDR_CKSUM)

#define M10BMC_PKVL_UPG_STATUS_MASK	(M10BMC_PKVL_PRELOAD | M10BMC_PKVL_PRELOAD_TIMEOUT |\
					 M10BMC_PKVL_DATA_TOO_BIG | M10BMC_PKVL_HDR_CHECKSUM)
#define M10BMC_PKVL_UPG_STATUS_GOOD	(M10BMC_PKVL_PRELOAD | M10BMC_PKVL_HDR_CHECKSUM)

/* interval 100ms and timeout 2s */
#define M10BMC_PKVL_LOAD_INTERVAL_US	(100 * 1000)
#define M10BMC_PKVL_LOAD_TIMEOUT_US	(2 * 1000 * 1000)

/* interval 100ms and timeout 30s */
#define M10BMC_PKVL_PRELOAD_INTERVAL_US	(100 * 1000)
#define M10BMC_PKVL_PRELOAD_TIMEOUT_US	(30 * 1000 * 1000)

/* Telemetry registers */
#define M10BMC_N3000_TELEM_START	0x100
#define M10BMC_N3000_TELEM_END		0x250
#define M10BMC_D5005_TELEM_START	0x100
#define M10BMC_D5005_TELEM_END		0x300
#define M10BMC_N5010_TELEM_START	0x100
#define M10BMC_N5010_TELEM_END		0x250

/* Secure update doorbell register, in system register region */
#define M10BMC_DOORBELL			0x400

/* Authorization Result register, in system register region */
#define M10BMC_AUTH_RESULT		0x404

/* Doorbell register fields */
#define DRBL_RSU_REQUEST		BIT(0)
#define DRBL_RSU_PROGRESS		GENMASK(7, 4)
#define DRBL_HOST_STATUS		GENMASK(11, 8)
#define DRBL_RSU_STATUS			GENMASK(23, 16)
#define DRBL_PKVL_EEPROM_LOAD_SEC	BIT(24)
#define DRBL_PKVL1_POLL_EN		BIT(25)
#define DRBL_PKVL2_POLL_EN		BIT(26)
#define DRBL_CONFIG_SEL			BIT(28)
#define DRBL_REBOOT_REQ			BIT(29)
#define DRBL_REBOOT_DISABLED		BIT(30)

/* Progress states */
#define RSU_PROG_IDLE			0x0
#define RSU_PROG_PREPARE		0x1
#define RSU_PROG_READY			0x3
#define RSU_PROG_AUTHENTICATING		0x4
#define RSU_PROG_COPYING		0x5
#define RSU_PROG_UPDATE_CANCEL		0x6
#define RSU_PROG_PROGRAM_KEY_HASH	0x7
#define RSU_PROG_RSU_DONE		0x8
#define RSU_PROG_PKVL_PROM_DONE		0x9

/* Device and error states */
#define RSU_STAT_NORMAL			0x0
#define RSU_STAT_TIMEOUT		0x1
#define RSU_STAT_AUTH_FAIL		0x2
#define RSU_STAT_COPY_FAIL		0x3
#define RSU_STAT_FATAL			0x4
#define RSU_STAT_PKVL_REJECT		0x5
#define RSU_STAT_NON_INC		0x6
#define RSU_STAT_ERASE_FAIL		0x7
#define RSU_STAT_WEAROUT		0x8
#define RSU_STAT_PMCI_SS_FAIL           0x9
#define RSU_STAT_FLASH_CMD              0xa
#define RSU_STAT_FACTORY_UNVERITY       0xb
#define RSU_STAT_FACTORY_ACTIVE         0xc
#define RSU_STAT_POWER_DOWN             0xd
#define RSU_STAT_CANCELLATION           0xe
#define RSU_STAT_HASH                   0xf
#define RSU_STAT_FLASH_ACCESS           0x10
#define RSU_STAT_SDM_PR_CERT	        0x20
#define RSU_STAT_SDM_PR_NIOS_BUSY	0x21
#define RSU_STAT_SDM_PR_TIMEOUT	        0x22
#define RSU_STAT_SDM_PR_FAILED		0x23
#define RSU_STAT_SDM_PR_MISMATCH	0x24
#define RSU_STAT_SDM_PR_FLUSH   	0x25
#define RSU_STAT_SDM_SR_CERT	        0x30
#define RSU_STAT_SDM_SR_NIOS_BUSY	0x31
#define RSU_STAT_SDM_SR_TIMEOUT	        0x32
#define RSU_STAT_SDM_SR_SDM_FAILED	0x33
#define RSU_STAT_SDM_SR_MISMATCH	0x34
#define RSU_STAT_SDM_SR_FLUSH   	0x35
#define RSU_STAT_SDM_KEY_CERT	        0x40
#define RSU_STAT_SDM_KEY_NIOS_BUSY	0x41
#define RSU_STAT_SDM_KEY_TIMEOUT	0x42
#define RSU_STAT_SDM_KEY_FAILED		0x43
#define RSU_STAT_SDM_KEY_MISMATCH	0x44
#define RSU_STAT_SDM_KEY_FLUSH   	0x45
#define RSU_STAT_NIOS_OK                0x80
#define RSU_STAT_USER_OK                0x81
#define RSU_STAT_FACTORY_OK             0x82
#define RSU_STAT_USER_FAIL              0x83
#define RSU_STAT_FACTORY_FAIL           0x84
#define RSU_STAT_NIOS_FLASH_ERR         0x85
#define RSU_STAT_FPGA_FLASH_ERR	        0x86

#define HOST_STATUS_IDLE		0x0
#define HOST_STATUS_WRITE_DONE		0x1
#define HOST_STATUS_ABORT_RSU		0x2

#define rsu_prog(doorbell)	FIELD_GET(DRBL_RSU_PROGRESS, doorbell)
#define rsu_stat(doorbell)	FIELD_GET(DRBL_RSU_STATUS, doorbell)

/* interval 100ms and timeout 5s */
#define NIOS_HANDSHAKE_INTERVAL_US	(100 * 1000)
#define NIOS_HANDSHAKE_TIMEOUT_US	(5 * 1000 * 1000)

/* RSU PREP Timeout (2 minutes) to erase flash staging area */
#define RSU_PREP_INTERVAL_MS		100
#define RSU_PREP_TIMEOUT_MS		(2 * 60 * 1000)

/* RSU Complete Timeout (40 minutes) for full flash update */
#define RSU_COMPLETE_INTERVAL_MS	1000
#define RSU_COMPLETE_TIMEOUT_MS		(40 * 60 * 1000)

/* Addresses for security related data in FLASH */
#define BMC_REH_ADDR	0x17ffc004
#define BMC_PROG_ADDR	0x17ffc000
#define BMC_PROG_MAGIC	0x5746

#define SR_REH_ADDR	0x17ffd004
#define SR_PROG_ADDR	0x17ffd000
#define SR_PROG_MAGIC	0x5253

#define PR_REH_ADDR	0x17ffe004
#define PR_PROG_ADDR	0x17ffe000
#define PR_PROG_MAGIC	0x5250

/* Address of 4KB inverted bit vector containing staging area FLASH count */
#define STAGING_FLASH_COUNT	0x17ffb000

#define M10BMC_PMCI_SYS_BASE 0x0
#define M10BMC_PMCI_SYS_END  0xfff

/* Telemetry registers */
#define M10BMC_PMCI_TELEM_START		0x400
#define M10BMC_PMCI_TELEM_END		0x78c
#define M10BMC_PMCI2_TELEM_END		0x7d0

#define M10BMC_PMCI_BUILD_VER   0x0
#define NIOS2_PMCI_FW_VERSION   0x4
#define M10BMC_PMCI_MAC_LOW    0x20
#define M10BMC_PMCI_MAC_HIGH    0x24

#define M10BMC_PMCI_TIME_LOW	0x178
#define M10BMC_PMCI_TIME_HIGH	0x17C

#define M10BMC_PMCI_FLASH_CTRL 0x1d0
#define FLASH_MUX_SELECTION GENMASK(2, 0)
#define FLASH_MUX_IDLE 0
#define FLASH_MUX_NIOS 1
#define FLASH_MUX_HOST 2
#define FLASH_MUX_PFL  4
#define get_flash_mux(mux)      FIELD_GET(FLASH_MUX_SELECTION, mux)

#define FLASH_NIOS_REQUEST BIT(4)
#define FLASH_HOST_REQUEST BIT(5)

#define M10BMC_PMCI_DOORBELL 0x1c0
#define PMCI_DRBL_REBOOT_DISABLED BIT(1)

#define M10BMC_PMCI_AUTH_RESULT 0x1c4

#define M10_FLASH_INT_US       1
#define M10_FLASH_TIMEOUT_US   10000

#define M10BMC_PMCI_MAX10_RECONF 0xfc
#define PMCI_MAX10_REBOOT_REQ BIT(0)
#define PMCI_MAX10_REBOOT_PAGE BIT(1)

#define M10BMC_PMCI_FPGA_CONF_STS 0xa0
#define PMCI_FPGA_BOOT_PAGE	GENMASK(2, 0)
#define PMCI_FPGA_CONFIGED	BIT(3)

#define M10BMC_PMCI_FPGA_POC	0xb0
#define PMCI_FPGA_POC		BIT(0)
#define PMCI_NIOS_REQ_CLEAR	BIT(1)
#define PMCI_NIOS_STATUS	GENMASK(5, 4)
#define NIOS_STATUS_IDLE	0
#define NIOS_STATUS_SUCCESS	1
#define NIOS_STATUS_FAIL	2
#define PMCI_USER_IMAGE_PAGE	GENMASK(10, 8)
#define POC_USER_IMAGE_1	1
#define POC_USER_IMAGE_2	2
#define PMCI_FACTORY_IMAGE_SEL	BIT(31)

#define M10BMC_PMCI_FPGA_POC_STS_BL 0xb4

#define M10BMC_PMCI_FPGA_RECONF 0xb8
#define PMCI_FPGA_RECONF_PAGE  GENMASK(22, 20)
#define PMCI_FPGA_RP_LOAD      BIT(23)

#define M10BMC_PMCI_SDM_SR_CTRL_STS 0x230
#define PMCI_SDM_SR_IMG_REQ	BIT(0)
#define PMCI_SDM_SR_PGM_ERROR	GENMASK(23, 16)

#define M10BMC_PMCI_SDM_PR_CTRL_STS 0x238
#define PMCI_SDM_PR_IMG_REQ	BIT(0)
#define PMCI_SDM_PR_PGM_ERROR	GENMASK(23, 16)

#define M10BMC_PMCI_SDM_SR_CNCL_CTRL_STS 0x23C
#define PMCI_SDM_SR_CNCL_REQ		 BIT(0)
#define PMCI_SDM_SR_CNCL_ERROR		 GENMASK(18, 8)

#define M10BMC_PMCI_SDM_PR_CNCL_CTRL_STS 0x240
#define PMCI_SDM_PR_CNCL_REQ		 BIT(0)
#define PMCI_SDM_PR_CNCL_ERROR		 GENMASK(18, 8)

#define M10BMC_PMCI_SDM_CTRL 0x234
#define SDM_CMD_TRIGGER        BIT(0)
#define SDM_CMD_DONE           BIT(2)
#define SDM_CMD_SELECT         GENMASK(11, 4)
#define SDM_CMD_PROV_DATA      0x3
#define SDM_CMD_STATUS         GENMASK(15, 12)
#define sdm_status(cmd)	FIELD_GET(SDM_CMD_STATUS, cmd)
#define SDM_CMD_STATUS_IDLE    0x0
#define SDM_CMD_ERROR          GENMASK(23, 16)
#define sdm_error(cmd)	FIELD_GET(SDM_CMD_ERROR, cmd)
#define SDM_CMD_SUCC           0x0

#define M10BMC_PMCI_SDM_PR_STS		0x820
#define M10BMC_PMCI_CERT_PROG_STS	0x824
#define M10BMC_PMCI_CERT_SPEC_STS	0x828

#define M10BMC_PMCI_SR_RH0 0x848
#define M10BMC_PMCI_SR_CSK 0x878
#define M10BMC_PMCI_PR_RH0 0x87c
#define M10BMC_PMCI_PR_CSK 0x8ac

#define PMCI_ERROR_LOG_ADDR  0x7fb0000
#define PMCI_ERROR_LOG_SIZE  0x40000

#define PMCI_FPGA_IMAGE_DIR_ADDR  0x7ff6000
#define PMCI_FPGA_IMAGE_DIR_SIZE  0x3000

#define PMCI_BOM_INFO_ADDR  0x7ff0000
#define PMCI_BOM_INFO_SIZE  0x2000

/* Addresses for security related data in FLASH */
#define PMCI_BMC_REH_ADDR 0x7ffc004
#define PMCI_BMC_PROG_ADDR 0x7ffc000
#define PMCI_BMC_PROG_MAGIC 0x5746

#define PMCI_SR_REH_ADDR  0x7ffd004
#define PMCI_SR_PROG_ADDR  0x7ffd000
#define PMCI_SR_PROG_MAGIC  0x5253

#define PMCI_PR_REH_ADDR  0x7ffe004
#define PMCI_PR_PROG_ADDR 0x7ffe000
#define PMCI_PR_PROG_MAGIC 0x5250

#define PMCI_STAGING_FLASH_COUNT 0x7ff5000

#define m10bmc_base(m10bmc) ((m10bmc)->csr->base)
#define doorbell_reg(m10bmc) ((m10bmc)->csr->doorbell)
#define auth_result_reg(m10bmc) ((m10bmc)->csr->auth_result)

#define bmc_prog_addr(m10bmc) ((m10bmc)->csr->bmc_prog_addr)
#define bmc_reh_addr(m10bmc) ((m10bmc)->csr->bmc_reh_addr)
#define bmc_magic(m10bmc) ((m10bmc)->csr->bmc_magic)
#define sr_prog_addr(m10bmc) ((m10bmc)->csr->sr_prog_addr)
#define sr_reh_addr(m10bmc) ((m10bmc)->csr->sr_reh_addr)
#define sr_magic(m10bmc) ((m10bmc)->csr->sr_magic)
#define pr_prog_addr(m10bmc) ((m10bmc)->csr->pr_prog_addr)
#define pr_reh_addr(m10bmc) ((m10bmc)->csr->pr_reh_addr)
#define pr_magic(m10bmc) ((m10bmc)->csr->pr_magic)
#define rsu_update_counter(m10bmc) ((m10bmc)->csr->rsu_update_counter)
#define pr_sdm_reh_reg(m10bmc) ((m10bmc)->csr->pr_sdm_reh_reg)
#define pr_sdm_csk_reg(m9bmc) ((m10bmc)->csr->pr_sdm_csk_reg)
#define sr_sdm_reh_reg(m10bmc) ((m10bmc)->csr->sr_sdm_reh_reg)
#define sr_sdm_csk_reg(m10bmc) ((m10bmc)->csr->sr_sdm_csk_reg)
#define staging_size(m10bmc) ((m10bmc)->csr->staging_size)

enum m10bmc_fw_state {
	M10BMC_FW_STATE_NORMAL,
	M10BMC_FW_STATE_SEC_UPDATE,
};

/**
 * struct m10bmc_csr - Intel MAX 10 BMC CSR register
 */
struct m10bmc_csr {
	unsigned int base;
	unsigned int build_version;
	unsigned int fw_version;
	unsigned int mac_low;
	unsigned int mac_high;
	unsigned int doorbell;
	unsigned int auth_result;
	unsigned int bmc_prog_addr;
	unsigned int bmc_reh_addr;
	unsigned int bmc_magic;
	unsigned int sr_prog_addr;
	unsigned int sr_reh_addr;
	unsigned int sr_magic;
	unsigned int pr_prog_addr;
	unsigned int pr_reh_addr;
	unsigned int pr_magic;
	unsigned int rsu_update_counter;
	unsigned int pr_sdm_reh_reg;
	unsigned int pr_sdm_csk_reg;
	unsigned int sr_sdm_reh_reg;
	unsigned int sr_sdm_csk_reg;
	unsigned int staging_size;
};

/**
 * struct fpga_flash_ops - device specific operations for flash R/W
 * @write_blk: write a block of data to flash
 * @read_blk: read a block of data from flash
 * @mux_lock: Prevent concurrent flash burst reads
 */
struct fpga_flash_ops {
	int (*write_blk)(struct intel_m10bmc *m10bmc, void *buf, u32 size);
	int (*read_blk)(struct intel_m10bmc *m10bmc, void *buf, u32 addr, u32 size);
	struct mutex mux_lock;	/* Prevent concurrent flash burst reads */
};

/**
 * struct m10bmc_ops - device specific operations
 * @flash_read: read a block of data from flash
 */
struct m10bmc_ops {
	int (*flash_read)(struct intel_m10bmc *m10bmc, void *buf,
			  u32 addr, u32 size);
};

/**
 * struct intel_m10bmc - Intel MAX 10 BMC parent driver data structure
 * @dev: this device
 * @regmap: the regmap used to access registers by m10bmc itself
 * @bmcfw_lock: read/write semaphore to BMC firmware running state
 * @bmcfw_state: BMC firmware running state
 * @type: the type of MAX10 BMC
 * @handshake_sys_reg_ranges: array of register ranges for fw handshake regs
 * @handshake_sys_reg_nranges: number of register ranges for fw handshake regs
 * @csr: the register definition of MAX10 BMC
 * @flash_ops: optional device specific operations for flash R/W
 * @ops: device specific operations
 */
struct intel_m10bmc {
	struct device *dev;
	struct regmap *regmap;
	struct rw_semaphore bmcfw_lock;
	enum m10bmc_fw_state bmcfw_state;
	enum m10bmc_type type;
	const struct regmap_range *handshake_sys_reg_ranges;
	unsigned int handshake_sys_reg_nranges;
	const struct m10bmc_csr *csr;
	struct fpga_flash_ops *flash_ops;
	struct m10bmc_ops ops;
};

/*
 * register access helper functions.
 *
 * m10bmc_raw_read - read m10bmc register per addr
 * m10bmc_sys_read - read m10bmc system register per offset
 * m10bmc_sys_update_bits - update m10bmc system register per offset
 */
static inline int
m10bmc_raw_read(struct intel_m10bmc *m10bmc, unsigned int addr,
		unsigned int *val)
{
	int ret;

	ret = regmap_read(m10bmc->regmap, addr, val);
	if (ret)
		dev_err(m10bmc->dev, "fail to read raw reg %x: %d\n",
			addr, ret);

	return ret;
}

int m10bmc_sys_read(struct intel_m10bmc *m10bmc, unsigned int offset,
		    unsigned int *val);

int m10bmc_sys_update_bits(struct intel_m10bmc *m10bmc, unsigned int offset,
			   unsigned int msk, unsigned int val);

/*
 * Track the state of the firmware, as it is not available for
 * register handshakes during secure updates.
 *
 * m10bmc_fw_state_enter - firmware is unavailable for handshakes
 * m10bmc_fw_state_exit  - firmware is available for handshakes
 */
int m10bmc_fw_state_enter(struct intel_m10bmc *m10bmc,
			  enum m10bmc_fw_state new_state);

void m10bmc_fw_state_exit(struct intel_m10bmc *m10bmc);

/*
 * MAX10 BMC Core support
 */
int m10bmc_dev_init(struct intel_m10bmc *m10bmc);
extern const struct attribute_group *m10bmc_dev_groups[];

#endif /* __MFD_INTEL_M10_BMC_H */
