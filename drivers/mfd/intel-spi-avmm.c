// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Intel SPI Slave to AVMM Bus Bridge
 *
 * Copyright (C) 2018-2020 Intel Corporation. All rights reserved.
 *
 */

#include "intel-spi-avmm.h"

/*
 * This driver implements the Read/write protocol for generic SPI master to
 * communicate with the "SPI slave to Avalon Master Bridge" (spi-avmm) IP.
 *
 * The spi-avmm IP act as a bridge to convert encoded streams of bytes from
 * host to internal mmio read/write on Avalon bus. In order to issue register
 * access request to the slave chip, the host should send formatted bytes that
 * conform to the transfer protocol.
 * The transfer protocol contains 3 layers: transaction layer, packet layer
 * and physical layer.
 *
 * Reference Documents could be found at:
 * https://www.intel.com/content/www/us/en/programmable/documentation/
 * sfo1400787952932.html
 *
 * Chapter "SPI Slave/JTAG to Avalon Master Bridge Cores" does general
 * introduction about the protocol.
 *
 * Chapter "Avalon-ST Serial Peripheral Interface Core" describes Physical
 * layer.
 *
 * Chapter "Avalon-ST Bytes to Packets and Packets to Bytes Converter Cores"
 * describes Packet layer.
 *
 * Chapter "Avalon Packets to Transactions Converter Core" describes
 * Transaction layer.
 *
 * The main function of Physical layer is the use of PHY_IDLE (4a). Host
 * issues SCLK to query data from slave, but if slave is not ready to submit
 * data yet, it will repeat PHY_IDLE until data is prepared.
 * Because of this special char, it also needs an ESCAPE char (4d), to help
 * represent data "4a". The escape rule is "4d first, following 4a ^ 20".
 * So "4d, 6a" for data "4a", and "4d, 6d" for data "4d".
 *
 * The Packet layer defines the boundary of a whole packet. It defines the
 * Start Of Packet (SOP, 7a) char and End Of Packet (EOP, 7b) char. Please
 * note that the non-special byte after EOP is the last byte of the packet.
 * Besides Packet layer defines a Channel char (7c) + Channel number for
 * multiple channel transfer. But it is now not supported by this driver. So
 * host will always send "7c, 00" when needed, and will drop the packet if
 * "7c, non-zero" is received.
 * Finally, a Packet layer ESCAPE char (7d) is also needed to represent data
 * value same as the special chars. The escape rule is the same.
 * The escape rule should be used if the last byte requires it. So if a packet
 * ends up with data 7a, the last bytes should be "7b, 7d, 5a".
 *
 * The transaction layer defines several transaction formats, including host
 * write/incrementing write request, slave write response, host
 * read/incrementing read request.
 *
 * +------+------------------+------------------------------+
 * | Byte |       Field      | Description                  |
 * +------+------------------+------------------------------+
 * |             Host transaction format                    |
 * +------+------------------+------------------------------+
 * |  0   | Transaction code | 0x0, Write non-incrementing  |
 * |      |                  | 0x4, Write incrementing      |
 * |      |                  | 0x10, Read non-incrementing  |
 * |      |                  | 0x14, Read incrementing      |
 * +------+------------------+------------------------------+
 * |  1   | Reserved         |                              |
 * +------+------------------+------------------------------+
 * | 3:2  | Size             | Big endian                   |
 * +------+------------------+------------------------------+
 * | 7:4  | Address          | Big endian                   |
 * +------+------------------+------------------------------+
 * | n:8  | Data             | For Write only, Little endian|
 * +------+------------------+------------------------------+
 * |       Slave write complete response format             |
 * +------+------------------+------------------------------+
 * |  0   | Response code    | Transaction code ^ 0x80      |
 * +------+------------------+------------------------------+
 * |  1   | Reserved         |                              |
 * +------+------------------+------------------------------+
 * | 3:2  | Size             | Big endian                   |
 * +------+------------------+------------------------------+
 *
 * For slave read response, there is no transaction header, simply returns the
 * read out data.
 *
 *
 * Here is a simple case to illustrate the protocol. Host request slave to
 * do a write32 to addr 0x024b7a40. The following diagram shows how the slave
 * parses the incoming byte streams from MOSI layer by layer.
 *
 *
 * LSB                Physical layer                            MSB
 *
 * |4a|7a|7c|4a|00|00|00|4a|00|04|02|4b|7d|5a|40|4d|6a|ff|03|7b|5f|
 *  |        |           |                       |  |
 *  +--------+-----------+                   Escape |
 *           |                                   +--+
 *      IDLE, Dropped                               |
 *                                           Escape dropped,
 *                                        Next byte XORed with 0x20
 *                                                  |
 *                                                  |
 *                    Packet layer                  |
 *                                                  |
 *             |7a|7c|00|00|00|00|04|02|4b|7d|5a|40|4a|ff|03|7b|5f|
 *              |  |  |                    |  |              |  |
 *            SOP  +--+                Escape |            EOP  |
 *                  |                      +--+                 |
 *                 Channel 0                  |            Last valid byte
 *                                     Escape dropped,
 *                              Next byte XORed with 0x20
 *                                            |
 *                                            |
 *                    Transaction layer       |
 *                                            |
 *                         |00|00|00|04|02|4b|7a|40|4a|ff|03|5f|
 *                          |     |  |  |  |  |  |  |  |  |  |
 *                       Write    +--+  +--+--+--+  +--+--+--+
 *                          |       |       |           |
 *                          |   size=4Byte  |           |
 *                          |       |       |           |
 *                          +-------+       |           |
 *                            |             |           |
 *                         Command      Addr(BE):     Data(LE):
 *                                     0x024b7a40    0x5f03ff4a
 *
 *
 * This is how host and slave interact for the single write32, only transaction
 * layer and PHY_IDLE chars are shown for simplicity:
 *
 * MOSI  |00|00|00|04|02|4b|3a|40|4a|ff|03|5f|XX|XX|...|XX|XX|XX|XX|XX|
 * MISO  |4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|...|4a|80|00|00|04|
 *                                                         |        |
 *                                      Write done, 0x00 ^ 0x80     |
 *                                                               4bytes written
 *
 * This is another case, a single read32 of addr 0x024b3a40, slave returns
 * 0x12345678.
 *
 * MOSI  |10|00|00|04|02|4b|3a|40|XX|XX|...............|XX|XX|XX|XX|XX|
 * MISO  |4a|4a|4a|4a|4a|4a|4a|4a|4a|4a|...............|4a|78|56|34|12|
 *                                                         |  |  |  |
 *                                                         +--+--+--+
 *                                                            |
 *                                                       just return data
 */

#define SPI_AVMM_XFER_TIMEOUT	(msecs_to_jiffies(200))

/*
 * Transaction Layer
 *
 * Transaction layer capsules transaction code (read/write), size (16 bits),
 * addr (32 bits) and value (32 bits) into transaction format.
 * SEQ_READ/WRITE will read/write number of bytes(specified by head->size)
 * on incrementing addr start from header->addr field.
 * Transaction header will be followed by register data for write operations.
 *
 * Please not that size and addr are sent in big endian but value is sent in
 * little endian according to transaction layer protocol.
 */

/* Format a transaction layer byte stream for tx_buf */
static void trans_tx_prepare(bool is_read, u32 reg, u32 *wr_val, u16 size,
			     char *tx_buf, unsigned int *tx_len)
{
	/* size parameter must be n * VAL_SIZE */
	u16 count = size / VAL_SIZE;
	struct trans_header *header;
	u8 trans_code;
	__le32 *data;
	int i;

	trans_code = is_read ?
			(count == 1 ? TRANS_CODE_READ : TRANS_CODE_SEQ_READ) :
			(count == 1 ? TRANS_CODE_WRITE : TRANS_CODE_SEQ_WRITE);

	header = (struct trans_header *)tx_buf;
	header->trans_code = trans_code;
	header->rsvd = 0;
	header->size = cpu_to_be16(size);
	header->addr = cpu_to_be32(reg);

	if (is_read) {
		*tx_len = RD_TRANS_TX_SIZE;
	} else {
		data = (__le32 *)(tx_buf + TRANS_HEAD_SIZE);

		for (i = 0; i < count; i++)
			*data++ = cpu_to_le32(*wr_val++);

		*tx_len = WR_TRANS_TX_SIZE(count);
	}
}

/*
 * For read transaction, avmm bus will directly return register values
 * without transaction response header.
 */
static int rd_trans_rx_parse(char *rx_buf, unsigned int rx_len, u32 *val)
{
	unsigned int count, i;
	__le32 *data;

	if (!rx_len || !IS_ALIGNED(rx_len, VAL_SIZE))
		return -EINVAL;

	count = rx_len / VAL_SIZE;

	data = (__le32 *)rx_buf;
	for (i = 0; i < count; i++)
		*val++ = le32_to_cpu(*data++);

	return 0;
}

/* For write transaction, slave will return a transaction response header. */
static int wr_trans_rx_parse(char *rx_buf, unsigned int rx_len,
			     u16 expected_len)
{
	struct trans_response *resp;
	u8 trans_code;
	u16 val_len;

	if (rx_len != TRANS_RESP_SIZE)
		return -EINVAL;

	resp = (struct trans_response *)rx_buf;

	trans_code = resp->r_trans_code ^ 0x80;
	val_len = be16_to_cpu(resp->size);
	if (!val_len || !IS_ALIGNED(val_len, VAL_SIZE) ||
	    val_len != expected_len)
		return -EINVAL;

	/* error out if trans code doesn't align with what host sent */
	if ((val_len == VAL_SIZE && trans_code != TRANS_CODE_WRITE) ||
	    (val_len > VAL_SIZE && trans_code != TRANS_CODE_SEQ_WRITE))
		return -EFAULT;

	return 0;
}

/* Input an transaction layer byte stream in rx_buf, output read out data. */
static int trans_rx_parse(char *rx_buf, unsigned int rx_len, bool is_read,
			  u16 expected_len, u32 *rd_val)
{
	if (is_read) {
		if (expected_len != rx_len)
			return -EINVAL;

		return rd_trans_rx_parse(rx_buf, rx_len, rd_val);
	}

	return wr_trans_rx_parse(rx_buf, rx_len, expected_len);
}

/* Packet Layer & Physical Layer */

#define PKT_SOP		0x7a
#define PKT_EOP		0x7b
#define PKT_CHANNEL	0x7c
#define PKT_ESC		0x7d

#define PHY_IDLE	0x4a
#define PHY_ESC		0x4d

/*
 * Input a trans stream in trans_tx_buf, format a phy stream in phy_tx_buf.
 */
static void pkt_phy_tx_prepare(char *trans_tx_buf, unsigned int trans_tx_len,
			       char *phy_tx_buf, unsigned int *phy_tx_len)
{
	unsigned int i;
	char *b, *p;

	b = trans_tx_buf;
	p = phy_tx_buf;

	*p++ = PKT_SOP;

	/*
	 * driver doesn't support multiple channel so channel number is
	 * always 0.
	 */
	*p++ = PKT_CHANNEL;
	*p++ = 0x0;

	for (i = 0; i < trans_tx_len; i++) {
		/* EOP should be inserted before last valid char */
		if (i == trans_tx_len - 1)
			*p++ = PKT_EOP;

		/* insert ESCAPE char if data value equals any special char */
		switch (*b) {
		case PKT_SOP:
		case PKT_EOP:
		case PKT_CHANNEL:
		case PKT_ESC:
			*p++ = PKT_ESC;
			*p++ = *b++ ^ 0x20;
			break;
		case PHY_IDLE:
		case PHY_ESC:
			*p++ = PHY_ESC;
			*p++ = *b++ ^ 0x20;
			break;
		default:
			*p++ = *b++;
			break;
		}
	}

	*phy_tx_len = p - phy_tx_buf;
}

/*
 * input a phy stream in pkt_rx_buf, parse out a trans stream in trans_rx_buf.
 */
static int pkt_phy_rx_parse(struct device *dev,
			    char *phy_rx_buf, unsigned int phy_rx_len,
			    char *trans_rx_buf, unsigned int *trans_rx_len)
{
	char *b, *p, *sop = NULL;

	b = phy_rx_buf;
	p = trans_rx_buf;

	/* Find the last SOP */
	while (b < phy_rx_buf + phy_rx_len) {
		if (*b == PKT_SOP)
			sop = b;
		b++;
	}

	if (!sop) {
		dev_err(dev, "%s no SOP\n", __func__);
		return -EINVAL;
	}

	b = sop + 1;

	while (b < phy_rx_buf + phy_rx_len) {
		switch (*b) {
		case PHY_IDLE:
			b++;
			break;
		case PKT_CHANNEL:
			/*
			 * We don't support multiple channel, so error out if
			 * a non-zero channel number is found.
			 */
			b++;
			if (*b != 0x0)
				return -EINVAL;
			b++;
			break;
		case PHY_ESC:
		case PKT_ESC:
			b++;
			*p++ = *b++ ^ 0x20;
			break;
		case PKT_SOP:
			dev_err(dev, "%s 2nd SOP\n", __func__);
			return -EINVAL;
		case PKT_EOP:
			/* the char after EOP is the last valid char*/
			b++;

			switch (*b) {
			case PHY_ESC:
			case PKT_ESC:
			/* the last char may also be escaped */
				b++;
				*p++ = *b++ ^ 0x20;
				break;
			case PHY_IDLE:
			case PKT_SOP:
			case PKT_CHANNEL:
			case PKT_EOP:
				dev_err(dev, "%s unexpected 0x%x\n",
					__func__, *b);
				return -EINVAL;
			default:
				*p++ = *b++;
				break;
			}

			*trans_rx_len = p - trans_rx_buf;

			return 0;
		default:
			*p++ = *b++;
			break;
		}
	}

	/* We parsed all the bytes but didn't find EOP */
	dev_err(dev, "%s no EOP\n", __func__);
	return -EINVAL;
}

/*
 * tx_buf len should be aligned with BPW of SPI. Spare bytes should be padded
 * with PHY_IDLE, then slave just drop them.
 *
 * Driver will not simply pad 4a at the tail. The concern is that driver will
 * not store MISO data during tx phase, if driver pad 4a at the tail, it is
 * possible that slave is fast enough to response at the padding time. As a
 * result these rx bytes lost. In the following case, 7a,7c,00 will lost.
 * MOSI ...|7a|7c|00|10| |00|00|04|02| |4b|7d|5a|7b| |40|4a|4a|4a| |XX|XX|...
 * MISO ...|4a|4a|4a|4a| |4a|4a|4a|4a| |4a|4a|4a|4a| |4a|7a|7c|00| |78|56|...
 *
 * So driver moves EOP and bytes after EOP to the end of aligned size, then
 * fill the hole with PHY_IDLE. As following:
 * before pad ...|7a|7c|00|10| |00|00|04|02| |4b|7d|5a|7b| |40|
 * after pad  ...|7a|7c|00|10| |00|00|04|02| |4b|7d|5a|4a| |4a|4a|7b|40|
 * Then slave will not get the entire packet before tx phase is over, it can't
 * response anything either.
 */
static void phy_tx_pad(unsigned int word_len, char *phy_buf,
		       unsigned int phy_buf_len, unsigned int *aligned_len)
{
	char *p = &phy_buf[phy_buf_len - 1], *dst_p;

	*aligned_len = ALIGN(phy_buf_len, word_len);

	if (*aligned_len == phy_buf_len)
		return;

	dst_p = &phy_buf[*aligned_len - 1];

	/* move EOP and bytes after EOP to the end of aligned size*/
	while (p > phy_buf) {
		*dst_p = *p;

		if (*p == PKT_EOP)
			break;

		p--;
		dst_p--;
	}

	/* fill the hole with PHY_IDLEs */
	while (p < dst_p)
		*p++ = PHY_IDLE;
}

static bool br_need_swap(struct spi_avmm_bridge *br)
{
	return (br->word_len == 4 && !(br->spi->mode & SPI_LSB_FIRST));
}

static void swap_word(u32 *p)
{
	*p = swab32p(p);
}

static void br_rx_swap_word(struct spi_avmm_bridge *br, char *rxbuf)
{
	if (!br_need_swap(br))
		return;

	swap_word((u32 *)rxbuf);
}

static void br_tx_swap(struct spi_avmm_bridge *br)
{
	unsigned int count;
	u32 *p;

	/*
	 * Phy layer data is filled byte by byte from low addr to high. And the
	 * protocol requires LSB first. If spi device cannot do LSB_FIRST
	 * transfer, driver need to swap the byte order word by word.
	 */
	if (!br_need_swap(br))
		return;

	count = br->phy_tx_len / 4;

	p = (u32 *)br->phy_tx_buf;
	while (count--) {
		swap_word(p);
		p++;
	}
}

#define RX_NOT_READY_1	PHY_IDLE
#define RX_NOT_READY_4	(PHY_IDLE << 24 | PHY_IDLE << 16 |	\
			 PHY_IDLE << 8 | PHY_IDLE)

static bool is_word_not_ready(const char *rxbuf, u32 word_len)
{
	return (word_len == 1 && *rxbuf == RX_NOT_READY_1) ||
	       (word_len == 4 && *(u32 *)rxbuf == RX_NOT_READY_4);
}

static const char *find_eop(const char *rxbuf, u32 word_len)
{
	return memchr(rxbuf, PKT_EOP, word_len);
}

static int br_tx_all(struct spi_avmm_bridge *br)
{
	return spi_write(br->spi, br->phy_tx_buf, br->phy_tx_len);
}

static int br_rx_word_timeout(struct spi_avmm_bridge *br, char *rxbuf)
{
	unsigned long poll_timeout;
	bool last_try = false;
	int ret;

	poll_timeout = jiffies + SPI_AVMM_XFER_TIMEOUT;
	for (;;) {
		ret = spi_read(br->spi, rxbuf, br->word_len);
		if (ret)
			return ret;

		/* keep on reading if rx word having no valid byte. */
		if (!is_word_not_ready(rxbuf, br->word_len))
			break;

		if (last_try)
			return -ETIMEDOUT;

		/*
		 * We timeout when rx keeps invalid for some time. But
		 * it is possible we are scheduled out for long time
		 * after spi_read. And when we are scheduled in, SW
		 * timeout happens. But actually HW may work fine and
		 * be ready long time ago. So we need to do an extra
		 * read, if we got valid word we return a valid rx word,
		 * otherwise real HW issue happens.
		 */
		if (time_after(jiffies, poll_timeout))
			last_try = true;
	}

	return 0;
}

static void br_tx_prepare(struct spi_avmm_bridge *br, bool is_read, u32 reg,
			  u32 *wr_val, u16 count)
{
	unsigned int tx_len;

	trans_tx_prepare(is_read, reg, wr_val, VAL_SIZE * count,
			 br->trans_tx_buf, &tx_len);
	pkt_phy_tx_prepare(br->trans_tx_buf, tx_len,
			   br->phy_tx_buf, &tx_len);
	phy_tx_pad(br->word_len, br->phy_tx_buf, tx_len, &tx_len);

	br->phy_tx_len = tx_len;
}

static int br_rx_parse(struct spi_avmm_bridge *br, bool is_read,
		       u16 expected_count, u32 *rd_val)
{
	struct device *dev = &br->spi->dev;
	unsigned int trans_rx_len;
	int ret;

	ret = pkt_phy_rx_parse(dev, br->phy_rx_buf, br->phy_rx_len,
			       br->trans_rx_buf, &trans_rx_len);
	if (ret) {
		dev_err(dev, "%s pkt_phy_rx_parse failed %d\n",
			__func__, ret);
		goto phy_pkt_rx_err;
	}

	ret = trans_rx_parse(br->trans_rx_buf, trans_rx_len, is_read,
			     expected_count * VAL_SIZE, rd_val);
	if (!ret)
		return 0;

	dev_err(dev, "%s trans_rx_parse failed %d\n", __func__, ret);
	print_hex_dump(KERN_DEBUG, "trans rx:", DUMP_PREFIX_OFFSET,
		       16, 1, br->trans_rx_buf, trans_rx_len, true);

phy_pkt_rx_err:
	print_hex_dump(KERN_DEBUG, "phy rx:", DUMP_PREFIX_OFFSET,
		       16, 1, br->phy_rx_buf, br->phy_rx_len, true);

	return ret;
}

static void rx_max_adjust(const char *w, const char *eop, u32 word_len,
			  u32 rx_len, u32 *rx_max)
{
	u32 remain_bytes  = w + word_len - 1 - eop, add_bytes = 0;
	const char *ptr;

	if (remain_bytes == 0) {
		/*
		 * EOP is the last byte in the word, rx 2 more bytes and
		 * finish.
		 */
		add_bytes = 2;
	} else if (remain_bytes == 1) {
		/* 1 byte left in the word after EOP. */
		ptr = eop + 1;
		/*
		 * If the byte is an ESCAPE char, rx 1 more byte and
		 * finish. Otherwise OK to finish rx immediately.
		 */
		if (*ptr == PHY_ESC || *ptr == PKT_ESC)
			add_bytes = 1;
	}
	/*
	 * 2 or more bytes left in the word after EOP, OK to finish rx
	 * immediately.
	 */

	/* Adjust rx_max, make sure we don't exceed the original rx_max. */
	*rx_max = min(*rx_max, ALIGN(rx_len + add_bytes, word_len));
}

/*
 * In tx phase, slave only returns PHY_IDLE (0x4a). So driver will ignore rx in
 * tx phase.
 *
 * Slave may send unknown number of PHY_IDLEs in rx phase, so we cannot prepare
 * a fixed length buffer to receive all rx data in a batch. We have to read word
 * by word and filter out pure PHY_IDLE words. The rest of words have
 * predictable max length, driver prepared enough buffer for them. See comments
 * for definition of PHY_RX_MAX.
 *
 * When EOP is detected, 1 or 2 (if the last byte is escaped) more bytes should
 * be received then rx should finish.
 */
static int br_txrx(struct spi_avmm_bridge *br)
{
	u32 wl = br->word_len, rx_max = PHY_RX_MAX, rx_len = 0;
	char *rxbuf = br->phy_rx_buf;
	const char *eop = NULL;
	int ret;

	/* reorder words for spi transfer */
	br_tx_swap(br);

	ret = br_tx_all(br);
	if (ret)
		goto out;

	while (rx_len <= rx_max - wl) {
		/* read word by word */
		ret = br_rx_word_timeout(br, rxbuf);
		if (ret)
			goto out;

		rx_len += wl;

		/* reorder word back now */
		br_rx_swap_word(br, rxbuf);

		if (!eop) {
			eop = find_eop(rxbuf, wl);
			if (eop) {
				/*
				 * EOP is found in the word, then we are about
				 * to finish rx, no need to fill the whole phy
				 * rx buf. But EOP is not the last byte in rx
				 * stream, we may read 1 or 2 more bytes and
				 * early finish rx by adjusting rx_max.
				 */
				rx_max_adjust(rxbuf, eop, wl, rx_len, &rx_max);
			}
		}

		rxbuf += wl;
	}

out:
	br->phy_rx_len = rx_len;

	ret = ret ? : (eop ? 0 : -EINVAL);
	if (ret) {
		dev_err(&br->spi->dev, "%s br txrx err %d\n", __func__, ret);
		print_hex_dump(KERN_DEBUG, "phy rx:", DUMP_PREFIX_OFFSET,
			       16, 1, br->phy_rx_buf, rx_len, true);
	}
	return ret;
}

static int do_reg_access(void *context, bool is_read, unsigned int reg,
			 unsigned int *value, u16 count)
{
	struct spi_avmm_bridge *br = context;
	int ret;

	br_tx_prepare(br, is_read, reg, value, count);

	ret = br_txrx(br);
	if (ret)
		return ret;

	return br_rx_parse(br, is_read, count, value);
}

#define do_reg_read(_ctx, _reg, _value, _count) \
	do_reg_access(_ctx, true, _reg, _value, _count)
#define do_reg_write(_ctx, _reg, _value, _count) \
	do_reg_access(_ctx, false, _reg, _value, _count)

static int regmap_spi_avmm_reg_read(void *context, unsigned int reg,
				    unsigned int *val)
{
	return do_reg_read(context, reg, val, 1);
}

static int regmap_spi_avmm_reg_write(void *context, unsigned int reg,
				     unsigned int val)
{
	return do_reg_write(context, reg, &val, 1);
}

int regmap_spi_avmm_gather_write(void *context,
				 const void *reg_buf, size_t reg_len,
				 const void *val_buf, size_t val_len)
{
	if (reg_len != REG_SIZE)
		return -EINVAL;

	return do_reg_write(context, *(u32 *)reg_buf, (u32 *)val_buf,
			    (u16)(val_len / VAL_SIZE));
}

int regmap_spi_avmm_write(void *context, const void *data, size_t count)
{
	if (count < REG_SIZE + VAL_SIZE)
		return -EINVAL;

	return regmap_spi_avmm_gather_write(context, data, REG_SIZE,
					    data + REG_SIZE, count - REG_SIZE);
}

int regmap_spi_avmm_read(void *context,
			 const void *reg_buf, size_t reg_len,
			 void *val_buf, size_t val_len)
{
	if (reg_len != REG_SIZE)
		return -EINVAL;

	return do_reg_read(context, *(u32 *)reg_buf, val_buf,
			   (u16)(val_len / VAL_SIZE));
}

static void spi_avmm_bridge_ctx_free(void *context)
{
	kfree(context);
}

static struct spi_avmm_bridge *
spi_avmm_bridge_ctx_gen(struct spi_device *spi)
{
	struct spi_avmm_bridge *br;

	br = kzalloc(sizeof(*br), GFP_KERNEL);
	if (br) {
		br->spi = spi;
		br->word_len = spi->bits_per_word / 8;
	}

	return br;
}

struct regmap_bus regmap_spi_avmm_bus = {
	.write = regmap_spi_avmm_write,
	.gather_write = regmap_spi_avmm_gather_write,
	.read = regmap_spi_avmm_read,
	.reg_format_endian_default = REGMAP_ENDIAN_NATIVE,
	.val_format_endian_default = REGMAP_ENDIAN_NATIVE,
	.max_raw_read = VAL_SIZE * MAX_RX_CNT,
	.max_raw_write = VAL_SIZE * MAX_TX_CNT,

	.reg_write = regmap_spi_avmm_reg_write,
	.reg_read = regmap_spi_avmm_reg_read,

	.free_context = spi_avmm_bridge_ctx_free,
};

struct regmap *__devm_regmap_init_spi_avmm(struct spi_device *spi,
					   const struct regmap_config *config,
					   struct lock_class_key *lock_key,
					   const char *lock_name)
{
	struct spi_avmm_bridge *bridge;
	struct regmap *map;

	/* Only support BPW == 8 or 32 now */
	if (!spi || (spi->bits_per_word != 8 && spi->bits_per_word != 32))
		return ERR_PTR(-EINVAL);

	bridge = spi_avmm_bridge_ctx_gen(spi);
	if (!bridge)
		return ERR_PTR(-ENOMEM);

	map = __devm_regmap_init(&spi->dev, &regmap_spi_avmm_bus,
				 bridge, config, lock_key, lock_name);
	if (IS_ERR(map)) {
		spi_avmm_bridge_ctx_free(bridge);
		return ERR_CAST(map);
	}

	return map;
}
