#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>
#include "hdparm.h"
#include "sgio.h"

#define DEVICE_ARRAY_LOCATION	63

enum sg_vars{
	SG_CDB2_TLEN_NODATA	= 0 << 0,
	SG_CDB2_TLEN_FEAT	= 1 << 0,
	SG_CDB2_TLEN_NSECT	= 2 << 0,

	SG_CDB2_TLEN_BYTES	= 0 << 2,
	SG_CDB2_TLEN_SECTORS	= 1 << 2,

	SG_CDB2_TDIR_TO_DEV	= 0 << 3,
	SG_CDB2_TDIR_FROM_DEV	= 1 << 3,

	SG_CDB2_CHECK_COND	= 1 << 5,
};
int verbose = 1;
static const unsigned int default_timeout_secs = 15;
unsigned short* id = NULL;
const int timeout_15secs = 15;


static inline int needs_lba48 (__u8 ata_op, __u64 lba, unsigned int nsect)
{
	switch (ata_op) {
		case ATA_OP_DSM:
		case ATA_OP_READ_PIO_EXT:
		case ATA_OP_READ_DMA_EXT:
		case ATA_OP_WRITE_PIO_EXT:
		case ATA_OP_WRITE_DMA_EXT:
		case ATA_OP_READ_VERIFY_EXT:
		case ATA_OP_WRITE_UNC_EXT:
		case ATA_OP_READ_NATIVE_MAX_EXT:
		case ATA_OP_SET_MAX_EXT:
		case ATA_OP_FLUSHCACHE_EXT:
			return 1;
		case ATA_OP_SECURITY_ERASE_PREPARE:
		case ATA_OP_SECURITY_ERASE_UNIT:
		case ATA_OP_VENDOR_SPECIFIC_0x80:
		case ATA_OP_SMART:
			return 0;
	}
	if (lba >= lba28_limit)
		return 1;
	if (nsect) {
		if (nsect > 0xff)
			return 1;
		if ((lba + nsect - 1) >= lba28_limit)
			return 1;
	}
	return 0;
}

void tf_init (struct ata_tf *tf, __u8 ata_op, __u64 lba, unsigned int nsect)
{
	memset(tf, 0, sizeof(*tf));
	tf->command  = ata_op;
	tf->dev      = ATA_USING_LBA;
	tf->lob.lbal = lba;
	tf->lob.lbam = lba >>  8;
	tf->lob.lbah = lba >> 16;
	tf->lob.nsect = nsect;
	if (needs_lba48(ata_op, lba, nsect)) {
		tf->is_lba48 = 1;
		tf->hob.nsect = nsect >> 8;
		tf->hob.lbal = lba >> 24;
		tf->hob.lbam = lba >> 32;
		tf->hob.lbah = lba >> 40;
	} else {
		tf->dev |= (lba >> 24) & 0x0f;
	}
}

__u64 tf_to_lba (struct ata_tf *tf)
{
	__u32 lba24, lbah;
	__u64 lba64;

	lba24 = (tf->lob.lbah << 16) | (tf->lob.lbam << 8) | (tf->lob.lbal);
	if (tf->is_lba48)
		lbah = (tf->hob.lbah << 16) | (tf->hob.lbam << 8) | (tf->hob.lbal);
	else
		lbah = (tf->dev & 0x0f);
	lba64 = (((__u64)lbah) << 24) | (__u64)lba24;
	return lba64;
}

static inline int is_dma (__u8 ata_op)
{
	switch (ata_op) {
		case ATA_OP_DSM:
		case ATA_OP_READ_DMA_EXT:
		case ATA_OP_READ_FPDMA:
		case ATA_OP_WRITE_DMA_EXT:
		case ATA_OP_WRITE_FPDMA:
		case ATA_OP_READ_DMA:
		case ATA_OP_WRITE_DMA:
			return SG_DMA;
		default:
			return SG_PIO;
	}
}

static void dump_bytes (const char *prefix, unsigned char *p, int len)
{
	int i;

	if (prefix)
		fprintf(stderr, "%s: ", prefix);
	for (i = 0; i < len; ++i)
		fprintf(stderr, " %02x", p[i]);
	fprintf(stderr, "\n");
}

int sg16 (int fd, int rw, int dma, struct ata_tf *tf,
	void *data, unsigned int data_bytes, unsigned int timeout_secs)
{
	unsigned char cdb[SG_ATA_16_LEN];
	unsigned char sb[32], *desc;
	struct scsi_sg_io_hdr io_hdr;
	//int prefer12 = prefer_ata12, demanded_sense = 0;
	int prefer12 = 0, demanded_sense = 0;

	if (tf->command == ATA_OP_PIDENTIFY)
		prefer12 = 0;

	memset(&cdb, 0, sizeof(cdb));
	memset(&sb,     0, sizeof(sb));
	memset(&io_hdr, 0, sizeof(struct scsi_sg_io_hdr));
	if (data && data_bytes && !rw)
		memset(data, 0, data_bytes);

	if (dma) {
		//cdb[1] = data ? (rw ? SG_ATA_PROTO_UDMA_OUT : SG_ATA_PROTO_UDMA_IN) : SG_ATA_PROTO_NON_DATA;
		cdb[1] = data ? SG_ATA_PROTO_DMA : SG_ATA_PROTO_NON_DATA;
	} else {
		cdb[1] = data ? (rw ? SG_ATA_PROTO_PIO_OUT : SG_ATA_PROTO_PIO_IN) : SG_ATA_PROTO_NON_DATA;
	}

	/* libata/AHCI workaround: don't demand sense data for IDENTIFY commands */
	if (data) {
		cdb[2] |= SG_CDB2_TLEN_NSECT | SG_CDB2_TLEN_SECTORS;
		cdb[2] |= rw ? SG_CDB2_TDIR_TO_DEV : SG_CDB2_TDIR_FROM_DEV;
	} else {
		cdb[2] = SG_CDB2_CHECK_COND;
	}

	if (!prefer12 || tf->is_lba48) {
		cdb[ 0] = SG_ATA_16;
		cdb[ 4] = tf->lob.feat;
		cdb[ 6] = tf->lob.nsect;
		cdb[ 8] = tf->lob.lbal;
		cdb[10] = tf->lob.lbam;
		cdb[12] = tf->lob.lbah;
		cdb[13] = tf->dev;
		cdb[14] = tf->command;
		if (tf->is_lba48) {
			cdb[ 1] |= SG_ATA_LBA48;
			cdb[ 3]  = tf->hob.feat;
			cdb[ 5]  = tf->hob.nsect;
			cdb[ 7]  = tf->hob.lbal;
			cdb[ 9]  = tf->hob.lbam;
			cdb[11]  = tf->hob.lbah;
		}
		io_hdr.cmd_len = SG_ATA_16_LEN;
	} else {
		cdb[ 0] = SG_ATA_12;
		cdb[ 3] = tf->lob.feat;
		cdb[ 4] = tf->lob.nsect;
		cdb[ 5] = tf->lob.lbal;
		cdb[ 6] = tf->lob.lbam;
		cdb[ 7] = tf->lob.lbah;
		cdb[ 8] = tf->dev;
		cdb[ 9] = tf->command;
		io_hdr.cmd_len = SG_ATA_12_LEN;
	}

	io_hdr.interface_id	= 'S';
	io_hdr.mx_sb_len	= sizeof(sb);
	io_hdr.dxfer_direction	= data ? (rw ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV) : SG_DXFER_NONE;
	io_hdr.dxfer_len	= data ? data_bytes : 0;
	io_hdr.dxferp		= data;
	io_hdr.cmdp		= cdb;
	io_hdr.sbp		= sb;
	io_hdr.pack_id		= tf_to_lba(tf);
	io_hdr.timeout		= (timeout_secs ? timeout_secs : default_timeout_secs) * 1000; /* msecs */

	if (verbose) {
		dump_bytes("outgoing cdb", cdb, sizeof(cdb));
		if (rw && data)
			dump_bytes("outgoing_data", (unsigned char *)data, data_bytes);
	}

	if (ioctl(fd, SG_IO, &io_hdr) == -1) {
		if (verbose)
			perror("ioctl(fd,SG_IO)");
		return -1;	/* SG_IO not supported */
	}

	if (verbose)
		fprintf(stderr, "SG_IO: ATA_%u status=0x%x, host_status=0x%x, driver_status=0x%x\n",
			io_hdr.cmd_len, io_hdr.status, io_hdr.host_status, io_hdr.driver_status);

	if (io_hdr.status && io_hdr.status != SG_CHECK_CONDITION) {
		if (verbose)
			fprintf(stderr, "SG_IO: bad status: 0x%x\n", io_hdr.status);
	  	errno = EBADE;
		return -1;
	}
	if (io_hdr.host_status) {
		if (verbose)
			fprintf(stderr, "SG_IO: bad host status: 0x%x\n", io_hdr.host_status);
	  	errno = EBADE;
		return -1;
	}
	if (verbose) {
		dump_bytes("SG_IO: sb[]", sb, sizeof(sb));
		if (!rw && data)
			dump_bytes("incoming_data", (unsigned char*)data, data_bytes);
	}

	if (io_hdr.driver_status && (io_hdr.driver_status != SG_DRIVER_SENSE)) {
		if (verbose)
			fprintf(stderr, "SG_IO: bad driver status: 0x%x\n", io_hdr.driver_status);
	  	errno = EBADE;
		return -1;
	}

	desc = sb + 8;
	if (io_hdr.driver_status != SG_DRIVER_SENSE) {
		if (sb[0] | sb[1] | sb[2] | sb[3] | sb[4] | sb[5] | sb[6] | sb[7] | sb[8] | sb[9]) {
			static int second_try = 0;
			if (!second_try++)
				fprintf(stderr, "SG_IO: questionable sense data, results may be incorrect\n");
		} else if (demanded_sense) {
			static int second_try = 0;
			if (!second_try++)
				fprintf(stderr, "SG_IO: missing sense data, results may be incorrect\n");
		}
	} else if (sb[0] != 0x72 || sb[7] < 14 || desc[0] != 0x09 || desc[1] < 0x0c) {
		dump_bytes("SG_IO: bad/missing sense data, sb[]", sb, sizeof(sb));
	}

	if (verbose) {
		unsigned int len = desc[1] + 2, maxlen = sizeof(sb) - 8 - 2;
		if (len > maxlen)
			len = maxlen;
		dump_bytes("SG_IO: desc[]", desc, len);
	}

	tf->is_lba48  = desc[ 2] & 1;
	tf->error     = desc[ 3];
	tf->lob.nsect = desc[ 5];
	tf->lob.lbal  = desc[ 7];
	tf->lob.lbam  = desc[ 9];
	tf->lob.lbah  = desc[11];
	tf->dev       = desc[12];
	tf->status    = desc[13];
	tf->hob.feat  = 0;
	if (tf->is_lba48) {
		tf->hob.nsect = desc[ 4];
		tf->hob.lbal  = desc[ 6];
		tf->hob.lbam  = desc[ 8];
		tf->hob.lbah  = desc[10];
	} else {
		tf->hob.nsect = 0;
		tf->hob.lbal  = 0;
		tf->hob.lbam  = 0;
		tf->hob.lbah  = 0;
	}

	if (verbose)
		fprintf(stderr, "      ATA_%u stat=%02x err=%02x nsect=%02x lbal=%02x lbam=%02x lbah=%02x dev=%02x\n",
				io_hdr.cmd_len, tf->status, tf->error, tf->lob.nsect, tf->lob.lbal, tf->lob.lbam, tf->lob.lbah, tf->dev);

	if (tf->status & (ATA_STAT_ERR | ATA_STAT_DRQ)) {
		if (verbose) {
			fprintf(stderr, "I/O error, ata_op=0x%02x ata_status=0x%02x ata_error=0x%02x\n",
				tf->command, tf->status, tf->error);
		}
		errno = EIO;
		return -1;
	}
	return 0;
}


int do_taskfile_cmd (int fd, struct hdio_taskfile *r, unsigned int timeout_secs)
{
	int rc;
#ifdef SG_IO
	struct ata_tf tf;
	void *data = NULL;
	//unsigned char *data = NULL;
	unsigned int data_bytes = 0;
	int rw = SG_READ;
	/*
	 * Reformat and try to issue via SG_IO:
	 */
	tf_init(&tf, 0, 0, 0);
#if 1 /* debugging */
	if (verbose) {
		printf("oflags.bits.lob_all=0x%02x, flags={", r->oflags.bits.lob_all);
		if (r->oflags.bits.lob.feat)	printf(" feat");
		if (r->oflags.bits.lob.nsect)	printf(" nsect");
		if (r->oflags.bits.lob.lbal)	printf(" lbal");
		if (r->oflags.bits.lob.lbam)	printf(" lbam");
		if (r->oflags.bits.lob.lbah)	printf(" lbah");
		if (r->oflags.bits.lob.dev)	printf(" dev");
		if (r->oflags.bits.lob.command) printf(" command");
		printf(" }\n");
		printf("oflags.bits.hob_all=0x%02x, flags={", r->oflags.bits.hob_all);
		if (r->oflags.bits.hob.feat)	printf(" feat");
		if (r->oflags.bits.hob.nsect)	printf(" nsect");
		if (r->oflags.bits.hob.lbal)	printf(" lbal");
		if (r->oflags.bits.hob.lbam)	printf(" lbam");
		if (r->oflags.bits.hob.lbah)	printf(" lbah");
		printf(" }\n");
	}
#endif
	if (r->oflags.bits.lob.feat)		tf.lob.feat  = r->lob.feat;
	if (r->oflags.bits.lob.lbal)		tf.lob.lbal  = r->lob.lbal;
	if (r->oflags.bits.lob.nsect)		tf.lob.nsect = r->lob.nsect;
	if (r->oflags.bits.lob.lbam)		tf.lob.lbam  = r->lob.lbam;
	if (r->oflags.bits.lob.lbah)		tf.lob.lbah  = r->lob.lbah;
	if (r->oflags.bits.lob.dev)		tf.dev       = r->lob.dev;
	if (r->oflags.bits.lob.command)	tf.command   = r->lob.command;
	if (needs_lba48(tf.command,0,0) || r->oflags.bits.hob_all || r->iflags.bits.hob_all) {
		tf.is_lba48 = 1;
		if (r->oflags.bits.hob.feat)	tf.hob.feat  = r->hob.feat;
		if (r->oflags.bits.hob.lbal)	tf.hob.lbal  = r->hob.lbal;
		if (r->oflags.bits.hob.nsect)	tf.hob.nsect = r->hob.nsect;
		if (r->oflags.bits.hob.lbam)	tf.hob.lbam  = r->hob.lbam;
		if (r->oflags.bits.hob.lbah)	tf.hob.lbah  = r->hob.lbah;
		if (verbose)
			fprintf(stderr, "using LBA48 taskfile\n");
	}
	switch (r->cmd_req) {
		case TASKFILE_CMD_REQ_OUT:
		case TASKFILE_CMD_REQ_RAW_OUT:
			data_bytes = r->obytes;
			data       = r->data;
			rw         = SG_WRITE;
			break;
		case TASKFILE_CMD_REQ_IN:
			data_bytes = r->ibytes;
			data       = r->data;
			break;
	}

	rc = sg16(fd, rw, is_dma(tf.command), &tf, data, data_bytes, timeout_secs);
	if (rc == -1) {
		if (errno == EINVAL || errno == ENODEV || errno == EBADE || errno == EIO)
			goto use_legacy_ioctl;
	}

	if (rc == 0 || errno == EIO) {
		if (r->iflags.bits.lob.feat)	r->lob.feat  = tf.error;
		if (r->iflags.bits.lob.lbal)	r->lob.lbal  = tf.lob.lbal;
		if (r->iflags.bits.lob.nsect)	r->lob.nsect = tf.lob.nsect;
		if (r->iflags.bits.lob.lbam)	r->lob.lbam  = tf.lob.lbam;
		if (r->iflags.bits.lob.lbah)	r->lob.lbah  = tf.lob.lbah;
		if (r->iflags.bits.lob.dev)	r->lob.dev   = tf.dev;
		if (r->iflags.bits.lob.command)	r->lob.command = tf.status;
		if (r->iflags.bits.hob.feat)	r->hob.feat  = tf.hob.feat;
		if (r->iflags.bits.hob.lbal)	r->hob.lbal  = tf.hob.lbal;
		if (r->iflags.bits.hob.nsect)	r->hob.nsect = tf.hob.nsect;
		if (r->iflags.bits.hob.lbam)	r->hob.lbam  = tf.hob.lbam;
		if (r->iflags.bits.hob.lbah)	r->hob.lbah  = tf.hob.lbah;
	}
	return rc;

use_legacy_ioctl:
#else
	timeout_secs = 0;	/* keep compiler happy */
#endif /* SG_IO */
	if (verbose)
		fprintf(stderr, "trying legacy HDIO_DRIVE_TASKFILE\n");
	errno = 0;

	rc = ioctl(fd, HDIO_DRIVE_TASKFILE, r);
	if (verbose) {
		int err = errno;
		fprintf(stderr, "error string %s, rc=%d, errno=%d, returned ATA registers: ", strerror(errno), rc, err);
		if (r->iflags.bits.lob.feat)	fprintf(stderr, " er=%02x", r->lob.feat);
		if (r->iflags.bits.lob.nsect)	fprintf(stderr, " ns=%02x", r->lob.nsect);
		if (r->iflags.bits.lob.lbal)	fprintf(stderr, " ll=%02x", r->lob.lbal);
		if (r->iflags.bits.lob.lbam)	fprintf(stderr, " lm=%02x", r->lob.lbam);
		if (r->iflags.bits.lob.lbah)	fprintf(stderr, " lh=%02x", r->lob.lbah);
		if (r->iflags.bits.lob.dev)	fprintf(stderr, " dh=%02x", r->lob.dev);
		if (r->iflags.bits.lob.command)	fprintf(stderr, " st=%02x", r->lob.command);
		if (r->iflags.bits.hob.feat)	fprintf(stderr, " err=%02x", r->hob.feat);
		if (r->iflags.bits.hob.nsect)	fprintf(stderr, " err=%02x", r->hob.nsect);
		if (r->iflags.bits.hob.lbal)	fprintf(stderr, " err=%02x", r->hob.lbal);
		if (r->iflags.bits.hob.lbam)	fprintf(stderr, " err=%02x", r->hob.lbam);
		if (r->iflags.bits.hob.lbah)	fprintf(stderr, " err=%02x", r->hob.lbah);
		fprintf(stderr, "\n");
		errno = err;
	}
	if (rc == -1 && errno == EINVAL) {
		fprintf(stderr, "The running kernel lacks CONFIG_IDE_TASK_IOCTL support for this device.\n");
		errno = EINVAL;
	}
	return rc;
}

void init_hdio_taskfile (struct hdio_taskfile *r, __u8 ata_op, int rw, int force_lba48,
				__u64 lba, unsigned int nsect, int data_bytes)
{
	memset(r, 0, sizeof(struct hdio_taskfile) + data_bytes);
	if (!data_bytes) {
		r->dphase  = TASKFILE_DPHASE_NONE;
		r->cmd_req = TASKFILE_CMD_REQ_NODATA;
	} else if (rw == RW_WRITE) {
		r->dphase  = TASKFILE_DPHASE_PIO_OUT;
		r->cmd_req = TASKFILE_CMD_REQ_RAW_OUT;
		r->obytes  = data_bytes;
	} else { /* rw == RW_READ */
		r->dphase  = TASKFILE_DPHASE_PIO_IN;
		r->cmd_req = TASKFILE_CMD_REQ_IN;
		r->ibytes  = data_bytes;
	}
	r->lob.command      = ata_op;
	r->oflags.bits.lob.command = 1;
	r->oflags.bits.lob.dev     = 1;
	r->oflags.bits.lob.lbal    = 1;
	r->oflags.bits.lob.lbam    = 1;
	r->oflags.bits.lob.lbah    = 1;
	r->oflags.bits.lob.nsect   = 1;

	r->iflags.bits.lob.command = 1;
	r->iflags.bits.lob.feat    = 1;

	r->lob.nsect = nsect;
	r->lob.lbal  = lba;
	r->lob.lbam  = lba >>  8;
	r->lob.lbah  = lba >> 16;
	r->lob.dev   = 0xa0 | ATA_USING_LBA;

	if (needs_lba48(ata_op, lba, nsect) || force_lba48) {
		r->hob.nsect = nsect >>  8;
		r->hob.lbal  = lba   >> 24;
		r->hob.lbam  = lba   >> 32;
		r->hob.lbah  = lba   >> 40;
		r->oflags.bits.hob.nsect = 1;
		r->oflags.bits.hob.lbal  = 1;
		r->oflags.bits.hob.lbam  = 1;
		r->oflags.bits.hob.lbah  = 1;
	} else {
		r->lob.dev |= (lba >> 24) & 0x0f;
	}
}

static int send_firmware (int fd, unsigned int xfer_mode, unsigned int offset,
			  const void *data, unsigned int bytecount)
{
	int err = 0;
	struct hdio_taskfile *r;
	unsigned int blockcount = bytecount / 512;
	unsigned int timeout_secs = 20;
	__u64 lba;

	lba = ((offset / 512) << 8) | ((blockcount >> 8) & 0xff);
	r = (struct hdio_taskfile*)malloc(sizeof(struct hdio_taskfile) + bytecount);
	if (!r) {
		if (xfer_mode == 3 || xfer_mode == 0x0e) {
			putchar('\n');
			fflush(stdout);
		}
		err = errno;
		perror("malloc()");
		return err;
	}
	init_hdio_taskfile(r, ATA_OP_DOWNLOAD_MICROCODE, RW_WRITE, LBA28_OK, lba, blockcount & 0xff, bytecount);

	r->lob.feat = xfer_mode;
	r->oflags.bits.lob.feat  = 1;
	r->iflags.bits.lob.nsect = 1;

	if (data && bytecount)
		memcpy(r->data, data, bytecount);

	if (do_taskfile_cmd(fd, r, timeout_secs)) {
		err = errno;
		if (xfer_mode == 3 || xfer_mode == 0x0e) {
			putchar('\n');
			fflush(stdout);
		}
		perror("FAILED");
	} else {
		if (xfer_mode == 3 || xfer_mode == 0x0e) {
			if (!verbose) {
				putchar('.');
				fflush(stdout);
			}
			switch (r->lob.nsect) {
				case 1:	// drive wants more data
				case 2:	// drive thinks it is all done
					err = - r->lob.nsect;
					break;
				default: // no status indication
					err = 0;
					break;
			}
		}
	}
	free(r);
	return err;
}

int get_id_log_page_data (int fd, __u8 pagenr, __u8 *buf)
{
	struct hdio_taskfile *r;
	int err = 0;

	r = (struct hdio_taskfile *)malloc(sizeof(struct hdio_taskfile) + 512);
	if (!r) {
		err = errno;
		perror("malloc()");
		return err;
	}

	init_hdio_taskfile(r, ATA_OP_READ_LOG_EXT, RW_READ, LBA48_FORCE, 0x30 + (pagenr << 8), 1, 512);
	if (do_taskfile_cmd(fd, r, timeout_15secs)) {
		printf("do_task_file returned error\n"); 
		err = errno;
	} else {
		printf("do_task_file returned success\n");
		memcpy(buf, r->data, 512);
	}
	free(r);
	return err;
}

int main()
{
	int fd = open("/dev/sda1", O_RDONLY | O_DIRECT);
	
	if(fd != -1)
	{
		int i = 0, retval = 0;;
		unsigned char buf[512 + 4];
		unsigned char logbuf[512];
		memset(buf, 0, sizeof(buf));
		memset(logbuf, 0, sizeof(logbuf));
		buf[0] = 0xEC;
		buf[3] = 1;
		printf("before:\n");
		struct hd_driveid driveid;
		// get device identification data
		//int ret = ioctl(fd, 0x030d, &driveid);
		int ret = ioctl(fd, HDIO_GET_IDENTITY, &driveid);


		printf("fw_rev model number: %s\n", driveid.fw_rev);
		printf("printf again: fw_rev");
		for(i = 0; i < 8; ++i)
			printf("%c", driveid.fw_rev[i]);
		printf("\n");

		if(driveid.command_set_2 & 0x01)
				printf("Download microcode: word 83:bit 0 is set\n");
	
		if(driveid.cfs_enable_2 & 0x01)
				printf("Download microcode: word 86:bit 0 is set\n");
		
		if(driveid.words94_125[25] & 0x10)
				printf("segmented firmware Download : word 119:bit 4 is set\n");
	
		if(driveid.words94_125[26] & 0x10)
				printf("segmented firmware Download : word 120:bit 4 is set\n");
		
		// another way to get device identification data
		ret = ioctl(fd, HDIO_DRIVE_CMD, buf);
		if(ret)
			printf("Failure");
		else
		{
			/*printf("BEFORE\n");
			for(i = 0; i < 512; ++i)
				printf("buf[%d]: %c\n", i, buf[i]);*/

			id = (unsigned short*)(buf + 4);
			/*for(i = 0; i < 0x100; ++i)
				printf("id[%d]: %c %d\n", i, id[i], id[i]);
			printf("---------------------------");
			*/
			/*for(i = 0; i < 512; ++i)
				if(i % 2 == 0)
				{
					int temp = buf[i];
					buf[i] = buf[i + 1];
					buf[i + 1] = temp;
				}
			printf("AFTER\n");
			for(i = 0; i < 512; ++i)
				printf("buf[%d]: %c\n", i, buf[i]);
			for(i = 0; i < 0x100; ++i)
				printf("id[%d]: %c %d\n", i, id[i], id[i]);
			*/
			int err = 0;
			const char *fw = NULL;
			const char *fwfd_new = NULL;
			struct stat st;
			const int max_bytes = 0xffff * 512;
			int xfer_min = 1, xfer_max = 0xffff, xfer_size, xfer_mode = 0x07;
			ssize_t offset = 0;

			int fwfd = open("/root/ananya/AA09.fwh", O_RDONLY);
			
			if(fwfd == -1)
			{
				printf("Error");
				exit(1);
			}
			//if((id[83] & 1) && (id[86] & 1))
			if(id[83] & 1)
				printf("id[83] Download microcode command is supported.\n");
			else
				printf("id[83] Download microcode command is not supported.\n");
			if(id[86] & 1)
				printf("id[86] Download microcode command is supported.\n");
			else
				printf("id[86] Download microcode command is not supported.\n");
			if(!((id[83] & 1) && (id[86] & 1)))
			{
				printf("firmware download not supported. exiting.\n");
				goto done;
			}
			if(id[119] & 0x10)
				printf("id[119] Segmented firmware feature for Download microcode command is supported.\n");
			else
				printf("id[119] Segmented firmware feature for Download microcode command is not supported.\n");
			if(id[120] & 0x10)
				printf("id[120] Segmented firmware feature for Download microcode command is supported.\n");
			else
				printf("id[120] Segmented firmware feature for Download microcode command is not supported.\n");
			if((id[119] & 0x10) && (id[120] & 0x10))
			{
				printf("segmented firmware download bit is set.\n");
				xfer_mode = 3;
				printf("xfer_mode = %d\n", xfer_mode);
			}
			else
			{
				printf("segmented firmware download bit is not set.\n");
				xfer_mode = 7;
				printf("xfer_mode = %d\n", xfer_mode);
			}
			if(xfer_mode ==3)
			{
				xfer_min = id[234];
				xfer_max = id[235];
				printf("xfer_min = %d xfer_max = %d\n", xfer_min, xfer_max);
				if(xfer_min == 0)
					xfer_min = 1;
				if(xfer_max == 0)
					xfer_max = 1;
				printf("after modifying: xfer_min = %d xfer_max = %d\n", xfer_min, xfer_max);
			}
			if(fstat(fwfd, &st) == -1)
			{
				printf("can't fstat file, error.\n");
				exit(1);
			}
			printf("fstat successful.\n");

			xfer_size = st.st_size/512;
			printf("firmware file size: %d\n", st.st_size);
			
			if (xfer_size > 0xffff)
			{
				printf("xfer_size is too large!\n");
				exit(1);
			}
			xfer_size *= 512;
			printf("xfer_size is fine.\n");
			
			
			// reading the firmware file as a binary file
			fw = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED|MAP_POPULATE|MAP_LOCKED, fwfd, 0);
			if (fw == MAP_FAILED)
			{
				printf("mmap failed.\n");
				exit(1);
			}
			
			printf("mmap successful.\n");
			
			FILE* fw_new=fopen("/root/ananya/AA09_new.fwh", "wb");
			for(int k = 208; k <= 1327312; k += 512)
				fwrite(&fw[k], sizeof(unsigned char), 512, fw_new);
			fclose(fw_new);
			int fd_new = open("/root/ananya/AA09_new.fwh", O_RDONLY);
			fwfd_new = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED|MAP_POPULATE|MAP_LOCKED, fd_new, 0);
			
			printf("firmware header: %dth byte: %x\n", 8, fw[8]);
			if(fw[8] & 0x20)
				printf("firmware header:deferred download bit is set.\n");
			else
				printf("firmware header:deferred download bit is not set.\n");

			if(fw[8] & 0x10)
				printf("firmware header:activate firmware bit is set.\n");
			else
				printf("firmware header:activate firmware bit is not set.\n");

			if(fw[8] & 0x08)
				printf("firmware header:strip header bit is set.\n");
			else
				printf("firmware header:strip header bit is not set.\n");

			if(fw[8] & 0x01)
				printf("firmware header:online download bit is set.\n");
			else
				printf("firmware header:online download bit is not set.\n");

			printf("\n Firmware Revision: ");
			for(i = 9; i <= 12; ++i)
				printf("%c", fw[i]);
			printf("\n Minimum Revision Level: ");
			for(i = 13; i <= 16; ++i)
				printf("%c", fw[i]);
			printf("\n");
			int numDevices = fw[DEVICE_ARRAY_LOCATION];
			printf("numDevices: %d\n", numDevices);
			// reading the drive log page 99h
			printf("Before reading log:11th byte %d\n", logbuf[11]);
			/*
			retval = get_id_log_page_data(fd, 0x99, logbuf);
			if(!retval)
				printf("get log page succeeded\n");
			else
				printf("get log page failed\n");
			*/
			//if(logbuf[
			printf("After reading log:11th byte %d\n", logbuf[11]);
			//send_firmware(fd_new, xfer_mode, 0, fw+208, xfer_size);

done:			munlock(fw, st.st_size);
			close(fwfd);
			close(fd_new);
		}
	}
	else
		printf("Error in open() call");
	
	close(fd);
	return 0;
}
