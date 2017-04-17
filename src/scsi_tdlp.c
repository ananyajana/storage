#define DEVICE "/dev/sg0"
/* Example program to demonstrate the generic SCSI interface */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <scsi/sg.h>

#define SCSI_OFF sizeof(struct sg_header)
static unsigned char cmd[SCSI_OFF + 18];      /* SCSI command buffer */
int fd;                               /* SCSI device/file descriptor */

/* process a complete scsi cmd. Use the generic scsi interface. */
static int handle_scsi_cmd(unsigned cmd_len,         /* command length */
                           unsigned in_size,         /* input data size */
                           unsigned char *i_buff,    /* input buffer */
                           unsigned out_size,        /* output data size */
                           unsigned char *o_buff     /* output buffer */
                           )
{
    int status = 0;
    struct sg_header *sg_hd;

    /* safety checks */
    if (!cmd_len) return -1;            /* need a cmd_len != 0 */
    if (!i_buff) return -1;             /* need an input buffer != NULL */
#ifdef SG_BIG_BUFF
    if (SCSI_OFF + cmd_len + in_size > SG_BIG_BUFF) return -1;
    if (SCSI_OFF + out_size > SG_BIG_BUFF) return -1;
#else
    if (SCSI_OFF + cmd_len + in_size > 4096) return -1;
    if (SCSI_OFF + out_size > 4096) return -1;
#endif

    if (!o_buff) out_size = 0;

    /* generic scsi device header construction */
    sg_hd = (struct sg_header *) i_buff;
    sg_hd->reply_len   = SCSI_OFF + out_size;
    sg_hd->twelve_byte = cmd_len == 12;
    sg_hd->result = 0;
#if     0
    sg_hd->pack_len    = SCSI_OFF + cmd_len + in_size; /* not necessary */
    sg_hd->pack_id;     /* not used */
    sg_hd->other_flags; /* not used */
#endif

    /* send command */
    status = write( fd, i_buff, SCSI_OFF + cmd_len + in_size );
    if ( status < 0 || status != SCSI_OFF + cmd_len + in_size ||
                       sg_hd->result ) {
        /* some error happened */
        fprintf( stderr, "write(generic) result = 0x%x cmd = 0x%x\n", 
                    sg_hd->result, i_buff[SCSI_OFF] );
        perror("");
        return status;
    }
    
    if (!o_buff) o_buff = i_buff;       /* buffer pointer check */

    /* retrieve result */
    status = read( fd, o_buff, SCSI_OFF + out_size);
    if ( status < 0 || status != SCSI_OFF + out_size || sg_hd->result ) {
        /* some error happened */
        fprintf( stderr, "read(generic) result = 0x%x cmd = 0x%x\n", 
                sg_hd->result, o_buff[SCSI_OFF] );
        fprintf( stderr, "read(generic) sense "
                "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n", 
                sg_hd->sense_buffer[0],         sg_hd->sense_buffer[1],
                sg_hd->sense_buffer[2],         sg_hd->sense_buffer[3],
                sg_hd->sense_buffer[4],         sg_hd->sense_buffer[5],
                sg_hd->sense_buffer[6],         sg_hd->sense_buffer[7],
                sg_hd->sense_buffer[8],         sg_hd->sense_buffer[9],
                sg_hd->sense_buffer[10],        sg_hd->sense_buffer[11],
                sg_hd->sense_buffer[12],        sg_hd->sense_buffer[13],
                sg_hd->sense_buffer[14],        sg_hd->sense_buffer[15]);
        if (status < 0)
            perror("");
    }
    /* Look if we got what we expected to get */
    if (status == SCSI_OFF + out_size) status = 0; /* got them all */

    return status;  /* 0 means no error */
}

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define INQUIRY_REPLY_LEN 96
#define INQUIRY_VENDOR  8       /* Offset in reply data to vendor name */
#define INQUIRY_VENDOR_VERSION	2 /* offset in reply data to get vendor version */
#define INQUIRY_PRODUCT_IDENTIFICATION	16
#define INQUIRY_PRODUCT_REVISION_LEVEL	32

#define INQUIRY_RESPONSE_DATA_FORMAT	3
/* request vendor brand and model */
static unsigned char *Inquiry ( void )
{
  unsigned char Inqbuffer[ SCSI_OFF + INQUIRY_REPLY_LEN ];
  unsigned char cmdblk [ INQUIRY_CMDLEN ] = 
      { INQUIRY_CMD,  /* command */
                  0,  /* lun/reserved */
                  0,  /* page code */
                  0,  /* reserved */
  INQUIRY_REPLY_LEN,  /* allocation length */
                  0 };/* reserved/flag/link */

  memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );

  /*
   * +------------------+
   * | struct sg_header | <- cmd
   * +------------------+
   * | copy of cmdblk   | <- cmd + SCSI_OFF
   * +------------------+
   */

  if (handle_scsi_cmd(sizeof(cmdblk), 0, cmd, 
                      sizeof(Inqbuffer) - SCSI_OFF, Inqbuffer )) {
      fprintf( stderr, "Inquiry failed\n" );
      exit(2);
  }
  //printf("111%s\n", Inqbuffer + SCSI_OFF + INQUIRY_VENDOR);
  printf("Inqbuffer:vendor details:%s\n", Inqbuffer + SCSI_OFF + INQUIRY_VENDOR);
  printf("Inqbuffer:product identification:%s\n", Inqbuffer + SCSI_OFF + INQUIRY_PRODUCT_IDENTIFICATION);
  printf("Inqbuffer:product version:%s\n", Inqbuffer + SCSI_OFF + INQUIRY_PRODUCT_REVISION_LEVEL);
  printf("Inqbuffer:vendor version:%x\n", *(Inqbuffer + SCSI_OFF + INQUIRY_VENDOR_VERSION));
  //printf("Inqbuffer:vendor version:%s\n", Inqbuffer + SCSI_OFF + INQUIRY_VENDOR_VERSION);
  printf("Inqbuffer:first byte:%x\n", *(Inqbuffer + SCSI_OFF));
  printf("Inqbuffer: peripheral qualifier:%x\n", (*(Inqbuffer + SCSI_OFF)) & 0xe0);
  printf("Inqbuffer: peripheral device type:%x\n", (*(Inqbuffer + SCSI_OFF)) & 0x1f);
  printf("Inqbuffer: response data format:%x\n", (*(Inqbuffer + SCSI_OFF + INQUIRY_RESPONSE_DATA_FORMAT)) & 0x0f);

  for(int i = 0; i < 100; ++i){
	  printf("Inqbuffer:%d byte in hex:%x\n", i, *(Inqbuffer + SCSI_OFF + i));
	  printf("Inqbuffer:%d byte string: %s\n",i,  Inqbuffer + SCSI_OFF + i);
  }

  return (Inqbuffer + SCSI_OFF);
}

#define TESTUNITREADY_CMD 0
#define TESTUNITREADY_CMDLEN 6

#define ADD_SENSECODE 12
#define ADD_SC_QUALIFIER 13
#define NO_MEDIA_SC 0x3a
#define NO_MEDIA_SCQ 0x00
int TestForMedium ( void )
{
  /* request READY status */
  static unsigned char cmdblk [TESTUNITREADY_CMDLEN] = {
      TESTUNITREADY_CMD, /* command */
                      0, /* lun/reserved */
                      0, /* reserved */
                      0, /* reserved */
                      0, /* reserved */
                      0};/* reserved */

  memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );

  /*
   * +------------------+
   * | struct sg_header | <- cmd
   * +------------------+
   * | copy of cmdblk   | <- cmd + SCSI_OFF
   * +------------------+
   */

  if (handle_scsi_cmd(sizeof(cmdblk), 0, cmd, 
                            0, NULL)) {
      fprintf (stderr, "Test unit ready failed\n");
      exit(2);
  }

  return 
   *(((struct sg_header*)cmd)->sense_buffer +ADD_SENSECODE) !=
                                                        NO_MEDIA_SC ||
   *(((struct sg_header*)cmd)->sense_buffer +ADD_SC_QUALIFIER) !=
                                                        NO_MEDIA_SCQ;
}

#define REPORT_LUNS_CMD     0xa0
#define REPORT_LUNS_CMDLEN  12
#define REPORT_LUNS_REPLY_LEN 16
#define SELECT_REPORT	0x00	
#define REPORT_LUNS_LUN_LIST_LENGTH	3
#define REPORT_LUNS_LUN_FIRST_OFFSET	8

static unsigned char* ReportLunsInfo( void )
{
  /* request READY status */
  unsigned char report_luns_buffer[ SCSI_OFF + REPORT_LUNS_REPLY_LEN];
  static unsigned char cmdblk[REPORT_LUNS_CMDLEN] = {
      REPORT_LUNS_CMD, /* command */
                      0, /* lun/reserved */
                      SELECT_REPORT, /* select report*/
                      0, /* reserved */
                      0, /* reserved */
                      0, /* reserved */
                      0, /* reserved */
                      0, /* reserved */
                      0, /* reserved */
		      REPORT_LUNS_REPLY_LEN, /* allocation length LSB */
		      0, /* reserved */
		      0	/* control */
  };

  memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );

  if (handle_scsi_cmd(sizeof(cmdblk), 0, cmd, 
                      sizeof(report_luns_buffer) - SCSI_OFF, report_luns_buffer)) {
      fprintf( stderr, "Report_luns failed\n" );
      exit(2);
  }
  printf("ReportLunsInfo: lun list length%x\n", *(report_luns_buffer + SCSI_OFF + REPORT_LUNS_LUN_LIST_LENGTH ));
  printf("ReportLunsInfo: lun[fisrt] %x\n", *(report_luns_buffer + SCSI_OFF + REPORT_LUNS_LUN_FIRST_OFFSET));
  int i = 0;
  for(i = 0; i < 50; ++i){
	  printf("ReportLunsInfo:%d byte in hex:%x\n", i, *(report_luns_buffer + SCSI_OFF + i));
	  printf("ReportLunsInfo:%d byte string: %s\n",i,  report_luns_buffer + SCSI_OFF + i);
  }
  return (report_luns_buffer + SCSI_OFF);
 }

#define READ_ATTRIBUTE_CMD	0x8c
#define READ_ATTRIBUTE_CMDLEN	16
#define READ_ATTRIBUTE_REPLY_LEN 96
#define SA_READ_ATTRIBUTES	0x00
#define SA_ATTRIBUTE_LIST	0x01
#define SA_LOGICAL_VOLUME_LIST	0x02
#define SA_PARTITION_LIST	0x03
#define SA_SUPPORTED_ATTRIBUTES	0x05
// attribute identifiers
#define ATTR_ID_REMAINING_CAPACITY_IN_PARTITION_HIBYTE 0x00
#define ATTR_ID_REMAINING_CAPACITY_IN_PARTITION_LOBYTE 0x00

#define ATTR_ID_MAX_CAPACITY_IN_PARTITION_HIBYTE	0x00
#define ATTR_ID_MAX_CAPACITY_IN_PARTITION_LOBYTE	0x01

#define ATTR_ID_TAPEALERT_FLAGS_HIBYTE	0x00
#define ATTR_ID_TAPEALERT_FLAGS_LOBYTE	0x02

#define ATTR_ID_MEDIUM_SERIAL_NUMBER_HIBYTE	0x04
#define ATTR_ID_MEDIUM_SERIAL_NUMBER_LOBYTE	0x01

static unsigned char* ReadAttribute()
{
  unsigned char read_attribute_buffer[SCSI_OFF + READ_ATTRIBUTE_REPLY_LEN];
  static unsigned char cmdblk[READ_ATTRIBUTE_CMDLEN] = {
      READ_ATTRIBUTE_CMD, /* command */
                      0, /* service action */
                      0, /* restricted */
                      0, /* restricted */
                      0, /* restricted */
		      0, /* Logical Volume Number */
		      0, /* reserved */
		      0, /* partition number */
		      ATTR_ID_MEDIUM_SERIAL_NUMBER_HIBYTE, /* first attribute identifier hi byte */
		      ATTR_ID_MEDIUM_SERIAL_NUMBER_LOBYTE, /* first attribute identifier  lo byte */
		      0, /* allocation length msbyte */
		      0, /* allocation length cont. */
		      0, /* allocation length cont. */
		      READ_ATTRIBUTE_REPLY_LEN,
		      0, /* reserved */
		      0 /* control */
  };
  memcpy( cmd + SCSI_OFF, cmdblk, sizeof(cmdblk) );

  printf("return code from read_attribute scsi _command: %x\n", handle_scsi_cmd(sizeof(cmdblk), 0, cmd, 
                      sizeof(read_attribute_buffer) - SCSI_OFF, read_attribute_buffer));
  /*if (handle_scsi_cmd(sizeof(cmdblk), 0, cmd, 
                      sizeof(read_attribute_buffer) - SCSI_OFF, read_attribute_buffer)) {
      fprintf( stderr, "read_attribute command failed\n" );
      exit(2);
  }*/
  printf("ReadAttribute: available_data[3]%sn", read_attribute_buffer + SCSI_OFF + 3);
  return (read_attribute_buffer + SCSI_OFF);
}

int main( void )
{
  fd = open(DEVICE, O_RDWR);
  if (fd < 0) {
    fprintf( stderr, "Need read/write permissions for "DEVICE".\n" );
    exit(1);
  }

  /* print some fields of the Inquiry result */
  //printf( "%s\n", Inquiry() + INQUIRY_VENDOR );

  /* look if medium is loaded */
  Inquiry();
/*
  if (!TestForMedium()) {
    printf("device is unloaded\n");
  } else {
    printf("device is loaded\n");
  }
  ReportLunsInfo();
  ReadAttribute();

  //printf("lun list length: %d\n", ReportLunsInfo());
*/
  close(fd);
  return 0;
}
