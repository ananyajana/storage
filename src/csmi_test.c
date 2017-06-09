// Author: Ananya Jana
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "csmi_test.h"
#include <errno.h>

extern int errno;

void csmiShowDriverInfo(CSMI_SAS_DRIVER_INFO Info)
{
	printf("\tName\t\t: %s\n", Info.szName);
	printf("\tDescription\t: %s\n", Info.szDescription);
	printf("\tMajor Rev.\t: %d\n", Info.usMajorRevision);
	printf("\tBuild Rev.\t: %d\n", Info.usBuildRevision);
	printf("\tRelease Rev.\t :%d\n", Info.usReleaseRevision);
	printf("\tCSMI Major Rev.\t: %d\n", Info.usCSMIMajorRevision);
	printf("\tCSMI Minor Rev.\t: %d\n", Info.usCSMIMinorRevision);
}

int main()
{
	int fd, retval;
	PCSMI_SAS_DRIVER_INFO_BUFFER pInfoBuffer;

	pInfoBuffer = (PCSMI_SAS_DRIVER_INFO_BUFFER)calloc(1, sizeof(CSMI_SAS_DRIVER_INFO_BUFFER));
	fd = open("/dev/sda", O_RDWR);
	printf("\tfd = %d\n", fd);
	retval = ioctl(fd, CC_CSMI_SAS_GET_DRIVER_INFO, pInfoBuffer);
	if(retval != 0)
		printf("\tioctl failed with retval = %d\n\t and error: %s\n", retval, strerror(errno));
	else
		csmiShowDriverInfo(pInfoBuffer->Information);

	close(fd);
	return 0;
}

