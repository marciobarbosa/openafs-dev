#include <afsconfig.h>
#include <afs/param.h>
#include <afs/cmd.h>

#include <fcntl.h>
#include <yaml.h>

#include "vlserver.h"

#define UBIKHDRSIZE		64
#define writeYAML(msg, ...)	fprintf(fd_yaml, msg, __VA_ARGS__)

int fd_vldb;
FILE *fd_yaml;

void
readVLDB(void *a_buffer, size_t a_size, int a_offset)
{
    int offset, r;

    offset = lseek(fd_vldb, a_offset, 0);
    if (offset != a_offset) {
    	fprintf(stdout, "error: lseek to %d failed\n", a_offset);
    	exit(1);
    }
    r = read(fd_vldb, a_buffer, a_size);
    if (r != a_size) {
    	fprintf(stdout, "error: could not read %d bytes from vldb\n", a_size);
    	exit(1);
    }
}

void
exportUbikHeader(void)
{
    struct ubik_hdr uheader;

    readVLDB((void *)&uheader, sizeof(uheader), 0);

    writeYAML("%s:\n", "ubik_header");
    writeYAML("    magic: 0x%x\n", ntohl(uheader.magic));
    writeYAML("    size: %u\n", ntohs(uheader.size));
    writeYAML("    epoch: %u\n", ntohl(uheader.version.epoch));
    writeYAML("    counter: %u\n", ntohl(uheader.version.counter));
}

void
exportVldbHeader(struct vlheader *a_vlheader, size_t a_size)
{
    int i, j;

    readVLDB((void *)a_vlheader, a_size, UBIKHDRSIZE);

    writeYAML("%s:\n", "vldb_header");
    writeYAML("    vldbversion: %u\n", ntohl(a_vlheader->vital_header.vldbversion));
    writeYAML("    headersize: %u\n", ntohl(a_vlheader->vital_header.headersize));
    writeYAML("    freePtr: 0x%x\n", ntohl(a_vlheader->vital_header.freePtr));
    writeYAML("    eofPtr: %u\n", ntohl(a_vlheader->vital_header.eofPtr));
    writeYAML("    allocs: %u\n", ntohl(a_vlheader->vital_header.allocs));
    writeYAML("    frees: %u\n", ntohl(a_vlheader->vital_header.frees));
    writeYAML("    MaxVolumeId: %u\n", ntohl(a_vlheader->vital_header.MaxVolumeId));
    writeYAML("    %s:\n", "totalEntries");
    writeYAML("        rw: %u\n", ntohl(a_vlheader->vital_header.totalEntries[0]));
    writeYAML("        ro: %u\n", ntohl(a_vlheader->vital_header.totalEntries[1]));
    writeYAML("        bk: %u\n", ntohl(a_vlheader->vital_header.totalEntries[2]));

    writeYAML("    %s:\n", "IpMappedAddr");
    for (i = 0; i <= MAXSERVERID; i++) {
    	if (a_vlheader->IpMappedAddr[i] != 0)
	    writeYAML("        %d: 0x%x\n", i, ntohl(a_vlheader->IpMappedAddr[i]));
    }
    writeYAML("    %s:\n", "VolnameHash");
    for (i = 0; i < HASHSIZE; i++) {
    	if (a_vlheader->VolnameHash[i] != 0)
    	    writeYAML("        %d: %u\n", i, ntohl(a_vlheader->VolnameHash[i]));
    }
    writeYAML("    %s:\n", "VolidHash");
    for (i = 0; i < MAXTYPES; i++) {
	for (j = 0; j < HASHSIZE; j++) {
	    if (a_vlheader->VolidHash[i][j] != 0) {
	    	writeYAML("        %d:\n", i);
		writeYAML("            %d: %u\n", j, ntohl(a_vlheader->VolidHash[i][j]));
	    }
	}
    }
    writeYAML("    SIT: 0x%x\n", ntohl(a_vlheader->SIT));
}

void
exportVldbEntries(struct vlheader *a_vlheader)
{
    int i, j;
    char buffer[16];
    struct nvlentry vlentry;
    struct extentaddr mhentry;
    afs_uint32 entrysize = 0;
    afs_uint32 addr;
    afs_uint32 addr_begin = ntohl(a_vlheader->vital_header.headersize);
    afs_uint32 addr_end = ntohl(a_vlheader->vital_header.eofPtr);
    addr_begin += UBIKHDRSIZE;

    for (addr = addr_begin; addr < addr_end; addr += entrysize) {
    	readVLDB((void *)&vlentry, sizeof(vlentry), addr);
    	switch(ntohl(vlentry.flags)) {
    	    case VLCONTBLOCK:
    	    	writeYAML("%s:\n", "mh_block");
    	    	readVLDB((void *)&mhentry, sizeof(mhentry), addr);
    	    	writeYAML("    %s:\n", "header");
	    	writeYAML("        count: %d\n", ntohl(mhentry.ex_count));
	    	writeYAML("        flags: %d\n", ntohl(mhentry.ex_flags));
	    	writeYAML("        %s:\n", "contaddrs");
	    	for (i = 0; i < VL_MAX_ADDREXTBLKS; i++) {
	    	    if (ntohl(mhentry.ex_contaddrs[i]) != 0)
	    	    	writeYAML("            %d: 0x%x\n", i, ntohl(mhentry.ex_contaddrs[i]));
	    	}
    	    	for (i = 1; i < VL_MHSRV_PERBLK; i++) {
    	    	    readVLDB((void *)&mhentry, sizeof(mhentry), addr + (i * sizeof(mhentry)));
    	    	    if (afs_uuid_is_nil(&mhentry.ex_hostuuid))
    	    	    	continue;
    	    	    writeYAML("    %s:\n", "entry");
	    	    writeYAML("        hostuuid: %x\n", mhentry.ex_hostuuid);
	    	    writeYAML("        uniquifier: %d\n", ntohl(mhentry.ex_uniquifier));
	    	    writeYAML("        %s:\n", "ip_addr");
	    	    for (j = 0; j < VL_MAXIPADDRS_PERMH; j++) {
	    	    	if (mhentry.ex_addrs[j] != 0)
	    	    	    writeYAML("            %d: %s\n", j, afs_inet_ntoa_r(mhentry.ex_addrs[j], buffer));
	    	    }
    	    	}
    	    	entrysize = VL_ADDREXTBLK_SIZE;
    	    	break;
    	    case VLFREE:
    	    	entrysize = sizeof(vlentry);
    	    	break;
    	    default:
    	    	writeYAML("%s:\n", "vol_entry");
    	    	writeYAML("    %s:\n", "volumeId");
	    	writeYAML("        rw: %u\n", ntohl(vlentry.volumeId[0]));
	    	writeYAML("        ro: %u\n", ntohl(vlentry.volumeId[1]));
	    	writeYAML("        bk: %u\n", ntohl(vlentry.volumeId[2]));
	    	writeYAML("    flags: %d\n", ntohl(vlentry.flags));
	    	writeYAML("    LockAfsId: %d\n", ntohl(vlentry.LockAfsId));
	    	writeYAML("    LockTimestamp: %d\n", ntohl(vlentry.LockTimestamp));
	    	writeYAML("    cloneId: %u\n", ntohl(vlentry.cloneId));
	    	writeYAML("    %s:\n", "nextIdHash");
	    	writeYAML("        rw: %u\n", ntohl(vlentry.nextIdHash[0]));
	    	writeYAML("        ro: %u\n", ntohl(vlentry.nextIdHash[1]));
	    	writeYAML("        bk: %u\n", ntohl(vlentry.nextIdHash[2]));
	    	writeYAML("    nextNameHash: %u\n", ntohl(vlentry.nextNameHash));
	    	writeYAML("    name: %s\n", vlentry.name);

	    	writeYAML("    %s:\n", "serverNumber");
	    	for (i = 0; i < NMAXNSERVERS; i++) {
	    	    if (vlentry.serverNumber[i] != 255)
	    	    	writeYAML("        %d: %u\n", i, vlentry.serverNumber[i]);
	    	}
	    	writeYAML("    %s:\n", "serverPartition");
	    	for (i = 0; i < NMAXNSERVERS; i++) {
	    	    if (vlentry.serverPartition[i] != 255)
	    	    	writeYAML("        %d: %u\n", i, vlentry.serverPartition[i]);
	    	}
	    	writeYAML("    %s:\n", "serverFlags");
	    	for (i = 0; i < NMAXNSERVERS; i++) {
	    	    if (vlentry.serverFlags[i] != 255)
	    	    	writeYAML("        %d: %u\n", i, vlentry.serverFlags[i]);
	    	}
	    	entrysize = sizeof(vlentry);
    	}
    }
}

static int
CommandProc(struct cmd_syndesc *a_as, void *arock)
{
    struct vlheader vlhdr;
    char *dbfile, *yamlfile;
    char *op;

    dbfile = a_as->parms[0].items->data; /* -database */
    yamlfile = a_as->parms[1].items->data; /* -yaml */
    op = a_as->parms[2].items->data; /* -op */

    fd_vldb = open(dbfile, O_RDONLY, 0);
    fd_yaml = fopen(yamlfile, "w");

    if (fd_vldb < 0 || fd_yaml == NULL) {
    	fprintf(stdout, "error: could not open the file\n");
    	return (fd_vldb < 0) ? fd_vldb : -1;
    }

    if (!strcmp(op, "export")) {
	exportUbikHeader();
	exportVldbHeader(&vlhdr, sizeof(vlhdr));
	exportVldbEntries(&vlhdr);
    }

    close(fd_vldb);
    fclose(fd_yaml);

    return 0;
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *cs;

    cs = cmd_CreateSyntax(NULL, CommandProc, NULL, "access volume database");
    cmd_AddParm(cs, "-database", CMD_SINGLE, CMD_REQUIRED, "vldb_file");
    cmd_AddParm(cs, "-yaml", CMD_SINGLE, CMD_REQUIRED, "yaml_file");
    cmd_AddParm(cs, "-op", CMD_SINGLE, CMD_REQUIRED, "import/export");

    return cmd_Dispatch(argc, argv);
}