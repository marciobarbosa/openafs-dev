#include <afsconfig.h>
#include <afs/param.h>
#include <afs/cmd.h>

#include <fcntl.h>
#include <yaml.h>

#include "vlserver.h"

#define UBIKHDRSIZE		64
#define HEX_T			0
#define UINT_T			1
#define INT_T 			2
#define SHORT_T			3
#define writeYAML(msg, ...)	fprintf(fd_yaml, msg, __VA_ARGS__)

int fd_vldb;
FILE *fd_yaml;
yaml_parser_t parser;

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
    writeYAML("    totalEntries_rw: %u\n", ntohl(a_vlheader->vital_header.totalEntries[0]));
    writeYAML("    totalEntries_ro: %u\n", ntohl(a_vlheader->vital_header.totalEntries[1]));
    writeYAML("    totalEntries_bk: %u\n", ntohl(a_vlheader->vital_header.totalEntries[2]));

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

void
importUbikHeader(void)
{
    yaml_token_t token;
    char bytes[64];
    char *bytes_p = bytes;
    int state, counter = 0;
    afs_uint32 value_uint;
    short value_short;

    memset(bytes, 0, sizeof(bytes));
    do {
    	yaml_parser_scan(&parser, &token);
    	switch (token.type) {
    	    case YAML_KEY_TOKEN:
    	    	state = 0;
    	    	break;
    	    case YAML_VALUE_TOKEN:
    	    	state = 1;
    	    	break;
    	    case YAML_SCALAR_TOKEN:
    	    	if (state && strcmp(token.data.scalar.value, "[Block mapping]")) {
    	    	    if (counter == 0) {
    	    	    	sscanf(token.data.scalar.value, "%x", &value_uint);
    	    	    	value_uint = htonl(value_uint);
    	    	    	memcpy(bytes_p, &value_uint, 4);
    	    	    	bytes_p += 6;
    	    	    } else if (counter == 1) {
    	    	    	sscanf(token.data.scalar.value, "%hu", &value_short);
    	    	    	value_short = htons(value_short);
    	    	    	memcpy(bytes_p, &value_short, 2);
    	    	    	bytes_p += 2;
    	    	    } else {
    	    	    	sscanf(token.data.scalar.value, "%u", &value_uint);
    	    	    	value_uint = htonl(value_uint);
    	    	    	memcpy(bytes_p, &value_uint, 4);
    	    	    	bytes_p += 4;
    	    	    }
    	    	    counter++;
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    write(fd_vldb, bytes, sizeof(bytes));
}

void
readValueYAML(afs_uint32 *a_buffer, short a_type)
{
    yaml_token_t token;
    afs_uint32 buffer_local;

    /* skipping YAML_VALUE_TOKEN */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);

    yaml_parser_scan(&parser, &token);
    if (a_type == HEX_T) {
    	sscanf(token.data.scalar.value, "%x", &buffer_local);
    } else {
    	sscanf(token.data.scalar.value, "%u", a_buffer);
    }
    *a_buffer = htonl(*a_buffer);
    yaml_token_delete(&token);
}

void
readBlockHexYAML(afs_uint32 *a_buffer, size_t a_size, short a_type)
{
    yaml_token_t token;
    afs_uint32 index, count = 0;
    int state;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);

    do {
    	yaml_parser_scan(&parser, &token);
    	switch (token.type) {
    	    case YAML_KEY_TOKEN:
    	    	state = 0;
    	    	break;
    	    case YAML_VALUE_TOKEN:
    	    	state = 1;
    	    	break;
    	    case YAML_SCALAR_TOKEN:
    	        if (!state) {
    	            sscanf(token.data.scalar.value, "%u", &index);
    	    	} else {
    	    	    if (count < a_size) {
    	    	    	if (a_type == HEX_T)
    	    	    	    sscanf(token.data.scalar.value, "%x", &a_buffer[index]);
    	    	    	else
    	    	    	    sscanf(token.data.scalar.value, "%u", &a_buffer[index]);
    	    	    	a_buffer[index] = htonl(a_buffer[index]);
    	    	    	count++;
    	    	    } else {
    	    	    	fprintf(stdout, "error: index out of range (readBlockHexYAML)\n");
    	    	    	exit(1);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
}

void
readDoubleBlockYAML(afs_uint32 (*a_buffer)[HASHSIZE], size_t a_line, size_t a_col)
{
    yaml_token_t token;
    afs_uint32 index, count = 0;
    int state;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);

    do {
    	yaml_parser_scan(&parser, &token);
    	switch (token.type) {
    	    case YAML_KEY_TOKEN:
    	    	state = 0;
    	    	break;
    	    case YAML_VALUE_TOKEN:
    	    	state = 1;
    	    	break;
    	    case YAML_SCALAR_TOKEN:
    	        if (!state) {
    	            sscanf(token.data.scalar.value, "%u", &index);
    	            if (index < a_line) {
    	            	readBlockHexYAML(a_buffer[index], a_col, UINT_T);
    	            } else {
    	            	fprintf(stdout, "error: index out of range (readDoubleBlockYAML)\n");
    	    	    	exit(1);
    	            }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
}

void
importVldbHeader(void)
{
    yaml_token_t token;
    char bytes[132120];
    char *bytes_p = bytes;
    int state, counter = 0;
    afs_uint32 value_uint;
    afs_uint32 IpMappedAddr[MAXSERVERID + 1];
    afs_uint32 VolnameHash[HASHSIZE];
    afs_uint32 VolidHash[MAXTYPES][HASHSIZE];

    memset(bytes, 0, sizeof(bytes));
    memset(IpMappedAddr, 0, sizeof(IpMappedAddr));
    memset(VolnameHash, 0, sizeof(VolnameHash));
    memset(VolidHash, 0, sizeof(VolidHash[0][0]) * MAXTYPES * HASHSIZE);
    do {
    	yaml_parser_scan(&parser, &token);
    	switch (token.type) {
    	    case YAML_KEY_TOKEN:
    	    	state = 0;
    	    	break;
    	    case YAML_VALUE_TOKEN:
    	    	state = 1;
    	    	break;
    	    case YAML_SCALAR_TOKEN:
    	    	if (state && strcmp(token.data.scalar.value, "[Block mapping]")) {
    	    	    if (counter == 2) {
    	    	    	sscanf(token.data.scalar.value, "%x", &value_uint);
    	    	    	value_uint = htonl(value_uint);
    	    	    	memcpy(bytes_p, &value_uint, 4);
    	    	    	bytes_p += 4;
    	    	    } else {
    	    	    	sscanf(token.data.scalar.value, "%u", &value_uint);
    	    	    	value_uint = htonl(value_uint);
    	    	    	memcpy(bytes_p, &value_uint, 4);
    	    	    	bytes_p += 4;
    	    	    }
    	    	    counter++;
    	    	}
    	    	if (!state) {
    	    	    if (!strcmp(token.data.scalar.value, "IpMappedAddr")) {
    	    	    	readBlockHexYAML(IpMappedAddr, MAXSERVERID + 1, HEX_T);
    	    	    	memcpy(bytes_p, IpMappedAddr, (MAXSERVERID + 1) * 4);
    	    	    	bytes_p += (MAXSERVERID + 1) * 4;
    	    	    } else if (!strcmp(token.data.scalar.value, "VolnameHash")) {
    	    	    	readBlockHexYAML(VolnameHash, HASHSIZE, UINT_T);
    	    	    	memcpy(bytes_p, VolnameHash, HASHSIZE * 4);
    	    	    	bytes_p += HASHSIZE * 4;
    	    	    } else if (!strcmp(token.data.scalar.value, "VolidHash")) {
    	    	    	readDoubleBlockYAML(VolidHash, MAXTYPES, HASHSIZE);
    	    	    	memcpy(bytes_p, VolidHash, MAXTYPES * HASHSIZE * 4);
    	    	    	bytes_p += MAXTYPES * HASHSIZE * 4;
    	    	    } else if (!strcmp(token.data.scalar.value, "SIT")) {
    	    	    	readValueYAML(&value_uint, HEX_T);
    	    	    	memcpy(bytes_p, &value_uint, 4);
    	    	    	bytes_p += 4;
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    write(fd_vldb, bytes, sizeof(bytes));
}

void
readYAML(void)
{
    yaml_token_t token;
    int state;

    do {
    	yaml_parser_scan(&parser, &token);
    	switch (token.type) {
    	    case YAML_KEY_TOKEN:
    	    	state = 0;
    	    	break;
    	    case YAML_VALUE_TOKEN:
    	    	state = 1;
    	    	break;
    	    case YAML_SCALAR_TOKEN:
    	    	if (!state) {
    	    	    if (!strcmp(token.data.scalar.value, "ubik_header")) {
    	    	    	importUbikHeader();
    	    	    }
    	    	    if (!strcmp(token.data.scalar.value, "vldb_header")) {
    	    	    	importVldbHeader();
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_STREAM_END_TOKEN)
      	    yaml_token_delete(&token);
    } while (token.type != YAML_STREAM_END_TOKEN);
    yaml_token_delete(&token);
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

    if (!strcmp(op, "import") && !strcmp(op, "export")) {
    	fprintf(stdout, "error: operation not found\n");
    	return -1;
    }

    if (!strcmp(op, "export")) {
    	fd_vldb = open(dbfile, O_RDONLY, 0);
	fd_yaml = fopen(yamlfile, "w");

	if (fd_vldb < 0 || fd_yaml == NULL) {
    	    fprintf(stdout, "error: could not open the file\n");
    	    return (fd_vldb < 0) ? fd_vldb : -1;
    	}
	exportUbikHeader();
	exportVldbHeader(&vlhdr, sizeof(vlhdr));
	exportVldbEntries(&vlhdr);
    } else {
    	fd_vldb = open(dbfile, O_WRONLY | O_CREAT, 0);
	fd_yaml = fopen(yamlfile, "r");

	if (fd_vldb < 0 || fd_yaml == NULL) {
    	    fprintf(stdout, "error: could not open the file\n");
    	    return (fd_vldb < 0) ? fd_vldb : -1;
    	}
    	if (!yaml_parser_initialize(&parser)) {
    	    fprintf(stdout, "error: could not initialize the parser\n");
    	    return -1;
    	}
    	yaml_parser_set_input_file(&parser, fd_yaml);
	readYAML();
	yaml_parser_delete(&parser);
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