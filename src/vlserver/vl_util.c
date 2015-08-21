#include <afsconfig.h>
#include <afs/param.h>
#include <afs/cmd.h>

#include <fcntl.h>
#include <errno.h>
#include <yaml.h>

#include "vlserver.h"

#define UBIKHDRSIZE		64

#define OP_IMPORT		0
#define OP_EXPORT		1

#define HEX_T			0
#define UINT_T			1
#define STR_T 			2
#define UCHAR_T			3
#define SHORT_T			4
#define IP_T			5

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
    	fprintf(stderr, "vl_util: lseek to %d failed: %s\n", a_offset, strerror(errno));
    	exit(1);
    }
    r = read(fd_vldb, a_buffer, a_size);
    if (r != a_size) {
    	fprintf(stderr, "vl_util: could not read %d bytes from vldb: %s\n", a_size, strerror(errno));
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
    writeYAML("    vldb_version: %u\n", ntohl(a_vlheader->vital_header.vldbversion));
    writeYAML("    header_size: %u\n", ntohl(a_vlheader->vital_header.headersize));
    writeYAML("    free_ptr: 0x%x\n", ntohl(a_vlheader->vital_header.freePtr));
    writeYAML("    eof_ptr: %u\n", ntohl(a_vlheader->vital_header.eofPtr));
    writeYAML("    allocs: %u\n", ntohl(a_vlheader->vital_header.allocs));
    writeYAML("    frees: %u\n", ntohl(a_vlheader->vital_header.frees));
    writeYAML("    max_volume_id: %u\n", ntohl(a_vlheader->vital_header.MaxVolumeId));
    writeYAML("    total_entries_rw: %u\n", ntohl(a_vlheader->vital_header.totalEntries[0]));
    writeYAML("    total_entries_ro: %u\n", ntohl(a_vlheader->vital_header.totalEntries[1]));
    writeYAML("    total_entries_bk: %u\n", ntohl(a_vlheader->vital_header.totalEntries[2]));

    writeYAML("    %s:\n", "ip_mapped_addr");
    for (i = 0; i <= MAXSERVERID; i++) {
    	if (a_vlheader->IpMappedAddr[i] != 0)
	    writeYAML("        %d: 0x%x\n", i, ntohl(a_vlheader->IpMappedAddr[i]));
    }
    writeYAML("    %s:\n", "vol_name_hash");
    for (i = 0; i < HASHSIZE; i++) {
    	if (a_vlheader->VolnameHash[i] != 0)
    	    writeYAML("        %d: %u\n", i, ntohl(a_vlheader->VolnameHash[i]));
    }
    writeYAML("    %s:\n", "vol_id_hash");
    for (i = 0; i < MAXTYPES; i++) {
	for (j = 0; j < HASHSIZE; j++) {
	    if (a_vlheader->VolidHash[i][j] != 0) {
	    	writeYAML("        %d:\n", i);
		writeYAML("            %d: %u\n", j, ntohl(a_vlheader->VolidHash[i][j]));
	    }
	}
    }
    writeYAML("    sit: 0x%x\n", ntohl(a_vlheader->SIT));
}

inline void
exportMhBlock(afs_uint32 a_addr)
{
    int i, j;
    char host_str[16];
    char uuid_str[40];
    struct extentaddr mh_entry;

    readVLDB((void *)&mh_entry, sizeof(mh_entry), a_addr);
    writeYAML("%s:\n", "mh_block");
    writeYAML("    %s:\n", "header");
    writeYAML("        count: %d\n", ntohl(mh_entry.ex_count));
    writeYAML("        flags: %d\n", ntohl(mh_entry.ex_flags));
    writeYAML("        %s:\n", "cont_addrs");
    for (i = 0; i < VL_MAX_ADDREXTBLKS; i++) {
	if (ntohl(mh_entry.ex_contaddrs[i]) != 0)
	    writeYAML("            %d: 0x%x\n", i, ntohl(mh_entry.ex_contaddrs[i]));
    }
    for (i = 1; i < VL_MHSRV_PERBLK; i++) {
	readVLDB((void *)&mh_entry, sizeof(mh_entry), a_addr + (i * sizeof(mh_entry)));
	if (afs_uuid_is_nil(&mh_entry.ex_hostuuid))
	    continue;
	writeYAML("    %s:\n", "entry");
	afsUUID_to_string(&mh_entry.ex_hostuuid, uuid_str, sizeof(uuid_str));
	writeYAML("        host_uuid: %s\n", uuid_str);
	writeYAML("        uniquifier: %d\n", ntohl(mh_entry.ex_uniquifier));
	writeYAML("        %s:\n", "ip_addr");
	for (j = 0; j < VL_MAXIPADDRS_PERMH; j++) {
	    if (mh_entry.ex_addrs[j] != 0)
	    writeYAML("            %d: %s\n", j, afs_inet_ntoa_r(mh_entry.ex_addrs[j], host_str));
	}
    }
}

inline void
exportVolume(struct nvlentry *a_vlentry)
{
    int i;

    writeYAML("%s:\n", "vol_entry");
    writeYAML("    volume_id_rw: %u\n", ntohl(a_vlentry->volumeId[0]));
    writeYAML("    volume_id_ro: %u\n", ntohl(a_vlentry->volumeId[1]));
    writeYAML("    volume_id_bk: %u\n", ntohl(a_vlentry->volumeId[2]));
    writeYAML("    flags: %d\n", ntohl(a_vlentry->flags));
    writeYAML("    lock_afs_id: %d\n", ntohl(a_vlentry->LockAfsId));
    writeYAML("    lock_time_stamp: %d\n", ntohl(a_vlentry->LockTimestamp));
    writeYAML("    clone_id: %u\n", ntohl(a_vlentry->cloneId));
    writeYAML("    next_id_hash_rw: %u\n", ntohl(a_vlentry->nextIdHash[0]));
    writeYAML("    next_id_hash_ro: %u\n", ntohl(a_vlentry->nextIdHash[1]));
    writeYAML("    next_id_hash_bk: %u\n", ntohl(a_vlentry->nextIdHash[2]));
    writeYAML("    next_name_hash: %u\n", ntohl(a_vlentry->nextNameHash));
    writeYAML("    name: %s\n", a_vlentry->name);

    writeYAML("    %s:\n", "server_number");
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverNumber[i] != 255)
	    writeYAML("        %d: %u\n", i, a_vlentry->serverNumber[i]);
    }
    writeYAML("    %s:\n", "server_partition");
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverPartition[i] != 255)
    	    writeYAML("        %d: %u\n", i, a_vlentry->serverPartition[i]);
    }
    writeYAML("    %s:\n", "server_flags");
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverFlags[i] != 255)
    	    writeYAML("        %d: %u\n", i, a_vlentry->serverFlags[i]);
    }
}

void
exportVldbEntries(struct vlheader *a_vlheader)
{
    int i, j;
    char buffer[16];
    char tmp[40];
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
    		exportMhBlock(addr);
    	    	entrysize = VL_ADDREXTBLK_SIZE;
    	    	break;
    	    case VLFREE:
    	    	entrysize = sizeof(vlentry);
    	    	break;
    	    default:
    	    	exportVolume(&vlentry);
	    	entrysize = sizeof(vlentry);
    	}
    }
}

void
readValueYAML(void *a_buffer, short a_type)
{
    yaml_token_t token;

    /* skipping YAML_VALUE_TOKEN */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);
    yaml_parser_scan(&parser, &token);

    switch (a_type) {
    	case HEX_T:
    	    sscanf(token.data.scalar.value, "%x", a_buffer);
    	    *(afs_uint32 *)a_buffer = htonl(*(afs_uint32 *)a_buffer);
    	    break;
    	case STR_T:
    	    memcpy(a_buffer, token.data.scalar.value, strlen(token.data.scalar.value));
    	    break;
    	case IP_T:
    	    inet_pton(AF_INET, token.data.scalar.value, a_buffer);
    	    break;
    	case UCHAR_T:
    	    sscanf(token.data.scalar.value, "%hhu", a_buffer);
    	    break;
    	case SHORT_T:
    	    sscanf(token.data.scalar.value, "%hu", a_buffer);
    	    *(short *)a_buffer = htons(*(short *)a_buffer);
    	    break;
    	default:
    	    sscanf(token.data.scalar.value, "%u", a_buffer);
    	    *(afs_uint32 *)a_buffer = htonl(*(afs_uint32 *)a_buffer);
    }
    yaml_token_delete(&token);
}

void
readBlockYAML(void *a_buffer, size_t a_size, short a_type)
{
    yaml_token_t token;
    afs_uint32 index;
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
    	            if (index < a_size) {
    	            	if (a_type == UCHAR_T)
    	            	    readValueYAML((void *)&((u_char *)a_buffer)[index], a_type);
    	            	else
    	            	    readValueYAML((void *)&((afs_uint32 *)a_buffer)[index], a_type);
    	            } else {
    	    	    	fprintf(stderr, "vl_util: index out of range (readBlockYAML)\n");
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
    afs_uint32 index;
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
    	            	readBlockYAML(a_buffer[index], a_col, UINT_T);
    	            } else {
    	            	fprintf(stderr, "vl_util: index out of range (readDoubleBlockYAML)\n");
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
importUbikHeader(void)
{
    yaml_token_t token;
    int state;
    struct ubik_hdr uheader;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);
    memset(&uheader, 0, sizeof(uheader));

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
    	    	    if (!strcmp(token.data.scalar.value, "magic")) {
    	    	    	readValueYAML((void *)&uheader.magic, HEX_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "size")) {
    	    	    	readValueYAML(&uheader.size, SHORT_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "epoch")) {
    	    	    	readValueYAML((void *)&uheader.version.epoch, UINT_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "counter")) {
    	    	    	readValueYAML((void *)&uheader.version.counter, UINT_T);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    write(fd_vldb, (void *)&uheader, UBIKHDRSIZE);
}

void
importVldbHeader(void)
{
    yaml_token_t token;
    struct vlheader vlhdr;
    char *vlhdr_p = (char *)&vlhdr;
    int state;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);
    memset(&vlhdr, 0, sizeof(vlhdr));

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
    	    	    if (!strcmp(token.data.scalar.value, "free_ptr") || !strcmp(token.data.scalar.value, "sit")) {
    	    	    	readValueYAML((void *)vlhdr_p, HEX_T);
    	    	    	vlhdr_p += sizeof(afs_uint32);
    	    	    } else if (!strcmp(token.data.scalar.value, "ip_mapped_addr")) {
    	    	    	readBlockYAML((void *)vlhdr.IpMappedAddr, MAXSERVERID + 1, HEX_T);
    	    	    	vlhdr_p += sizeof(afs_uint32) * (MAXSERVERID + 1);
    	    	    } else if (!strcmp(token.data.scalar.value, "vol_name_hash")) {
    	    	    	readBlockYAML((void *)vlhdr.VolnameHash, HASHSIZE, UINT_T);
    	    	    	vlhdr_p += sizeof(afs_uint32) * HASHSIZE;
    	    	    } else if (!strcmp(token.data.scalar.value, "vol_id_hash")) {
    	    	    	readDoubleBlockYAML(vlhdr.VolidHash, MAXTYPES, HASHSIZE);
    	    	    	vlhdr_p += sizeof(afs_uint32) * MAXTYPES * HASHSIZE;
    	    	    } else {
    	    	    	readValueYAML((void *)vlhdr_p, UINT_T);
    	    	    	vlhdr_p += sizeof(afs_uint32);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    write(fd_vldb, (void *)&vlhdr, sizeof(vlhdr));
}

void
importVolEntry(void)
{
    yaml_token_t token;
    struct nvlentry vlentry;
    char *vlentry_p = (char *)&vlentry;
    int state;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);
    memset(&vlentry, 0, sizeof(vlentry));

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
    	    	    if (!strcmp(token.data.scalar.value, "name")) {
    	    	    	readValueYAML((void *)vlentry_p, STR_T);
    	    	    	vlentry_p += sizeof(vlentry.name);
    	    	    } else if (!strcmp(token.data.scalar.value, "server_number")) {
    	    	    	memset(vlentry.serverNumber, 255, sizeof(vlentry.serverNumber));
    	    	    	readBlockYAML((void *)vlentry.serverNumber, NMAXNSERVERS, UCHAR_T);
    	    	    	vlentry_p += sizeof(vlentry.serverNumber);
    	    	    } else if (!strcmp(token.data.scalar.value, "server_partition")) {
    	    	    	memset(vlentry.serverPartition, 255, sizeof(vlentry.serverPartition));
    	    	    	readBlockYAML((void *)vlentry.serverPartition, NMAXNSERVERS, UCHAR_T);
    	    	    	vlentry_p += sizeof(vlentry.serverPartition);
    	    	    } else if (!strcmp(token.data.scalar.value, "server_flags")) {
    	    	    	memset(vlentry.serverFlags, 255, sizeof(vlentry.serverFlags));
    	    	    	readBlockYAML((void *)vlentry.serverFlags, NMAXNSERVERS, UCHAR_T);
    	    	    	vlentry_p += sizeof(vlentry.serverFlags);
    	    	    } else {
    	    	    	readValueYAML((void *)vlentry_p, UINT_T);
    	    	    	vlentry_p += sizeof(afs_uint32);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    write(fd_vldb, (void *)&vlentry, sizeof(vlentry));
}

void
importMhHeader(struct extentaddr *a_mhentry)
{
    yaml_token_t token;
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
    	    	    if (!strcmp(token.data.scalar.value, "count")) {
    	    	    	readValueYAML((void *)&a_mhentry->ex_count, UINT_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "flags")) {
    	    	    	readValueYAML((void *)&a_mhentry->ex_flags, UINT_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "cont_addrs")) {
    	    	    	readBlockYAML((void *)&a_mhentry->ex_contaddrs, VL_MAX_ADDREXTBLKS, HEX_T);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
}

void
importMhEntry(struct extentaddr *a_mhentry)
{
    yaml_token_t token;
    struct extentaddr mhentry;
    int state;
    char uuid_str[40];

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
    	    	    if (!strcmp(token.data.scalar.value, "host_uuid")) {
    	    	    	readValueYAML((void *)uuid_str, STR_T);
    	    	    	afsUUID_from_string(uuid_str, &a_mhentry->ex_hostuuid);
    	    	    } else if (!strcmp(token.data.scalar.value, "uniquifier")) {
    	    	    	readValueYAML((void *)&a_mhentry->ex_uniquifier, UINT_T);
    	    	    } else if (!strcmp(token.data.scalar.value, "ip_addr")) {
    	    	    	readBlockYAML((void *)a_mhentry->ex_addrs, VL_MAX_ADDREXTBLKS, IP_T);
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
    	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
}

void
importMhBlock(afs_uint32 a_mhblock_no)
{
    yaml_token_t token;
    struct extentaddr mhblock[VL_MHSRV_PERBLK];
    int state;
    afs_uint32 mhblock_addr;
    afs_uint32 mh_entry_no = 0;

    /* skipping [Block mapping] */
    yaml_parser_scan(&parser, &token);
    yaml_token_delete(&token);
    memset(mhblock, 0, sizeof(mhblock));

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
    	    	    if (!strcmp(token.data.scalar.value, "header")) {
    	    	    	importMhHeader(&mhblock[mh_entry_no]);
    	    	    	mhblock_addr = mhblock[mh_entry_no].ex_contaddrs[a_mhblock_no];
    	    	    	mh_entry_no++;
    	    	    } else if (!strcmp(token.data.scalar.value, "entry")) {
    	    	    	importMhEntry(&mhblock[mh_entry_no]);
    	    	    	mh_entry_no++;
    	    	    }
    	    	}
    	    	break;
    	}
    	if (token.type != YAML_BLOCK_END_TOKEN)
      	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
    lseek(fd_vldb, ntohl(mhblock_addr) + UBIKHDRSIZE, 0);
    write(fd_vldb, (void *)mhblock, sizeof(mhblock));
}

void
readYAML(void)
{
    yaml_token_t token;
    int state;
    afs_uint32 mhblock_no = 0;

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
    	    	    } else if (!strcmp(token.data.scalar.value, "vldb_header")) {
    	    	    	importVldbHeader();
    	    	    } else if (!strcmp(token.data.scalar.value, "vol_entry")) {
    	    	    	importVolEntry();
    	    	    } else if (!strcmp(token.data.scalar.value, "mh_block")) {
    	    	    	importMhBlock(mhblock_no);
    	    	    	mhblock_no++;
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
CommandProc(struct cmd_syndesc *a_cs, void *a_rock)
{
    struct vlheader vl_hdr;
    char *vldb_file, *yaml_file;
    char *op;
    int op_no;
    int vldb_mode;
    char *yaml_mode;

    vldb_file = a_cs->parms[0].items->data;	/* -vldb */
    yaml_file = a_cs->parms[1].items->data;	/* -yaml */
    op = a_cs->parms[2].items->data;		/* -op   */

    if (!strcmp(op, "import") && !strcmp(op, "export")) {
    	fprintf(stderr, "vl_util: operation '%s' not found\n", op);
    	exit(1);
    }
    op_no = (!strcmp(op, "import")) ? OP_IMPORT : OP_EXPORT;
    vldb_mode = (op_no == OP_IMPORT) ? (O_WRONLY | O_CREAT) : O_RDONLY;
    yaml_mode = (op_no == OP_IMPORT) ? "r" : "w";

    fd_vldb = open(vldb_file, vldb_mode, 0);
    if (fd_vldb < 0) {
    	fprintf(stderr, "vl_util: cannot open %s: %s\n", vldb_file, strerror(errno));
    	exit(1);
    }
    fd_yaml = fopen(yaml_file, yaml_mode);
    if (fd_yaml == NULL) {
    	fprintf(stderr, "vl_util: cannot open %s: %s\n", yaml_file, strerror(errno));
    	exit(1);
    }

    if (op_no == OP_EXPORT) {
	exportUbikHeader();
	exportVldbHeader(&vl_hdr, sizeof(vl_hdr));
	exportVldbEntries(&vl_hdr);
    } else {
    	if (!yaml_parser_initialize(&parser)) {
    	    fprintf(stderr, "vl_util: could not initialize the parser\n");
    	    exit(1);
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

    cs = cmd_CreateSyntax(NULL, CommandProc, NULL, "import/export volume location database");
    cmd_AddParm(cs, "-vldb", CMD_SINGLE, CMD_REQUIRED, "vldb_file");
    cmd_AddParm(cs, "-yaml", CMD_SINGLE, CMD_REQUIRED, "yaml_file");
    cmd_AddParm(cs, "-op", CMD_SINGLE, CMD_REQUIRED, "import/export");

    return cmd_Dispatch(argc, argv);
}