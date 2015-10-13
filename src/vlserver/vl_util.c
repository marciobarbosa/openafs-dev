#include <afsconfig.h>
#include <afs/param.h>
#include <afs/cmd.h>

#include <fcntl.h>
#include <errno.h>
#include <yaml.h>

#include "vlserver.h"

#define UBIKHDRSIZE     64

#define OP_IMPORT	0
#define OP_EXPORT	1

#define HEX_T           0
#define UINT_T          1
#define STR_T           2
#define UCHAR_T         3
#define SHORT_T         4
#define IP_T            5

#define VLDB		0
#define YAML		1
#define XML		2
#define JSON		3

#define writeYAML(msg, ...)         fprintf(stdout, msg, __VA_ARGS__)
#define isKeyYAML(key)              !strcmp((char *)token.data.scalar.value, key)
#define readTokenYAML(type, buffer) sscanf((char *)token.data.scalar.value, type, buffer)
#define SKIP_TOKEN()                yaml_parser_scan(&parser, &token); \
                                    yaml_token_delete(&token)

struct tuple {
    char *tag;
    int type;
    void *value;
    struct tuple *next;
};

FILE *fd_input;
int output_format;
yaml_parser_t parser;

struct tuple*
insertTuple(struct tuple *a_tuple, char *a_tag, int a_type, void *a_value)
{
    if (a_tuple == NULL) {
	a_tuple = (struct tuple *)calloc(1, sizeof(struct tuple));
	a_tuple->tag = a_tag;
	a_tuple->type = a_type;
	a_tuple->value = a_value;
    } else {
	a_tuple->next = insertTuple(a_tuple->next, a_tag, a_type, a_value);
    }
    return a_tuple;
}

void
removeList(struct tuple *a_begin)
{
    struct tuple *next_p;

    while (a_begin) {
    	next_p = a_begin->next;
	free(a_begin);
	a_begin = next_p;
    }
}

void
printValue(struct tuple *a_tuple)
{
    switch (a_tuple->type) {
	case HEX_T:
	    printf("0x%x\n", *(int *)a_tuple->value);
	    break;
	case UINT_T:
	    printf("%u\n", *(unsigned int *)a_tuple->value);
	    break;
	case STR_T:
	    printf("%s\n", (char *)a_tuple->value);
	    break;
	case SHORT_T:
	    printf("%hu\n", *(short *)a_tuple->value);
	    break;
    }
}

void
exportYAML(struct tuple *a_begin, int a_level)
{
    if (a_begin == NULL) {
    	return;
    }

    if (a_begin->value == NULL) {
	printf("%*s%s:\n", a_level, "", a_begin->tag);	
	exportYAML(a_begin->next, a_level + 4);
    } else {
	printf("%*s%s: ", a_level, "", a_begin->tag);	
	printValue(a_begin);
	exportYAML(a_begin->next, a_level);
    }
}

void
exportList(struct tuple *a_begin)
{
    switch (output_format) {
	case YAML:
	    exportYAML(a_begin, 0);
	    break;
    }
}

void
readVLDB(void *a_buffer, long int a_size, int a_offset)
{
    int code, r;

    code = fseek(fd_input, a_offset, 0);
    if (code) {
	fprintf(stderr, "vl_util: fseek failed\n");
	exit(1);
    }
    r = fread(a_buffer, 1, a_size, fd_input);
    if (r != a_size) {
	fprintf(stderr, "vl_util: could not read %ld bytes from vldb\n", a_size);
	exit(1);
    }
}

void
exportUbikHeader(void)
{
    struct ubik_hdr uheader;
    struct tuple *begin = NULL;

    readVLDB((void *)&uheader, sizeof(uheader), 0);
    uheader.magic = ntohl(uheader.magic); 
    uheader.size = ntohs(uheader.size);
    uheader.version.epoch = ntohl(uheader.version.epoch);
    uheader.version.counter = ntohl(uheader.version.counter); 

    begin = insertTuple(begin, "ubik_header", STR_T, NULL);
    begin = insertTuple(begin, "magic", HEX_T, (void *)&uheader.magic);
    begin = insertTuple(begin, "size", SHORT_T, (void *)&uheader.size);
    begin = insertTuple(begin, "epoch", UINT_T, (void *)&uheader.version.epoch);
    begin = insertTuple(begin, "counter", UINT_T, (void *)&uheader.version.counter);

    exportList(begin);
    removeList(begin);
}
/*
void
exportVldbHeader(struct vlheader *a_vlheader, size_t a_size)
{
    int i, j;

    readVLDB((void *)a_vlheader, a_size, UBIKHDRSIZE);

    writeYAML("%s:\n", "vldb_header");
    writeYAML("    vldb_version: %u\n",
	      ntohl(a_vlheader->vital_header.vldbversion));
    writeYAML("    header_size: %u\n",
	      ntohl(a_vlheader->vital_header.headersize));
    writeYAML("    free_ptr: 0x%x\n",
	      ntohl(a_vlheader->vital_header.freePtr));
    writeYAML("    eof_ptr: %u\n", ntohl(a_vlheader->vital_header.eofPtr));
    writeYAML("    allocs: %u\n", ntohl(a_vlheader->vital_header.allocs));
    writeYAML("    frees: %u\n", ntohl(a_vlheader->vital_header.frees));
    writeYAML("    max_volume_id: %u\n",
	      ntohl(a_vlheader->vital_header.MaxVolumeId));
    writeYAML("    total_entries_rw: %u\n",
	      ntohl(a_vlheader->vital_header.totalEntries[0]));
    writeYAML("    total_entries_ro: %u\n",
	      ntohl(a_vlheader->vital_header.totalEntries[1]));
    writeYAML("    total_entries_bk: %u\n",
	      ntohl(a_vlheader->vital_header.totalEntries[2]));

    writeYAML("    %s:\n", "ip_mapped_addr");
    for (i = 0; i <= MAXSERVERID; i++) {
	if (a_vlheader->IpMappedAddr[i] != 0)
	    writeYAML("        %d: 0x%x\n", i,
		      ntohl(a_vlheader->IpMappedAddr[i]));
    }
    writeYAML("    %s:\n", "vol_name_hash");
    for (i = 0; i < HASHSIZE; i++) {
	if (a_vlheader->VolnameHash[i] != 0)
	    writeYAML("        %d: %u\n", i,
		      ntohl(a_vlheader->VolnameHash[i]));
    }
    writeYAML("    %s:\n", "vol_id_hash");
    for (i = 0; i < MAXTYPES; i++) {
	for (j = 0; j < HASHSIZE; j++) {
	    if (a_vlheader->VolidHash[i][j] != 0) {
		writeYAML("        %d:\n", i);
		writeYAML("            %d: %u\n", j,
			  ntohl(a_vlheader->VolidHash[i][j]));
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
	    writeYAML("            %d: 0x%x\n", i,
		      ntohl(mh_entry.ex_contaddrs[i]));
    }
    for (i = 1; i < VL_MHSRV_PERBLK; i++) {
	readVLDB((void *)&mh_entry, sizeof(mh_entry),
		 a_addr + (i * sizeof(mh_entry)));
	if (afs_uuid_is_nil(&mh_entry.ex_hostuuid))
	    continue;
	writeYAML("    %s:\n", "entry");
	afsUUID_to_string(&mh_entry.ex_hostuuid, uuid_str, sizeof(uuid_str));
	writeYAML("        host_uuid: %s\n", uuid_str);
	writeYAML("        uniquifier: %d\n", ntohl(mh_entry.ex_uniquifier));
	writeYAML("        %s:\n", "ip_addr");
	for (j = 0; j < VL_MAXIPADDRS_PERMH; j++) {
	    if (mh_entry.ex_addrs[j] != 0)
		writeYAML("            %d: %s\n", j,
			  afs_inet_ntoa_r(mh_entry.ex_addrs[j], host_str));
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
    struct nvlentry vlentry;
    afs_uint32 entrysize = 0;
    afs_uint32 addr;
    afs_uint32 addr_begin = ntohl(a_vlheader->vital_header.headersize);
    afs_uint32 addr_end = ntohl(a_vlheader->vital_header.eofPtr);
    addr_begin += UBIKHDRSIZE;

    for (addr = addr_begin; addr < addr_end; addr += entrysize) {
	readVLDB((void *)&vlentry, sizeof(vlentry), addr);
	switch (ntohl(vlentry.flags)) {
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

    SKIP_TOKEN();
    yaml_parser_scan(&parser, &token);

    switch (a_type) {
    case HEX_T:
	readTokenYAML("%x", (afs_uint32 *) a_buffer);
	*(afs_uint32 *) a_buffer = htonl(*(afs_uint32 *) a_buffer);
	break;
    case STR_T:
	memcpy(a_buffer, token.data.scalar.value,
	       strlen((char *)token.data.scalar.value));
	break;
    case IP_T:
	inet_pton(AF_INET, (char *)token.data.scalar.value, a_buffer);
	break;
    case UCHAR_T:
	readTokenYAML("%hhu", (u_char *) a_buffer);
	break;
    case SHORT_T:
	readTokenYAML("%hu", (short *)a_buffer);
	*(short *)a_buffer = htons(*(short *)a_buffer);
	break;
    default:
	readTokenYAML("%u", (afs_uint32 *) a_buffer);
	*(afs_uint32 *) a_buffer = htonl(*(afs_uint32 *) a_buffer);
    }
    yaml_token_delete(&token);
}

void
readBlockYAML(void *a_buffer, size_t a_size, short a_type)
{
    yaml_token_t token;
    afs_uint32 index;

    SKIP_TOKEN();

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    readTokenYAML("%u", &index);
	    if (index >= a_size) {
		fprintf(stderr,
			"vl_util: index out of range (readBlockYAML)\n");
		exit(1);
	    }
	    if (a_type == UCHAR_T)
		readValueYAML((void *)&((u_char *) a_buffer)[index], a_type);
	    else
		readValueYAML((void *)&((afs_uint32 *) a_buffer)[index],
			      a_type);
	}
	if (token.type != YAML_BLOCK_END_TOKEN)
	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
}

void
readDoubleBlockYAML(afs_uint32(*a_buffer)[HASHSIZE], size_t a_line,
		    size_t a_col)
{
    yaml_token_t token;
    afs_uint32 index;

    SKIP_TOKEN();

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    readTokenYAML("%u", &index);
	    if (index >= a_line) {
		fprintf(stderr,
			"vl_util: index out of range (readDoubleBlockYAML)\n");
		exit(1);
	    }
	    readBlockYAML(a_buffer[index], a_col, UINT_T);
	}
	if (token.type != YAML_BLOCK_END_TOKEN)
	    yaml_token_delete(&token);
    } while (token.type != YAML_BLOCK_END_TOKEN);
    yaml_token_delete(&token);
}

void
importUbikHeader(void)
{
    yaml_token_t token;
    struct ubik_hdr uheader;

    SKIP_TOKEN();
    memset(&uheader, 0, sizeof(uheader));

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("magic")) {
		readValueYAML((void *)&uheader.magic, HEX_T);
	    } else if (isKeyYAML("size")) {
		readValueYAML((void *)&uheader.size, SHORT_T);
	    } else if (isKeyYAML("epoch")) {
		readValueYAML((void *)&uheader.version.epoch, UINT_T);
	    } else if (isKeyYAML("counter")) {
		readValueYAML((void *)&uheader.version.counter, UINT_T);
	    }
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

    SKIP_TOKEN();
    memset(&vlhdr, 0, sizeof(vlhdr));

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("free_ptr") || isKeyYAML("sit")) {
		readValueYAML((void *)vlhdr_p, HEX_T);
		vlhdr_p += sizeof(afs_uint32);
	    } else if (isKeyYAML("ip_mapped_addr")) {
		readBlockYAML((void *)vlhdr.IpMappedAddr, MAXSERVERID + 1,
			      HEX_T);
		vlhdr_p += sizeof(afs_uint32) * (MAXSERVERID + 1);
	    } else if (isKeyYAML("vol_name_hash")) {
		readBlockYAML((void *)vlhdr.VolnameHash, HASHSIZE, UINT_T);
		vlhdr_p += sizeof(afs_uint32) * HASHSIZE;
	    } else if (isKeyYAML("vol_id_hash")) {
		readDoubleBlockYAML(vlhdr.VolidHash, MAXTYPES, HASHSIZE);
		vlhdr_p += sizeof(afs_uint32) * MAXTYPES * HASHSIZE;
	    } else {
		readValueYAML((void *)vlhdr_p, UINT_T);
		vlhdr_p += sizeof(afs_uint32);
	    }
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

    SKIP_TOKEN();
    memset(&vlentry, 0, sizeof(vlentry));

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("name")) {
		readValueYAML((void *)vlentry_p, STR_T);
		vlentry_p += sizeof(vlentry.name);
	    } else if (isKeyYAML("server_number")) {
		memset(vlentry.serverNumber, 255,
		       sizeof(vlentry.serverNumber));
		readBlockYAML((void *)vlentry.serverNumber, NMAXNSERVERS,
			      UCHAR_T);
		vlentry_p += sizeof(vlentry.serverNumber);
	    } else if (isKeyYAML("server_partition")) {
		memset(vlentry.serverPartition, 255,
		       sizeof(vlentry.serverPartition));
		readBlockYAML((void *)vlentry.serverPartition, NMAXNSERVERS,
			      UCHAR_T);
		vlentry_p += sizeof(vlentry.serverPartition);
	    } else if (isKeyYAML("server_flags")) {
		memset(vlentry.serverFlags, 255, sizeof(vlentry.serverFlags));
		readBlockYAML((void *)vlentry.serverFlags, NMAXNSERVERS,
			      UCHAR_T);
		vlentry_p += sizeof(vlentry.serverFlags);
	    } else {
		readValueYAML((void *)vlentry_p, UINT_T);
		vlentry_p += sizeof(afs_uint32);
	    }
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

    SKIP_TOKEN();

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("count")) {
		readValueYAML((void *)&a_mhentry->ex_count, UINT_T);
	    } else if (isKeyYAML("flags")) {
		readValueYAML((void *)&a_mhentry->ex_flags, UINT_T);
	    } else if (isKeyYAML("cont_addrs")) {
		readBlockYAML((void *)&a_mhentry->ex_contaddrs,
			      VL_MAX_ADDREXTBLKS, HEX_T);
	    }
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
    char uuid_str[40];

    SKIP_TOKEN();

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("host_uuid")) {
		readValueYAML((void *)uuid_str, STR_T);
		afsUUID_from_string(uuid_str, &a_mhentry->ex_hostuuid);
	    } else if (isKeyYAML("uniquifier")) {
		readValueYAML((void *)&a_mhentry->ex_uniquifier, UINT_T);
	    } else if (isKeyYAML("ip_addr")) {
		readBlockYAML((void *)a_mhentry->ex_addrs,
			      VL_MAXIPADDRS_PERMH, IP_T);
	    }
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
    afs_uint32 mhblock_addr;
    afs_uint32 mh_entry_no = 0;

    SKIP_TOKEN();
    memset(mhblock, 0, sizeof(mhblock));

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("header")) {
		importMhHeader(&mhblock[mh_entry_no]);
		mhblock_addr =
		    mhblock[mh_entry_no].ex_contaddrs[a_mhblock_no];
		mh_entry_no++;
	    } else if (isKeyYAML("entry")) {
		importMhEntry(&mhblock[mh_entry_no]);
		mh_entry_no++;
	    }
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
    afs_uint32 mhblock_no = 0;

    do {
	yaml_parser_scan(&parser, &token);
	if (token.type == YAML_KEY_TOKEN) {
	    yaml_token_delete(&token);
	    yaml_parser_scan(&parser, &token);
	    if (isKeyYAML("ubik_header")) {
		importUbikHeader();
	    } else if (isKeyYAML("vldb_header")) {
		importVldbHeader();
	    } else if (isKeyYAML("vol_entry")) {
		importVolEntry();
	    } else if (isKeyYAML("mh_block")) {
		importMhBlock(mhblock_no);
		mhblock_no++;
	    }
	}
	if (token.type != YAML_STREAM_END_TOKEN)
	    yaml_token_delete(&token);
    } while (token.type != YAML_STREAM_END_TOKEN);
    yaml_token_delete(&token);
}
*/
static int
getFileExt(const char *a_file)
{
    char *ext = strrchr(a_file, '.');

    if (ext == NULL) {
	fprintf(stderr, "vl_util: could not get the extension of %s\n", a_file);
	exit(1);
    }

    ext += 1;
    if (!strncmp(ext, "DB", 2)) {
	return VLDB;
    } else if (!strncmp(ext, "yaml", 4)) {
	return YAML;
    }
    return -1;
}

static int
CommandProc(struct cmd_syndesc *a_cs, void *a_rock)
{
    /*struct vlheader vl_hdr;*/
    char *input_file;
    char *output_ext;
    int op_no = OP_EXPORT;

    input_file = a_cs->parms[0].items->data;	/* -input */
    output_ext = a_cs->parms[1].items->data;	/* -format */

    if (strcmp(output_ext, "yaml")) {
	fprintf(stderr, "vl_util: format not supported\n");
	exit(1);
    }
    output_format = YAML;

    if (getFileExt(input_file) != VLDB) {
	op_no = OP_IMPORT;
    }
    fd_input = fopen(input_file, op_no == OP_EXPORT ? "rb" : "r");

    if (fd_input == NULL) {
	fprintf(stderr, "vl_util: cannot open %s: %s\n", input_file,
		strerror(errno));
	exit(1);
    }

    if (op_no == OP_EXPORT) {
	exportUbikHeader();
	/*exportVldbHeader(&vl_hdr, sizeof(vl_hdr));
	exportVldbEntries(&vl_hdr);*/
    } /*else {
	if (!yaml_parser_initialize(&parser)) {
	    fprintf(stderr, "vl_util: could not initialize the parser\n");
	    exit(1);
	}
	yaml_parser_set_input_file(&parser, fd_input);
	readYAML();
	yaml_parser_delete(&parser);
    }*/
    fclose(fd_input);

    return 0;
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *cs;

    cs = cmd_CreateSyntax(NULL, CommandProc, NULL,
			  "import/export volume location database");
    cmd_AddParm(cs, "-input", CMD_SINGLE, CMD_REQUIRED, "vldb/yaml (so far...");
    cmd_AddParm(cs, "-format", CMD_SINGLE, CMD_REQUIRED, "output format (yaml so far...)");

    return cmd_Dispatch(argc, argv);
}
