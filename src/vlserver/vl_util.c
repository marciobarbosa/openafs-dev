#include <afsconfig.h>
#include <afs/param.h>
#include <afs/cmd.h>

#include <fcntl.h>
#include <errno.h>

#include "vlserver.h"

#define UBIKHDRSIZE     64

#define NONE_T		0
#define UCHAR_T         1
#define SHORT_T         2
#define UINT_T          3
#define INT_T		4
#define HEX_T           5
#define STR_T           6
#define IP_T		7
#define UUID_T		8

#define YAML		0
#define XML		1
#define JSON		2

#define insert(tag, type, value, level) \
    root = insert_tuple(root, tuple_wrapper(tag, type, (void *)value, level))

FILE *fd_input;
int output_format;
struct vldb_tuple *root;

struct vldb_tuple {
    char *vt_tag;
    short vt_type;
    void *vt_value;
    unsigned int vt_level;
    struct vldb_tuple *vt_left;
    struct vldb_tuple *vt_right;
};

struct vldb_tuple *
insert_tuple(struct vldb_tuple *a_tree, struct vldb_tuple *a_element)
{
    if (a_tree == NULL) {
	return a_element;
    }
    if (a_tree->vt_right != NULL) {
	a_tree->vt_right = insert_tuple(a_tree->vt_right, a_element);
    } else {
	if (a_element->vt_level > a_tree->vt_level)
	    a_tree->vt_left = insert_tuple(a_tree->vt_left, a_element);
	else
	    a_tree->vt_right = insert_tuple(a_tree->vt_right, a_element);
    }
    return a_tree;
}

void
read_vldb(void *a_buffer, long int a_size, int a_offset)
{
    int code, r;

    code = fseek(fd_input, a_offset, 0);
    if (code) {
	fprintf(stderr, "vl_util: fseek failed\n");
	exit(1);
    }
    r = fread(a_buffer, 1, a_size, fd_input);
    if (r != a_size) {
	fprintf(stderr, "vl_util: could not read %ld bytes from vldb\n",
		a_size);
	exit(1);
    }
}

struct vldb_tuple *
tuple_wrapper(char *a_tag, short a_type, void *a_value, unsigned int a_level)
{
    struct vldb_tuple *tuplep;

    tuplep = (struct vldb_tuple *)calloc(1, sizeof(*tuplep));

    if (tuplep == NULL) {
	fprintf(stderr, "vl_util: no memory\n");
	exit(1);
    }
    tuplep->vt_tag = a_tag;
    tuplep->vt_type = a_type;
    tuplep->vt_value = a_value;
    tuplep->vt_level = a_level;

    return tuplep;
}

void
print_value(struct vldb_tuple *a_tuple)
{
    char host_str[16];
    char uuid_str[40];

    switch (a_tuple->vt_type) {
    case HEX_T:
	fprintf(stdout, "0x%x", ntohl(*(int *)a_tuple->vt_value));
	break;
    case UINT_T:
	fprintf(stdout, "%u", ntohl(*(unsigned int *)a_tuple->vt_value));
	break;
    case STR_T:
	fprintf(stdout, "%s", (char *)a_tuple->vt_value);
	break;
    case SHORT_T:
	fprintf(stdout, "%hu", ntohs(*(short *)a_tuple->vt_value));
	break;
    case INT_T:
	fprintf(stdout, "%d", ntohl(*(int *)a_tuple->vt_value));
	break;
    case IP_T:
	afs_inet_ntoa_r(*(afs_uint32 *) a_tuple->vt_value, host_str);
	fprintf(stdout, "%s", host_str);
	break;
    case UUID_T:
	afsUUID_to_string((afsUUID *) a_tuple->vt_value, uuid_str,
			  sizeof(uuid_str));
	fprintf(stdout, "%s", uuid_str);
	break;
    }
}

void
export_yaml(struct vldb_tuple *root)
{
    if (root == NULL) {
	return;
    }
    fprintf(stdout, "%*s%s:", 4 * root->vt_level, "", root->vt_tag);
    if (root->vt_value == NULL) {
	fprintf(stdout, "\n");
    } else {
	fprintf(stdout, " ");
	print_value(root);
	fprintf(stdout, "\n");
    }
    if (root->vt_left != NULL) {
	export_yaml(root->vt_left);
    }
    if (root->vt_right != NULL) {
	export_yaml(root->vt_right);
    }
    free(root);
}

void
export_xml(struct vldb_tuple *root)
{
    if (root == NULL) {
	return;
    }
    fprintf(stdout, "%*s<%s>", 4 * root->vt_level, "", root->vt_tag);
    if (root->vt_value == NULL) {
	fprintf(stdout, "\n");
    } else {
	fprintf(stdout, " ");
	print_value(root);
	fprintf(stdout, " </%s>\n", root->vt_tag);
    }
    if (root->vt_left != NULL) {
	export_xml(root->vt_left);
    }
    if (root->vt_value == NULL) {
	fprintf(stdout, "%*s</%s>\n", 4 * root->vt_level, "", root->vt_tag);
    }
    if (root->vt_right != NULL) {
	export_xml(root->vt_right);
    }
    free(root);
}

void
export_json(struct vldb_tuple *root)
{
    if (root == NULL) {
	return;
    }
    root->vt_level += 1;
    if (root->vt_value == NULL) {
	fprintf(stdout, "%*s\"%s\" : {\n", 4 * root->vt_level, "",
		root->vt_tag);
    } else {
	fprintf(stdout, "%*s\"%s\": ", 4 * root->vt_level, "", root->vt_tag);
	print_value(root);
	if (root->vt_right != NULL)
	    fprintf(stdout, ",\n");
	else
	    fprintf(stdout, "\n");
    }
    if (root->vt_left != NULL) {
	export_json(root->vt_left);
    }
    if (root->vt_value == NULL) {
	if (root->vt_right != NULL)
	    fprintf(stdout, "%*s},\n", 4 * root->vt_level, "");
	else
	    fprintf(stdout, "%*s}\n", 4 * root->vt_level, "");
    }
    if (root->vt_right != NULL) {
	export_json(root->vt_right);
    }
    free(root);
}

void
export_list(void)
{
    switch (output_format) {
    case YAML:
	export_yaml(root);
	break;
    case XML:
	export_xml(root);
	break;
    case JSON:
	export_json(root);
	break;
    }
    root = NULL;
}

void
export_ubik_header(void)
{
    struct ubik_hdr uheader;

    read_vldb((void *)&uheader, sizeof(uheader), 0);

    insert("ubik_header", NONE_T, NULL, 0);
    insert("magic", HEX_T, &uheader.magic, 1);
    insert("size", SHORT_T, &uheader.size, 1);
    insert("epoch", UINT_T, &uheader.version.epoch, 1);
    insert("counter", UINT_T, &uheader.version.counter, 1);

    export_list();
}

void
export_vldb_header(struct vlheader *a_vlheader)
{
    int i;

    read_vldb((void *)a_vlheader, sizeof(*a_vlheader), UBIKHDRSIZE);

    insert("vldb_header", NONE_T, NULL, 0);
    insert("vldb_version", UINT_T, &a_vlheader->vital_header.vldbversion, 1);
    insert("header_size", UINT_T, &a_vlheader->vital_header.headersize, 1);
    insert("free_ptr", HEX_T, &a_vlheader->vital_header.freePtr, 1);
    insert("eof_ptr", UINT_T, &a_vlheader->vital_header.eofPtr, 1);
    insert("allocs", UINT_T, &a_vlheader->vital_header.allocs, 1);
    insert("frees", UINT_T, &a_vlheader->vital_header.frees, 1);
    insert("max_volume_id", UINT_T, &a_vlheader->vital_header.MaxVolumeId, 1);
    insert("total_rw", UINT_T, &a_vlheader->vital_header.totalEntries[0], 1);
    insert("total_ro", UINT_T, &a_vlheader->vital_header.totalEntries[1], 1);
    insert("total_bk", UINT_T, &a_vlheader->vital_header.totalEntries[2], 1);
    insert("sit", HEX_T, &a_vlheader->SIT, 1);
    insert("ip_mapped_addr", NONE_T, NULL, 1);

    for (i = 0; i <= MAXSERVERID; i++) {
	if (a_vlheader->IpMappedAddr[i] != 0)
	    insert("addr", HEX_T, &a_vlheader->IpMappedAddr[i], 2);
    }
    export_list();
}

inline void
export_mh_block(afs_uint32 a_addr)
{
    int i, j;
    struct extentaddr mh_entry[VL_MHSRV_PERBLK];

    read_vldb((void *)&mh_entry[0], sizeof(mh_entry[0]), a_addr);

    insert("mh_block", NONE_T, NULL, 0);
    insert("header", NONE_T, NULL, 1);
    insert("count", INT_T, &mh_entry[0].ex_count, 2);
    insert("flags", INT_T, &mh_entry[0].ex_flags, 2);
    insert("cont_addrs", NONE_T, NULL, 2);

    for (i = 0; i < VL_MAX_ADDREXTBLKS; i++) {
	if (ntohl(mh_entry[0].ex_contaddrs[i]) != 0) {
	    insert("addr", HEX_T, &mh_entry[0].ex_contaddrs[i], 3);
	}
    }
    for (i = 1; i < VL_MHSRV_PERBLK; i++) {
	read_vldb((void *)&mh_entry[i], sizeof(mh_entry[i]),
		  a_addr + (i * sizeof(mh_entry[i])));
	if (afs_uuid_is_nil(&mh_entry[i].ex_hostuuid))
	    continue;
	insert("entry", NONE_T, NULL, 1);
	insert("host_uuid", UUID_T, &mh_entry[i].ex_hostuuid, 2);
	insert("uniquifier", INT_T, &mh_entry[i].ex_uniquifier, 2);
	insert("ip_addr", NONE_T, NULL, 2);
	for (j = 0; j < VL_MAXIPADDRS_PERMH; j++) {
	    if (mh_entry[i].ex_addrs[j] != 0)
		insert("ip", IP_T, &mh_entry[i].ex_addrs[j], 3);
	}
    }
    export_list();
}

inline void
export_volume(struct nvlentry *a_vlentry)
{
    int i;

    insert("vol_entry", NONE_T, NULL, 0);
    insert("volume_id_rw", UINT_T, &a_vlentry->volumeId[0], 1);
    insert("volume_id_ro", UINT_T, &a_vlentry->volumeId[1], 1);
    insert("volume_id_bk", UINT_T, &a_vlentry->volumeId[2], 1);
    insert("flags", INT_T, &a_vlentry->flags, 1);
    insert("lock_afs_id", INT_T, &a_vlentry->LockAfsId, 1);
    insert("lock_time_stamp", INT_T, &a_vlentry->LockTimestamp, 1);
    insert("clone_id", UINT_T, &a_vlentry->cloneId, 1);
    insert("next_id_hash_rw", UINT_T, &a_vlentry->nextIdHash[0], 1);
    insert("next_id_hash_ro", UINT_T, &a_vlentry->nextIdHash[1], 1);
    insert("next_id_hash_bk", UINT_T, &a_vlentry->nextIdHash[2], 1);
    insert("next_name_hash", UINT_T, &a_vlentry->nextNameHash, 1);
    insert("name", STR_T, &a_vlentry->name, 1);

    insert("server_number", NONE_T, NULL, 1);
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverNumber[i] != 255)
	    insert("number", UINT_T, &a_vlentry->serverNumber[i], 2);
    }
    insert("server_partition", NONE_T, NULL, 1);
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverPartition[i] != 255)
	    insert("part", INT_T, &a_vlentry->serverPartition[i], 2);
    }
    insert("server_flags", NONE_T, NULL, 1);
    for (i = 0; i < NMAXNSERVERS; i++) {
	if (a_vlentry->serverFlags[i] != 255)
	    insert("flag", INT_T, &a_vlentry->serverFlags[i], 2);
    }
    export_list();
}

void
export_vldb_entries(struct vlheader *a_vlheader)
{
    struct nvlentry vlentry;
    afs_uint32 entrysize = 0;
    afs_uint32 addr;
    afs_uint32 addr_begin = ntohl(a_vlheader->vital_header.headersize);
    afs_uint32 addr_end = ntohl(a_vlheader->vital_header.eofPtr);
    addr_begin += UBIKHDRSIZE;

    for (addr = addr_begin; addr < addr_end; addr += entrysize) {
	read_vldb((void *)&vlentry, sizeof(vlentry), addr);
	switch (ntohl(vlentry.flags)) {
	case VLCONTBLOCK:
	    export_mh_block(addr);
	    entrysize = VL_ADDREXTBLK_SIZE;
	    break;
	case VLFREE:
	    entrysize = sizeof(vlentry);
	    break;
	default:
	    export_volume(&vlentry);
	    entrysize = sizeof(vlentry);
	}
    }
}

static int
command_proc(struct cmd_syndesc *a_cs, void *a_rock)
{
    char *input_file;
    char *output_ext;
    struct vlheader vl_hdr;

    input_file = a_cs->parms[0].items->data;	/* -input */
    output_ext = a_cs->parms[1].items->data;	/* -format */

    if (strcmp(output_ext, "yaml") == 0) {
	output_format = YAML;
    } else if (strcmp(output_ext, "xml") == 0) {
	output_format = XML;
    } else if (strcmp(output_ext, "json") == 0) {
	output_format = JSON;
    } else {
	fprintf(stderr, "vl_util: format not supported\n");
	exit(1);
    }
    fd_input = fopen(input_file, "rb");

    if (fd_input == NULL) {
	fprintf(stderr, "vl_util: cannot open %s\n", input_file);
	exit(1);
    }

    if (output_format == JSON) {
	fprintf(stdout, "{\n");
    }
    export_ubik_header();
    export_vldb_header(&vl_hdr);
    export_vldb_entries(&vl_hdr);
    if (output_format == JSON) {
	fprintf(stdout, "}\n");
    }
    fclose(fd_input);

    return 0;
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *cs;

    cs = cmd_CreateSyntax(NULL, command_proc, NULL, "export VLDB");
    cmd_AddParm(cs, "-input", CMD_SINGLE, CMD_REQUIRED, "input file");
    cmd_AddParm(cs, "-format", CMD_SINGLE, CMD_REQUIRED, "output format");

    return cmd_Dispatch(argc, argv);
}
