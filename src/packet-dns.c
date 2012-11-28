#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#define DNS_PORT 53

#define LABDNS_FLAG_QR	  	128
#define LABDNS_FLAG_TYPE	0x78
#define LABDNS_FLAG_AA		4
#define LABDNS_FLAG_TC		2
#define LABDNS_FLAG_RD		1
#define LABDNS_FLAG_RA		128
#define LABDNS_FLAG_RCODE	0x0f

static int proto_labdns = -1;
static gint ett_labdns = -1;
static int hf_labdns_hdr_id = -1;
static int hf_labdns_hdr_flags = -1;
static int hf_labdns_hdr_questions = -1;
static int hf_labdns_hdr_answers = -1;
static int hf_labdns_hdr_entries = -1;
static int hf_labdns_hdr_additional_entries = -1;

static int hf_labdns_hdr_flags_qr = -1;
static int hf_labdns_hdr_flags_type = -1;
static int hf_labdns_hdr_flags_aa = -1;
static int hf_labdns_hdr_flags_tc = -1;
static int hf_labdns_hdr_flags_rd = -1;
static int hf_labdns_hdr_flags_ra = -1;
static int hf_labdns_hdr_flags_rcode = -1;

int queries_number, answers_number;
int entries_number, additional_entries_number;

static const value_string flags_type[] = {
	{ 1, "Inverse" },
	{ 2, "Server status query" },
	{ 0, "Standart" }
};
static const value_string flags_rcode[] = {
	{ 1, "Error in response format" },
	{ 2, "Server error" },
	{ 3, "Name not exists" },
	{ 0, "OK" }
};

value_string entry_types[] = {
	{ 1, "A" },
	{ 2, "NS" },
	{ 5, "CNAME" },
	{ 6, "SOA" },
	{ 7, "MB" },
	{ 11, "WKS" },
	{ 12, "PTR" },
	{ 13, "HINFO" },
	{ 14, "MINFO" },
	{ 15, "MX" },
	{ 16, "ISDN" },
	{ 252, "AXFR" },
	{ 255, "ANY" }
};

// Find entry in entry_types array using numeric value
gchar * find_entry_type(guint32 value) {
	int i;
	int size = sizeof(entry_types) / sizeof(entry_types[0]);
	for (i = 0; i < size; i++) {
		if (entry_types[i].value == value) {
			return entry_types[i].strptr;
		}
	}
	return NULL;
}

// Function to parse domain name
/* NOTE: It is complicated because of DNS packet structure - in domain
   name may be pointer to another byte in package.
   For futher information see DNS package structure.
   
   This function may be simplified, I know.
*/
int get_domain(tvbuff_t *tvb, proto_item *item, int offset) {
	guint8 ui8_small, ui8_big, ui8;
	guint8 *part;
	int pointer;
	
	ui8_big = tvb_get_guint8(tvb, offset);
	if (ui8_big >= 192) {
		ui8_small = tvb_get_guint8(tvb, offset + 1);
		pointer = (ui8_big & 0x3f) * 256 + ui8_small;
		offset += 2;
		
		// check pointer
		ui8 = tvb_get_guint8(tvb, pointer);
		while (ui8 >= 192) {
			ui8_small = tvb_get_guint8(tvb, pointer + 1);
			pointer = (ui8 & 0x3f) * 256 + ui8_small;
			ui8 = tvb_get_guint8(tvb, pointer); 
		}
	} else {
		pointer = offset;
	}
	
	do {	
		ui8 = tvb_get_guint8(tvb, pointer);
		pointer++;
		
		if (ui8 >= 192) {
			// jump
			ui8_small = tvb_get_guint8(tvb, pointer);
			pointer = (ui8 & 0x3f) * 256 + ui8_small;
		}		
		else if (ui8 != 0) {
			part = tvb_get_string(tvb, pointer, ui8);
			proto_item_append_text(item, "%s.", part);
			pointer += ui8;
		}
	} while (ui8 != 0);
	
	if (ui8_big < 192) offset = pointer;
	return offset;
}

// Function to add answers, entries & additional_entries
// Structure of it all is the same. That's why all proccessing is here.
int add_entries(tvbuff_t *tvb, proto_tree *labdns_tree, int offset, char* name, int limiter) 
{
	proto_item *item = NULL;
	proto_item *ti_entries = NULL;
	proto_item *item_inside = NULL;
	proto_tree *labdns_tree_entries, *labdns_tree_entry = NULL;
	guint8 ui8_small, ui8_big;
	guint8 *part;
	int i, j;
	
	ti_entries = proto_tree_add_text(labdns_tree, tvb, 0, -1, "%s", name);
	labdns_tree_entries = proto_item_add_subtree(ti_entries, ett_labdns);
		
	for (i = 0; i < limiter; i++) {
		guint16 rdl;
		guint32 ttl;
		guint8 byte;
		int type;
			
		item = proto_tree_add_text(labdns_tree_entries, tvb, 0, -1, "");
		labdns_tree_entry = proto_item_add_subtree(item, ett_labdns);

		// NAME
		offset = get_domain(tvb, item, offset);
			
		// TYPE
		ui8_big = tvb_get_guint8(tvb, offset++);
		ui8_small = tvb_get_guint8(tvb, offset++);
		type = ui8_big * 256 + ui8_small;
		proto_item_append_text(item, "  %s", find_entry_type(type));
		proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Type: %s (%d)", find_entry_type(type), type);
			
		// CLASS
		ui8_big = tvb_get_guint8(tvb, offset++);
		ui8_small = tvb_get_guint8(tvb, offset++);
		ui8_big = ui8_big * 256 + ui8_small;
		if (ui8_big == 1) {
			proto_item_append_text(item, "  IN");
			proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Class: IN (1)");
		} else {
			proto_item_append_text(item, "  %d", ui8_big);
			proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Class: %d", ui8_big);
		}
			
		// TIME-TO-LIVE
		ttl = tvb_get_ntohl(tvb, offset);
		proto_item_append_text(item, "  %d", ttl);
		proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Time to live: %d", ttl);
		offset += 4;
			
		// Resource data length
		rdl = tvb_get_ntohs(tvb, offset);
		proto_item_append_text(item, "  %d", rdl);
		proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Resource data length: %d", rdl);
		offset += 2;
			
		// Resource data
		// Type A entry (contains IP)
		if (type == 1) {
			proto_item_append_text(item, "  ");
			item_inside = proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Resource data: ");
			for (j = 0; j < rdl; j++) {
				byte = tvb_get_guint8(tvb, offset + j);
				proto_item_append_text(item, "%d", byte);
				proto_item_append_text(item_inside, "%d", byte);
				if (j != rdl - 1) {
					proto_item_append_text(item, ".");
					proto_item_append_text(item_inside, ".");
				}
			}
		} 
		// Type NS or CNAME or MB (contains domain)
		else if (type == 2 || type == 5 || type == 7) {
			proto_item_append_text(item, "  ");
			item_inside = proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Resource data: ");
			get_domain(tvb, item_inside, offset);
			get_domain(tvb, item, offset);
		}
		// any other entries
		else {
			part = tvb_get_string(tvb, offset, rdl);
			proto_item_append_text(item, "  %s", part);
			proto_tree_add_text(labdns_tree_entry, tvb, 0, -1, "Resource data: %s", part);
		}
		offset += rdl;
	}
	
	return offset;
}

// Main function to dissect DNS package. Needed by Wireshark. Used to parse everything.
static void dissect_labdns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset, i;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LabDNS");
	col_clear(pinfo->cinfo, COL_INFO);
	
	if (tree) {
		proto_item *ti = NULL;
		proto_item *ti_flags, *ti_queries = NULL;
		proto_tree *labdns_tree;
		proto_tree *labdns_tree_flags, *labdns_tree_queries;
		proto_item *item = NULL;
		guint8 ui8_small, ui8_big; // for storing bytes

		ti = proto_tree_add_item(tree, proto_labdns, tvb, 0, -1, FALSE);
		labdns_tree = proto_item_add_subtree(ti, ett_labdns);
		proto_tree_add_item(labdns_tree, hf_labdns_hdr_id, tvb, 0, 2, FALSE);
		
		// add flags
		ti_flags = proto_tree_add_item(labdns_tree, hf_labdns_hdr_flags, tvb, 2, 2, FALSE);
		labdns_tree_flags = proto_item_add_subtree(ti_flags, ett_labdns);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_qr, tvb, 2, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_type, tvb, 2, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_aa, tvb, 2, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_tc, tvb, 2, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_rd, tvb, 2, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_ra, tvb, 3, 1, FALSE);
		proto_tree_add_item(labdns_tree_flags, hf_labdns_hdr_flags_rcode, tvb, 3, 1, FALSE);
		
		ui8_big = tvb_get_guint8(tvb, 4);
		ui8_small = tvb_get_guint8(tvb, 5);
		queries_number = ui8_big * 256 + ui8_small;

		ui8_big = tvb_get_guint8(tvb, 6);
		ui8_small = tvb_get_guint8(tvb, 7);
		answers_number = ui8_big * 256 + ui8_small;
		
		ui8_big = tvb_get_guint8(tvb, 8);
		ui8_small = tvb_get_guint8(tvb, 9);
		entries_number = ui8_big * 256 + ui8_small;
		
		ui8_big = tvb_get_guint8(tvb, 8);
		ui8_small = tvb_get_guint8(tvb, 9);
		additional_entries_number = ui8_big * 256 + ui8_small;
		
		proto_tree_add_item(labdns_tree, hf_labdns_hdr_questions, tvb, 4, 2, FALSE);
		proto_tree_add_item(labdns_tree, hf_labdns_hdr_answers, tvb, 6, 2, FALSE);
		proto_tree_add_item(labdns_tree, hf_labdns_hdr_entries, tvb, 8, 2, FALSE);
		proto_tree_add_item(labdns_tree, hf_labdns_hdr_additional_entries, tvb, 10, 2, FALSE);
		
		offset = 12;
		
		// Questions section
		ti_queries = proto_tree_add_text(labdns_tree, tvb, 0, -1, "Questions section");
		labdns_tree_queries = proto_item_add_subtree(ti_queries, ett_labdns);
		
		for (i = 0; i < queries_number; i++) {
			item = proto_tree_add_text(labdns_tree_queries, tvb, 0, -1, "");

			// QNAME
			offset = get_domain(tvb, item, offset);
			
			// QTYPE
			ui8_big = tvb_get_guint8(tvb, offset++);
			ui8_small = tvb_get_guint8(tvb, offset++);
			proto_item_append_text(item, "  %s", find_entry_type(ui8_big * 256 + ui8_small));
			
			// QCLASS
			ui8_big = tvb_get_guint8(tvb, offset++);
			ui8_small = tvb_get_guint8(tvb, offset++);
			ui8_big = ui8_big * 256 + ui8_small;
			if (ui8_big == 1) {
				proto_item_append_text(item, "  IN");
			} else {
				proto_item_append_text(item, "  %d", ui8_big);
			}
		}
		
		// add answers
		offset = add_entries(tvb, labdns_tree, offset, "Answers section", answers_number);
		offset = add_entries(tvb, labdns_tree, offset, "Entries section", entries_number);
		offset = add_entries(tvb, labdns_tree, offset, "Additional entries section", additional_entries_number);
	}
}

void proto_register_labdns(void) 
{
	static gint *ett[] = { &ett_labdns };
	static hf_register_info hf[] = {
		{ &hf_labdns_hdr_id,
			{ "ID", "labdns.hdr.id",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags,
			{ "Flags", "labdns.hdr.flags",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_qr,
			{ "QR", "labdns.hdr.flags.qr",
			FT_BOOLEAN, FT_INT8,
			NULL, LABDNS_FLAG_QR,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_type,
			{ "Type", "labdns.hdr.flags.type",
			FT_UINT8, BASE_DEC,
			VALS(flags_type), LABDNS_FLAG_TYPE,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_aa,
			{ "AA", "labdns.hdr.flags.aa",
			FT_BOOLEAN, FT_INT8,
			NULL, LABDNS_FLAG_AA,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_tc,
			{ "TC", "labdns.hdr.flags.tc",
			FT_BOOLEAN, FT_INT8,
			NULL, LABDNS_FLAG_TC,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_rd,
			{ "RD", "labdns.hdr.flags.rd",
			FT_BOOLEAN, FT_INT8,
			NULL, LABDNS_FLAG_RD,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_ra,
			{ "RA", "labdns.hdr.flags.ra",
			FT_BOOLEAN, FT_INT8,
			NULL, LABDNS_FLAG_RA,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_flags_rcode,
			{ "RCode", "labdns.hdr.flags.rcode",
			FT_UINT8, BASE_DEC,
			VALS(flags_rcode), LABDNS_FLAG_RCODE,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_questions,
			{ "Number of questions", "labdns.hdr.questions",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_answers,
			{ "Number of answers", "labdns.hdr.answers",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_entries,
			{ "Number of entries", "labdns.hdr.entries",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_labdns_hdr_additional_entries,
			{ "Number of additional entries", "labdns.hdr.additional_entries",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}
	};
	
	proto_labdns = proto_register_protocol("Lab DNS Protocol", "LabDNS", "labdns");
	proto_register_field_array(proto_labdns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_labdns(void) 
{
	static dissector_handle_t labdns_handle;

	labdns_handle = create_dissector_handle(dissect_labdns, proto_labdns);
	dissector_add_uint("udp.port", DNS_PORT, labdns_handle);
}
