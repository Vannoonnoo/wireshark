#include <epan/packet.h>

#define WEAVE_PORT 11095

#define WEAVE_VERSION_BITMASK	0xF0
#define WEAVE_TUNNEL_BITMASK 	0x04
#define WEAVE_SOURCE_BITMASK	0x02
#define WEAVE_DEST_BITMASK		0x01

static int proto_weave				= -1;

static int hf_weave_msg_len			= -1;
static int hf_weave_encryption_type	= -1;
static int hf_weave_flags			= -1;
static int hf_weave_version			= -1;
static int hf_weave_tunnel			= -1;
static int hf_weave_source			= -1;
static int hf_weave_dest			= -1;
static int hf_weave_msg_id			= -1;

static gint ett_weave				= -1;

static const value_string encryption_type[] = {
    { 0x00, "Plaintext" },
    { 0x10, "Encrypted" },
    { 0, NULL }
};

static int* const flag_bits[] = {
	&hf_weave_version,
	&hf_weave_tunnel,
	&hf_weave_source,
	&hf_weave_dest,
	NULL
};

static int dissect_weave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WEAVE");

	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_weave, tvb, 0, -1, ENC_NA);

	proto_tree *weave_tree = proto_item_add_subtree(ti, ett_weave);

	proto_tree_add_item(weave_tree, hf_weave_msg_len, tvb, 0, 2, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(weave_tree, hf_weave_encryption_type, tvb, 2, 1, ENC_NA);

	proto_tree_add_bitmask(weave_tree, tvb, 3, hf_weave_flags, ett_weave, flag_bits, ENC_NA);

	proto_tree_add_item(weave_tree, hf_weave_msg_id, tvb, 4, 4, ENC_NA);

	return tvb_captured_length(tvb);
}

void proto_register_weave(void)
{
	static hf_register_info hf[] = {
		{ &hf_weave_msg_len,
			{ "Message Length", "weave.len",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_weave_encryption_type,
			{ "Encryption Type", "weave.encryption",
			FT_UINT8, BASE_DEC,
			VALS(encryption_type), 0x0,
			NULL, HFILL },
		},
		{ &hf_weave_flags,
			{ "Flags", "weave.flags",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_weave_version,
			{ "Version", "weave.flags.version",
			FT_UINT8, BASE_DEC,
			NULL, WEAVE_VERSION_BITMASK,
			NULL, HFILL }
		},
		{ &hf_weave_tunnel,
			{ "Tunnel", "weave.flags.tunnel",
			FT_BOOLEAN, 8,
			NULL, WEAVE_TUNNEL_BITMASK,
			NULL, HFILL }
		},
		{ &hf_weave_source,
			{ "Source Node ID", "weave.flags.src",
			FT_BOOLEAN, 8,
			NULL, WEAVE_SOURCE_BITMASK,
			NULL, HFILL }
		},
		{ &hf_weave_dest,
			{ "Destination Node ID", "weave.flags.dst",
			FT_BOOLEAN, 8,
			NULL, WEAVE_DEST_BITMASK,
			NULL, HFILL }
		},
		{ &hf_weave_msg_id,
			{ "Message ID", "weave.msg_id",
			FT_UINT32, BASE_HEX_DEC,
			NULL, 0x0,
			NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_weave
	};

	proto_weave = proto_register_protocol("Weave Protocol", "Weave", "weave");

	proto_register_field_array(proto_weave, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_weave(void)
{
	static dissector_handle_t weave_handle;

	weave_handle = create_dissector_handle(dissect_weave, proto_weave);
	dissector_add_uint("tcp.port", WEAVE_PORT, weave_handle);
}
