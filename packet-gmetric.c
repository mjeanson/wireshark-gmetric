/* packet-gmetric.c
 * Routines for Ganglia metric protocol packet disassembly
 * By Michael Jeanson <mjeanson@gmail.com>
 * Copyright 2013 Michael Jeanson
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-rpc.h>
#include "packet-gmetric.h"

static int proto_gmetric = -1;
static int hf_gmetric_pdu_type = -1;
static int hf_gmetric_hostname = -1;
static int hf_gmetric_metric_name = -1;
static int hf_gmetric_spoofed = -1;
static int hf_gmetric_metric_type = -1;
static int hf_gmetric_metric_name2 = -1;
static int hf_gmetric_metric_units = -1;
static int hf_gmetric_slope = -1;
static int hf_gmetric_tmax = -1;
static int hf_gmetric_dmax = -1;
static int hf_gmetric_xd_key = -1;
static int hf_gmetric_xd_value = -1;
static int hf_gmetric_format = -1;
static int hf_gmetric_data_float = -1;
static int hf_gmetric_data_double = -1;
static int hf_gmetric_data_int = -1;
static int hf_gmetric_data_uint = -1;
static int hf_gmetric_data_str = -1;

static gint ett_gmetric = -1;
static gint ett_gmetric_xd = -1;

static const value_string packettypenames[] = {
    { 128,   "Metadata full" },
    { 128+1, "Metric (ushort)" },
    { 128+2, "Metric (short)" },
    { 128+3, "Metric (int)" },
    { 128+4, "Metric (uint)" },
    { 128+5, "Metric (string)" },
    { 128+6, "Metric (float)" },
    { 128+7, "Metric (double)" },
    { 128+8, "Metadata request" },
    { 0, NULL }
};

static const value_string slopetypenames[] = {
    { 0, "Zero"},
    { 1, "Positive"},
    { 2, "Negative"},
    { 3, "Both"},
    { 4, "Unspecified"}
};

static int
gmetric_dissect_xd(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree)
{
    //proto_item *xd_item;
    //proto_tree *xd_tree;
    //int start_offset = offset;

    //xd_item = proto_tree_add_text(tree, tvb, offset, -1, "Extra data");
    //xd_tree = proto_item_add_subtree(xd_item, ett_gmetric_xd);

    offset = dissect_rpc_string(tvb, tree, hf_gmetric_xd_key, offset, NULL);
    offset = dissect_rpc_string(tvb, tree, hf_gmetric_xd_value, offset, NULL);

    //proto_item_set_len(xd_item, offset - start_offset);

    return offset;
}


static int
dissect_gmetric_metric_id(tvbuff_t *tvb, proto_tree *gmetric_tree, int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_hostname,
            offset, NULL);
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_metric_name,
            offset, NULL);
    offset = dissect_rpc_bool(tvb, gmetric_tree, hf_gmetric_spoofed, offset);

    return offset;
}

static int
dissect_gmetric_metadata_message(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *gmetric_tree, int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_metric_type,
            offset, NULL);
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_metric_name2,
            offset, NULL);
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_metric_units,
            offset, NULL);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_slope, offset);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_tmax, offset);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_dmax, offset);

    //guint32 extra_data = tvb_get_ntohl(tvb, offset);
    //offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_extra_data,
    //      offset);
    offset =  dissect_rpc_list(tvb, pinfo, gmetric_tree, offset,
            gmetric_dissect_xd);

    return offset;
}

static int
dissect_gmetric_metric_ushort(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_data_uint,
            offset);

    return offset;
}

static int
dissect_gmetric_metric_short(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_data_int,
            offset);

    return offset;
}

static int
dissect_gmetric_metric_int(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_data_int,
            offset);

    return offset;
}

static int
dissect_gmetric_metric_uint(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_data_uint,
            offset);

    return offset;
}

static int
dissect_gmetric_metric_string(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_data_str,
            offset, NULL);

    return offset;
}

static int
dissect_gmetric_metric_float(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    proto_tree_add_item(gmetric_tree, hf_gmetric_data_float, tvb, offset, 4,
            ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_gmetric_metric_double(tvbuff_t *tvb, proto_tree *gmetric_tree,
        int offset)
{
    offset = dissect_rpc_string(tvb, gmetric_tree, hf_gmetric_format, offset,
            NULL);
    proto_tree_add_item(gmetric_tree, hf_gmetric_data_double, tvb, offset, 8,
            ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static void
dissect_gmetric(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint32 packet_type = tvb_get_ntohl(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "gmetric");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
             val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *gmetric_tree = NULL;
        gint offset = 0;

        ti = proto_tree_add_item(tree, proto_gmetric, tvb, 0, -1, ENC_NA);

        proto_item_append_text(ti, ", Type %s",
            val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

        gmetric_tree = proto_item_add_subtree(ti, ett_gmetric);

        offset = dissect_rpc_uint32(tvb, gmetric_tree, hf_gmetric_pdu_type,
                offset);

        if (packet_type == 128) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metadata_message(tvb, pinfo,
                    gmetric_tree, offset);
        }
        else if (packet_type == 128+1) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_ushort(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+2) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_short(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+3) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_int(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+4) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_uint(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+5) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_string(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+6) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_float(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+7) {
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
            offset = dissect_gmetric_metric_double(tvb, gmetric_tree, offset);
        }
        else if (packet_type == 128+8)
            offset = dissect_gmetric_metric_id(tvb, gmetric_tree, offset);
    }
}

void
proto_register_gmetric(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details */
    static hf_register_info hf[] = {
        { &hf_gmetric_pdu_type,
            { "gmetric PDU Type", "gmetric.type",
            FT_UINT32, BASE_DEC,
            VALS(packettypenames), 0x0,
            NULL, HFILL }
        },
        { &hf_gmetric_hostname,
            { "Hostname", "gmetric.hostname",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_metric_name,
            { "Metric name", "gmetric.metric_name",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_spoofed,
            { "Spoofed", "gmetric.spoofed",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /* Metadata packet specific */
        { &hf_gmetric_metric_type,
            { "Metric type", "gmetric.metric_type",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_metric_name2,
            { "Metric name 2", "gmetric.metric_name2",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_metric_units,
            { "Metric units", "gmetric.metric_units",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_slope,
            { "Slope", "gmetric.slope",
                FT_UINT32, BASE_DEC,
                VALS(slopetypenames), 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_tmax,
            { "TMAX", "gmetric.tmax",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_dmax,
            { "DMAX", "gmetric.dmax",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_xd_key,
            { "Extra data key", "gmetric.xd_key",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_xd_value,
            { "Extra data value", "gmetric.xd_value",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /* Data packet specific */
        { &hf_gmetric_format,
            { "Format", "gmetric.format",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_data_float,
            { "Data", "gmetric.data",
                FT_FLOAT, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_data_double,
            { "Data", "gmetric.data",
                FT_DOUBLE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_data_int,
            { "Data", "gmetric.data",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_data_uint,
            { "Data", "gmetric.data",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_gmetric_data_str,
            { "Data", "gmetric.data",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_gmetric,
        &ett_gmetric_xd
    };

    /* Register the protocol name and description */
    proto_gmetric = proto_register_protocol (
        "Ganglia Metric Protocol", /* name       */
        "gmetric",                  /* short name */
        "gmetric"                   /* abbrev     */
        );

    proto_register_field_array(proto_gmetric, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gmetric(void)
{
    static dissector_handle_t gmetric_handle;

    gmetric_handle = create_dissector_handle(dissect_gmetric, proto_gmetric);
    dissector_add_uint("udp.port", GMETRIC_PORT, gmetric_handle);
}
