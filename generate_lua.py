#! /usr/bin/python

##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <http://www.gnu.org/licenses/>.
##
##    Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.2 generator
##
##    Copyright (c) 2017 Daniele Palmas <dnlplm@gmail.com>

## pathlib required

import sys
import json
import ntpath
from pathlib import Path

bad_words = ['//']

services = {'ctl' : 0x00, 'wds' : 0x01, 'dms' : 0x02, 'nas' : 0x03, 'qos' : 0x04, 'wms' : 0x05, 'pds' : 0x06, 'auth' : 0x07, 'at' : 0x08, 'voice' : 0x09, 'cat2' : 0x0A, 'uim' : 0x0B, 'pbm' : 0x0C, 'rmtfs' : 0x0E, 'loc' : 0x10, 'sar' : 0x11, 'wda' : 0x1A, 'pdc' : 0x24, 'unknown' : 0xFF}

common_refs = {}

def include_file(src_file_name, dest_file_obj):
    with open(src_file_name) as src_file_obj:
        for line in src_file_obj:
            dest_file_obj.write(line)

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

if (len(sys.argv) != 2):
    sys.stderr.write("Usage: generate.lua.py <libqmi json directory path>\n")
    sys.exit(1)

dissector_name = 'qmi_dissector_gen.lua'
dissector_file = open(dissector_name, 'w')
include_file('qmi_dissector_header.part', dissector_file)

## Generate service list
dissector_file.write("\nservices = { ")
for service in services.items():
    if service[0] == 'unknown':
        continue
    else:
        dissector_file.write("[" + str(service[1]) + "] = \"" + service[0] + "\"")
    dissector_file.write(", ")
dissector_file.write(" }\n\n")
dissector_file.write("f.svcid =     ProtoField.uint8(\"qmi.service_id\", \"Service ID\", base.HEX, services)\n")

# Generate dictionary of common refs
pathlist = Path(sys.argv[1]).glob('**/*.json')
for path in pathlist:
    path_in_str = str(path)
    if (path_in_str.find('common') == -1):
        continue
    name = path_leaf(path_in_str) + "_mod"

    with open(path_in_str) as oldfile, open(name, 'w') as newfile:
        for line in oldfile:
            if not any(bad_word in line for bad_word in bad_words):
                newfile.write(line)

    json_data=open(name)
    data = json.load(json_data)
    json_data.close()

    for item in data:
        if 'id' in item:
            common_refs.update({item['common-ref']: {'name': item['name'], 'id': item['id']}})

# Generate requests and related TLVs data structures starting from libqmi json files
pathlist = Path(sys.argv[1]).glob('**/*.json')
for path in pathlist:
    path_in_str = str(path)
    if (path_in_str.find('common') != -1) or (path_in_str.find('FULL') != -1):
        continue
    name = path_leaf(path_in_str) + "_mod"

    with open(path_in_str) as oldfile, open(name, 'w') as newfile:
        for line in oldfile:
            if not any(bad_word in line for bad_word in bad_words):
                newfile.write(line)

    json_data=open(name)
    data = json.load(json_data)
    json_data.close()

    for service in services.keys():
        if (name.find(service) != -1):
            break

    if service == 'unknown':
        continue

    lua_file = service + ".lua"
    lua_file_obj = open(lua_file, 'w')
    lua_file_obj.write(service + "_messages  = { ")
    tlv_definitions_req = "tlv_" + service + "_req = { "
    tlv_definitions_resp = "tlv_" + service + "_resp = { "

    for item in data:
        if 'type' in item:
            # TBD: Still to be managed indications
            if (item['type'] == "Message"):
                lua_file_obj.write("[" + item['id'] + "] = \"" + item['name'] + "\"")
                if item != data[-1]:
                    lua_file_obj.write(", ")
                tlv_definitions_req += ("[" + item['id'] + "] = { ")
                tlv_definitions_resp += ("[" + item['id'] + "] = { ")
                if item.get('input', 0) != 0:
                    for tlv in item['input']:
                        if tlv.get('id', 0) != 0:
                            if tlv.get('name', 0) != 0:
                                tlv_definitions_req += ("[" + tlv['id'] + "] = '" + tlv['name'] + "', ")
                            else:
                                tlv_definitions_req += ("[" + tlv['id'] + "] = 'unknown name', ")
                        else:
                            if tlv.get('common-ref', 0) != 0:
                                if common_refs.get(tlv['common-ref'], 0) != 0:
                                    tlv_definitions_req += ("[" + common_refs.get(tlv['common-ref']).get('id') + "] = '" + common_refs.get(tlv['common-ref']).get('name') + "', ")
                    tlv_definitions_req += ("}, ")
                else:
                    tlv_definitions_req += ("}, ")
                if item.get('output', 0) != 0:
                    for tlv in item['output']:
                        if tlv.get('id', 0) != 0:
                            if tlv.get('name', 0) != 0:
                                tlv_definitions_resp += ("[" + tlv['id'] + "] = '" + tlv['name'] + "', ")
                            else:
                                tlv_definitions_resp += ("[" + tlv['id'] + "] = 'unknown name', ")
                        else:
                            if tlv.get('common-ref', 0) != 0:
                                if common_refs.get(tlv['common-ref'], 0) != 0:
                                    tlv_definitions_resp += ("[" + common_refs.get(tlv['common-ref']).get('id') + "] = '" + common_refs.get(tlv['common-ref']).get('name') + "', ")
                    tlv_definitions_resp += ("}, ")
                else:
                    tlv_definitions_resp += ("}, ")
    lua_file_obj.write(" }" + '\n')
    lua_file_obj.write("f.msgid_" + service + " = ProtoField.uint16(\"qmi.message_id\", \"Message ID\", base.HEX," + " " + service + "_messages)")
    lua_file_obj.write('\n\n')
    lua_file_obj.write(tlv_definitions_req + '}\n\n')
    lua_file_obj.write(tlv_definitions_resp + '}\n\n')
    lua_file_obj.close()
    include_file(lua_file, dissector_file)

include_file('qmi_dissector_body_1.part', dissector_file)

# Link TLV data structures to service
first_item = 1
for service in services.items():
    if service[0] == 'unknown':
        continue
    else:
        if (first_item == 1):
            dissector_file.write("\tif svcid:uint() == " + str(service[1]) + " then\n")
            first_item = 0
        else:
            dissector_file.write("\telseif svcid:uint() == " + str(service[1]) + " then\n")
        dissector_file.write("\t\tmhdrtree:add_le(f.msgid_" + str(service[0]) + ", msgid)\n")
        dissector_file.write("\t\tmsgstr = " + str(service[0]) + "_messages[msgid:le_uint()]\n")
        dissector_file.write("\t\tif responsebit == 1 or indicationbit == 1 then\n")
        dissector_file.write("\t\t\ttlv_description = tlv_" + str(service[0]) + "_resp\n")
        dissector_file.write("\t\telse\n")
        dissector_file.write("\t\t\ttlv_description = tlv_" + str(service[0]) + "_req\n")
        dissector_file.write("\t\tend\n")

include_file('qmi_dissector_trailer.part', dissector_file)
dissector_file.close()
