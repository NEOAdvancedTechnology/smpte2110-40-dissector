-- Lua Dissector for ST 2110-40
-- Author: Thomas Edwards (thomas.edwards@fox.com)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "ST-2110_40.lua" 
-- 3) In Wireshark Preferences, under "Protocols", set st_2110_40 as dynamic payload type being used
-- 4) Capture packets of ST 2110_40
-- 5) "Decode As" those UDP packets as RTP
-- 6) You will now see the ST 2110_40 Data dissection of the RTP payload
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--
------------------------------------------------------------------------------------------------  
do  
    local st_2110_40 = Proto("st_2110_40", "ST 2110_40")  
     
    local prefs = st_2110_40.prefs  
    prefs.dyn_pt = Pref.uint("ST 2110_40 dynamic payload type", 0, "The value > 95")  
 
    local F = st_2110_40.fields

    F.ESN = ProtoField.uint16("st_2110_40.ExtendedSequenceNumber","Extended Sequence Number",base.HEX,nil)
    F.Length = ProtoField.uint16("st_2110_40.Length","Length",base.DEC,nil)
    F.ANC_Count = ProtoField.uint8("st_2110_40.ANC_Count","ANC_Count",base.DEC,nil)
    F.C = ProtoField.bool("st_2110_40.C","C",8,{"C:Color-difference","Y:Luma"},0x80)
    F.Data_Count = ProtoField.uint16("st_2110_40.Data_Count","Data_Count",base.DEC,nil,0x03FC)
    F.Line_Number = ProtoField.uint16("st_2110_40.Line_Number","Line_Number",base.DEC,nil,0x7FF0)
    F.HO=ProtoField.uint16("st_2110_40.HO","Horizontal_Offset",base.DEC,nil,0x0FFF)
    F.DID=ProtoField.uint16("st_2110_40.DID","DID",base.HEX,nil,0x3FC0)
    F.SDID=ProtoField.uint16("st_2110_40.SDID","SDID",base.HEX,nil,0x0FF0)
    F.UDW=ProtoField.bytes("smpte_2022_6.UDW","User_Data_Words")

    function st_2110_40.dissector(tvb, pinfo, tree)
        local subtree = tree:add(st_2110_40, tvb(),"ST 2110_40 Data")  
        subtree:add(F.ESN, tvb(0,2))
	subtree:add(F.Length, tvb(2,2))
   	subtree:add(F.ANC_Count, tvb(4,1)) 
	local ANC_Count=tvb(4,1):uint()
	local Data_Count=0
	local offset=8
	for i=1,ANC_Count do
		subtree:add(F.C,tvb(offset,1))
		subtree:add(F.Line_Number,tvb(offset,2))
		subtree:add(F.HO,tvb(offset+1,2))
		subtree:add(F.DID,tvb(offset+4,2))
		subtree:add(F.SDID,tvb(offset+5,2))
		subtree:add(F.Data_Count,tvb(offset+6,2))
		Data_Count=tvb(offset+6,2):bitfield(6,8)
		subtree:add(F.UDW,tvb(offset+7,math.ceil((Data_Count*10)/8)))
		offset=offset+(math.ceil((62+(Data_Count*10)+8)/32)*4)
		subtree:append_text("--DEBUG: would skip "..(math.ceil((62+(Data_Count*10)+8)/32)*4).." bytes to next ANC packet")
	end
    end  
  
    -- register dissector to dynamic payload type dissectorTable  
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")  
    dyn_payload_type_table:add("st_2110_40", st_2110_40)  
  
    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")  
    local old_dissector = nil  
    local old_dyn_pt = 0  
    function st_2110_40.init()  
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, st_2110_40)  
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)  
                end  
            end  
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)  
            if (prefs.dyn_pt > 0) then  
                payload_type_table:add(prefs.dyn_pt, st_2110_40)  
            end  
        end   
    end  
end
