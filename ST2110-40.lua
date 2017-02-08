-- Lua Dissector for SMPTE ST 2110-40
-- (which references IETF draft-ietf-payload-rtp-ancillary-07)
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
    F.UDW=ProtoField.bytes("st_2110_40.UDW","User_Data_Words_bytes")
    F.Checksum_Word=ProtoField.bytes("st_2110_40.Checksum_Word","Checksum_Word_bytes")

-- DID / SDID info from https://smpte-ra.org/smpte-ancillary-data-smpte-st-291 as per 7 Feb 2017

    local DID_SDID={}
   
    DID_SDID[0x08]={}
    DID_SDID[0x40]={}
    DID_SDID[0x41]={}
    DID_SDID[0x43]={}
    DID_SDID[0x44]={}
    DID_SDID[0x45]={}
    DID_SDID[0x46]={}
    DID_SDID[0x50]={}
    DID_SDID[0x51]={}
    DID_SDID[0x60]={}
    DID_SDID[0x61]={}
    DID_SDID[0x62]={}
    DID_SDID[0x64]={}

    DID_SDID[0x00]="Undefined data deleted, (Deprecated; revision of ST291-2010) (S291)"
    DID_SDID[0x80]="Packet marked for deletion (S291)"
    DID_SDID[0x84]="End packet deleted  (Deprecated; revision of ST291-2010) (S291)"
    DID_SDID[0x88]="Start packet deleted (Deprecated; revision of ST291-2010) (S291)"
    DID_SDID[0xA0]="Audio data in HANC space (3G) - Group 8 Control pkt (ST 299-2)"
    DID_SDID[0xA1]="Audio data in HANC space (3G) - Group 7 Control pkt (ST 299-2)"
    DID_SDID[0xA2]="Audio data in HANC space (3G) - Group 6 Control pkt (ST 299-2)"
    DID_SDID[0xA3]="Audio data in HANC space (3G- Group 5 Control pkt) (ST 299-2)"
    DID_SDID[0xA4]="Audio data in HANC space (3G) - Group 8 (ST 299-2)"
    DID_SDID[0xA5]="Audio data in HANC space (3G) - Group 7 (ST 299-2)"
    DID_SDID[0xA6]="Audio data in HANC space (3G) - Group 6 (ST 299-2)"
    DID_SDID[0xA7]="Audio data in HANC space (3G)- Group 5 (ST 299-2)"
    DID_SDID[0xE0]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE1]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE2]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE3]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE4]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE5]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE6]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xE7]="Audio data in HANC space (HDTV) (ST 299-1)"
    DID_SDID[0xEc]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xEd]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xEe]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xEf]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xF0]="Camera position (HANC or VANC space) (S315)"
    DID_SDID[0xF4]="Error Detection and Handling (HANC space) (RP165)"
    DID_SDID[0xF8]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xF9]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFa]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFB]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFC]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFD]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFE]="Audio Data in HANC space (SDTV) (S272)"
    DID_SDID[0xFF]="Audio Data in HANC space (SDTV) (S272)"
 
    DID_SDID[0x60][0x60]="Ancillary Time Code"
    DID_SDID[0x08][0x08]="MPEG recoding data, VANC space (S353)"
    DID_SDID[0x08][0x0C]="MPEG recoding data, HANC space (S353)"
    DID_SDID[0x40][0x01]="SDTI transport in active frame space (S305)"
    DID_SDID[0x40][0x02]="HD-SDTI transport in active frame space (S348)"
    DID_SDID[0x40][0x04]="Link Encryption Message 1 (S427)"
    DID_SDID[0x40][0x05]="Link Encryption Message 2 (S427)"
    DID_SDID[0x40][0x06]="Link Encryption Metadata (S427)"
    DID_SDID[0x41][0x01]="Payload Identification , HANC space (S352)"
    DID_SDID[0x41][0x05]="AFD and Bar Data (S2016-3)"
    DID_SDID[0x41][0x06]="Pan-Scan Data (S2016-4)"
    DID_SDID[0x41][0x07]="ANSI/SCTE 104 messages (S2010)"
    DID_SDID[0x41][0x08]="DVB/SCTE VBI data (S2031)"
    DID_SDID[0x41][0x09]="MPEG TS packets in VANC (ST 2056)"
    DID_SDID[0x41][0x0A]="Stereoscopic 3D Frame Compatible Packing and Signaling (ST 2068)"
    DID_SDID[0x41][0x0B]="Lip Sync data as specified by ST 2064-1 (standard in preparation) (ST 2064-2 (in preparation))"
    DID_SDID[0x43][0x01]="Structure of inter-station control data conveyed by ancillary data packets (ITU-R BT.1685)"
    DID_SDID[0x43][0x02]="Subtitling Distribution packet (SDP) (RDD 8)"
    DID_SDID[0x43][0x03]="Transport of ANC packet in an ANC Multipacket (RDD 8)"
    DID_SDID[0x43][0x04]="Metadata to monitor errors of audio and video signals on a broadcasting chain ARIB http://www.arib.or.jp/english/html/overview/archives/br/8-TR-B29v1_0-E1.pdf (ARIB TR-B29)"
    DID_SDID[0x43][0x05]="Acquisition Metadata Sets for Video Camera Parameters (RDD18)"
    DID_SDID[0x44][0x04]="KLV Metadata transport in VANC space (RP214)"
    DID_SDID[0x44][0x14]="KLV Metadata transport in HANC space (RP214)"
    DID_SDID[0x44][0x44]="Packing UMID and Program Identification Label Data into SMPTE 291M Ancillary Data Packets (RP223)"
    DID_SDID[0x45][0x01]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x02]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x03]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x04]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x05]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x06]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x07]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x08]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x45][0x09]="Compressed Audio Metadata (S2020-1)"
    DID_SDID[0x46][0x01]="Two Frame Marker in HANC (ST 2051)"
    DID_SDID[0x50][0x01]="WSS data per RDD 8 (RDD 8)"
    DID_SDID[0x51][0x01]="Film Codes in VANC space (RP215)"
    DID_SDID[0x60][0x60]="Ancillary Time Code (S12M-2)"
    DID_SDID[0x60][0x61]="Time Code for High Frame Rate Signals (ST 12-3)"
    DID_SDID[0x61][0x01]="EIA 708B Data mapping into VANC space (S334-1)"
    DID_SDID[0x61][0x02]="EIA 608 Data mapping into VANC space (S334-1)"
    DID_SDID[0x62][0x01]="Program Description in VANC space (RP207)"
    DID_SDID[0x62][0x02]="Data broadcast (DTV) in VANC space (S334-1)"
    DID_SDID[0x62][0x03]="VBI Data in VANC space (RP208)"
    DID_SDID[0x64][0x64]="Time Code in HANC space (Deprecated; for reference only) (RP196 (Withdrawn))"
    DID_SDID[0x64][0x7F]="VITC in HANC space (Deprecated; for reference only) (RP196 (Withdrawn))"
    DID_SDID[0x60][0x62]="Generic Time Label (ST 2103 (in development))"

    function st_2110_40.dissector(tvb, pinfo, tree)
        local subtree = tree:add(st_2110_40, tvb(),"ST 2110_40 Data")  
        subtree:add(F.ESN, tvb(0,2))
	subtree:add(F.Length, tvb(2,2))
   	subtree:add(F.ANC_Count, tvb(4,1)) 
	local ANC_Count=tvb(4,1):uint()
	local Data_Count=0
	local offset=8
	local CS_offset=0
	local CS_length=2
	local DID
	local SDID
	local SDID_proto
	for i=1,ANC_Count do
		subtree:add(F.C,tvb(offset,1))
		subtree:add(F.Line_Number,tvb(offset,2))
		subtree:add(F.HO,tvb(offset+1,2))
		subtree:add(F.DID,tvb(offset+4,2))
		DID=tvb(offset+4,2):bitfield(2,8)
		SDID_proto=subtree:add(F.SDID,tvb(offset+5,2))
		SDID=tvb(offset+5,2):bitfield(4,8)
		if DID_SDID[DID] and not DID_SDID[DID][SDID] then
			SDID_proto:append_text(":"..DID_SDID[DID])
		end	
		if DID_SDID[DID] and DID_SDID[DID][SDID] then
			SDID_proto:append_text(":"..DID_SDID[DID][SDID])
		end
		subtree:add(F.Data_Count,tvb(offset+6,2))
		Data_Count=tvb(offset+6,2):bitfield(6,8)
		local UDW_length=1+math.ceil(((Data_Count*10)-2)/8)
		subtree:add(F.UDW,tvb(offset+7,UDW_length))
		CS_offset=0
		CS_length=2
		UDW_bits=(Data_Count*10)-2
		if (UDW_bits % 8 == 0) then
			CS_offset = 1 
		else
			CS_offset=0
		end
		if (UDW_bits % 8 == 7) then
			CS_length=3
		end
		subtree:add(F.Checksum_Word,tvb(offset+6+UDW_length+CS_offset,CS_length))
		offset=offset+(math.ceil((62+(Data_Count*10)+8)/32)*4)
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
