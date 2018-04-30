-- Lua Dissector for SMPTE ST 2110-40
-- (which references RFC 8331)
-- Author: Thomas Edwards (thomas.edwards@fox.com)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, 
--    "About Wireshark/Plugins" should list "ST-2110_40.lua"
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
  local VALS_F = {[0] = "unspecified or progressive scan", [1] = "not valid",[2] = "Field 1",[3]="Field 2"}
  F.F = ProtoField.uint8("st_2110_40.F","(F)ield",base.HEX,VALS_F,0xC0)
  F.C = ProtoField.bool("st_2110_40.C","(C) or Y",8,{"C:Color-difference","Y:Luma"},0x80)
  F.Data_Count = ProtoField.uint16("st_2110_40.Data_Count","Data_Count",base.DEC,nil,0x03FC)
  F.Line_Number = ProtoField.uint16("st_2110_40.Line_Number","Line_Number",base.DEC,nil,0x7FF0)
  F.HO=ProtoField.uint16("st_2110_40.HO","Horizontal_Offset",base.DEC,nil,0x0FFF)
  F.S = ProtoField.bool("st_2110_40.S","S",8,{"StreamNum used","StreamNum not used"},0x80)
  F.StreamNum = ProtoField.uint8("st_2110_40.StreamNum","StreamNum",base.DEC,nil,0x7F)
  F.DID=ProtoField.uint16("st_2110_40.DID","DID",base.HEX,nil,0x3FC0)
  F.SDID=ProtoField.uint16("st_2110_40.SDID","SDID",base.HEX,nil,0x0FF0)
  F.UDW=ProtoField.bytes("st_2110_40.UDW","User_Data_Words_bytes")
  F.Checksum_Word=ProtoField.bytes("st_2110_40.Checksum_Word","Checksum_Word_bytes")

-- User Data Structure

  F.Magic=ProtoField.uint16("st_2110_40.Data.Magic","MagicHeader", base.HEX,nil)
  F.DataWord_Count=ProtoField.uint8("st_2110_40.Data.DW_Count","Data Count", base.DEC,nil)
  F.Frame_Rate=ProtoField.uint8("st_2110_40.Data.FrameRate","Frame Rate", base.HEX,nil)
  F.CDP_Section_Type=ProtoField.uint8("st_2110_40.Data.Section_Type","CDP Section Type", base.HEX,nil)

  -- Ancillary Time Code (S12M-2)
  F.TimeCode=ProtoField.string("st_2110_40.Data.TimeCode","TimeCode")
  F.VITC=ProtoField.string("st_2110_40.Data.VITC","VITC")

  -- EIA 708B Data mapping into VANC space (S334-1)

  F.CCDataSection=ProtoField.uint8("st_2110_40.Data.CCDataSection","CC Data Section", base.HEX,nil)
  F.CCDataCount=ProtoField.uint8("st_2110_40.Data.CCDataCount","CC Data Count", base.DEC,nil)
  F.CCType=ProtoField.uint8("st_2110_40.Data.CCType","CC Data Type", base.HEX,nil)
  F.CCValue=ProtoField.uint16("st_2110_40.Data.CCValue","CC Data Value", base.HEX,nil)
  F.CCData1=ProtoField.string("st_2110_40.Data.CCCData1","CC Packet_Data_Structure Service 1", ftypes.STRING)
  F.CCData2=ProtoField.string("st_2110_40.Data.CCCData2","CC Packet_Data_Structure Service 2", ftypes.STRING)

  F.CCServiceNb=ProtoField.uint8("st_2110_40.Data.CCServiceNb","CC Block Service Number", base.DEC,nil)
  F.CCBlockSize=ProtoField.uint8("st_2110_40.Data.CCBlockSize","CC Block Size", base.DEC,nil)
  F.CCBlockData=ProtoField.string("st_2110_40.Data.CCBlockData","CC Block Data")

  -- Line_Number codes

  local LNC={}
  LNC[0x7ff]="Without specific line location within the field or frame"
  LNC[0x7fe]="Line between 2nd line after RP 168 switch line to the last line before active video"
  LNC[0x7fd]="Line number larger than can be represented in 11 bits"

  -- Horizontal_Offset codes

  local HOC={}
  HOC[0xfff]="Without specific horizontal location"
  HOC[0xffe]="Horizontal ancillary data space (HANC)"
  HOC[0xffd]="Between SAV and EAV"
  HOC[0xffc]="Horizontal offset is larger than can be represented in 12 bits"

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
  DID_SDID[0x41][0x01]="Payload Identification, HANC space (S352)"
  DID_SDID[0x41][0x05]="AFD and Bar Data (S2016-3)"
  DID_SDID[0x41][0x06]="Pan-Scan Data (S2016-4)"
  DID_SDID[0x41][0x07]="ANSI/SCTE 104 messages (S2010)"
  DID_SDID[0x41][0x08]="DVB/SCTE VBI data (S2031)"
  DID_SDID[0x41][0x09]="MPEG TS packets in VANC (ST 2056)"
  DID_SDID[0x41][0x0A]="Stereoscopic 3D Frame Compatible Packing and Signaling (ST 2068)"
  DID_SDID[0x41][0x0B]="Lip Sync data (ST 2064)"
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

  -- Values for CDP Section IDs
  local CDP_Section_Type={}
  CDP_Section_Type[0x71]="TimeCode Section ID"
  CDP_Section_Type[0x72]="CC Data Section ID"
  CDP_Section_Type[0x73]="CC Service Information Section ID"
  CDP_Section_Type[0x71]="CC Footer Section ID"

  -- Values for CDP Closed Caption Data
  -- EIA 708B Data mapping into VANC space (S334-1)
  -- Values from https://en.wikipedia.org/wiki/CEA-708#Packets_in_CEA-708
  local CC_TYPE={}
  CC_TYPE[0xFC]="NTSC line 21 field 1 Closed Captions"    -- should be interpreted as EIA-608
  CC_TYPE[0xFD]="NTSC line 21 field 2 Closed Captions"    -- should be interpreted as EIA-608
  CC_TYPE[0xFE]="DTVCC Channel Packet Data"
  CC_TYPE[0xFF]="DTVCC Channel Packet Start"
  CC_TYPE[0xFA]="DTVCC Channel Packet Data Inactive"

  function st_2110_40.dissector(tvb, pinfo, tree)
    local subtree = tree:add(st_2110_40, tvb(),"ST 2110_40 Data")
    ---
    --- Read ANC RTP payload header
    ---
    subtree:add(F.ESN, tvb(0,2))
    subtree:add(F.Length, tvb(2,2))
    subtree:add(F.ANC_Count, tvb(4,1))
    local ANC_Count=tvb(4,1):uint()
    subtree:add(F.F,tvb(5,1))
    local Data_Count=0
    local offset=8
    local CS_offset=0
    local CS_length=2
    local DID
    local SDID
    local SDID_proto
    local Line_Number
    local LN_proto
    local Horiz_Offset
    local HO_proto
    ---
    --- Read ANC packets in payload
    ---
    for i=1,ANC_Count do
      subtree:add(F.C,tvb(offset,1))
      LN_proto=subtree:add(F.Line_Number,tvb(offset,2))
      Line_Number=tvb(offset,2):bitfield(1,11)
      if LNC[Line_Number] then
        LN_proto:append_text(":"..LNC[Line_Number])
      end
      HO_proto=subtree:add(F.HO,tvb(offset+1,2))
      Horiz_Offset=tvb(offset+1,2):bitfield(4,12)
      subtree:add(F.S,tvb(offset+3,1))
      subtree:add(F.StreamNum,tvb(offset+3,1))
      StreamNum=tvb(offset+2,1):bitfield(1,7)
      if HOC[Horiz_Offset] then
        HO_proto:append_text(":"..HOC[Horiz_Offset])
      end
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

      local data_Table=ByteArray.new()

      --
      -- User Data Words is an array of 10 bits words
      -- For each 10 bits words, 2 MSB bits (b8 and b9)
      -- are bits used to error detection.
      -- These bits won't be extracted in the byte Array.
      --
      local c=0
      local it=0
      local off=8
      data_Table:set_size(Data_Count)
      for i=0,UDW_length do
      if (i % 5 == 0) then
        c=tvb(offset+off+i,2):bitfield(0,8)
      elseif (i % 5 == 1) then
        c=tvb(offset+off+i,2):bitfield(2,8)
      elseif (i % 5 == 2) then
        c=tvb(offset+off+i,2):bitfield(4,8)
      elseif (i % 5 == 3) then
        c=tvb(offset+off+i,2):bitfield(6,8)
      elseif (i % 5 == 4 ) then
        -- do nothing, skip to next word
      else
        error("Problem")
      end
      if (it<Data_Count and (i % 5 ~= 4) ) then
        data_Table:set_index(it,c)
        it = it+1
      end
      end

      local ntvb=data_Table:tvb()
      local tree_data = subtree:add(tree,ntvb(), "User Data Words")

      --
      -- Parsing time code DID=0x60 and SDID=0x60
      -- Ancillary Time Code (S12M-2)
      -- https://www.itu.int/dms_pubrec/itu-r/rec/bt/R-REC-BT.1366-0-199802-S!!PDF-E.pdf
      -- The bits b4-b7 (4 MSB bits of the UDW) contains the timecode data
      -- VITC is contained in the b3 bit of each word (where b0 is the LSB bit)
      --

      if ( DID==0x60 and SDID==0x60 and Data_Count==16 ) then
        local time_Table=ByteArray.new()
        local vitc_Table=ByteArray.new()
        time_Table:set_size(Data_Count)
        vitc_Table:set_size(Data_Count)
        for x=0, Data_Count-1 do
          time=ntvb(x,1):bitfield(0,4)
          vitc=ntvb(x,1):bitfield(5,1)
          vitc_Table:set_index(x,vitc)
          time_Table:set_index(x,time)
        end

        -- Timecode format
        -- (UDW-15 & UDW-13)hours | (UDW-11 & UDW-9)minutes | (UDW-7 & UDW-5)seconds |
        -- (UDW-3 & UDW-1)frames
        local ttvb=time_Table:tvb()
        local timeStr = string.format("%d%dH:%d%dm:%d%ds:%d%dframes",
          ttvb(14,1):bitfield(6,2),
          ttvb(12,1):bitfield(4,4),
          ttvb(10,1):bitfield(5,3),
          ttvb(8,1):bitfield(4,4),
          ttvb(6,1):bitfield(5,3),
          ttvb(4,1):bitfield(4,4),
          ttvb(2,1):bitfield(6,2),
          ttvb(0,1):bitfield(4,4) )
        tree_data:add(F.TimeCode, timeStr)

        -- VITC format
        -- Distributed binary groups (DBB1 and DBB2) are formed by bit 3 of each UDW
        -- TODO: do a decoder, array of bits to uint8
        local vtvb=vitc_Table:tvb()
        local vitc_str=string.format("0x%d%d%d%d%d%d%d%d",
          vtvb(8,1):bitfield(7,1),
          vtvb(9,1):bitfield(7,1),
          vtvb(10,1):bitfield(7,1),
          vtvb(11,1):bitfield(7,1),
          vtvb(12,1):bitfield(7,1),
          vtvb(13,1):bitfield(7,1),
          vtvb(14,1):bitfield(7,1),
          vtvb(15,1):bitfield(7,1) )
        tree_data:add(F.VITC, vitc_str)
              --
      -- Parsing EIA 708B Data mapping into VANC space (S334-1)
      -- DID=0x61 and SDID=0x01
      -- Documentation followed from https://en.wikipedia.org/wiki/CEA-708#Packets_in_CEA-708
      -- 
      elseif ( DID == 0x61 and SDID == 0x01 ) then
        tree_data:add(F.Magic,ntvb(0,2))
        tree_data:add(F.DataWord_Count, ntvb(2,1))
        tree_data:add(F.Frame_Rate, ntvb(3,1))
        tree_data:add(F.CCDataSection,ntvb(7,1))
        tree_data:add(F.CCDataCount, ntvb(8,1):bitfield(3,5))

        local CDPsection=ntvb(7,1):bitfield(0,8)
        section=tree_data:add(F.CDP_Section_Type, CDPsection)
        if CDP_Section_Type[CDPsection] then
          section:append_text(":"..CDP_Section_Type[CDPsection])
        end

        if CDPsection == 0x72 then
          local dataSection_Count = ntvb(8,1):bitfield(3,5)
          local n=0
          local CDP_CC_Type = 0
          local CC_type_str
          local value = 0
          local buffer_size=0

          --
          -- Parsing DTVCC packet (CC_data_pkt) inside user_data_type_structure
          -- CC_data_pkt (24bits): Type[1 byte] - Pkt_Data[2 bytes]
          --
          local data_CC1=ByteArray.new()
          local data_CC2=ByteArray.new()
          data_CC1:set_size(dataSection_Count)
          data_CC2:set_size(dataSection_Count)

          for c=1, dataSection_Count do
            -- parsing CC_Data type
            -- TODO: maybe take the 2 LSB bits
            CDP_CC_Type=ntvb(9+n,1):bitfield(0,8)
            CC_type_str=tree_data:add(F.CCType, CDP_CC_Type)
            if CC_TYPE[CDP_CC_Type] then
              CC_type_str:append_text(": "..CC_TYPE[CDP_CC_Type])
            end
            value=ntvb(9+n+1,2)
            tree_data:add(F.CCValue,value)

            -- Fill the Packet_Data_Structure
            -- Value: cc_data1[1byte] - cc_data_2[1byte]
            -- Service 1 is designated as the Primary Caption Service
            -- Service 2 is the Secondary Language Service
            if CDP_CC_Type == 0xFE then
              data_CC1:set_index(buffer_size, ntvb(9+n+1,1):bitfield(0,8))
              data_CC2:set_index(buffer_size, ntvb(9+n+2,1):bitfield(0,8))
              buffer_size=buffer_size+1
            end
            n = n+3
          end

          data_CC1:set_size(buffer_size)
          data_CC2:set_size(buffer_size)

          -- Print both Pkt_Data_Structure
          -- TODO: find a way to print UTF8-ascii
          if buffer_size~=0 then
            str1 = tostring(data_CC1,ENC_UTF8)
            tree_data:add(F.CCData1, str1)
            str2 = tostring(data_CC2,ENC_UTF8)
            tree_data:add(F.CCData2, str2)
          end

          --
          -- Parsing Service Block Packet (packet_data)
          --
          local service_nb=0
          local block_size=0
          local null_fill=0
          local extended_service_nb=0
          local block_data=ByteArray.new()

          local btvb=data_CC1:tvb()
          local b = 1
          while (b < 3) do

            local block_tree = subtree:add(tree,btvb(),string.format("Service Block Packet %d",b))
            block_tree:add(F.CCServiceNb,btvb(0,1):bitfield(0,3))
            block_size=btvb(0,1):bitfield(3,5)
            block_tree:add(F.CCBlockSize,block_size)
            block_data:set_size(block_size)
            for n=0, block_size-1 do
              block_data:set_index(n,btvb(2+n,1):bitfield(0,8))
            end

            if block_size~=0 then
              str=tostring(block_data,ENC_UTF8)
              block_tree:add(F.CCBlockData,str)
            end

            -- switch to the next block data
            btvb=data_CC2:tvb()
            b=b+1
          end
        end     -- end if CDPSection = 0x72
      end       -- end if

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
      ---
      --- C,Line_Number,Horizontal_Offset,reserved,DID,SDID,Data_Count,Checksum_Word=72
      --- determine offset to next ANC packet, including Word_Align to 32 bit boundary
      ---
      offset=offset+(math.ceil((72+(Data_Count*10))/32)*4)
    end       -- end while
  end         -- end function

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

