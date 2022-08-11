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
  F.UDW=ProtoField.bytes("st_2110_40.UDW","UDW Bytes", base.SPACE)
  F.UDW_array=ProtoField.bytes("st_2110_40.UDW_array","UDW Array", base.SPACE)
  F.Checksum=ProtoField.uint16("st_2110_40.Checksum","Checksum Word",base.HEX,nil)
  F.Checksum_Calc=ProtoField.uint16("st_2110_40.Checksum_Calculated","Calculated Checksum",base.HEX,nil)

-- User Data Structure

  F.Magic=ProtoField.uint16("st_2110_40.Data.Magic","MagicHeader", base.HEX,nil)
  F.DataWord_Count=ProtoField.uint8("st_2110_40.Data.DW_Count","Data Count", base.DEC,nil)
  F.Frame_Rate=ProtoField.uint8("st_2110_40.Data.FrameRate","Frame Rate", base.HEX,nil)
  F.Section_Available=ProtoField.uint8("st_2110_40.Data.Section_Available","Section available", base.HEX,nil,0xFF)
  F.CDP_Section_Type=ProtoField.uint8("st_2110_40.Data.Section_Type","CDP Section Type", base.HEX,nil)
  F.CDP_Seq_Counter=ProtoField.uint16("st_2110_40.Data.CDP_Seq_Counter","CDP Sequence Counter", base.HEX,nil)

  -- VBI data
  -- Spec: EN 301 775 - V1.2.1
  local PES_DATA_ID = {}
  for i=0,255 do
    if (i >= 0x10 and i <= 0x1F or i >= 0x99 and i <= 0x9B) then PES_DATA_ID[i] =  "EBU Teletext/VPS/WSS/CC/VBI sample data"
    elseif (i >= 0x80 and i <= 0x98 or i >= 0x9C and i <= 0xFF) then PES_DATA_ID[i] = "User defined"
    else PES_DATA_ID[i] = "Reserved for future use"
    end
  end
  F.Data_Identifier=ProtoField.uint8("st_2110_40.Data.Data_Identifier", "Data Identifier", base.HEX, PES_DATA_ID)

  -- Spec: ST2031-2007
  local PES_DATA_UNIT_ID = {}
  for i=0,255 do
    if (i == 0x00 or i == 0x01) then PES_DATA_UNIT_ID[i] = "DVB reserved"
    elseif (i == 0x02) then PES_DATA_UNIT_ID[i] = "EBU Teletext non-subtitle data"
    elseif (i == 0x03) then PES_DATA_UNIT_ID[i] = "EBU Teletext subtitle data"
    elseif (i >= 0x04 or i <= 0x7F) then PES_DATA_UNIT_ID[i] = "DVB reserved"
    elseif (i >= 0x80 or i <= 0xBF) then PES_DATA_UNIT_ID[i] = "User defined"
    elseif (i == 0xC0) then PES_DATA_UNIT_ID[i] = "Inverted Teletext"
    elseif (i == 0xC1 or i == 0xC2) then PES_DATA_UNIT_ID[i] = "DVB reserved"
    elseif (i == 0xC3) then PES_DATA_UNIT_ID[i] = "VPS"
    elseif (i == 0xC4) then PES_DATA_UNIT_ID[i] = "WSS"
    elseif (i == 0xC5) then PES_DATA_UNIT_ID[i] = "CEA-608 Closed Captioning"
    elseif (i == 0xC6) then PES_DATA_UNIT_ID[i] = "monochrome 4:2:2 samples"
    elseif (i >= 0xC7 or i <= 0xCF) then PES_DATA_UNIT_ID[i] = "User defined"
    elseif (i == 0xD0) then PES_DATA_UNIT_ID[i] = "AMOL48"
    elseif (i == 0xD1) then PES_DATA_UNIT_ID[i] = "AMOL96"
    elseif (i == 0xD2 or i >= 0xDA and i <= 0xE5) then PES_DATA_UNIT_ID[i] = "SCTE reserved"
    elseif (i == 0xD3 or i == 0xD4 or i == 0xD8) then PES_DATA_UNIT_ID[i] = "Protected"
    elseif (i == 0xD5) then PES_DATA_UNIT_ID[i] = "NABTS"
    elseif (i == 0xD6) then PES_DATA_UNIT_ID[i] = "TVG2X"
    elseif (i == 0xD7) then PES_DATA_UNIT_ID[i] = "Copy Protection"
    elseif (i == 0xD9) then PES_DATA_UNIT_ID[i] = "VITC"
    elseif (i >= 0xE6 and i <= 0xFE) then PES_DATA_UNIT_ID[i] = "SCTE USer defined"
    elseif (i == 0xFF) then PES_DATA_UNIT_ID[i] = "MPEG stuffing"
    else PES_DATA_UNIT_ID[i] = "Reserved or user defined"
    end 
  end
  F.Data_UnitId=ProtoField.uint8("st_2110_40.Data.Data_UnitId", "Data Unit Id", base.HEX, PES_DATA_UNIT_ID)
  F.Data_UnitLength=ProtoField.uint8("st_2110_40.Data.Data_UnitLength", "Data Unit Length", base.DEC)

  -- Spec: ST RDD 08, aka OP-47 Subtitle Distribution Packet
  F.SDP_Identifier = ProtoField.uint16("st_2210_40.Data.SDP_Identifier", "Identifier", base.HEX)
  F.SDP_Length = ProtoField.uint8("st_2210_40.Data.SDP_Length", "Length", base.HEX)
  F.SDP_FormatCode = ProtoField.uint8("st_2210_40.Data.SDP_FormatCode", "Format Code", base.HEX)
  F.SDP_AdaptionHeader = ProtoField.bytes("st_2110_40.Data.SDP_AdaptionHeader","Adaption Header", base.SPACE)
  F.SDP_PktDescB = ProtoField.bytes("st_2110_40.Data.SDP_PktDescB","Packet Descriptor B", base.SPACE)

  -- Spec: EN 300 472
  F.Field_Parity = ProtoField.bool("st_2110_40.Data.Field_Parity", "Field Parity", 8, {"First field of a frame", "Second field of a frame"}, 0x20)
  F.Line_Offset = ProtoField.uint8("st_2110_40.Data.Line_Offset", "Line Offset", base.DEC, nil, 0x1F)

  -- Spec: EN 300 706
  F.Clock_RunIn = ProtoField.uint16("st_2110_40.Data.Clock_RunIn","Clock Run-In", base.HEX, nil, 0XFFFF)
  F.Framing_Code = ProtoField.uint8("st_2110_40.Data.Framing_Code", "Framing Code", base.HEX, nil, 0xFF)
  F.Magazine_Hamming = ProtoField.uint16("st_2110_40.Data.Magazine_Hamming", "Magazine (Hamming 8/4)", base.DEC, nil, 0xFC00)
  F.Magazine = ProtoField.uint8("st_2110_40.Data.Magazine", "Magazine", base.DEC, nil)
  F.PacketNumber_Hamming = ProtoField.uint16("st_2110_40.Data.PacketNumber_Hamming", "Packet Number (Hamming 8/4)", base.DEC, nil, 0x3FF)
  F.PacketNumber = ProtoField.uint8("st_2110_40.Data.PacketNumber", "Packet Number", base.DEC, nil)
  F.PageUnits_Hamming = ProtoField.uint8("st_2110_40.Data.PageUnits_Hamming", "Page Units (Hamming 8/4)", base.HEX, nil, 0xFF)
  F.PageUnits = ProtoField.uint8("st_2110_40.Data.PageUnits", "Page Units", base.HEX, nil)

  F.PageTens_Hamming = ProtoField.uint8("st_2110_40.Data.PageTens_Hamming", "Page Tens (Hamming 8/4)", base.HEX, nil, 0xFF)
  F.PageTens = ProtoField.uint8("st_2110_40.Data.PageTens", "Page Tens", base.HEX, nil)

  F.DataString = ProtoField.string("st_2110_40.Data.Data_String", "Data String")
  F.TextData_Array = ProtoField.bytes("st_2110_40.Data.Textdata","Text Data", base.SPACE)

  local NATIONAL_SUBSET = {
    [0] = "English",
    [1] = "German",
    [4] = "Swedish/Finnish/Hungarian",
    [5] = "Italian",
    [0x10] = "French",
    [0x11] = "Portuguese/Spanish",
    [0x14] = "Czech/Slovak"
  }
  F.ErasePage = ProtoField.bool("st_2110_40.Data.ErasePage", "Erase Page", 8, nil, 0x01)
  F.Newsflash = ProtoField.bool("st_2110_40.Data.Newsflash", "Newsflash", 8, nil, 0x04)
  F.Subtitle = ProtoField.bool("st_2110_40.Data.Subtitle", "Subtitle", 8, {"Subtitle", "Non-subtitle"}, 0x01)
  F.SuppressHeader = ProtoField.bool("st_2110_40.Data.SuppressHeader", "Suppress Header", 8, nil, 0x40)
  F.UpdateIndicator = ProtoField.bool("st_2110_40.Data.UpdateIndicator", "Update Indicator", 8, nil, 0x10)
  F.InterruptedSequence = ProtoField.bool("st_2110_40.Data.InterruptedSequence", "Interrupted Sequence", 8, nil, 0x04)
  F.InhibitDisplay = ProtoField.bool("st_2110_40.Data.InhibitDisplay", "Inhibit Display", 8, nil, 0x01)
  F.MagazineSerial = ProtoField.bool("st_2110_40.Data.MagazineSerial", "MagazineSerial", 8, {"Serial Mode", "Parallel Mode"}, 0x40)
  F.CharacterSet = ProtoField.uint8("st_2110_40.Data.CharacterSet", "Character Subset", base.DEC, NATIONAL_SUBSET, 0x15)

  -- Ancillary Time Code (S12M-2)
  local ANC_DBB1={}
  for i=0,255 do
    if     (i == 0x00) then ANC_DBB1[i]="Linear time code (ATC_LTC)"
    elseif (i == 0x01) then ANC_DBB1[i]="Vertical interval time code #1 (ATC_VITC1)"
    elseif (i == 0x02) then ANC_DBB1[i]="Vertical interval time code #2 (ATC_VITC2)"
    elseif (i <= 0x05) then ANC_DBB1[i]="User defined"
    elseif (i == 0x06) then ANC_DBB1[i]="Film data block (transferred from reader)"
    elseif (i == 0x07) then ANC_DBB1[i]="Production data block (transferred from reader)"
    elseif (i <= 0x7C) then ANC_DBB1[i]="Locally generated time address and user data (user defined)"
    elseif (i == 0x7D) then ANC_DBB1[i]="Video tape data block (locally generated)"
    elseif (i == 0x7E) then ANC_DBB1[i]="Film data block (locally generated)"
    elseif (i == 0x7F) then ANC_DBB1[i]="Production data block (locally generated)"
    else                    ANC_DBB1[i]="Reserved"
    end
  end

  F.TimeCode=ProtoField.string("st_2110_40.Data.TimeCode","TimeCode")
  F.TimeCodePT=ProtoField.uint8("st_2110_40.Data.TimeCodePT","Payload Type", base.HEX, ANC_DBB1)
  F.TimeCodeVITC=ProtoField.uint8("st_2110_40.Data.TimeCodeVITC","VITC Data", base.HEX, nil)
  F.TimeCodeVitcLineSel=ProtoField.uint8("st_2110_40.Data.TimeCodeVITC.LineSel","Line Select", base.DEC, nil, 0x1F)
  F.TimeCodeVitcLineDup=ProtoField.uint8("st_2110_40.Data.TimeCodeVITC.LineDup","Duplication", base.BOOL, nil, 0x20)
  local VITC_VLD = {[0] = "No time code error received or locally generated time code address",
                    [1] = "Transmitted time code interpolated from previous time code (received a time code error)"}
  F.TimeCodeVitcValidity=ProtoField.uint8("st_2110_40.Data.TimeCodeVITC.Validity","TC Validity", base.DEC, VITC_VLD, 0x40)
  local VITC_PROC = {[0] = "Binary groups in time code data stream are processed to compensate for latency",
                     [1] = "Binary groups in time code data stream are only retransmitted (no delay compensation)"}
  F.TimeCodeVitcProcess=ProtoField.uint8("st_2110_40.Data.TimeCodeVITC.Process","Process bit", base.DEC, VITC_PROC, 0x80)

  -- EIA 708B Data mapping into VANC space (S334-1)

  F.CCDataSection=ProtoField.uint8("st_2110_40.Data.CCDataSection","CC Data Section", base.HEX,nil)
  F.CCDataCount=ProtoField.uint8("st_2110_40.Data.CCDataCount","CC Data Count", base.DEC,nil)
  F.CCType=ProtoField.uint8("st_2110_40.Data.CCType","CC Data Type", base.HEX,nil)
  F.CCValue=ProtoField.uint16("st_2110_40.Data.CCValue","CC Data Value", base.HEX,nil)
  F.CCData=ProtoField.string("st_2110_40.Data.CCData","CC Data Extracted", base.UNICODE)

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
  DID_SDID[0x43][0x02]="Subtitling Distribution packet (SDP) (RDD 8, aka OP-47)"
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

  -- Array of bit-flipped byte values used in processing OP-47 payloads:
  local ReverseByte = {
    0x00,0x80,0x40,0xc0,0x20,0xa0,0x60,0xe0,0x10,0x90,0x50,0xd0,0x30,0xb0,0x70,0xf0,
    0x08,0x88,0x48,0xc8,0x28,0xa8,0x68,0xe8,0x18,0x98,0x58,0xd8,0x38,0xb8,0x78,0xf8,
    0x04,0x84,0x44,0xc4,0x24,0xa4,0x64,0xe4,0x14,0x94,0x54,0xd4,0x34,0xb4,0x74,0xf4,
    0x0c,0x8c,0x4c,0xcc,0x2c,0xac,0x6c,0xec,0x1c,0x9c,0x5c,0xdc,0x3c,0xbc,0x7c,0xfc,
    0x02,0x82,0x42,0xc2,0x22,0xa2,0x62,0xe2,0x12,0x92,0x52,0xd2,0x32,0xb2,0x72,0xf2,
    0x0a,0x8a,0x4a,0xca,0x2a,0xaa,0x6a,0xea,0x1a,0x9a,0x5a,0xda,0x3a,0xba,0x7a,0xfa,
    0x06,0x86,0x46,0xc6,0x26,0xa6,0x66,0xe6,0x16,0x96,0x56,0xd6,0x36,0xb6,0x76,0xf6,
    0x0e,0x8e,0x4e,0xce,0x2e,0xae,0x6e,0xee,0x1e,0x9e,0x5e,0xde,0x3e,0xbe,0x7e,0xfe,
    0x01,0x81,0x41,0xc1,0x21,0xa1,0x61,0xe1,0x11,0x91,0x51,0xd1,0x31,0xb1,0x71,0xf1,
    0x09,0x89,0x49,0xc9,0x29,0xa9,0x69,0xe9,0x19,0x99,0x59,0xd9,0x39,0xb9,0x79,0xf9,
    0x05,0x85,0x45,0xc5,0x25,0xa5,0x65,0xe5,0x15,0x95,0x55,0xd5,0x35,0xb5,0x75,0xf5,
    0x0d,0x8d,0x4d,0xcd,0x2d,0xad,0x6d,0xed,0x1d,0x9d,0x5d,0xdd,0x3d,0xbd,0x7d,0xfd,
    0x03,0x83,0x43,0xc3,0x23,0xa3,0x63,0xe3,0x13,0x93,0x53,0xd3,0x33,0xb3,0x73,0xf3,
    0x0b,0x8b,0x4b,0xcb,0x2b,0xab,0x6b,0xeb,0x1b,0x9b,0x5b,0xdb,0x3b,0xbb,0x7b,0xfb,
    0x07,0x87,0x47,0xc7,0x27,0xa7,0x67,0xe7,0x17,0x97,0x57,0xd7,0x37,0xb7,0x77,0xf7,
    0x0f,0x8f,0x4f,0xcf,0x2f,0xaf,0x6f,0xef,0x1f,0x9f,0x5f,0xdf,0x3f,0xbf,0x7f,0xff
  }

  -- 
  -- ProcessWstPacket()
  --
  --  parameters:
  --  o inBuf   - Assumed to a be buffer of 42 bytes of WST information, starting
  --              with the MRAG (Magazine and Row Address Group).  Bits in the
  --              payload bytes are assumed to be in VBI transmission order.
  --  o subtree - dissection tree that display items should be added to.
  --
  -- Routine to process World System Teletext packets, and add results to the given
  -- dissection tree.
  --
  function ProcessWstPacket(inBuf, subtree)
    local packet_address_tvb = inBuf(0, 2)

    -- extract Magazine number
    subtree:add(F.Magazine_Hamming, packet_address_tvb)
    local magazine =  packet_address_tvb:bitfield(1,1) +
                    2*packet_address_tvb:bitfield(3,1) +
                    4*packet_address_tvb:bitfield(5,1)

    -- Reference: ETSI EN 300 706 v1.2.1, 3.1 Definitions
    -- "magazine number 8:" and "page number: M Pt Pu"
    if (magazine == 0) then
        magazine = 8
    end

    subtree:add(F.Magazine, magazine):set_generated()

    -- extract Packet number
    subtree:add(F.PacketNumber_Hamming, packet_address_tvb)
    local packet_number =    packet_address_tvb:bitfield( 7,1) +
                           2*packet_address_tvb:bitfield( 9,1) +
                           4*packet_address_tvb:bitfield(11,1) +
                           8*packet_address_tvb:bitfield(13,1) +
                          16*packet_address_tvb:bitfield(15,1)
    subtree:add(F.PacketNumber, packet_number):set_generated()
    local data_start_offset = 0
    local number_of_data_bytes = 0

    -- Packet number 0 is a Page Header
    if (packet_number == 0) then
      data_start_offset = 10
      number_of_data_bytes = 32
      -- Extracting Page Units and Page Tens
      local page_units_hamming = inBuf(2, 1)
      local page_units =  page_units_hamming:bitfield(1,1) +
                        2*page_units_hamming:bitfield(3,1) +
                        4*page_units_hamming:bitfield(5,1) +
                        8*page_units_hamming:bitfield(7,1)

      local page_tens_hamming = inBuf(3, 1)
      local page_tens =   page_tens_hamming:bitfield(1,1) +
                        2*page_tens_hamming:bitfield(3,1) +
                        4*page_tens_hamming:bitfield(5,1) +
                        8*page_tens_hamming:bitfield(7,1)
      subtree:add(F.PageUnits_Hamming, page_units_hamming)
      subtree:add(F.PageTens_Hamming, page_tens_hamming)
      subtree:add(F.PageUnits, page_units):set_generated()
      subtree:add(F.PageTens, page_tens):set_generated()

      local ttPage = bit32.bor(
          bit32.lshift(magazine, 8), bit32.lshift(page_tens, 4), page_units)
      subtree:add("Control bits for TT Page " .. string.format("0x%x", ttPage) .. ":")

      -- Control bytes
      subtree:add(F.ErasePage,           inBuf(5,1))
      subtree:add(F.Newsflash,           inBuf(7,1))
      subtree:add(F.Subtitle,            inBuf(7,1))
      subtree:add(F.SuppressHeader,      inBuf(8,1))
      subtree:add(F.UpdateIndicator,     inBuf(8,1))
      subtree:add(F.InterruptedSequence, inBuf(8,1))
      subtree:add(F.InhibitDisplay,      inBuf(8,1))
      subtree:add(F.MagazineSerial,      inBuf(9,1))
      subtree:add(F.CharacterSet,        inBuf(9,1))

    -- packet numbers between 1 and 25 contain data
    elseif (packet_number >= 1 and packet_number <=25) then
      data_start_offset = 2
      number_of_data_bytes = 40
    end

    local text_data=ByteArray.new()
    text_data:set_size(number_of_data_bytes)

    -- Reference: ETSI EN 300 706, section 9.3.1.4 and 9.3.2
    local data_string = ""
    for data_index=0,number_of_data_bytes-1 do
      -- Getting rid of parity bit
      local data_byte = inBuf(data_start_offset + data_index, 1)
      local data_char =    data_byte:bitfield(0,1) +
                         2*data_byte:bitfield(1,1) +
                         4*data_byte:bitfield(2,1) +
                         8*data_byte:bitfield(3,1) +
                        16*data_byte:bitfield(4,1) +
                        32*data_byte:bitfield(5,1) +
                        64*data_byte:bitfield(6,1)
      text_data:set_index(data_index, data_char)
      data_string = data_string .. string.char(data_char)
    end

    subtree:add(F.DataString, data_string):set_generated()
    local textdata_tvb=ByteArray.tvb(text_data, "Text data")
    local text_data_tree = subtree:add(F.TextData_Array, textdata_tvb())
    text_data_tree:set_generated()
  end -- function ProcessWstPacket()

dprint = function(...)
    print(table.concat({"Lua:", ...}," "))
end

  function st_2110_40.dissector(tvb, pinfo, tree)
    local length = tvb(2,2):uint() + 8 -- ST2110-40 header not included in length
    local datatree = tree:add(st_2110_40, tvb(0,length),"ST 2110_40 Data")
    ---
    --- Read ANC RTP payload header
    ---
    datatree:add(F.ESN, tvb(0,2))
    datatree:add(F.Length, tvb(2,2))
    datatree:add(F.ANC_Count, tvb(4,1))
    local ANC_Count=tvb(4,1):uint()
    datatree:add(F.F,tvb(5,1))
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

      ---
      --- C,Line_Number,Horizontal_Offset,reserved,DID,SDID,Data_Count,Checksum_Word=72
      --- determine offset to next ANC packet, including Word_Align to 32 bit boundary
      ---
      local Data_Count = tvb(offset+6,2):bitfield(6,8)
      local PacketLen_Bytes = (math.ceil((72+(Data_Count*10))/32)*4)
      local subtree = datatree:add(tvb(offset, PacketLen_Bytes), string.format("Packet %d", i))

      subtree:add(F.C,tvb(offset,1))
      LN_proto=subtree:add(F.Line_Number,tvb(offset,2))
      Line_Number=tvb(offset,2):bitfield(1,11)
      if LNC[Line_Number] then
        LN_proto:append_text(": "..LNC[Line_Number])
      end
      HO_proto=subtree:add(F.HO,tvb(offset+1,2))
      Horiz_Offset=tvb(offset+1,2):bitfield(4,12)
      subtree:add(F.S,tvb(offset+3,1))
      subtree:add(F.StreamNum,tvb(offset+3,1))
      StreamNum=tvb(offset+2,1):bitfield(1,7)
      if HOC[Horiz_Offset] then
        HO_proto:append_text(": "..HOC[Horiz_Offset])
      end
      subtree:add(F.DID,tvb(offset+4,2))
      DID=tvb(offset+4,2):bitfield(2,8)
      SDID_proto=subtree:add(F.SDID,tvb(offset+5,2))
      SDID=tvb(offset+5,2):bitfield(4,8)
      subtree:append_text(string.format(": DID 0x%02x, SDID 0x%02x", DID, SDID))

      if DID_SDID[DID] and not DID_SDID[DID][SDID] then
        subtree:append_text(": "..DID_SDID[DID])
        SDID_proto:append_text(": "..DID_SDID[DID])
      end
      if DID_SDID[DID] and DID_SDID[DID][SDID] then
        subtree:append_text(": "..DID_SDID[DID][SDID])
        SDID_proto:append_text(": "..DID_SDID[DID][SDID])
      end
      subtree:add(F.Data_Count,tvb(offset+6,2))

      -- the calculation of the UDW length includes math.floor
      -- to round the numer to the smaller or equal
      local UDW_length=1+math.floor(((Data_Count*10)-2)/8)

      -- Highlight the raw UDW bytes in the data display. This includes bytes
      -- which overlap with the Data_Count and checksum word.
      if (((Data_Count*10)-2) % 8) then
        subtree:add(F.UDW,tvb(offset+7,UDW_length+1))
      else
        subtree:add(F.UDW,tvb(offset+7,UDW_length))
      end


      -- Extract the user data words from the payload.
      -- User Data Words is an array of 10 bits words
      -- For each 10 bits words, 2 MSB bits (b8 and b9)
      -- are bits used to error detection.
      -- These bits won't be extracted in the byte Array,
      -- but we extract b8 to include it in the checksum.

      local data_Table=ByteArray.new()
      data_Table:set_size(Data_Count)

      -- Initialise checksum with 9 LSBs of DID, SDID, Data_Count
      local cs_calc = tvb(offset+4,2):bitfield(1,9) + -- DID
                      tvb(offset+5,2):bitfield(3,9) + -- SDID
                      tvb(offset+6,2):bitfield(5,9)   -- Data_Count
      local dw_off=offset+7
      local dw_rem=6

      for i=0,Data_Count-1 do
        local v
        -- +1 here to ignore the MSB (b9)
        v=tvb(dw_off,2):bitfield(dw_rem+1,9)

        -- Checksum includes sum of bits 8:0 of all UDWs
        cs_calc=cs_calc+v
        -- UDW table contains the 8 LSBs of each UDW
        data_Table:set_index(i,(v % 256))

        if (dw_rem == 6) then
          -- Data word ends on byte boundary, no overlap with next UDW
          dw_off=dw_off+2
          dw_rem=0
        else
          dw_off=dw_off+1
          dw_rem=dw_rem+2
        end
      end


      -- Extract the checksum value (immediately after the last UDW)
      local cs_received=tvb(dw_off,2):bitfield(dw_rem,10)
      local cs_item=subtree:add(F.Checksum,tvb(dw_off,2),cs_received,string.format("Checksum Word: 0x%03x", cs_received))


      -- Finish the checksum calculation and attach the result to the received checksum.
      -- Checksum value is sum[8:0], b9= ~b8
      cs_calc=(cs_calc % 0x200) -- wrap at 9 LSBs
      if (math.floor(cs_calc / 0x100) == 0) then
        cs_calc=cs_calc+0x200
      end
      cs_item:add(F.Checksum_Calc, cs_calc, string.format("Calculated Checksum: 0x%03x", cs_calc)):set_generated()

      -- Add warning if checksum validation failed
      if cs_received ~= cs_calc then
        -- Invalid payload checksum
        cs_item:add_expert_info(PI_CHECKSUM,PI_WARN,"The calculated ANC checksum and ANC checksum word do not match.")
      end


      -- Add the decoded UDW array to the dissector output
      local ntvb=ByteArray.tvb(data_Table, "UDW Array")
      local tree_data = subtree:add(F.UDW_array, ntvb())
      tree_data:set_generated()



      --
      -- Protocol specific decodes below this point
      ----------------------------------------------

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
        local ttvb=ByteArray.tvb(time_Table, "TimeCode")
        local timeStr = string.format("%d%dH:%d%dm:%d%ds:%d%dframes",
          ttvb(14,1):bitfield(6,2),
          ttvb(12,1):bitfield(4,4),
          ttvb(10,1):bitfield(5,3),
          ttvb(8,1):bitfield(4,4),
          ttvb(6,1):bitfield(5,3),
          ttvb(4,1):bitfield(4,4),
          ttvb(2,1):bitfield(6,2),
          ttvb(0,1):bitfield(4,4) )
        tree_data:add(F.TimeCode, ttvb(), timeStr):set_generated()


        -- Decode DBB1 (payload type) and DBB2 (VITC status) fields
        local dbb1=0
        local dbb2=0
        for x=0, (Data_Count/2)-1 do
          -- Poor man's ((value<<1) | LSB), Lua doesn't seem to do bitwise operators...
          -- UDW1 b3 contains LSB, UDW8 b3 contains MSB (similarly for UDW 9-16).
          -- NOTE: Wireshark Bitfields have MSB=b0, so UDW b3 = Wireshark b4
          dbb1=(dbb1 * 2) + ntvb(7-x,1):bitfield(4,1)
          dbb2=(dbb2 * 2) + ntvb(15-x,1):bitfield(4,1)
        end

        -- We display DBB1 as the payload type
        tree_data:add(F.TimeCodePT, dbb1):set_generated()

        -- Display the DBB2 data next, even if it isn't VITC (probably zero)
        local tree_dbb2 = tree_data:add(F.TimeCodeVITC, dbb2):set_generated()

        -- Decode DBB2 (VITC) details when DBB1 == VITC
        if (dbb1 == 0x01 or dbb1 == 0x02) then
          tree_dbb2:add(F.TimeCodeVitcLineSel, dbb2):set_generated()
          tree_dbb2:add(F.TimeCodeVitcLineDup, dbb2):set_generated()
          tree_dbb2:add(F.TimeCodeVitcValidity, dbb2):set_generated()
          tree_dbb2:add(F.TimeCodeVitcProcess, dbb2):set_generated()
        end
      -- End of timecode format parsing

      --
      -- Parsing EIA 708B Data mapping into VANC space (S334-1)
      -- DID=0x61 and SDID=0x01
      -- Documentation followed from https://en.wikipedia.org/wiki/CEA-708#Packets_in_CEA-708
      --
      elseif ( DID == 0x61 and SDID == 0x01 ) then
        --
        -- CDP Header Syntax
        -- Magic[2bytes] = 0x9669 | CDP Length [1bytes] | Frame Rate[1bytes]
        -- Sections available [1byte] | Counter[2bytes] | Sections ...
        --
        tree_data:add(F.Magic,ntvb(0,2))
        CDP_size = ntvb(2,1):bitfield(0,8)
        tree_data:add(F.DataWord_Count, CDP_size)
        tree_data:add(F.Frame_Rate, ntvb(3,1):bitfield(0,4))
        tree_data:add(F.Section_Available, ntvb(4,1))
        tree_data:add(F.CDP_Seq_Counter, ntvb(5,2))

        local s=7
        while s < CDP_size do

          local CDPsection=ntvb(s,1):bitfield(0,8)
          section=tree_data:add(F.CDP_Section_Type, CDPsection)
          if CDP_Section_Type[CDPsection] then
            section:append_text(":"..CDP_Section_Type[CDPsection])
          end

          -- Parsing CDP CC Service Information
          if CDPsection == 0x73 then
            tree_data:add(F.CCDataCount, ntvb(s+1,1):bitfield(4,4))
            s=s+16
          -- Parsing CDP Footer Section
          elseif CDPsection == 0x74 then
            -- FooterSequence Counter (16bits)
            -- Packet Checksum (8bits)
            s=s+4
          elseif CDPsection == 0x71 then
            timeStr = string.format("%d%dH:%d%dm:%d%ds:%d%dframes",
              ntvb(s+1,1):bitfield(2,2),
              ntvb(s+1,1):bitfield(4,4),
              ntvb(s+2,1):bitfield(1,3),
              ntvb(s+2,1):bitfield(4,4),
              ntvb(s+3,1):bitfield(1,3),
              ntvb(s+3,1):bitfield(4,4),
              ntvb(s+4,1):bitfield(2,2),
              ntvb(s+4,1):bitfield(4,4) )
            tree_data:add(F.TimeCode, timeStr)
            s=s+4
          -- Parsing CC Data Section
          elseif CDPsection == 0x72 then
            local dataSection_Count = ntvb(s+1,1):bitfield(3,5)
            tree_data:add(F.CCDataCount, dataSection_Count)
            local n=0
            local CDP_CC_Type = 0
            local CC_type_str
            local value = 0
            local buffer_size=0

            local cdp_offset=s+2
            s=s+2   -- section type + section count
            dSize=dataSection_Count*3
            s=s+dSize

            --
            -- Parsing DTVCC packet (CC_data_pkt) inside user_data_type_structure
            -- CC_data_pkt (24bits): Type[1 byte] - Pkt_Data[2 bytes]
            --
            -- Initialize the array at each packet
            -- with the dataSection Count
            -- after the loop the length will be refitted
            local CC_concat = ByteArray.new()
            CC_concat:set_size(dataSection_Count*2)

            for c=1, dataSection_Count do

              -- parsing CC_Data type
              -- TODO: maybe take the 2 LSB bits
              CDP_CC_Type=ntvb(cdp_offset+n,1):bitfield(0,8)
              CC_type_str=tree_data:add(F.CCType, CDP_CC_Type)
              if CC_TYPE[CDP_CC_Type] then
                CC_type_str:append_text(": "..CC_TYPE[CDP_CC_Type])
              end
              value=ntvb(cdp_offset+n+1,2)
              tree_data:add(F.CCValue,value)

              -- The first CDP_CC_Type is the service designated
              if c==1 then
                serviceNb=CDP_CC_Type
              end

              -- Fill the Packet_Data_Structure
              -- Value: cc_data1[1byte] - cc_data_2[1byte]
              -- Service 1 is designated as the Primary Caption Service
              -- Service 2 is the Secondary Language Service
              -- We collect only data from the first service (serviceNb==0xfc)
              if CDP_CC_Type == 0xFE and serviceNb == 0xFC then
                CC_concat:set_index(buffer_size*2, ntvb(cdp_offset+n+1,1):bitfield(0,8))
                CC_concat:set_index(buffer_size*2+1, ntvb(cdp_offset+n+2,1):bitfield(0,8))
                buffer_size=buffer_size+1
              end
              n=n+3
            end

            if ( buffer_size > 1 ) then

              if CC_concat:get_index(0)==0x0D
                and CC_concat:get_index(1)==0x90
                and CC_concat:get_index(4)==0x91 then
                -- do nothing
                -- 0x0D is a code control
                -- 0x90 is a "Set Pen Attribute" code
                -- 0x91 is "Set Pen Color" code
                CC_concat:set_size(0)

              -- If the frame contains these caption commands, they are "DefineWindow0-7" command
              -- This command creates one of the eight windows used by the caption decoder.
              -- The command is followed by 6 bytes defining relative positionning, row and anchor count
              -- In this plugin, this command is replaced by "\n" ascii code.
              elseif CC_concat:get_index(0)>=0x98 and CC_concat:get_index(0)<=0x9f then
                CC_concat:set_size(1)
                CC_concat:set_index(0, 0x0A)
              else
                -- Remove the two last bytes
                CC_concat:set_size((buffer_size-1)*2)
              end
            end

            -- Print both Pkt_Data_Structure
            -- TODO: find a way to print UTF8-ascii
            if buffer_size~=0 then
              str = tostring(CC_concat,ENC_UTF8)
              tree_data:add(F.CCData, str)
            end

          else
            s=s+1
          end   -- end if CDPSection = 0x72
        end     -- end for CDP Section

      --
      -- Parsing EBU Teletext data in VANC space (ST 2031)
      -- DID=0x41 and SDID=0x08
      --
      elseif ( DID==0x41 and SDID==0x08 ) then
        tree_data:add(F.Data_Identifier, ntvb(0, 1))
        tree_data:add(F.Data_UnitId, ntvb(1, 1))
        local unitId = ntvb(1, 1):uint()
        -- EBU Teletext
        if (unitId == 0x02 or unitId == 0x03) then
          tree_data:add(F.Data_UnitLength, ntvb(2, 1))
          tree_data:add(F.Field_Parity, ntvb(3, 1))
          tree_data:add(F.Line_Offset, ntvb(3, 1))
          tree_data:add(F.Framing_Code, ntvb(4, 1))

          -- Process EN 301 775 Section 4.5.2 txt_data_block():
          ProcessWstPacket(ntvb(5, 42), tree_data)

        end

      --
      -- Parsing Subtitling Distribution Packets in VANC space (ST RDD-8)
      --  (Free TV Australia Operational Practice OP-47)
      -- DID=0x43 and SDID=0x02
      --
      elseif ( DID == 0x43 and SDID == 0x02 ) then
        tree_data:add(F.SDP_Identifier, ntvb(0, 2))
        tree_data:add(F.SDP_Length, ntvb(2, 1))
        tree_data:add(F.SDP_FormatCode, ntvb(3, 1))
        local formatCode = ntvb(3, 1):uint()

        -- '0x02' ==> WST teletext subtitles
        if (formatCode == 0x02) then
          tree_data:add(F.SDP_AdaptionHeader, ntvb(4, 5)):set_generated()

          -- Offsets to Packet Descriptor Structures A and B
          local offsetA = 4
          local offsetB = 9
          for i=1, 5 do -- OP-47 can carry up to five WST Packets per VANC packet.
            local pktDescA = ntvb(offsetA,1):uint()
            if (pktDescA == 0) then
              break -- Per OP-47 5.4.2, no more WSTs to parse
            end

            local isField1 = ntvb(offsetA,1):bitfield(0,1) -- b7    => VBI field flag
            local lineNum = ntvb(offsetA,1):bitfield(3,5)  -- b4..0 => VBI line number
            local tree_wst = tree_data:add(F.SDP_PktDescB, ntvb(offsetB, 45)):set_generated()
            tree_wst:add(F.Clock_RunIn, ntvb(offsetB,2)):set_generated()
            tree_wst:add(F.Framing_Code, ntvb(offsetB+2,1)):set_generated()

            -- NB: The bit ordering of WST payload bytes carried in OP-47 is
            -- the reverse of EN 300 706, which uses VBI transmission order.
            -- Starting with the Magazine and Row Address Group, reverse the
            -- bits in the remaining 42 WST payload bytes, and then process
            -- per EN 300 706.
            -- (Note that ByteArray uses 0-based indexing, whereas Lua arrays
            --  are 1-based, hence use of 'byte+1'.)
            local bitFlippedData = ByteArray.new()
            bitFlippedData:set_size(42)
            for i=0,41 do
              local byte = ntvb(offsetB+3+i, 1):uint()
              if (byte >= 255) then byte = 0 end
              byte = byte+1
              local reversed = ReverseByte[byte]
              bitFlippedData:set_index(i, reversed)
            end

            ProcessWstPacket(bitFlippedData:tvb(wst), tree_wst)

            offsetA = offsetA + 1  -- increment to next A descriptor
            offsetB = offsetB + 45 -- increment to next corresponding payload
          end -- for i=1, 5

        end -- if (formatCode == 0x02)

      end       -- end if DID


      --- Increment offset for next packet
      offset=offset+PacketLen_Bytes
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

