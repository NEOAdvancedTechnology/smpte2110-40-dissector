# smpte2110-40-dissector
Dissector for SMPTE ST 2110-40 Ancillary Data

Lua Dissector for ST 2110-40 in Wireshark

Project Lead: Thomas Edwards (thomas.edwards@disney.com)

to use in Wireshark:

1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
    should list "ST-2110_40.lua"

3) In Wireshark Preferences, under "Protocols", set st_2110_40 as dynamic payload type being used

4) Capture packets of ST 2110_40

5) "Decode As" those UDP packets as RTP

6) You will now see the ST 2110_40 Data dissection of the RTP payload

7) You can extract the Closed Captionning Data with the script parse_CC.sh.
The utility tshark has to be installed.
The script extracts with tshark the CC Data from a pcap file and concatenates
them into an output file:

```
./parse_CC.sh --in=<PCAP_FILE> --out=<CC_DATA_EXTRACTED_FILE>
```
or to output in stdout:
```
./parse_CC.sh --in=<PCAP_FILE> -v
```

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
