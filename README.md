# smpte2110-40-dissector
Dissector for SMPTE ST 2110-40 Ancillary Data

Note that ST 2110-40 is currently under development by SMPTE, and a final version has not been published yet.  However it is expected to reference IETF RFC 8331 which has been published.

Lua Dissector for ST 2110-40 in Wireshark
Author: Thomas Edwards (thomas.edwards@fox.com)

to use in Wireshark:

1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
    should list "ST-2110_40.lua"

3) In Wireshark Preferences, under "Protocols", set st_2110_40 as dynamic payload type being used

4) Capture packets of ST 2110_40

5) "Decode As" those UDP packets as RTP

6) You will now see the ST 2110_40 Data dissection of the RTP payload

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
