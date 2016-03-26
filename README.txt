NAME:

PCAP Send (pcaps)


DESCRIPTION:

A small program to send packets using Pcap libraries.  Packets are provided 
as hex strings and the program converts and sends them.  Options are 
provided to override MAC and IP level source / destinations with station 
addresses.


REQUIRES:

Pcap developer resources (headers and libraries)
http://www.winpcap.org/devel.htm


BUILD:

This has been built on Windows 7 x64 using the GCC (4.7.3) compiler bundled 
with Strawberry Perl (5.18.1).

You need to unzip the files in this distribution into a working directory:

  working_dir\pcaps

Unzip the Pcap developer's pack into the same working directory:

  working_dir\WpdPack

If you're building on x64 with a 64-bit MinGW-based compiler, you will 
probably find Pcap developer's pack is missing the .a libraries for x64.
Check with:

  C:\working_dir> dir WpdPack\lib\x64\*.a

If they don't exist, build them; otherwise, skip these next 5 commands:

  cd WpdPack\lib\x64
  pexports \Windows\system32\wpcap.dll > wpcap.def
  dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libwpcap.a --input-def wpcap.def
  pexports \Windows\system32\Packet.dll > Packet.def
  dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libpacket.a --input-def Packet.def

Build from the 'working_dir\pcaps' directory:

  gmake

The Makefile is pretty simple and can be edited.  Defining -DDEBUG may 
help troubleshoot issues if they are occurring in operation.  Defining 
-DADDRS is required for packet rewrites.


RUN:

From the command line:

  pcaps.exe --help
