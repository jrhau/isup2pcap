# isup2pcap

**isup2pcap** converts a traditional SS7 ISUP trace from a text format to a pcap format. It then can be viewed and analyzed in Wireshark. Having the SS7 ISUP trace in a pcap format allows us to merge it with a SIP trace pcap and do a side-by-side comparison using the SIP ladder diagram. It's great for troubleshooting when SIP and ISUP are in the same place!

## Dependencies

**isup2pcap** leverages Wireshark **text2pcap.exe** and **mergecap.exe**.


## Installation

### Recommended way:
1. Copy isup2pcap.exe into your Wireshark folder.
2. Add your Wireshark folder to your system path. This will make the script available from anywhere in your cmd prompt.

### Alternative way:
1. Copy isup2pcap.exe in your desired location.
2. When running the command, use the **-w** option to specify where your Wireshark folder is located.

### Verification
```bash
> isup2pcap --version
isup2pcap 1.3 BETA
```


## Usage
By default, it will output the pcap file in your current working directory.

```
usage: isup2pcap [-h] [-V] [-m <Pcap filename>] [-s] [-o <Output Filename>]
                 [-M <Merge Filename>] [-d] [-t] [-p <Output Path>] [-D]
                 [-w <Wireshark Path>] [--debug]
                 <ISUP File>


================================================================================

positional arguments:
  <ISUP File>           ISUP trace full decode in a .txt format

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Display current version
  -m <Pcap filename>    Allow to merge with another pcap, (typically the SIP
                        portion of the call)
  -s                    Separate in an ISUP only pcap and an ISUP + SIP pcap.
  -o <Output Filename>  Set the output filename. Default:
                        ISUP2PCAP_{datetime}.pcap
  -M <Merge Filename>   Set the merged filename. Only work with -s option
                        Default: ISUP2PCAP_MERGED_{datetime}.pcap
  -d, --no-duplicate    Remove duplicate ISUP message
  -t, --time            Show the elapsed time for each section.
  -p <Output Path>      Set the output directory. Default: Current working
                        directory
  -D, --dump            Keep the auto-generated ISUP_HEX_DUMP.txt. Default:
                        Auto-Remove after execution
  -w <Wireshark Path>   Indicate your Wireshark directory. Use this option if
                        you did not add Wireshark to your system path.
  --debug               Print debug output. WARNING: very timing!

================================================================================

PS: Set your Point Codes display format in Wireshark to our standards.

wireshark / Edit / Preference / Protocols / MTP3 / MTP3 standard = ANSI

================================================================================
```

### Usage Examples
- **Basic conversion**
```bash
>isup2pcap isup_decode.txt
DONE! 37 ISUP msg converted
```

- **Basic conversion + removing Duplicate ISUP msg**
```bash
>isup2pcap isup_decode.txt -d
DONE! 17 ISUP msg converted
```

- **Basic conversion + removing Duplicate ISUP msg + Merging with a SIP trace**
```bash
>isup2pcap isup_decode.txt -dm sip.pcap
DONE! 17 ISUP msg converted
```

- **Basic conversion + removing Duplicate ISUP msg + Merging with a SIP trace + timing info**
```bash
>isup2pcap isup_decode.txt -dtm sip.pcap
--------------------------------------------------------------------------------
Generated ISUP HEX dump in 0.02064 seconds
Generated ISUP pcap in 0.1215 seconds
Merged in 0.09302 seconds
--------------------------------------------------------------------------------
Total elapsed time: 0.7079 seconds

DONE! 17 ISUP msg converted
```


## Contributing
Pull requests are welcome. Currently compatible with Oracle Tekelec Protrace full decode in a .txt format. I'm looking to make this compatible with other ss7 trace decode format. If you would like to contribute, contact me. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT License](https://choosealicense.com/licenses/mit)

Copyright (c) 2020 Jonathan Rhau

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
