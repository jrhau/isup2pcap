#!/usr/bin/env python
# coding: utf-8

import re
import time
import os
import subprocess
from hexdump import hexdump
import argparse
from pathlib import Path
from datetime import datetime
import textwrap
from codetiming import Timer


class isup2pcap:
    """\
        Convert a traditional ISUP trace from a .txt to a .pcap format.
        It uses Wireshark 'text2pcap' and 'mergecap'.

        Compatible with Oracle ProTrace Tekelect "Full Decode" in a .TXT format

        For the easiest use, add your Wireshark path to your system path.

        If a file or path contains spaces, enclose it in quotes ('' or "").
            EX: isup2pcap "folder name/file name.txt"

        =======================================================================

        PS: To see the Pointe Codes in the right format set your MTP3 setting.

        wireshark / Edit / Preference / Protocols / MTP3 / MTP3 standard = ANSI

        =======================================================================

        To report an issue, email me at jonathan.rhau@bell.ca with details.

                                                             - By Jonathan Rhau
    """

    def __init__(
        self,
        isup_trace,
        sip_pcap=None,
        rm_isup_duplicate=False,
        out_path=None,
        out_name=None,
        merge_name=None,
        seperate_files=False,
        dump=False,
        wireshark_path=None,
        debug=False,
        timing=False,
        duplicate_window=5,
    ):
        """Step 1: Extract the HEX dump to a file using Regular expression.
        Step 2: Convert the ISUP HEX dumps to pcap using Wireshark "text2pcap".
        Step 3: Remove ISUP duplicate entries.
        Step 3: Merge the ISUP pcap with a SIP pcap using Wireshark "mergecap".
        """
        #######################################################################
        # Using Pathlib.Path for path manipulation and correct slashes direction

        # To adapt this script to a different kind of ISUP trace dump,
        # You can modify the following two regex.
        # Currently adapted for Oracle ProTrace Tekelec tool
        self.regex_timestamp = (
         r"^[0-9]{2}/[0-9]{2}/[0-9]{4}\s[0-9]{2}:[0-9]{2}:[0-9]{2}\t[0-9]{1,6}"
        )
        self.regex_decode = r"^([A-F,0-9]{2}\s)+$"
        self.wireshark_path = Path(wireshark_path) if wireshark_path else None
        self.rm_isup_duplicate = rm_isup_duplicate
        self.out_path = Path(out_path) if out_path else Path(os.getcwd())
        date = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        default_outfile = Path(f"ISUP2PCAP_{date}.pcap")
        default_mergefile = Path(f"ISUP2PCAP_MERGED_{date}.pcap")
        self.out_name = Path(out_name) if out_name else default_outfile
        self.merge_name = Path(merge_name) if merge_name else default_mergefile
        self.sip_pcap = Path(sip_pcap) if sip_pcap else None
        self.isup_hex_dump = self.out_path / Path(f"HEX_DUMP_{date}.txt")
        self.isup_pcap = self.out_path / self.out_name
        self.isup_w_sip_pcap = self.out_path / self.merge_name
        self.dump = dump
        self.debug = debug
        self.timing = timing
        self.duplicate_window = duplicate_window
        self.seperate_files = seperate_files

        if self.debug:
            print("=" * 80)
            print("Variable values on init:")
            print("-" * 80)
            print(f"self.regex_timestamp = {self.regex_timestamp}")
            print(f"self.regex_decode = {self.regex_decode}")
            print(f"self.wireshark_path = {self.wireshark_path}")
            print(f"self.rm_isup_duplicate = {self.rm_isup_duplicate}")
            print(f"self.out_path = {self.out_path}")
            print(f"self.out_name = {self.out_name}")
            print(f"self.merge_name = {self.merge_name}")
            print(f"self.sip_pcap = {self.sip_pcap}")
            print(f"self.isup_hex_dump = {self.isup_hex_dump}")
            print(f"self.isup_pcap = {self.isup_pcap}")
            print(f"self.isup_w_sip_pcap = {self.isup_w_sip_pcap}")
            print(f"self.dump = {self.dump}")
            print(f"self.debug = {self.debug}")
            print(f"self.timing = {self.timing}")
            print(f"self.duplicate_window = {self.duplicate_window}")
            print(f"self.seperate_files = {self.seperate_files}")
        #######################################################################
        # Paths and files validation
        if not Path.exists(Path(isup_trace)):
            msg = f'Cannot find "{Path(isup_trace)}"'
            raise Exception(msg)

        if self.sip_pcap and not Path.exists(self.sip_pcap):
            msg = f'Cannot find "{self.sip_pcap}"'
            raise Exception(msg)

        if not Path.exists(self.out_path):
            msg = f'Cannot find "{self.out_path}"'
            raise Exception(msg)

        if self.wireshark_path:
            if not Path.exists(self.wireshark_path):
                msg = f'Cannot find "{self.wireshark_path}"'
                raise Exception(msg)

            fullpath = self.wireshark_path / Path("text2pcap")
            if not Path.exists(fullpath):
                msg = f'Cannot find "text2pcap" in "{self.wireshark_path}"'
                raise Exception(msg)

            fullpath = self.wireshark_path / Path("mergecap")
            if self.sip_pcap and not Path.exists(fullpath):
                msg = f'Cannot find "mergecap" in "{self.wireshark_path}"'
                raise Exception(msg)
        else:
            if not self.run_win_cmd("text2pcap -h"):
                msg = 'Cannot run "text2pcap".\n'
                msg += "Verify that Wireshark path was added to the system path\n"
                msg += 'A simple test is to run the "text2pcap -h" command\n'
                raise Exception(msg)
            if self.sip_pcap and not self.run_win_cmd("mergecap -h"):
                msg = 'Cannot run "mergecap".\n'
                msg += "Verify that Wireshark path was added to the system path\n"
                msg += 'A simple test is to run the "mergecap -h" command\n'
                raise Exception(msg)
        #######################################################################
        # Auto executes on launch

        with open(Path(isup_trace)) as full_decoding_file:
            self.full_decoding = full_decoding_file.read()

        if self.debug:
            print("=" * 80 + f"\nFull decoding = {self.full_decoding}")

        with Timer(
            text="-" * 80 + "\nGenerated ISUP HEX dump in {:0.4} seconds",
            logger=print if timing else None,
        ):
            self.isup2hex()
        with Timer(
            text="Generated ISUP pcap in {:0.4} seconds",
            logger=print if timing else None,
        ):
            self.generate_isup_pcap()

        if self.sip_pcap:
            with Timer(
                text="Merged in {:0.4} seconds",
                logger=print if timing else None
            ):
                self.merge_w_sip()

        #######################################################################

    def remove_duplicate(self):
        self.no_dup = []
        for idx, msg in enumerate(self.raw):
            found = 0
            for window_msg in self.raw[idx+1:idx+self.duplicate_window]:
                if msg[1]["mtp3_no_sls"] == window_msg[1]["mtp3_no_sls"]:
                    found += 1
            if not found:
                self.no_dup.append(msg)

    def isup2hex(self):
        """Step 1: Extract the HEX and the timestamp from the trace,
        Step 2: Dump the data to a temporary file."""

        self.timestamps = []
        self.decodes = []

        if self.debug:
            msg = "Step 1: Capturing all timestamps + ISUP HEX\n"
            print(msg + "-" * 80)
        for line in self.full_decoding.split("\n"):
            time_match = re.finditer(self.regex_timestamp, line, re.MULTILINE)
            decode_match = re.finditer(self.regex_decode, line, re.MULTILINE)

            for match in time_match:
                if self.debug:
                    print(f"\tFound: {match.group()}")

                t = match.group().split("\t")
                dt = datetime(
                    *(time.strptime(t[0], "%d/%m/%Y %H:%M:%S")[0:6]),
                    microsecond=int(t[1]) * 1000,
                )
                self.timestamps.append(dt)

            for match in decode_match:
                if self.debug:
                    print(f"\tFound: {match.group()}")

                # Capturing key decode attributes for feature ideas,
                # but not currently necessary
                decode_list = match.group().split(" ")
                decode_list.remove("")
                OPC = decode_list[4:7]
                DPC = decode_list[7:10]
                CIC = decode_list[11:13]
                msg_type = decode_list[13]
                mtp3_no_sls = " ".join(decode_list[2:10] + decode_list[11:])
                self.decodes.append(
                    {
                        "decode": match.group(),
                        "mtp3_no_sls": mtp3_no_sls,
                        "OPC": OPC,
                        "DPC": DPC,
                        "CIC": CIC,
                        "type": msg_type,
                        "lenght": len(decode_list),
                    }
                )

        # Validation: The number of timestamp must match the number of HEX msg
        if len(self.timestamps) == len(self.decodes):
            self.raw = list(zip(self.timestamps, self.decodes))
            self.raw.sort(key=lambda time_decode: time_decode[0])

        else:
            self.raw = None
            msg = f"Match error: {len(self.timestamps)} timestamps found "
            msg += f"vs {len(self.decodes)} decodes found"
            raise Exception(msg)

        if self.rm_isup_duplicate:
            self.remove_duplicate()
            self.raw = self.no_dup

        self.decode_txt = ""
        for msg in self.raw:
            self.decode_txt += msg[0].strftime("%d/%m/%Y %H:%M:%S.%f") + "\n"
            HEX = hexdump(bytes.fromhex(msg[1]["decode"]), result="return")
            self.decode_txt += HEX + "\n\n"

        with open(self.out_path / self.isup_hex_dump, "w") as out_name:
            out_name.write(self.decode_txt)

        if self.debug:
            print("=" * 80 + f"\nself.decode_txt = \n{self.decode_txt}")

    def run_win_cmd(self, cmd):
        """Quick method to run a windows command and display the output"""

        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text="UTF-8",
        )

        # Using .communicate here to avoid a deadlock when there is
        # a lot of data to output instead of process.stdout
        output = process.communicate()

        if process.returncode:
            print(output[0])
            print(output[1])
            raise Exception(f'\n\ncmd "{cmd}" failed, see above for details')

        return output

    def generate_isup_pcap(self):
        """Using Wireshark "text2pcap" tool to convert the ISUP HEX dump """

        # Adding quotes around the command path in case some directory contains
        # spaces. Ex: "/Program Files/"

        # If no Wireshark path provided, we assume it was added to the system
        # path and we can run the command directly.

        cmd = (
            f'''"{self.wireshark_path / Path('text2pcap')}"'''
            if self.wireshark_path
            else "text2pcap"
        )
        # -t to match the time format using strftime(3).
        # The trailing "." is to match milliseconds.
        # -l To specify the type of payload. Our dump start at the MTP2 (140)
        options = f' -t "%d/%m/%Y %H:%M:%S." -l 140 '
        options += f'"{self.isup_hex_dump}" "{self.isup_pcap}"'

        self.run_win_cmd(cmd + options)

        # Option to keep the ISUP HEX dump. Good for troubleshooting
        if not self.dump:
            os.remove(self.isup_hex_dump)

    def merge_w_sip(self):
        """Merging the isup pcap with the external SIP pcap file"""

        cmd = (
            f'''"{self.wireshark_path / Path('mergecap')}"'''
            if self.wireshark_path
            else "mergecap"
        )

        # -w is to specify an output file
        # adding double quotes around the filename in case they contain
        # spaces. EX: ".../Test folder/file name.pcap"
        options = f' -w "{self.isup_w_sip_pcap}" '
        options += f'"{self.isup_pcap}" "{self.sip_pcap}"'

        self.run_win_cmd(cmd + options)

        # If -s (separate) option is not used and Merge was call
        # Remove the ISUP only pcap and rename the Merge pcap
        if not self.seperate_files:
            os.remove(self.isup_pcap)
            os.rename(self.merge_name, self.out_name)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog="isup2pcap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # usage="isup2pcap [OPTION] ... <ISUP Trace file>",
        description=textwrap.dedent(
        f"""\
        Convert a traditional ISUP trace from a .txt to a .pcap format.
        It uses Wireshark text2pcap and mergecap.

        Compatible with Oracle ProTrace Tekelect Full Decode in a .txt format

        For the easiest use, add your Wireshark path to your system path.

        If a file or path contains spaces, enclose it within quotes (' or ").
            EX: isup2pcap "folder name/file name.txt"

        {'='*80}
        """
        ),
        epilog=textwrap.dedent(
        f"""\
        {'='*80}

        PS: Set your Point Codes display format in Wireshark to our standards.

        wireshark / Edit / Preference / Protocols / MTP3 / MTP3 standard = ANSI

        {'='*80}

        To report an issue, email me at jonathan.rhau@bell.ca with details.

                                                            - By Jonathan Rhau
        """
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        help="Display current version",
        action="version",
        version="%(prog)s 1.3 BETA",
    )
    parser.add_argument(
        "isup_trace",
        metavar="<ISUP Filename>",
        help="ISUP trace full decode in a .txt format",
    )
    parser.add_argument(
        "-m",
        dest="merge",
        metavar="<PCAP Filename>",
        help="Allow to merge with another pcap, \
            (typically the SIP portion of the call)",
    )

    parser.add_argument(
        "-s",
        dest="seperate_files",
        help="Separate in a ISUP only pcap and a ISUP + SIP pcap.",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        dest="out_name",
        metavar="<Output Filename>",
        help="Set the output filename. Default: ISUP2PCAP_{datetime}.pcap",
    )
    parser.add_argument(
        "-M",
        dest="merge_name",
        metavar="<Merge Filename>",
        help="Set the merged filename. Only work with -s option \
            Default: ISUP2PCAP_MERGED_{datetime}.pcap",
    )
    parser.add_argument(
        "-d",
        "--no-duplicate",
        help="Remove duplicate ISUP message",
        action="store_true",
    )
    parser.add_argument(
        "-t", "--time", 
        help="Show the elapsed time for each section.", 
        action="store_true"
    )
    parser.add_argument(
        "-p",
        dest="path",
        metavar="<Output Path>",
        help="Set the output directory. Default: Current working directory",
    )
    parser.add_argument(
        "-D",
        "--dump",
        help="Keep the auto-generated ISUP_HEX_DUMP.txt. \
            Default: Auto-Remove after execution",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        dest="wireshark_path",
        metavar="<Wireshark Path>",
        help="Indicate your Wireshark directory. Use this option if you did \
            not add Wireshark to your system path.",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Print debug output. WARNING: very verbose!",
    )

    args = parser.parse_args()

    if args.debug:
        print(f"Argparse variable = \n{args}\n")

    with Timer(
        text="-" * 80 + "\nTotal elapsed time: {:0.4} seconds\n",
        logger=print if args.time else None
    ):
        i2p = isup2pcap(
            isup_trace=args.isup_trace,
            sip_pcap=args.merge,
            rm_isup_duplicate=args.no_duplicate,
            out_path=args.path,
            out_name=args.out_name,
            merge_name=args.merge_name,
            seperate_files=args.seperate_files,
            dump=args.dump,
            wireshark_path=args.wireshark_path,
            debug=args.debug,
            timing=args.time,
        )

    print(f"DONE! {len(i2p.raw)} ISUP msg converted\n")
