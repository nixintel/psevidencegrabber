# psevidencegrabber
Powershell Script for Live Forensics by Steven Harris https://github.com/ipversion7 

PS-EvidenceGrabber is a Powershell script designed for capturing live forensic evidence including volatile network, 
system, user and registry information. It takes full advantage of the Cmdlets available with Powershell and replaces many of
the legacy CMD commands such as ipconfig, netstat, arp -a etc from older scripts with more current PS equivalents.

The output is saved as an HTML file which makes the information easier to read and analyse.

HOW TO USE PS-EVIDENCE GRABBER

1. The script assumes you have physical access to the machine you are examining and is intended to be run from a USB stick.

2. Powershell must be run as Admin. To do this right-click on Powershell and select "Run As Administrator"

3. Powershell scripts cannot be executed by default and they need to be enabled. To do this open Powershell and type the following:

Set-ExecutionPolicy RemoteSigned

This will allow you to run the script. This makes a change to the settings on the computer so should be recorded and
rationalised as part of the the documentation process.

4. The script prompts you for information that will added to the final report such as the examiner name, the device description and exhibit reference etc. This information is incorporated into the final report for ease of reference.

5. The script takes several minutes to run and then exits. The HTML report is then saved on the Harvest drive that you specified. It's advisable to check the report for any errors as soon as possible after the script has executed. Please note that if there is no output for a particular field, it may be that the computer does not hold any relevant information.

DISCLAIMER

The script has been tested on Windows 10 (build 1803 - April 2018) and works without any errors. Please contact me via GitHub 
if you experience any difficulties. The script will only work on 64-bit Windows and will not work on any versions of Windows prior to Windows 7 (i.e. XP and Vista). I haven't tested it on any older Win 7/8 builds but let me know what works/doesn't work so the script can be modified accordingly.

LICENSE

Copyright <2018 Steven Harris>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
