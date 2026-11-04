@echo off
setlocal
cd /d "%~dp0"
title Packet Sniffer + ARP Spoofing Detector

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup.
  pause
  exit /b 1
)

if not exist .venv (
  echo Creating a virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -q --disable-pip-version-check -r requirements-dev.txt

set LIVE=yes
if not exist "%SystemRoot%\System32\Npcap" (
  set LIVE=no
  echo.
  echo  Note: Npcap is not installed, so live capture is off. Everything else works with .pcap files.
  echo  For live capture install Npcap from https://npcap.com and run this file as Administrator.
)
net session >nul 2>nul
if errorlevel 1 if "%LIVE%"=="yes" (
  echo.
  echo  Note: not running as Administrator, so live capture is off.
  echo  Right-click run.bat and choose "Run as administrator" to enable it.
  set LIVE=no
)

:menu
echo.
echo  ==== Packet Sniffer + ARP Spoofing Detector ====  (live capture: %LIVE%)
echo   1. Open the web dashboard (http://127.0.0.1:5000)
echo   2. Analyse the ARP spoofing sample
echo   3. Analyse all samples and write HTML reports to the "reports" folder
echo   4. Analyse my own .pcap file
echo   5. List network interfaces
echo   6. Live capture for 30 seconds (needs Npcap + Administrator)
echo   7. Run unit tests
echo   0. Exit
set /p c=Choose: 
if "%c%"=="1" start "" http://127.0.0.1:5000 & python webapp\app.py & goto menu
if "%c%"=="2" python sniff.py --pcap samples\arp_spoof.pcap --proto arp & goto menu
if "%c%"=="3" for %%f in (samples\*.pcap) do python sniff.py --pcap "%%f" --quiet --report "reports\%%~nf.html" --alerts-csv "reports\%%~nf_alerts.csv"
if "%c%"=="3" goto menu
if "%c%"=="4" set /p f=Path to .pcap: & call python sniff.py --pcap "%%f%%" --report reports\my_capture.html & goto menu
if "%c%"=="5" python sniff.py --list-ifaces & goto menu
if "%c%"=="6" python sniff.py --iface --timeout 30 --save-pcap reports\live_capture.pcap --report reports\live_capture.html & goto menu
if "%c%"=="7" python -m pytest -q & goto menu
if "%c%"=="0" exit /b 0
goto menu
