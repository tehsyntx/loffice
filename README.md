# loffice - Lazy Office Analyzer

Requirements:
- Microsoft Office
- WinDbg - https://msdn.microsoft.com/en-us/windows/hardware/hh852365
- WinAppDbg - http://winappdbg.sourceforge.net/
- Python 2.7 
- pefile - https://github.com/erocarrera/pefile
- capstone - https://pypi.python.org/pypi/capstone-windows

Loffice is making use of WinAppDbg to extract URLs' from Office documents but also VB-script and Javascript. By setting strategical breakpoints it's possible to neutralize obfuscation and get the URL and file destination.
Anti-analysis via WMI, for example detecting running processes or installed software is handled by patching the query string before the query is run.

Loffice have three different exit-modes which determine if execution is to be aborted:
- url - Exit when the first URL is found
- proc - Exit if a new process is to be created
- thread - Before resuming a suspended thread (RunPE style)
- none - Do not interupt execution, URL and file information will still be printed.
 
It will also give an insight if there is any evasion/sandbox detection going on by checking string comparisons and logging everything to file located in the "logs" directory.

To make analysis as quick as possible macro should be enabled in Office otherwise you would have to manually enable macro for each analysis. After completed analysis the host application (ex. Word) will be terminated.

If you've got any suggestions/thoughts/comments, let me know!

