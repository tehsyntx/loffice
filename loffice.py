#!/bin/env python

"""
Loffice - Lazy Office Analyzer

Requirements:
- Microsoft Office (32-bit)
- WinDbg (x86) - https://msdn.microsoft.com/en-us/windows/hardware/hh852365
- WinAppDbg - http://winappdbg.sourceforge.net/

Author: @tehsyntx
"""

from winappdbg import Debug, EventHandler
import sys
import os

# Root path to Microsoft Office
OFFICE_PATH = 'C:\\Program Files\\Microsoft Office\\Office14\\'

def cb_crackurl(event):
	
	proc = event.get_process()
	thread  = event.get_thread()

	lpszUrl = thread.read_stack_dwords(2)[1]

	print 'FOUND URL\n\t%s\n' % proc.peek_string(lpszUrl, fUnicode=True)

	if exit_on == 'url':
		print 'Exiting on first URL, bye!'
		sys.exit()

		
def cb_createfilew(event):

	proc = event.get_process()
	thread = event.get_thread()
	
	lpFileName, dwDesiredAccess = thread.read_stack_dwords(3)[1:]

	if dwDesiredAccess == 0x80000100:
		print 'OPEN FILE HANDLE\n\t%s\n' % (proc.peek_string(lpFileName, fUnicode=True))

		
def cb_createprocessw(event):

	proc = event.get_process()
	thread  = event.get_thread()

	lpApplicationName = thread.read_stack_dwords(2)[1]
		
	print 'CREATE PROCESS\n\t%s\n' % proc.peek_string(lpApplicationName, fUnicode=True)
	
	if exit_on == 'url':
		print 'Process created before URL was found, exiting for safety'
		sys.exit()
		
	if exit_on == 'proc':
		print 'Exiting on process creation, bye!'
		sys.exit()

		
class EventHandler(EventHandler):

	def load_dll(self, event):

		module = event.get_module()
		pid = event.get_pid()

		if module.match_name("kernel32.dll"):
			address = module.resolve("CreateProcessW")
			event.debug.break_at(pid, address, cb_createprocessw)

			address = module.resolve("CreateFileW")
			event.debug.break_at(pid, address, cb_createfilew)
			
		if module.match_name("wininet.dll"):
			address = module.resolve("InternetCrackUrlW")
			event.debug.break_at(pid, address, cb_crackurl)


		if module.match_name("winhttp.dll"):
			address = module.resolve("WinHttpCrackUrl")
			event.debug.break_at(pid, address, cb_crackurl)
			
		
def usage():

	print ''
	print 'Lazy Office Analyzer - Analyze documents with WinDbg'
	print ''
	print 'loffice.py [type] [exit-on] [filename]'
	print 'Type:'
	print '\tword   - Word document'
	print '\texcel  - Excel spreadsheet'
	print '\tpower  - Powerpoint document'
	print '\tscript - VBscript & Javascript'
	print 'Exit-on:'
	print '\turl  - After first URL extraction (no remote fetching)'
	print '\tproc - Before process creation (allow remote fetching)'
	print '\tnone - Allow uniterupted execution (dangerous)'
	
	sys.exit()
	
if __name__ == "__main__":

	if len(sys.argv) < 4:
		usage()

	args = []

	if sys.argv[1] == 'script':
		args.append('%s\\system32\\wscript.exe' % os.environ['WINDIR'])
	elif sys.argv[1] == 'word':
		args.append('%s\\WINWORD.EXE' % OFFICE_PATH)
	elif sys.argv[1] == 'excel':
		args.append('%s\\EXCEL.EXE %s' % OFFICE_PATH)
	elif sys.argv[1] == 'power':
		args.append('%s\\POWERPNT.EXE' % OFFICE_PATH)
	else:
		print 'Unsupported type: %s' % sys.argv[1]
		sys.exit()

	if not os.path.isfile(args[0]):
		print 'Host process path could not be found: %s' % args[0]
		sys.exit()
		
	global exit_on
	if sys.argv[2] == 'url' or sys.argv[2] == 'proc' or sys.argv[2] == 'none':
		exit_on = sys.argv[2]
	else:
		print 'Unsupported exit-on: %s' % sys.argv[2]
		sys.exit()
		
	args.append(sys.argv[3]) # Document to analyze

	with Debug(EventHandler(), bKillOnExit = True) as debug:
		debug.execv(args)
		try:
			debug.loop()
		except KeyboardInterrupt:
			print 'Exiting, bye!'
			pass