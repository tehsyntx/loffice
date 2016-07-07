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
OFFICE_PATH = 'C:\\Program Files\\Microsoft Office\\Office15\\'

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

	lpApplicationName, lpCommandLine = thread.read_stack_dwords(3)[1:]
	application = proc.peek_string(lpApplicationName, fUnicode=True)
	cmdline = proc.peek_string(lpCommandLine, fUnicode=True)

	print 'CREATE PROCESS\n\tApp: "%s"\n\tCmd-line: "%s"\n' % (application, cmdline)		
	
	if exit_on == 'url' and 'splwow64' not in application:
		print 'Process created before URL was found, exiting for safety'
		sys.exit()
		
	if exit_on == 'proc' and 'splwow64' not in application:
		print 'Exiting on process creation, bye!'
		sys.exit()

def cb_stubclient20(event):

	proc = event.get_process()
	thread  = event.get_thread()

	print 'DETECTED WMI QUERY'

	strQueryLanguage, strQuery = thread.read_stack_dwords(4)[2:]

	language = proc.peek_string(strQueryLanguage, fUnicode=True)
	query = proc.peek_string(strQuery, fUnicode=True)

	print '\tLanguage: %s' % language
	print '\tQuery: %s' % query

	if 'win32_product' in query.lower() or 'win32_process' in query.lower():

		if '=' in query or 'like' in query.lower():
			decoy = "SELECT Name FROM Win32_Fan WHERE Name='1'"
		else:
			decoy = "SELECT Name FROM Win32_Fan"

		i = len(decoy)

		for c in decoy:
			proc.write_char(strQuery + (i - len(decoy)), ord(c))
			i += 2

		proc.write_char(strQuery + (len(decoy) * 2), 0x00)
		proc.write_char(strQuery + (len(decoy) * 2) + 1, 0x00) # Ensure UNICODE string termination

		patched_query = proc.peek_string(strQuery, fUnicode=True)

		print '\tPatched with: %s' % patched_query


class EventHandler(EventHandler):

	def load_dll(self, event):

		module = event.get_module()
		pid = event.get_pid()

		if module.match_name("kernel32.dll"):
			address = module.resolve("CreateProcessW")
			try:
				event.debug.break_at(pid, address, cb_createprocessw)
			except:
				print '[?] Could not break at CreateProcessW'

			address = module.resolve("CreateFileW")
			try:
				event.debug.break_at(pid, address, cb_createfilew)
			except:
				print '[?] Could not break at CreateFileW'
			
		if module.match_name("wininet.dll"):
			address = module.resolve("InternetCrackUrlW")
			try:
				event.debug.break_at(pid, address, cb_crackurl)
			except:
				print '[?] Could not break at InternetCrackUrlW'

		if module.match_name("winhttp.dll"):
			address = module.resolve("WinHttpCrackUrl")
			try:
				event.debug.break_at(pid, address, cb_crackurl)
			except:
				print '[?] Could not break at WinHttpCrackUrl'

		if module.match_name("ole32.dll"):
			address = module.resolve("ObjectStublessClient20")
			try:
				event.debug.break_at(pid, address, cb_stubclient20)
			except:
				print '[?] Could not break at ObjectStublessClient20'

		
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
		args.append('%s\\EXCEL.EXE' % OFFICE_PATH)
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
			print 'Launching...\n'
			debug.loop()
		except KeyboardInterrupt:
			print 'Exiting, bye!'
			pass
