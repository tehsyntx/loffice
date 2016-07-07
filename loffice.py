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
import optparse
import logging

logging.basicConfig(format='%(levelname)s%(message)s')
logging.addLevelName( logging.INFO, '')
logging.addLevelName( logging.DEBUG, '[%s] ' % logging.getLevelName(logging.DEBUG))
logging.addLevelName( logging.ERROR, '[%s] ' % logging.getLevelName(logging.ERROR))
logger = logging.getLogger()

# Root path to Microsoft Office
DEFAULT_OFFICE_PATH = 'C:\\Program Files\\Microsoft Office\\Office15'


def cb_crackurl(event):
	
	proc = event.get_process()
	thread  = event.get_thread()

	lpszUrl = thread.read_stack_dwords(2)[1]

	logger.info('FOUND URL:\n\t%s\n' % proc.peek_string(lpszUrl, fUnicode=True))

	if exit_on == 'url':
		logger.info('Exiting on first URL, bye!')
		sys.exit()

		
def cb_createfilew(event):

	proc = event.get_process()
	thread = event.get_thread()
	
	lpFileName, dwDesiredAccess = thread.read_stack_dwords(3)[1:]

	if dwDesiredAccess == 0x80000100:
		logger.info('OPEN FILE HANDLE\n\t%s\n' % (proc.peek_string(lpFileName, fUnicode=True)))

		
def cb_createprocessw(event):

	proc = event.get_process()
	thread  = event.get_thread()

	lpApplicationName, lpCommandLine = thread.read_stack_dwords(3)[1:]
	application = proc.peek_string(lpApplicationName, fUnicode=True)
	cmdline = proc.peek_string(lpCommandLine, fUnicode=True)

	logger.info('CREATE PROCESS\n\tApp: "%s"\n\tCmd-line: "%s"\n' % (application, cmdline))
	
	if exit_on == 'url' and 'splwow64' not in application:
		logger.info('Process created before URL was found, exiting for safety')
		sys.exit()
		
	if exit_on == 'proc' and 'splwow64' not in application:
		logger.info('Exiting on process creation, bye!')
		sys.exit()

def cb_stubclient20(event):

	proc = event.get_process()
	thread  = event.get_thread()

	logger.info('DETECTED WMI QUERY')

	strQueryLanguage, strQuery = thread.read_stack_dwords(4)[2:]

	language = proc.peek_string(strQueryLanguage, fUnicode=True)
	query = proc.peek_string(strQuery, fUnicode=True)

	logger.info('\tLanguage: %s' % language)
	logger.info('\tQuery: %s' % query)

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

		logger.info('\tPatched with: %s' % patched_query)


class EventHandler(EventHandler):

	def load_dll(self, event):

		module = event.get_module()
		pid = event.get_pid()

		if module.match_name("kernel32.dll"):
			address = module.resolve("CreateProcessW")
			try:
				event.debug.break_at(pid, address, cb_createprocessw)
			except:
				logger.error('Could not break at: CreateProcessW')

			address = module.resolve("CreateFileW")
			try:
				event.debug.break_at(pid, address, cb_createfilew)
			except:
				logger.error('Could not break at: CreateFileW')
			
		if module.match_name("wininet.dll"):
			address = module.resolve("InternetCrackUrlW")
			try:
				event.debug.break_at(pid, address, cb_crackurl)
			except:
				logger.error('Could not break at: InternetCrackUrlW')

		if module.match_name("winhttp.dll"):
			address = module.resolve("WinHttpCrackUrl")
			try:
				event.debug.break_at(pid, address, cb_crackurl)
			except:
				logger.error('Could not break at: WinHttpCrackUrl')

		if module.match_name("ole32.dll"):
			address = module.resolve("ObjectStublessClient20")
			try:
				event.debug.break_at(pid, address, cb_stubclient20)
			except:
				logger.error('Could not break at: ObjectStublessClient20')


def options():

	valid_types = ['word', 'excel', 'power', 'script']
	valid_exit_ons = ['url', 'proc', 'none']

	usage = '''
	%prog [options] <type> <exit-on> <filename>
	
Type:
	word   - Word document
	excel  - Excel spreadsheet
	power  - Powerpoint document
	script - VBscript & Javascript

Exit-on:
	url  - After first URL extraction (no remote fetching)
	proc - Before process creation (allow remote fetching)
	none - Allow uniterupted execution (dangerous)
'''
	parser = optparse.OptionParser(usage=usage)
	parser.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.', action='store_true')
	parser.add_option('-p', '--path', dest='path', help='Path to the Microsoft Office suite.', default=DEFAULT_OFFICE_PATH)

	opts, args = parser.parse_args()

	if not os.path.exists(opts.path):
		logger.error('Specified Office path does not exists: "%s"' % opts.path)
		sys.exit(1)

	if args[0] not in valid_types:
		logger.error('Specified <type> is not recognized: "%s".' % args[0])
		sys.exit(1)

	if args[1] not in valid_exit_ons:
		logger.error('Specified <exit-on> is not recognized: "%s".' % args[1])
		sys.exit(1)

	if not os.path.isfile(args[2]):
		logger.error('Specified file to analyse does not exists: "%s"' % args[2])
		sys.exit(1)

	if opts.verbose:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)

	return (opts, args)


if __name__ == "__main__":

	(opts, args) = options()

	logger.info('\n\tLazy Office Analyzer - Analyze documents with WinDbg\n')

	office_invoke = []
	if args[0] == 'script':
		office_invoke.append('%s\\system32\\wscript.exe' % os.environ['WINDIR'])
	elif args[0] == 'word':
		office_invoke.append('%s\\WINWORD.EXE' % opts.path)
	elif args[0] == 'excel':
		office_invoke.append('%s\\EXCEL.EXE' % opts.path)
	elif args[0] == 'power':
		office_invoke.append('%s\\POWERPNT.EXE' % opts.path)
	else:
		print 'Unsupported type: %s' % args[0]
		sys.exit(1)

	logger.debug('Using office path:')
	logger.debug('\t"%s"' % office_invoke[0])
		
	global exit_on
	exit_on = args[1]
		
	office_invoke.append(args[2]) # Document to analyze

	logger.debug('Invocation command:')
	logger.debug('\t"%s"' % ' '.join(office_invoke))

	with Debug(EventHandler(), bKillOnExit = True) as debug:
		debug.execv(office_invoke)
		try:
			logger.debug('Launching...')
			debug.loop()
		except KeyboardInterrupt:
			logger.info('Exiting, bye!')
			pass
