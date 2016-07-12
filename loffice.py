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
import os
import sys
import logging
import optparse
import mimetypes

# Setting up logger facilities.
logging.basicConfig(format='%(levelname)s%(message)s')
logging.addLevelName( logging.INFO, '')
logging.addLevelName( logging.DEBUG, '[%s] ' % logging.getLevelName(logging.DEBUG))
logging.addLevelName( logging.ERROR, '[%s] ' % logging.getLevelName(logging.ERROR))
logging.addLevelName( logging.WARNING, '[%s] ' % logging.getLevelName(logging.WARNING))
logger = logging.getLogger()

# Root path to Microsoft Office suite.
if os.environ['PROCESSOR_ARCHITECTURE'] == 'x86':
	DEFAULT_OFFICE_PATH = os.environ['PROGRAMFILES'] + '\\Microsoft Office\\Office14'
else:
	DEFAULT_OFFICE_PATH = os.environ['PROGRAMFILES'] + ' (x86)\\Microsoft Office\\Office14'


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

	access = ''
	if dwDesiredAccess & 0x80000000: access += 'R'
	if dwDesiredAccess & 0x40000000: access += 'W'

	if access is not '':
		logger.info('Opened file (access: %s):\n\t%s\n' % (access, proc.peek_string(lpFileName, fUnicode=True)))


def cb_createprocessw(event):
	proc = event.get_process()
	thread  = event.get_thread()

	lpApplicationName, lpCommandLine = thread.read_stack_dwords(3)[1:]
	application = proc.peek_string(lpApplicationName, fUnicode=True)
	cmdline = proc.peek_string(lpCommandLine, fUnicode=True)

	logger.info('CREATE PROCESS\n\tApp: "%s"\n\tCommand line: "%s"\n' % (application, cmdline))
	
	if exit_on == 'url' and 'splwow64' not in application:
		logger.info('Process created before URL was found, exiting for safety.')
		sys.exit()
		
	if exit_on == 'proc' and 'splwow64' not in application:
		logger.info('Exiting on process creation, bye!')
		sys.exit()


def cb_regsetvalueexw(event):
	proc = event.get_process()
	thread  = event.get_thread()

	hkey, lpValueName, _, dwType, lpData, cbData = thread.read_stack_dwords(7)[1:]

	# reg_sz = 1, reg_expand_sz = 2
	if dwType == 1 or dwType == 2:
		valuename = proc.peek_string(lpValueName, fUnicode=True)
		data = proc.peek_string(lpData, fUnicode=True)

		# TODO: Implement obtaining full registry path from given hkey.
		#		SHGetRegPath, NtQuerySystemInformation(..., SystemHandleInformation, ...), NtQueryKey(...), etc.

		path = valuename
		logger.info('REGISTRY MODIFICATION\n\tRegistry path: "%s"\n\tData: "%s"\n' % (path, data))


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

		logger.info('\tPatched with: "%s"' % patched_query)


class EventHandler(EventHandler):

	def load_dll(self, event):

		module = event.get_module()
		pid = event.get_pid()

		def setup_breakpoint(modulename, function, callback):
			if module.match_name(modulename + '.dll'):
				address = module.resolve(function)
				try:
					if address:
						event.debug.break_at(pid, address, callback)
					else:
						logger.warning("Couldn't resolve or address not belong to module: %s!%s" % (modulename, function))
				except:
					logger.error('Could not break at: %s!%s.' % (modulename, function))

		setup_breakpoint('kernel32', 'CreateProcessW', cb_createprocessw)
		setup_breakpoint('kernel32', 'CreateFileW', cb_createfilew)
		setup_breakpoint('wininet', 'InternetCrackUrlW', cb_crackurl)
		setup_breakpoint('winhttp', 'WinHttpCrackUrl', cb_crackurl)
		setup_breakpoint('ole32', 'ObjectStublessClient20', cb_stubclient20)
		

def options():

	valid_types = ['auto', 'word', 'excel', 'power', 'script']
	valid_exit_ons = ['url', 'proc', 'none']

	usage = '''
	%prog [options] <type> <exit-on> <filename>
	
Type:
	auto   - Automatically detect program to launch
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

	if len(args) < 3:
		parser.print_help()
		sys.exit(0)

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


def setup_office_path(prog, filename, office_path):

	def detect_ext(exts, type_):
		for ext in exts:
			if filename.endswith('.' + ext):
				return type_
		return None

	if prog == 'auto':

		# Stage 1: Let the Mime detect file type.
		guessed = mimetypes.MimeTypes().guess_type(filename)
		p = None

		if 'msword' in guessed or 'officedocument.wordprocessing' in guessed:
			p = 'WINWORD'
		elif 'ms-excel' in guessed or 'officedocument.spreadsheet' in guessed:
			p = 'EXCEL'
		elif 'ms-powerpoint' in guessed or 'officedocument.presentation' in guessed:
			p = 'POWERPNT'


		# Stage 2: Detect based on extension
		if p == None:
			logger.debug('Could not detect type via mimetype')
			word = ['doc', 'docx', 'docm', 'dot', 'dotx', 'docb', 'dotm']
			#word_patterns = ['MSWordDoc', 'Word.Document', 'word/_rels/document', 'word/font']
			excel = ['xls', 'xlsx', 'xlsm', 'xlt', 'xlm', 'xltx', 'xltm', 'xlsb', 'xla', 'xlw', 'xlam']
			#excel_patterns = ['xl/_rels/workbook', 'xl/worksheets/', 'Microsoft Excel', 'Excel.Sheet']
			ppt = ['ppt', 'pptx', 'pptm', 'pot', 'pps', 'potx', 'potm', 'ppam', 'ppsx', 'sldx', 'sldm']
			#ppt_patterns = ['drs/shapexml.xml', 'Office PowerPoint', 'ppt/slideLayouts', 'ppt/presentation']
			script = ['js', 'jse', 'vbs', 'vbe', 'vb']

			p = detect_ext(word, 'WINWORD')
			if not p:
				p = detect_ext(excel, 'EXCEL')
				if not p:
					p = detect_ext(ppt, 'POWERPNT')
					if not p:
						p = detect_ext(script, 'system32\\wscript')
		
		if p == None:
			logger.error('Failed to detect file\'s type!')
			sys.exit(1)

		logger.debug('Auto-detected program to launch: "%s.exe"' % p)
		return '%s\\%s.exe' % (office_path, p)
	
	elif prog == 'script':
		return '%s\\system32\\wscript.exe' % os.environ['WINDIR']
	elif prog == 'word':
		return '%s\\WINWORD.EXE' % office_path
	elif prog == 'excel':
		return '%s\\EXCEL.EXE' % office_path
	elif prog == 'power':
		return '%s\\POWERPNT.EXE' % office_path


if __name__ == "__main__":

	global exit_on

	(opts, args) = options()
	prog = args[0]
	exit_on = args[1]
	filename = args[2]

	logger.info('\n\tLazy Office Analyzer - Analyze documents with WinDbg\n')

	office_invoke = []
	office_invoke.append(setup_office_path(prog, filename, opts.path))

	logger.debug('Using office path:')
	logger.debug('\t"%s"' % office_invoke[0])
		
	office_invoke.append(filename) # Document to analyze

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
