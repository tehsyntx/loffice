#!/bin/env python

"""
Loffice - Lazy Office Analyzer

Requirements:
- Microsoft Office
- WinDbg - https://msdn.microsoft.com/en-us/windows/hardware/hh852365
- WinAppDbg - http://winappdbg.sourceforge.net/
- pefile - https://github.com/erocarrera/pefile
- capstone - https://pypi.python.org/pypi/capstone-windows

Author: @tehsyntx
"""

from __future__ import print_function
from winappdbg import Debug, EventHandler
from time import strftime, gmtime
from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86
import os
import sys
import pefile
import random
import string
import logging
import warnings
import optparse
import mimetypes

# Setting up logger facilities.
if not os.path.exists('%s\\logs' % os.getcwd()):
	os.mkdir('%s\\logs' % os.getcwd())

logfile = '%s\\logs\\%s_%s.log' % (os.getcwd(), sys.argv[-1].split('\\')[-1], strftime('%Y%d%m%H%M%S', gmtime()))
logging.basicConfig(filename=logfile, format='%(asctime)s - %(levelname)s %(message)s')
logging.addLevelName( logging.INFO, '')
logging.addLevelName( logging.DEBUG, '[%s] ' % logging.getLevelName(logging.DEBUG))
logging.addLevelName( logging.ERROR, '[%s] ' % logging.getLevelName(logging.ERROR))
logging.addLevelName( logging.WARNING, '[%s] ' % logging.getLevelName(logging.WARNING))
logger = logging.getLogger()

# Root path to Microsoft Office suite.
DEFAULT_OFFICE_PATH = os.environ['PROGRAMFILES'] + '\\Microsoft Office\\Office14'

results = {'instr' : {}, 'filehandle' : {}, 'urls' : [], 'procs' : [], 'wmi' : []}
stats = { 'str' : 0, 'url' : 0, 'filew' : 0, 'filer' : 0, 'wmi' : 0, 'proc' : 0 }


def cb_crackurl(event):

	stats['url'] += 1

	proc = event.get_process()
	thread  = event.get_thread()

	if proc.get_bits() == 32:
		lpszUrl = thread.read_stack_dwords(2)[1]
	else:
		context = thread.get_context()
		lpszUrl = context['Rcx']

	url = proc.peek_string(lpszUrl, fUnicode=True)

	logger.info('FOUND URL: %s' % url)
	results['urls'].append(url)

	if exit_on == 'url':
		logger.info('Exiting on first URL, bye!')
		safe_exit('Found a URL, exiting as specified exit mode.\nURL: %s' % url)

	print_stats()


def cb_createfilew(event):

	proc = event.get_process()
	thread = event.get_thread()

	if proc.get_bits() == 32:
		lpFileName, dwDesiredAccess = thread.read_stack_dwords(3)[1:]
	else:
		context = thread.get_context()
		lpFileName = context['Rcx']
		dwDesiredAccess = context['Rdx']

	access = ''
	if dwDesiredAccess & 0x80000000: access += 'R'
	if dwDesiredAccess & 0x40000000: access += 'W'

	filename = proc.peek_string(lpFileName, fUnicode=True)

	if access is not '' and '\\\\' not in filename[:2]: # Exclude PIPE and WMIDataDevice
		if writes_only and 'W' in access:
			logger.info('Opened file handle (access: %s):%s' % (access, filename))
		elif not writes_only:
			logger.info('Opened file handle (access: %s):%s' % (access, filename))

		if results['filehandle'].has_key(filename):
			results['filehandle'][filename].append(access)
		else:
			results['filehandle'][filename] = []
			results['filehandle'][filename].append(access)

		if 'W' in access:
			stats['filew'] += 1
		else:
			stats['filer'] += 1

	print_stats()


def cb_createprocess(event):

	stats['proc'] += 1

	proc = event.get_process()
	thread  = event.get_thread()

	if proc.get_bits() == 32:
		args = thread.read_stack_dwords(8)
		lpApplicationName = args[2]
		lpCommandLine = args[3]
		dwCreationFlags = args[7]
	else:
		context = thread.get_context()
		lpApplicationName = context['Rdx']
		lpCommandLine = context['R8']
		stack = thread.read_stack_qwords(8)
		dwCreationFlags = stack[7] & 0xff

	application = proc.peek_string(lpApplicationName, fUnicode=True)
	cmdline = proc.peek_string(lpCommandLine, fUnicode=True)

	logger.info('CreateProcess: App: "%s" Cmd: %s" CreationFlags: 0x%x' % (application, cmdline, dwCreationFlags))

	results['procs'].append({'cmd' : cmdline, 'app' : application, 'cflags' : dwCreationFlags})

	print_stats()

	if exit_on == 'url' and 'splwow64' not in application and dwCreationFlags != 0x4:
		logger.info('Process created before URL was found, exiting for safety.')
		safe_exit('A process was created before a URL was found, exiting before losing control')

	if exit_on == 'proc' and 'splwow64' not in application:
		logger.info('Exiting on process creation, bye!')
		safe_exit('A process was created, exiting via specified exit mode')


def cb_stubclient20(event):

	stats['wmi'] += 1

	proc = event.get_process()
	thread  = event.get_thread()

	logger.info('DETECTED WMI QUERY')

	if proc.get_bits() == 32:
		strQueryLanguage, strQuery = thread.read_stack_dwords(4)[2:]
	else:
		context = thread.get_context()
		strQueryLanguage = context['Rdx']
		strQuery = context['R8']

	language = proc.peek_string(strQueryLanguage, fUnicode=True)
	query = proc.peek_string(strQuery, fUnicode=True)

	logger.info('Language: %s' % language)
	logger.info('Query: %s' % query)

	r_query = {'query' : query, 'patched' : ''}

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
		r_query['patched'] = patched_query

		logger.info('Patched with: "%s"' % patched_query)

	results['wmi'].append(r_query)

	print_stats()


def cb_stubclient24(event):

	stats['wmi'] += 1

	proc = event.get_process()
	thread  = event.get_thread()

	if proc.get_bits() == 32:
		sObject, cObject = thread.read_stack_dwords(4)[2:]
	else:
		context = thread.get_context()
		sObject = context['Rdx']
		cObject = context['R8']

	object = proc.peek_string(sObject, fUnicode=True)
	method = proc.peek_string(cObject, fUnicode=True)

	if object.lower() == 'win32_process' and method.lower() == 'create':
		logger.info('Process creation via WMI detected')
		if exit_on == 'url' or exit_on == 'proc':
			logger.info('Exiting for safety')
			safe_exit('A process tried to be created via WMI')

	print_stats()


def cb_vbeinstr(event):

	# str1: search for string
	# str2: string to search in

	stats['str'] += 1

	thread = event.get_thread()
	proc = event.get_process()

	if proc.get_bits() == 32:
		str1, str2 = thread.read_stack_dwords(3)[1:]
	else:
		context = thread.get_context()
		str1 = context['Rdx']
		str2 = context['R8']

	s1 = proc.peek_string(str1, fUnicode=True)
	s2 = proc.peek_string(str2, fUnicode=True)

	logger.info('COMPARE:\n\tstr1: "%s"\n\tstr2: "%s"\n' % (s1, s2))

	if results['instr'].has_key(s2) and s1 not in results['instr'][s2]:
		results['instr'][s2].append(s1)
	else:
		results['instr'][s2] = []
		results['instr'][s2].append(s1)

	print_stats()


def cb_writeprocessmemory(event):

	global inject
	inject += 1
	thread = event.get_thread()
	proc = event.get_process()
	if proc.get_bits() == 32:
		hProc, lpBase, lpBuffer, nSize = thread.read_stack_dwords(5)[1:]
	else:
		context = thread.get_context()
		hProc = context['Rcx']
		lpBase = context['Rdx']
		lpBuffer = context['R8']
		nSize = context['R9']
		logging.info('WriteProcessMemory: Base: 0x%x, Buf: 0x%x, Size: 0x%x\n' % (lpBase, lpBuffer, nSize))

	logging.info('WriteProcessMemory called, inject = %d, suggests injection is at hand' % inject)

	if 'MZ' in proc.read(lpBuffer, 4):
		logging.info('Found MZ signature in buffer written to 0x%x' % lpBase)


def cb_zwresumethread(event):
	global inject
	if inject > 2 and exit_on == 'thread':
		logging.info('ResumeThread called, inject = %d, shutting down for safety' % inject)
		safe_exit('ResumeThread called, inject > 2, possible code injection.\nCheck for a suspended process')


def cb_getthreadcontext(event):
	global inject
	inject += 1
	logging.info('GetThreadContext called, inject = %d, suggests injection is at hand' % inject)


def cb_setthreadcontext(event):
	global inject
	inject += 1
	logger.info('SetThreadContext called, inject = %d, suggests injection is at hand' % inject)


def safe_exit(reason):
	logger.info('Exiting for safety...')
	display_summary()
	print('\n\nExiting for safety: %s' % reason)
	print('Remember to check the runtime log in the "logs" directory')
	sys.exit()


def print_stats():
	if logger.getEffectiveLevel() == 10:
		return
	else:
		msg = 'URL: %d  |  File(W): %d  |  File(R): %d  | Proc: %d  |  WMI: %d  |  StrCmp: %d\r' % (stats['url'], stats['filew'], stats['filer'], stats['proc'], stats['wmi'], stats['str'])
		print(msg, end='')


def display_summary():

	print('\n\n\t==== FILE HANDLES OPENED ====\n')
	for fname in results['filehandle'].keys():
		print('%s \t %s' % (','.join(list(set(results['filehandle'][fname]))), fname))

	print('\n\n\t==== STRING COMPARISONS ====\n')
	for sc in results['instr'].keys():
		print('\nSubject: %s' % sc.encode('ascii', errors='replace'))
		print('Search for: %s' % ', '.join(results['instr'][sc]))

	print('\n\n\t==== WMI QUERIES ====\n')
	for wmi in results['wmi']:
		if wmi['patched'] != '':
			print('Query: %s\n Patched with: %s\n' % (wmi['query'], wmi['patched']))
		else:
			print('Query: %s\n' % wmi['query'])

	print('\n\n\t==== URL ====\n')
	print('\n'.join(results['urls']))

	print('\n\n\t==== PROCESS CREATION ====\n')

	for proc in results['procs']:
		print('Cmd: %s\nApp: %s\nCreationFlags: 0x%x' % (proc['cmd'], proc['app'], proc['cflags']))


def randomString():
	return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(random.randint(5,15)))


def checkRecentDocuments():

	# Check number of Recent Documents (add fakes if needed)

	def addDocuments(existing, fakes):

		version = DEFAULT_OFFICE_PATH[-2:]
		apps = ['Word', 'Excel', 'PowerPoint']

		for app in apps:
			try:
				hKey = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Office\\%s.0\\%s\\File MRU' % (version, app), 0, _winreg.KEY_SET_VALUE)
			except:
				hKey = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Office\\%s.0\\%s\\File MRU' % (version, app))

			if existing <= 0:
				existing = 1

			for i in xrange(existing, fakes):
				name = randomString()
				_winreg.SetValueEx(hKey, 'Item %d' % i, 0, _winreg.REG_SZ, '[F00000000][T01D228AEF15B51C0][O00000000]*C:\\Documents\\%s.doc' % name)

			hKey.Close()


	try:
		import _winreg
	except ImportError:
		print('Can\'t import _winreg (needed for evasion)')

	version = DEFAULT_OFFICE_PATH[-2:]
	apps = ['Word', 'Excel', 'PowerPoint']

	for app in apps:
		try:
			hKey = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Microsoft\\Office\\%s.0\\%s\\File MRU' % (version, app))
			recent = _winreg.QueryInfoKey(hKey)[1] - 1 # Get number of recent documents
			hKey.Close()
		except:
			recent = 0

		fakes = random.randint(10, 15)
		if recent < 3:
			while True:
				choice = raw_input('Recent docs < 3:\nWant to add some more, like %d fake ones (for Word, Excel & PowerPoint)? (y/n) ' % fakes)
				if choice == 'y':
					addDocuments(recent, fakes)
					print('Fakes added, moving on :)\n')
					return
				elif choice == 'n':
					print('Aight, but be aware that the macro might not run as expected... :(\n')
					return


def find_instr_addr(mod_name, bits):

	dll = pefile.PE(mod_name)

	for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
		if entry.name == 'rtcInStrChar':
			exp_addr = entry.address
			break

	for imp in dll.DIRECTORY_ENTRY_IMPORT:
		for entry in imp.imports:
			if entry.name == 'SysFreeString':
				imp_addr = entry.address
				break

	memory = dll.get_memory_mapped_image()
	if bits == 32:
		dsm = Cs(CS_ARCH_X86, CS_MODE_32)
	else:
		dsm = Cs(CS_ARCH_X86, CS_MODE_64)

	for op in dsm.disasm(memory[exp_addr:exp_addr + 0xA0], (exp_addr + dll.OPTIONAL_HEADER.ImageBase)):
		if op.mnemonic == 'call':
			last_call = op.op_str
		if op.mnemonic == 'ret':
			break
	next_func = int(last_call, 16) - dll.OPTIONAL_HEADER.ImageBase
	calls = 0
	call_free = 0
	for op in dsm.disasm(memory[next_func:next_func + 0x200], (next_func + dll.OPTIONAL_HEADER.ImageBase)):

		if op.mnemonic == 'call' and ('0x%x' % imp_addr in op.op_str or 'qword ptr' in op.op_str):
			call_free += 1
		if call_free > 2:
			return last_call
		if op.mnemonic == 'call':
			last_call = op.address - dll.OPTIONAL_HEADER.ImageBase
		if op.mnemonic == 'ret':
			return


class EventHandler(EventHandler):

	def load_dll(self, event):

		module = event.get_module()
		proc = event.get_process()
		pid = event.get_pid()

		def setup_breakpoint(modulename, function, callback):

			if module.match_name(modulename + '.dll'):
				if isinstance(function, long):
					address = module.lpBaseOfDll + function
				else:
					address = module.resolve(function)
				try:
					if address:
						event.debug.break_at(pid, address, callback)
					else:
						print("Couldn't resolve or address not belong to module: %s!%s" % (modulename, function))
						while True:
							choice = raw_input('Continue anyway? (y/n): ')
							if choice == 'y':
								break
							elif choice == 'n':
								sys.exit()
				except:
					print('Could not break at: %s!%s.' % (modulename, function))
					while True:
						choice = raw_input('Continue anyway? (y/n): ')
						if choice == 'y':
							break
						elif choice == 'n':
							sys.exit()


		setup_breakpoint('ntdll', 'ZwResumeThread', cb_zwresumethread)
		setup_breakpoint('kernel32', 'GetThreadContext', cb_getthreadcontext)
		setup_breakpoint('kernel32', 'SetThreadContext', cb_setthreadcontext)
		setup_breakpoint('kernel32', 'WriteProcessMemory', cb_writeprocessmemory)
		setup_breakpoint('kernel32', 'CreateProcessInternalW', cb_createprocess)
		setup_breakpoint('kernel32', 'CreateFileW', cb_createfilew)
		setup_breakpoint('wininet', 'InternetCrackUrlW', cb_crackurl)
		setup_breakpoint('winhttp', 'WinHttpCrackUrl', cb_crackurl)
		setup_breakpoint('ole32', 'ObjectStublessClient20', cb_stubclient20)
		setup_breakpoint('ole32', 'ObjectStublessClient24', cb_stubclient24)

		if module.match_name('vbe7.dll'):
			instr_addr = find_instr_addr(module.get_filename(), proc.get_bits())
			setup_breakpoint('vbe7', instr_addr, cb_vbeinstr)


def options():

	valid_types = ['auto', 'word', 'excel', 'power', 'script']
	valid_exit_ons = ['url', 'proc', 'thread', 'none']

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
	thread - Before resuming a suspended thread (RunPE style)
	none - Allow uniterupted execution (dangerous)

'''
	parser = optparse.OptionParser(usage=usage)
	parser.add_option('-v', '--verbose', dest='verbose', help='Verbose mode.', action='store_true')
	parser.add_option('-w', '--writes-only', dest='writes_only', help='Log file writes only (exclude reads)', action='store_true')
	parser.add_option('-p', '--path', dest='path', help='Path to the Microsoft Office suite.', default=DEFAULT_OFFICE_PATH)

	opts, args = parser.parse_args()

	if len(args) < 3:
		parser.print_help()
		sys.exit(0)

	if not os.path.exists(opts.path):
		print('Specified Office path does not exists: "%s"' % opts.path)
		sys.exit(1)

	if args[0] not in valid_types:
		print('Specified <type> is not recognized: "%s".' % args[0])
		sys.exit(1)

	if args[1] not in valid_exit_ons:
		print('Specified <exit-on> is not recognized: "%s".' % args[1])
		sys.exit(1)

	if not os.path.isfile(args[2]):
		print('Specified file to analyse does not exists: "%s"' % args[2])
		sys.exit(1)

	if opts.verbose:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)

	return (opts, args)


def setup_office_path(prog, filename, office_path):
	# TODO: rewrite the whole function
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
			logger.info('Could not detect type via mimetype')
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
				print('Failed to detect file\'s type!')
				sys.exit(1)

		logger.info('Auto-detected program to launch: "%s.exe"' % p)
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

	global inject
	global exit_on
	global writes_only

	(opts, args) = options()
	prog = args[0]
	exit_on = args[1]
	filename = args[2]
	writes_only = opts.writes_only
	inject = 0 
	print('\n\t\tLazy Office Analyzer\n')

	office_invoke = []
	office_invoke.append(setup_office_path(prog, filename, opts.path))

	logger.info('Using office path: "%s"' % office_invoke[0])
	office_invoke.append(filename) # Document to analyze

	logger.info('Invocation command: "%s"' % ' '.join(office_invoke))

	with Debug(EventHandler(), bKillOnExit = True) as debug:
		try:
			debug.execv(office_invoke)
		except Exception, e:
			if not os.path.exists(office_invoke[0]):
				print('Error launching application (%s), correct Office path?' % prog)
			else:
				print('Error launching: %s' % str(e))
			sys.exit()
		try:
			logger.info('Launching...')
			checkRecentDocuments()
			debug.loop()
		except KeyboardInterrupt:
			print('\nExiting, summary below...')
			pass
	display_summary()
	print('Remember to check the runtime log in the "logs" directory')
	print('Goodbye...\n')