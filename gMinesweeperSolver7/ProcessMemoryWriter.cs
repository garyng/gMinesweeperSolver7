using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace gMinesweeperSolver7
{
	public class ProcessMemoryWriter
	{
		#region Constants

		public const int PROCESS_VM_WRITE = 0x0020;
		public const int PROCESS_VM_OPERATION = 0x0008;

		#endregion

		#region APIs

		//		HANDLE OpenProcess(
		//			DWORD dwDesiredAccess,  // access flag
		//			BOOL bInheritHandle,    // handle inheritance option
		//			DWORD dwProcessId       // process identifier
		//			);
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheritHandle, UInt32 dwProcessId);

		//		BOOL CloseHandle(
		//			HANDLE hObject   // handle to object
		//			);
		[DllImport("kernel32.dll")]
		public static extern Int32 CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 dwSize, out IntPtr lpNumberOfBytesWritten);

		#endregion

		#region Public Properties

		/// <summary>	
		/// Process from which to read		
		/// </summary>
		public Process Process
		{
			get
			{
				return _pProcess;
			}
			set
			{
				_pProcess = value;
			}
		}

		#endregion

		#region Public Functions

		public void OpenProcess()
		{
			_hProcess = openProcess(_pProcess.Id);
		}

		public int CloseHandle()
		{
			return closeHandle(_hProcess);
		}

		public void WriteProcessMemory(IntPtr memoryAddress, byte[] buffer, UInt32 size, out int bytesWritten)
		{
			writeProcessMemory(_hProcess, memoryAddress, buffer, size, out bytesWritten);
		}

		#endregion

		#region Private Fields

		private Process _pProcess;
		private IntPtr _hProcess = IntPtr.Zero;

		#endregion

		#region Private Functions

		private IntPtr openProcess(int processId)
		{
			IntPtr pHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 1, (uint)processId);
			return pHandle;
		}
		private int closeHandle(IntPtr handle)
		{
			int iRet = CloseHandle(handle);
			if (iRet == 0)
			{
				throw new Exception("CloseHandle() failed.");
			}
			return iRet;
		}
		private void writeProcessMemory(IntPtr handle, IntPtr address, byte[] buffer, uint size, out int bytesWritten)
		{
			//byte[] buffer = new byte[size];
			IntPtr ptrBytesWritten;

			//ReadProcessMemory(handle, address, buffer, size, out ptrBytesRead);
			WriteProcessMemory(handle, address, buffer, size, out ptrBytesWritten);

			bytesWritten = ptrBytesWritten.ToInt32();

		}



		#endregion

	}
}
