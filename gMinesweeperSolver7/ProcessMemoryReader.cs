using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace gMinesweeperSolver7
{
	public class ProcessMemoryReader
	{
		#region Constants

		public const uint PROCESS_VM_READ = 0x0010;

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

		//		BOOL ReadProcessMemory(
		//			HANDLE hProcess,              // handle to the process
		//			LPCVOID lpBaseAddress,        // base of memory area
		//			LPVOID lpBuffer,              // data buffer
		//			SIZE_T nSize,                 // number of bytes to read
		//			SIZE_T * lpNumberOfBytesRead  // number of bytes read
		//			);
		[DllImport("kernel32.dll")]
		public static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);

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

		public byte[] ReadProcessMemory(IntPtr memoryAddress, uint sizeToRead, out int bytesRead)
		{
			return readProcessMemory(_hProcess, memoryAddress, sizeToRead, out bytesRead);
		}

		#endregion

		#region Private Fields

		private Process _pProcess;
		private IntPtr _hProcess = IntPtr.Zero;

		#endregion

		#region Private Functions

		private IntPtr openProcess(int processId)
		{
			IntPtr pHandle = OpenProcess(PROCESS_VM_READ, 1, (uint)processId);
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
		private byte[] readProcessMemory(IntPtr handle, IntPtr address, uint size, out int bytesRead)
		{
			byte[] buffer = new byte[size];
			IntPtr ptrBytesRead;

			ReadProcessMemory(handle, address, buffer, size, out ptrBytesRead);
			bytesRead = ptrBytesRead.ToInt32();

			return buffer;
		}

		#endregion

	}

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

		public void WriteProcessMemory(IntPtr memoryAddress,byte[] buffer,UInt32 size, out int bytesWritten)
		{
			writeProcessMemory(_hProcess,memoryAddress,buffer,size,out bytesWritten);
		}

		#endregion

		#region Private Fields

		private Process _pProcess;
		private IntPtr _hProcess = IntPtr.Zero;

		#endregion

		#region Private Functions

		private IntPtr openProcess(int processId)
		{
			IntPtr pHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE , 1, (uint)processId);
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
		private void writeProcessMemory(IntPtr handle, IntPtr address,byte[] buffer, uint size, out int bytesWritten)
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
