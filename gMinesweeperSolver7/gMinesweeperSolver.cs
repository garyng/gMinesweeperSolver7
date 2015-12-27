using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace gMinesweeperSolver7
{
	public class gMinesweeperSolver
	{
		#region APIs

		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_DOS_HEADER
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
			public char[] e_magic;       // Magic number
			public UInt16 e_cblp;    // Bytes on last page of file
			public UInt16 e_cp;      // Pages in file
			public UInt16 e_crlc;    // Relocations
			public UInt16 e_cparhdr;     // Size of header in paragraphs
			public UInt16 e_minalloc;    // Minimum extra paragraphs needed
			public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
			public UInt16 e_ss;      // Initial (relative) SS value
			public UInt16 e_sp;      // Initial SP value
			public UInt16 e_csum;    // Checksum
			public UInt16 e_ip;      // Initial IP value
			public UInt16 e_cs;      // Initial (relative) CS value
			public UInt16 e_lfarlc;      // File address of relocation table
			public UInt16 e_ovno;    // Overlay number
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public UInt16[] e_res1;    // Reserved words
			public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
			public UInt16 e_oeminfo;     // OEM information; e_oemid specific
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
			public UInt16[] e_res2;    // Reserved words
			public Int32 e_lfanew;      // File address of new exe header

			private string _e_magic
			{
				get { return new string(e_magic); }
			}

			public bool isValid
			{
				get { return _e_magic == "MZ"; }
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_FILE_HEADER
		{
			public UInt16 Machine;
			public UInt16 NumberOfSections;
			public UInt32 TimeDateStamp;
			public UInt32 PointerToSymbolTable;
			public UInt32 NumberOfSymbols;
			public UInt16 SizeOfOptionalHeader;
			public UInt16 Characteristics;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_DATA_DIRECTORY
		{
			public UInt32 VirtualAddress;
			public UInt32 Size;
		}

		private enum MachineType : ushort
		{
			Native = 0,
			I386 = 0x014c,
			Itanium = 0x0200,
			x64 = 0x8664
		}
		private enum MagicType : ushort
		{
			IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
			IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
		}
		private enum SubSystemType : ushort
		{
			IMAGE_SUBSYSTEM_UNKNOWN = 0,
			IMAGE_SUBSYSTEM_NATIVE = 1,
			IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
			IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
			IMAGE_SUBSYSTEM_POSIX_CUI = 7,
			IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
			IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
			IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
			IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
			IMAGE_SUBSYSTEM_EFI_ROM = 13,
			IMAGE_SUBSYSTEM_XBOX = 14

		}
		private enum DllCharacteristicsType : ushort
		{
			RES_0 = 0x0001,
			RES_1 = 0x0002,
			RES_2 = 0x0004,
			RES_3 = 0x0008,
			IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
			IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
			IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
			IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
			IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
			IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
			RES_4 = 0x1000,
			IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct IMAGE_OPTIONAL_HEADER32
		{
			[FieldOffset(0)]
			public MagicType Magic;

			[FieldOffset(2)]
			public byte MajorLinkerVersion;

			[FieldOffset(3)]
			public byte MinorLinkerVersion;

			[FieldOffset(4)]
			public uint SizeOfCode;

			[FieldOffset(8)]
			public uint SizeOfInitializedData;

			[FieldOffset(12)]
			public uint SizeOfUninitializedData;

			[FieldOffset(16)]
			public uint AddressOfEntryPoint;

			[FieldOffset(20)]
			public uint BaseOfCode;

			// PE32 contains this additional field
			[FieldOffset(24)]
			public uint BaseOfData;

			[FieldOffset(28)]
			public uint ImageBase;

			[FieldOffset(32)]
			public uint SectionAlignment;

			[FieldOffset(36)]
			public uint FileAlignment;

			[FieldOffset(40)]
			public ushort MajorOperatingSystemVersion;

			[FieldOffset(42)]
			public ushort MinorOperatingSystemVersion;

			[FieldOffset(44)]
			public ushort MajorImageVersion;

			[FieldOffset(46)]
			public ushort MinorImageVersion;

			[FieldOffset(48)]
			public ushort MajorSubsystemVersion;

			[FieldOffset(50)]
			public ushort MinorSubsystemVersion;

			[FieldOffset(52)]
			public uint Win32VersionValue;

			[FieldOffset(56)]
			public uint SizeOfImage;

			[FieldOffset(60)]
			public uint SizeOfHeaders;

			[FieldOffset(64)]
			public uint CheckSum;

			[FieldOffset(68)]
			public SubSystemType Subsystem;

			[FieldOffset(70)]
			public DllCharacteristicsType DllCharacteristics;

			[FieldOffset(72)]
			public uint SizeOfStackReserve;

			[FieldOffset(76)]
			public uint SizeOfStackCommit;

			[FieldOffset(80)]
			public uint SizeOfHeapReserve;

			[FieldOffset(84)]
			public uint SizeOfHeapCommit;

			[FieldOffset(88)]
			public uint LoaderFlags;

			[FieldOffset(92)]
			public uint NumberOfRvaAndSizes;

			[FieldOffset(96)]
			public IMAGE_DATA_DIRECTORY ExportTable;

			[FieldOffset(104)]
			public IMAGE_DATA_DIRECTORY ImportTable;

			[FieldOffset(112)]
			public IMAGE_DATA_DIRECTORY ResourceTable;

			[FieldOffset(120)]
			public IMAGE_DATA_DIRECTORY ExceptionTable;

			[FieldOffset(128)]
			public IMAGE_DATA_DIRECTORY CertificateTable;

			[FieldOffset(136)]
			public IMAGE_DATA_DIRECTORY BaseRelocationTable;

			[FieldOffset(144)]
			public IMAGE_DATA_DIRECTORY Debug;

			[FieldOffset(152)]
			public IMAGE_DATA_DIRECTORY Architecture;

			[FieldOffset(160)]
			public IMAGE_DATA_DIRECTORY GlobalPtr;

			[FieldOffset(168)]
			public IMAGE_DATA_DIRECTORY TLSTable;

			[FieldOffset(176)]
			public IMAGE_DATA_DIRECTORY LoadConfigTable;

			[FieldOffset(184)]
			public IMAGE_DATA_DIRECTORY BoundImport;

			[FieldOffset(192)]
			public IMAGE_DATA_DIRECTORY IAT;

			[FieldOffset(200)]
			public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

			[FieldOffset(208)]
			public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

			[FieldOffset(216)]
			public IMAGE_DATA_DIRECTORY Reserved;
		}
		[StructLayout(LayoutKind.Explicit)]
		private struct IMAGE_OPTIONAL_HEADER64
		{
			[FieldOffset(0)]
			public MagicType Magic;

			[FieldOffset(2)]
			public byte MajorLinkerVersion;

			[FieldOffset(3)]
			public byte MinorLinkerVersion;

			[FieldOffset(4)]
			public uint SizeOfCode;

			[FieldOffset(8)]
			public uint SizeOfInitializedData;

			[FieldOffset(12)]
			public uint SizeOfUninitializedData;

			[FieldOffset(16)]
			public uint AddressOfEntryPoint;

			[FieldOffset(20)]
			public uint BaseOfCode;

			[FieldOffset(24)]
			public ulong ImageBase;

			[FieldOffset(32)]
			public uint SectionAlignment;

			[FieldOffset(36)]
			public uint FileAlignment;

			[FieldOffset(40)]
			public ushort MajorOperatingSystemVersion;

			[FieldOffset(42)]
			public ushort MinorOperatingSystemVersion;

			[FieldOffset(44)]
			public ushort MajorImageVersion;

			[FieldOffset(46)]
			public ushort MinorImageVersion;

			[FieldOffset(48)]
			public ushort MajorSubsystemVersion;

			[FieldOffset(50)]
			public ushort MinorSubsystemVersion;

			[FieldOffset(52)]
			public uint Win32VersionValue;

			[FieldOffset(56)]
			public uint SizeOfImage;

			[FieldOffset(60)]
			public uint SizeOfHeaders;

			[FieldOffset(64)]
			public uint CheckSum;

			[FieldOffset(68)]
			public SubSystemType Subsystem;

			[FieldOffset(70)]
			public DllCharacteristicsType DllCharacteristics;

			[FieldOffset(72)]
			public ulong SizeOfStackReserve;

			[FieldOffset(80)]
			public ulong SizeOfStackCommit;

			[FieldOffset(88)]
			public ulong SizeOfHeapReserve;

			[FieldOffset(96)]
			public ulong SizeOfHeapCommit;

			[FieldOffset(104)]
			public uint LoaderFlags;

			[FieldOffset(108)]
			public uint NumberOfRvaAndSizes;

			[FieldOffset(112)]
			public IMAGE_DATA_DIRECTORY ExportTable;

			[FieldOffset(120)]
			public IMAGE_DATA_DIRECTORY ImportTable;

			[FieldOffset(128)]
			public IMAGE_DATA_DIRECTORY ResourceTable;

			[FieldOffset(136)]
			public IMAGE_DATA_DIRECTORY ExceptionTable;

			[FieldOffset(144)]
			public IMAGE_DATA_DIRECTORY CertificateTable;

			[FieldOffset(152)]
			public IMAGE_DATA_DIRECTORY BaseRelocationTable;

			[FieldOffset(160)]
			public IMAGE_DATA_DIRECTORY Debug;

			[FieldOffset(168)]
			public IMAGE_DATA_DIRECTORY Architecture;

			[FieldOffset(176)]
			public IMAGE_DATA_DIRECTORY GlobalPtr;

			[FieldOffset(184)]
			public IMAGE_DATA_DIRECTORY TLSTable;

			[FieldOffset(192)]
			public IMAGE_DATA_DIRECTORY LoadConfigTable;

			[FieldOffset(200)]
			public IMAGE_DATA_DIRECTORY BoundImport;

			[FieldOffset(208)]
			public IMAGE_DATA_DIRECTORY IAT;

			[FieldOffset(216)]
			public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

			[FieldOffset(224)]
			public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

			[FieldOffset(232)]
			public IMAGE_DATA_DIRECTORY Reserved;
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct IMAGE_NT_HEADERS32
		{
			[FieldOffset(0)]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public char[] Signature;

			[FieldOffset(4)]
			public IMAGE_FILE_HEADER FileHeader;

			[FieldOffset(24)]
			public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

			private string _Signature
			{
				get { return new string(Signature); }
			}

			public bool isValid
			{
				get { return _Signature == "PE\0\0" && (OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC || OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC); }
			}
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct IMAGE_SECTION_HEADER
		{
			[FieldOffset(0)]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public char[] Name;

			[FieldOffset(8)]
			public UInt32 VirtualSize;

			[FieldOffset(12)]
			public UInt32 VirtualAddress;

			[FieldOffset(16)]
			public UInt32 SizeOfRawData;

			[FieldOffset(20)]
			public UInt32 PointerToRawData;

			[FieldOffset(24)]
			public UInt32 PointerToRelocations;

			[FieldOffset(28)]
			public UInt32 PointerToLinenumbers;

			[FieldOffset(32)]
			public UInt16 NumberOfRelocations;

			[FieldOffset(34)]
			public UInt16 NumberOfLinenumbers;

			[FieldOffset(36)]
			public DataSectionFlags Characteristics;

			public string Section
			{
				get { return new string(Name); }
			}
		}
		[Flags]
		private enum DataSectionFlags : uint
		{
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeReg = 0x00000000,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeDsect = 0x00000001,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeNoLoad = 0x00000002,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeGroup = 0x00000004,
			/// <summary>
			/// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
			/// </summary>
			TypeNoPadded = 0x00000008,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeCopy = 0x00000010,
			/// <summary>
			/// The section contains executable code.
			/// </summary>
			ContentCode = 0x00000020,
			/// <summary>
			/// The section contains initialized data.
			/// </summary>
			ContentInitializedData = 0x00000040,
			/// <summary>
			/// The section contains uninitialized data.
			/// </summary>
			ContentUninitializedData = 0x00000080,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			LinkOther = 0x00000100,
			/// <summary>
			/// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
			/// </summary>
			LinkInfo = 0x00000200,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			TypeOver = 0x00000400,
			/// <summary>
			/// The section will not become part of the image. This is valid only for object files.
			/// </summary>
			LinkRemove = 0x00000800,
			/// <summary>
			/// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
			/// </summary>
			LinkComDat = 0x00001000,
			/// <summary>
			/// Reset speculative exceptions handling bits in the TLB entries for this section.
			/// </summary>
			NoDeferSpecExceptions = 0x00004000,
			/// <summary>
			/// The section contains data referenced through the global pointer (GP).
			/// </summary>
			RelativeGP = 0x00008000,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			MemPurgeable = 0x00020000,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			Memory16Bit = 0x00020000,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			MemoryLocked = 0x00040000,
			/// <summary>
			/// Reserved for future use.
			/// </summary>
			MemoryPreload = 0x00080000,
			/// <summary>
			/// Align data on a 1-byte boundary. Valid only for object files.
			/// </summary>
			Align1Bytes = 0x00100000,
			/// <summary>
			/// Align data on a 2-byte boundary. Valid only for object files.
			/// </summary>
			Align2Bytes = 0x00200000,
			/// <summary>
			/// Align data on a 4-byte boundary. Valid only for object files.
			/// </summary>
			Align4Bytes = 0x00300000,
			/// <summary>
			/// Align data on an 8-byte boundary. Valid only for object files.
			/// </summary>
			Align8Bytes = 0x00400000,
			/// <summary>
			/// Align data on a 16-byte boundary. Valid only for object files.
			/// </summary>
			Align16Bytes = 0x00500000,
			/// <summary>
			/// Align data on a 32-byte boundary. Valid only for object files.
			/// </summary>
			Align32Bytes = 0x00600000,
			/// <summary>
			/// Align data on a 64-byte boundary. Valid only for object files.
			/// </summary>
			Align64Bytes = 0x00700000,
			/// <summary>
			/// Align data on a 128-byte boundary. Valid only for object files.
			/// </summary>
			Align128Bytes = 0x00800000,
			/// <summary>
			/// Align data on a 256-byte boundary. Valid only for object files.
			/// </summary>
			Align256Bytes = 0x00900000,
			/// <summary>
			/// Align data on a 512-byte boundary. Valid only for object files.
			/// </summary>
			Align512Bytes = 0x00A00000,
			/// <summary>
			/// Align data on a 1024-byte boundary. Valid only for object files.
			/// </summary>
			Align1024Bytes = 0x00B00000,
			/// <summary>
			/// Align data on a 2048-byte boundary. Valid only for object files.
			/// </summary>
			Align2048Bytes = 0x00C00000,
			/// <summary>
			/// Align data on a 4096-byte boundary. Valid only for object files.
			/// </summary>
			Align4096Bytes = 0x00D00000,
			/// <summary>
			/// Align data on an 8192-byte boundary. Valid only for object files.
			/// </summary>
			Align8192Bytes = 0x00E00000,
			/// <summary>
			/// The section contains extended relocations.
			/// </summary>
			LinkExtendedRelocationOverflow = 0x01000000,
			/// <summary>
			/// The section can be discarded as needed.
			/// </summary>
			MemoryDiscardable = 0x02000000,
			/// <summary>
			/// The section cannot be cached.
			/// </summary>
			MemoryNotCached = 0x04000000,
			/// <summary>
			/// The section is not pageable.
			/// </summary>
			MemoryNotPaged = 0x08000000,
			/// <summary>
			/// The section can be shared in memory.
			/// </summary>
			MemoryShared = 0x10000000,
			/// <summary>
			/// The section can be executed as code.
			/// </summary>
			MemoryExecute = 0x20000000,
			/// <summary>
			/// The section can be read.
			/// </summary>
			MemoryRead = 0x40000000,
			/// <summary>
			/// The section can be written to.
			/// </summary>
			MemoryWrite = 0x80000000
		}

		[DllImport("user32.dll", EntryPoint = "SetForegroundWindow")]
		private static extern int SetForegroundWindow(IntPtr hwnd);
		[DllImport("user32.dll")]
		private static extern bool GetWindowRect(IntPtr hwnd, ref Rect rectangle);

		[StructLayout(LayoutKind.Sequential)]
		private struct Rect
		{
			public int Left, Top, Right, Bottom;

			public Rect(int left, int top, int right, int bottom)
			{
				Left = left;
				Top = top;
				Right = right;
				Bottom = bottom;
			}

			public int X
			{
				get { return Left; }
				set { Right -= (Left - value); Left = value; }
			}

			public int Y
			{
				get { return Top; }
				set { Bottom -= (Top - value); Top = value; }
			}

			public int Height
			{
				get { return Bottom - Top; }
				set { Bottom = value + Top; }
			}

			public int Width
			{
				get { return Right - Left; }
				set { Right = value + Left; }
			}

			public static bool operator ==(Rect r1, Rect r2)
			{
				return r1.Equals(r2);
			}

			public static bool operator !=(Rect r1, Rect r2)
			{
				return !r1.Equals(r2);
			}

			public bool Equals(Rect r)
			{
				return r.Left == Left && r.Top == Top && r.Right == Right && r.Bottom == Bottom;
			}

			public override string ToString()
			{
				return string.Format(System.Globalization.CultureInfo.CurrentCulture, "{{Left={0},Top={1},Right={2},Bottom={3}}}", Left, Top, Right, Bottom);
			}
		}

		[DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
		private static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint cButtons, uint dwExtraInfo);

		private const int MOUSEEVENTF_LEFTDOWN = 0x02;
		private const int MOUSEEVENTF_LEFTUP = 0x04;
		private const int MOUSEEVENTF_RIGHTDOWN = 0x08;
		private const int MOUSEEVENTF_RIGHTUP = 0x10;


		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool SetCursorPos(int X, int Y);

		[DllImport("user32.dll")]
		private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

		private static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
		private static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);

		private const UInt32 SWP_NOSIZE = 0x0001;
		private const UInt32 SWP_NOMOVE = 0x0002;
		private const UInt32 SWP_SHOWWINDOW = 0x0040;

		private const int SW_SHOWNORMAL = 1;
		private const int SW_SHOWMAXIMIZED = 3;
		private const int SW_RESTORE = 9;

		[DllImport("user32.dll")]
		private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

		#endregion

		#region Private Structs

		[StructLayout(LayoutKind.Sequential)]
		private struct Board
		{
			public UInt32 unused1;
			public UInt32 MineCount;
			public UInt32 Height;
			public UInt32 Width;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public UInt32[] unused2;
			public UInt32 Difficulty;
			public UInt32 HitX;
			public UInt32 HitY;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
			public UInt32[] unused3;
			public UInt32 MineArrayPtr;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct Game
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public UInt32[] unused1;
			public UInt32 BoardPtr;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct ArrayA
		{
			public UInt32 unused1;
			public UInt32 unused2;
			public UInt32 unused3;
			public UInt32 ArrayBPtr;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct ArrayB
		{
			public UInt32 unused1;
			public UInt32 unused2;
			public UInt32 unused3;
			public UInt32 ByteArrayPtr;
		}

		#endregion

		#region Private Global Variable

		private Process _pMine = new Process();
		private IntPtr _ipBaseAdd;
		private int _iModuleSize;
		private ProcessMemoryReader _pmr = new ProcessMemoryReader();
		private IntPtr _ipHwnd;
		private Rect _rRect = new Rect();

		#endregion


		private const string MINESWEEPER_PROCESS_NAME = "minesweeper";
		private const string MINESWEEPER_EXE_PATH = @"C:\Program Files\Microsoft Games\Minesweeper\MineSweeper.exe";

		public void Solve()
		{
			solve();
		}

		private void solve()
		{
			_pMine = findProcess(MINESWEEPER_PROCESS_NAME, MINESWEEPER_EXE_PATH);

			Thread.Sleep(500);	// Sleep a while

			ProcessModule pmMine = _pMine.MainModule;
			_ipBaseAdd = pmMine.BaseAddress;
			_iModuleSize = pmMine.ModuleMemorySize;
			_ipHwnd = getHwnd(_pMine);
			


			bringWindowToFront(_ipHwnd);
			setTopMost(_ipHwnd, false);

			Thread.Sleep(500); // Sleep, just sleep

			_rRect = getWindowRect(_ipHwnd);

			_pmr = readerOpenProcess(_pMine);
			IMAGE_SECTION_HEADER ish = findSection(_pmr, _ipBaseAdd, _iModuleSize, ".data");

			// Anonymous method FTW!
			IntPtr iGamePtr = (IntPtr)readMemoryToT<UInt32>(
				_pmr,
				_ipBaseAdd + (int)ish.VirtualAddress + 0x88B4, 
				new Func<byte[], UInt32>(delegate(byte[] buffer) 
					{
						return BitConverter.ToUInt32(buffer, 0); 
					}));

			Game game = bytesToStruct<Game>(_pmr, iGamePtr);

			IntPtr iBoardPtr = (IntPtr)game.BoardPtr;
			Board board = bytesToStruct<Board>(_pmr, iBoardPtr);

			IntPtr iArrayAPtr = (IntPtr)board.MineArrayPtr;
			ArrayA arrayA = bytesToStruct<ArrayA>(_pmr, iArrayAPtr);

			IntPtr iArrayBPtr = (IntPtr)arrayA.ArrayBPtr;
			List<UInt32> lArrayBPtr = pointersToList(
				_pmr, 
				(int)board.Width, 
				new Func<int,IntPtr>(delegate(int index)
					{
						return iArrayBPtr + Marshal.SizeOf(typeof(UInt32)) * index;
					}),
				new Func<byte[], UInt32>(delegate(byte[] buffer) 
					{ 
						return BitConverter.ToUInt32(buffer, 0); 
					}));

			List<ArrayB> lArrayB = pointersToList(
				_pmr, 
				lArrayBPtr.Count, 
				new Func<int, IntPtr>(delegate(int index) 
					{
						return (IntPtr)lArrayBPtr[index];
					}), 
				new Func<byte[], ArrayB>(delegate(byte[] buffer)
					{ 
						return buffer.ToStruct<ArrayB>(); 
					}));

			bool isEmpty;
			int[,] iMines = pointersToMinesArray(_pmr,board,lArrayB,out isEmpty);
			if (isEmpty)
			{
				initMinesweeper(_rRect);
				iMines = pointersToMinesArray(_pmr, board, lArrayB, out isEmpty);
			}

			printMinesArray(iMines, (int)board.Height, (int)board.Width);

			clickMines(_rRect, iMines, (int)board.Height, (int)board.Width);

			readerCloseHandle(_pmr);
		}

		private int[,] pointersToMinesArray(ProcessMemoryReader pmr, Board board, List<ArrayB> lArrayB, out bool isEmpty)
		{
			int[,] iMines = new int[board.Height, board.Width];
			isEmpty = true;
			int sum = 0;
			for (int y = 0; y < board.Width; y++)
			{
				for (int x = 0; x < board.Height; x++)
				{
					int mine = readMemoryToT<byte>(
						pmr, 
						(IntPtr)lArrayB[y].ByteArrayPtr + x, 
						new Func<byte[], byte>(delegate(byte[] buffer) 
							{
								return buffer[0]; 
							}));
					sum += mine;
					iMines[x, y] = mine;
				}
			}
			isEmpty = sum == 0;
			return iMines;
		}
		private void initMinesweeper(Rect rect)
		{
			mouseClick(rect, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, 1, 1);
			mouseClick(rect, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, 1, 1);
			Thread.Sleep(100);
		}

		private void clickMines(Rect rect, int[,] minesArray, int height, int width)
		{
			for (int y = 0; y < height; y++)
			{
				for (int x = 0; x < width; x++)
				{
					if (minesArray[y, x] == 0) //Left click
					{
						mouseClick(rect, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, x, y);
					}
					else if (minesArray[y, x] == 1) //Right click
					{
						mouseClick(rect, MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, x, y);
					}
					// -1 = No Click
					Thread.Sleep(20);
				}
			}
		}

		private void mouseClick(Rect rect, uint dwFlags, int x, int y)
		{
			int xCoor = rect.X + 40 + 18 * x + 8;
			int yCoor = rect.Y + 80 + 18 * y + 8;
			SetCursorPos(xCoor, yCoor);
			mouse_event(dwFlags, (uint)xCoor, (uint)yCoor, 0, 0);
		}

		private void printMinesArray(int[,] minesArray, int height, int width)
		{
			for (int y = 0; y < height; y++)
			{
				for (int x = 0; x < width; x++)
				{
					//Console.Write(minesArray[y, x]);
					if (minesArray[y, x] == 0)
					{
						Console.Write(calSurroundMinesSum(minesArray, x, y, height, width));
					}
					else
					{
						Console.Write("X");
					}
				}
				Console.WriteLine();
			}
		}
		private int calSurroundMinesSum(int[,] minesArray, int x, int y, int height, int width)
		{
			int sum = 0;
			//Right
			if (y < height - 1 && minesArray[y + 1, x] == 1)
			{
				sum += 1;
			}
			//Up Right
			if (y < height - 1 && x > 0 && minesArray[y + 1, x - 1] == 1)
			{
				sum += 1;
			}
			//Down Right
			if (y < height - 1 && x < width - 1 && minesArray[y + 1, x + 1] == 1)
			{
				sum += 1;
			}
			//Left
			if (y > 0 && minesArray[y - 1, x] == 1)
			{
				sum += 1;
			}
			//Left Up
			if (y > 0 && x > 0 && minesArray[y - 1, x - 1] == 1)
			{
				sum += 1;
			}
			//Left Down
			if (y > 0 && x < width - 1 && minesArray[y - 1, x + 1] == 1)
			{
				sum += 1;
			}
			//Up
			if (x > 0 && minesArray[y, x - 1] == 1)
			{
				sum += 1;
			}
			//Down
			if (x < width - 1 && minesArray[y, x + 1] == 1)
			{
				sum += 1;
			}
			return sum;
		}

		private Process findProcess(string processName, string exePath )
		{
			Process[] pr = Process.GetProcessesByName(processName);
			if (pr.Count() == 0)
			{
				return Process.Start(exePath);
			}

			return pr[0];
		}
		private IntPtr getHwnd(Process proc)
		{
			return proc.MainWindowHandle;
		}
		private void bringWindowToFront(IntPtr hwnd)
		{
			ShowWindow(hwnd, SW_SHOWNORMAL);
			ShowWindow(hwnd, SW_RESTORE);
			SetForegroundWindow(hwnd);
		}
		private void setTopMost(IntPtr hwnd, bool cancelTopMost)
		{
			SetWindowPos(hwnd, cancelTopMost ? HWND_NOTOPMOST : HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
		}
		private Rect getWindowRect(IntPtr hwnd)
		{
			Rect r = new Rect();
			GetWindowRect(hwnd, ref r);
			return r;
		}

		private ProcessMemoryReader readerOpenProcess(Process proc)
		{
			ProcessMemoryReader pmr = new ProcessMemoryReader() { Process = proc };
			pmr.OpenProcess();
			return pmr;
		}
		private void readerCloseHandle(ProcessMemoryReader pmr)
		{
			pmr.CloseHandle();
		}

		private IMAGE_SECTION_HEADER findSection(ProcessMemoryReader pmr, IntPtr baseAddr, int modSize,string secName)
		{
			byte[] buffer = pmr.ReadProcessMemory(baseAddr, _iModuleSize);
			IMAGE_DOS_HEADER idh = buffer.ToStruct<IMAGE_DOS_HEADER>();

			IMAGE_NT_HEADERS32 inh = bytesToStruct<IMAGE_NT_HEADERS32>(pmr, baseAddr + idh.e_lfanew);

			IMAGE_SECTION_HEADER ish = new IMAGE_SECTION_HEADER();

			for (int i = 0; i < inh.FileHeader.NumberOfSections; i++)
			{
				ish = bytesToStruct<IMAGE_SECTION_HEADER>(
					pmr,
					baseAddr + idh.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * i)
					);

				if (new string(ish.Name).ToLower().TrimEnd('\0') == secName.ToLower())
				{
					break;
				}
			}
			return ish;
		}
		
		private T bytesToStruct<T>(ProcessMemoryReader pmr, IntPtr pointer) where T:struct
		{
			return readMemoryToT<T>(pmr, 
				pointer, 
				new Func<byte[], T>(delegate(byte[] buffer)
					{
						return buffer.ToStruct<T>();
					}));
		}
		private List<T> pointersToList<T>(ProcessMemoryReader pmr, int length, Func<int, IntPtr> calculatePointer, Func<byte[], T> converterFunc)
		{
			List<T> lT = new List<T>();
			for (int i = 0; i < length; i++)
			{
				T item = readMemoryToT<T>(pmr, calculatePointer(i), converterFunc);
				lT.Add(item);
			}
			return lT;
		}

		private T readMemoryToT<T>(ProcessMemoryReader pmr, IntPtr address, Func<byte[], T> converterFunc)
		{
			byte[] buffer = pmr.ReadProcessMemory(
				address,
				Marshal.SizeOf(typeof(T)));
			return converterFunc(buffer);
		}
	}
}
