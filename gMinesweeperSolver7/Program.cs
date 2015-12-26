using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace gMinesweeperSolver7
{
	class Program
	{

		#region APIs

		[StructLayout(LayoutKind.Sequential)]
		public struct IMAGE_DOS_HEADER
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
		public struct IMAGE_FILE_HEADER
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
		public struct IMAGE_DATA_DIRECTORY
		{
			public UInt32 VirtualAddress;
			public UInt32 Size;
		}

		public enum MachineType : ushort
		{
			Native = 0,
			I386 = 0x014c,
			Itanium = 0x0200,
			x64 = 0x8664
		}
		public enum MagicType : ushort
		{
			IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
			IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
		}
		public enum SubSystemType : ushort
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
		public enum DllCharacteristicsType : ushort
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
		public struct IMAGE_OPTIONAL_HEADER32
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
		public struct IMAGE_OPTIONAL_HEADER64
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
		public struct IMAGE_NT_HEADERS32
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
		public struct IMAGE_SECTION_HEADER
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
		public enum DataSectionFlags : uint
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
		public static extern int SetForegroundWindow(IntPtr hwnd);
		[DllImport("user32.dll")]
		public static extern bool GetWindowRect(IntPtr hwnd, ref Rect rectangle);

		[StructLayout(LayoutKind.Sequential)]
		public struct Rect
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
		public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint cButtons, uint dwExtraInfo);

		private const int MOUSEEVENTF_LEFTDOWN = 0x02;
		private const int MOUSEEVENTF_LEFTUP = 0x04;
		private const int MOUSEEVENTF_RIGHTDOWN = 0x08;
		private const int MOUSEEVENTF_RIGHTUP = 0x10;


		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool SetCursorPos(int X, int Y);


		[DllImport("user32.dll")]
		static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

		static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
		const UInt32 SWP_NOSIZE = 0x0001;
		const UInt32 SWP_NOMOVE = 0x0002;
		const UInt32 SWP_SHOWWINDOW = 0x0040;

		private const int SW_SHOWNORMAL = 1;
		private const int SW_SHOWMAXIMIZED = 3;
		private const int SW_RESTORE = 9;

		[DllImport("user32.dll")]
		private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

		#endregion


		[StructLayout(LayoutKind.Sequential)]
		public struct Board
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
			public UInt32 pMineArray;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct Game
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
			public UInt32[] unused1;
			public UInt32 pBoard;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct ArrayA
		{
			public UInt32 unused1;
			public UInt32 unused2;
			public UInt32 unused3;
			public UInt32 pArray;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct ArrayB
		{
			public UInt32 unused1;
			public UInt32 unused2;
			public UInt32 unused3;
			public UInt32 pByteArray;
		}

		static Process _pMine = new Process();
		static IntPtr _ipBaseAdd;
		static int _iModuleSize;
		static ProcessMemoryReader _pmr = new ProcessMemoryReader();

		static void Main(string[] args)
		{

			_pMine = findMS();

			ProcessModule pmMine = _pMine.MainModule;
			_ipBaseAdd = pmMine.BaseAddress;
			_iModuleSize = pmMine.ModuleMemorySize;

			_pmr = new ProcessMemoryReader();
			_pmr.Process = _pMine;
			_pmr.OpenProcess();

			IMAGE_SECTION_HEADER ish = findMSDataSection();

			int pGame = getGamePointer(ish);
			Game g = getGameFromPtr(pGame);

			Board b = getBoardFromPtr(g);


			// Array1 -> Array2 -> BYTE

			ArrayA arrayA = getArrayAFromPtr(b);
			List<UInt32> lpArrayB = getPointersOfArrayB(b, arrayA);
			List<ArrayB> lArrayB = getArrayBfromPtr(lpArrayB);

			int checkSum = 0;
			int[,] iMines = getMinesArrayFromPtr(b, lArrayB, out checkSum);


			IntPtr hwnd = _pMine.MainWindowHandle;

			bringMSToFront(hwnd);

			Rect rect = new Rect();
			GetWindowRect(hwnd, ref rect);


			if (checkSum == 0)
			{
				click(rect, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, 1, 1);
				Thread.Sleep(100);
				iMines = getMinesArrayFromPtr(b, lArrayB, out checkSum);
			}



			for (int i = 0; i < b.Height; i++)
			{
				for (int j = 0; j < b.Width; j++)
				{
					if (iMines[i, j] == 0)
					{
						
						click(rect, MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, j, i);
					}
					else
					{
						click(rect,MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, j, i);
					}
					Thread.Sleep(20);
					//Console.Write(iMines[i, j]);
					Console.Write(checkNeighbourMine(iMines, i, j, (int)b.Width, (int)b.Height) );

				}
				Console.WriteLine();
			}

			_pmr.CloseHandle();
			Console.ReadKey();
		}


		static Process findMS()
		{
			Process[] pr = Process.GetProcessesByName("minesweeper");
			if (pr.Count() == 0)
			{
				runMS();
				pr = Process.GetProcessesByName("minesweeper");
			}

			return pr[0];
		}
		static void runMS()
		{
			Process.Start(@"C:\Program Files\Microsoft Games\Minesweeper\MineSweeper.exe");
		}

		static IMAGE_SECTION_HEADER findMSDataSection()
		{
			byte[] buffer = readMemory(
				_ipBaseAdd,
				_iModuleSize);
			IMAGE_DOS_HEADER idh = buffer.ToStruct<IMAGE_DOS_HEADER>();

			buffer = readMemory(
				_ipBaseAdd + idh.e_lfanew,
				Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32))
				);

			IMAGE_NT_HEADERS32 inh = buffer.ToStruct<IMAGE_NT_HEADERS32>();

			IMAGE_SECTION_HEADER ish = new IMAGE_SECTION_HEADER();

			for (int i = 0; i < inh.FileHeader.NumberOfSections; i++)
			{
				buffer = readMemory(
					_ipBaseAdd + idh.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)) + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * i),
					Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))
					);
				ish = buffer.ToStruct<IMAGE_SECTION_HEADER>();
				if (new string(ish.Name).ToLower().TrimEnd('\0') == ".data")
				{
					break;
				}
			}

			return ish;
		}

		static int getGamePointer(IMAGE_SECTION_HEADER ish)
		{
			byte[] buffer = readMemory(
				_ipBaseAdd + (int)ish.VirtualAddress + 0x88B4,
				Marshal.SizeOf(typeof(UInt32))
			);
			return (int)BitConverter.ToUInt32(buffer, 0);
		}
		static Game getGameFromPtr(int gamePointer)
		{
			byte[] buffer = readMemory(
				(IntPtr)gamePointer,
				Marshal.SizeOf(typeof(Game))
				);
			return buffer.ToStruct<Game>();
		}

		static Board getBoardFromPtr(Game g)
		{
			byte[] buffer = readMemory(
				(IntPtr)g.pBoard,
				Marshal.SizeOf(typeof(Board))
				);
			return buffer.ToStruct<Board>();
		}

		static ArrayA getArrayAFromPtr(Board b)
		{
			byte[] buffer = readMemory(
				(IntPtr)b.pMineArray,
				Marshal.SizeOf(typeof(ArrayA))
				);
			return buffer.ToStruct<ArrayA>();
		}

		static List<UInt32> getPointersOfArrayB(Board b, ArrayA arrayA)
		{
			List<UInt32> lpArrayB = new List<UInt32>();
			byte[] buffer;
			for (int i = 0; i < b.Width; i++)
			{
				buffer = readMemory(
					(IntPtr)arrayA.pArray + Marshal.SizeOf(typeof(UInt32)) * i,
					Marshal.SizeOf(typeof(UInt32))
				);
				lpArrayB.Add(BitConverter.ToUInt32(buffer, 0));
			}

			return lpArrayB;
		}

		static List<ArrayB> getArrayBfromPtr(List<UInt32> lpArrayB)
		{
			List<ArrayB> lArrayB = new List<ArrayB>();
			byte[] buffer;
			for (int i = 0; i < lpArrayB.Count; i++)
			{
				buffer = readMemory(
					(IntPtr)lpArrayB[i],
					Marshal.SizeOf(typeof(ArrayB))
					);
				lArrayB.Add(buffer.ToStruct<ArrayB>());
			}
			return lArrayB;
		}

		static int[,] getMinesArrayFromPtr(Board b, List<ArrayB> lArrayB, out int sum)
		{

			int[,] iMines = new int[b.Height, b.Width];
			sum = 0;
			byte[] buffer;


			for (int i = 0; i < b.Width; i++)
			{
				for (int j = 0; j < b.Height; j++)
				{
					buffer = readMemory(
						(IntPtr)lArrayB[i].pByteArray + j,
						1
						);
					int isMine = buffer[0];
					sum += isMine;
					iMines[j, i] = isMine;
				}
			}

			return iMines;
		}

		static byte[] readMemory(IntPtr addr, int size)
		{
			int bytesRead;
			return _pmr.ReadProcessMemory(addr, (uint)size, out bytesRead);
		}

		static void click(Rect rect, uint dwFlags, int width, int height)
		{
			int x = rect.X + 40 + 18 * width + 8;
			int y = rect.Y + 80 + 18 * height + 8;
			SetCursorPos(x, y);
			mouse_event(dwFlags, (uint)x, (uint)y, 0, 0);
		}

		static string checkNeighbourMine(int[,] iMines, int x, int y, int width, int height)
		{
			int sum = 0;
			if (iMines[x, y] == 1)
			{
				return "<";
			}
			//Right
			if (x < height - 1 && iMines[x + 1, y] == 1)
			{
				sum += 1;
			}
			//Up Right
			if (x < height - 1 && y > 0 && iMines[x + 1, y - 1] == 1)
			{
				sum += 1;
			}
			//Down Right
			if (x < height - 1 && y < width - 1 && iMines[x + 1, y + 1] == 1)
			{
				sum += 1;
			}
			//Left
			if (x > 0 && iMines[x - 1, y] == 1)
			{
				sum += 1;
			}
			//Left Up
			if (x > 0 && y > 0 && iMines[x - 1, y - 1] == 1)
			{
				sum += 1;
			}
			//Left Down
			if (x > 0 && y < width - 1 && iMines[x - 1, y + 1] == 1)
			{
				sum += 1;
			}
			//Up
			if (y > 0 && iMines[x, y - 1] == 1)
			{
				sum += 1;
			}
			//Down
			if (y < width - 1 && iMines[x, y + 1] == 1)
			{
				sum += 1;
			}
			return sum == 0 ? " " : sum.ToString();
		}


		static void bringMSToFront(IntPtr hwnd)
		{
			ShowWindow(hwnd, SW_SHOWNORMAL);
			ShowWindow(hwnd, SW_RESTORE);
			SetForegroundWindow(hwnd);
			SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
		}
	}
}