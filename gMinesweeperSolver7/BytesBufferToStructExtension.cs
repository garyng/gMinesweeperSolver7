using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace gMinesweeperSolver7
{
	public static class BytesBufferToStructExtension
	{
		public static T ToStruct<T>(this byte[] buffer) where T : struct
		{
			GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
			T obj = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
			handle.Free();
			return obj;
		}
	}
}