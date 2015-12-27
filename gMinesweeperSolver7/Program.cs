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

		static void Main(string[] args)
		{
			gMinesweeperSolver gms = new gMinesweeperSolver();
			gms.Solve();

			Console.ReadKey();
		}

	}

}