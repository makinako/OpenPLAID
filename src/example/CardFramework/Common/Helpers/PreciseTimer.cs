#region "Copyright"
/******************************************************************************************
 Copyright (C) 2012 Kim O'Sullivan (kim@makina.com.au)

 Permission is hereby granted, free of charge, to any person obtaining a copy of 
 this software and associated documentation files (the "Software"), to deal in the 
 Software without restriction, including without limitation the rights to use, copy, 
 modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 and to permit persons to whom the Software is furnished to do so, subject to the 
 following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies 
 or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT 
 OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************************/
#endregion

#region "Namespace definitions"
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
#endregion

#region "Class definitions"
namespace CardFramework.Helpers
{
    /// <summary>
    /// Imports native methods.
    /// </summary>
    internal static class SafeNativeMethods
    {
#if PocketPC || WindowsCE
    [DllImport("Coredll.dll")]
    public static extern bool QueryPerformanceCounter(
      out long lpPerformanceCount);
    [DllImport("Coredll.dll")]
    public static extern bool QueryPerformanceFrequency(out long lpFrequency);
#else
        [DllImport("Kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

        [DllImport("Kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryPerformanceFrequency(out long lpFrequency);
#endif
    }

    public class PreciseTimer
    {
        #region "Members - Public"

        public PreciseTimer()
        {
            if (Frequency == 0)
            {
                long freq = 0;
                if (SafeNativeMethods.QueryPerformanceFrequency(out freq) == false)
                {
                    throw new Win32Exception();
                }
                else
                {
                    Frequency = freq;
                }
            }

            Reset();
        }

        public void Reset()
        {
            myStartTicks = ReadTick();
        }

        public double Ticks
        {
            get
            {
                return (ReadTick() - myStartTicks);
            }
        }

        public double Microseconds
        {
            get
            {
                return ((ReadTick() - myStartTicks) / (Frequency / 1000000));
            }
        }

        public double Milliseconds
        {
            get
            {
                return ((ReadTick() - myStartTicks) / (Frequency / 1000));
            }
        }

        public double Seconds
        {
            get
            {
                return ((ReadTick() - myStartTicks) / Frequency);
            }
        }

        public double Minutes
        {
            get
            {
                return ((ReadTick() - myStartTicks) / Frequency) / 60;
            }
        }

        public double Hours
        {
            get
            {
                return ((ReadTick() - myStartTicks) / Frequency) / 3600;
            }
        }


        public double Days
        {
            get
            {
                return ((ReadTick() - myStartTicks) / Frequency) / 86400;
            }
        }

        public double Weeks
        {
            get
            {
                return ((ReadTick() - myStartTicks) / Frequency) / 604800;
            }
        }

        /// <summary>
        /// Returns a high resolution timer in ticks.
        /// </summary>
        /// <returns>The timer value.</returns>
        public long ReadTick()
        {
            long tick;
            SafeNativeMethods.QueryPerformanceCounter(out tick);
            return tick;
        }

        /// <summary>
        /// Frequency of the high-resolution performance counter in counts-per-second
        /// </summary>
        public static double Frequency { get; internal set; }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"

        private double myStartTicks;

        #endregion
    }
}
#endregion