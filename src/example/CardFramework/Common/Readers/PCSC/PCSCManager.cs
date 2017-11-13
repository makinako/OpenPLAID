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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Collections;
using System.Diagnostics;

namespace CardFramework.Readers.PCSC
{
    public class PCSCManager : Reader, IDisposable, IEnumerable
    {
        #region "Members - Public"

        ~PCSCManager()
        {
            Disconnect();
        }

        /// <summary>
        /// A simple check to see if the PC/SC service is able to perform smartcard operations
        /// </summary>
        /// <returns></returns>
        public bool IsPCSCAvailable()
        {
            IntPtr context = IntPtr.Zero;
            PCSCResult result = NativeMethods.SCardEstablishContext(SCardScope.System, IntPtr.Zero, IntPtr.Zero, out context);
            if (result == PCSCResult.None) NativeMethods.SCardReleaseContext(context);
            return (result == PCSCResult.None);
        }

        public void Connect(SCardScope scope)
        {
            // If we are already connected, ignore
            if (myContext != IntPtr.Zero) return;

            // Establish a resource manager context
            PCSCResult result = NativeMethods.SCardEstablishContext(scope, IntPtr.Zero, IntPtr.Zero, out myContext);

            if (result != PCSCResult.None)
            {
                throw new PCSCException("PCSCManager.Connect(): Unable to establish resource manager context");
            }

            // Create our reader list
            myReaders = new Dictionary<string, PCSCReader>();

            string[] readers = ListReaders();

            // Check for our initial list of readers readers
            foreach (string r in readers)
            {
                lock (myReaders)
                {
                    myReaders.Add(r, new PCSCReader(r));
                }
                SpawnOnReaderInsertedEvent(r);
            }
        }

        public override void Connect()
        {
            Connect(SCardScope.User);
        }

        public override void Disconnect()
        {
            // If we are not connected, ignore
            if (myContext == IntPtr.Zero) return;

            // If we are polling, abort
            if (IsRunning) Stop();

            // Disconnect any cards in our readers
            foreach (PCSCReader r in myReaders.Values)
            {
                if (r.ActiveCard != null) r.ActiveCard.Dispose();
            }

            // Release the context
            // NOTE: We ignore the response here as it is often called in the destructor/Dispose statement, and the most
            // likely cause of a failure will be a failure of the PCSC service
            NativeMethods.SCardReleaseContext(myContext);

            myContext = IntPtr.Zero;
            myReaders = null;
        }

        public override void Start()
        {
            if (!IsConnected) throw new PCSCException("PCSC Manager not connected, call 'Connect' first.");

            // Are we already running?
            if (IsRunning) return;

            // Create our new thread
            myPollingThread = new Thread(new ThreadStart(PollingProcedure));

            // Call Resume so that we clear any suspended state
            Resume();

            // Wait for at least one round to execute, so that when we return there is an active state of each reader
            myRunOnceEvent.Reset();

            // Start the thread (reset the thread abort request flag)
            myThreadAbortRequested = false;
            myPollingThread.Start();

            // Now wait for the first round
            if (!myRunOnceEvent.WaitOne(2000))
            {
                Stop();
                throw new PCSCException("PCSC Manager timeout while waiting for the polling loop to begin");
            }
        }

        public override void Stop()
        {
            // Are we running?
            if (!IsRunning) return;

            // Request the abort
            myThreadAbortRequested = true;

            // If it is suspended allow it to resume
            Resume();

            // Cancel any pending status requests
            NativeMethods.SCardCancel(myContext);

            // Join the aborted thread
            myPollingThread.Join();
            myPollingThread = null;
        }

        public override void Suspend()
        {
            // Clear the suspend manual event
            mySuspendEvent.Reset();
        }

        public override void Resume()
        {
            // Set the suspend event
            mySuspendEvent.Set();
            Thread.Sleep(50);
        }

        public override bool IsRunning
        {
            get
            {
                return (myPollingThread != null);
            }
        }

        public override bool IsSuspended
        {
            get
            {
                // If the event is set, we are not suspended
                return !mySuspendEvent.WaitOne(TimeSpan.Zero);
            }
        }

        public override bool IsConnected
        {
            get
            {
                return (myContext != IntPtr.Zero);
            }
        }

        public override bool SupportsCardRemoval
        {
            get { return true; }
        }

        public string[] ListReaderGroups()
        {
            PCSCResult result = 0;

            char[] delimiter = new char[] { '\0' };

            uint length = 0;
            string groups = "";

            result = NativeMethods.SCardListReaderGroups(myContext, ref groups, ref length);
            if (result != PCSCResult.None) throw new PCSCException("ListReaderGroups(): Error listing groups.");

            return groups.Split(delimiter);
        }

        public string[] ListReaders()
        {
            return ListReaders("");
        }

        public string[] ListReaders(string readerGroup)
        {
            PCSCResult result = PCSCResult.None;

            char[] delimiter = new char[] { '\0' };

            string readers = "";

            if (String.IsNullOrEmpty(readerGroup))
            {
                uint len = 0;

                // Get the buffer length
                NativeMethods.SCardListReaders(myContext, null, null, ref len);

                // Get the reader string
                byte[] buffer = new byte[len];
                result = NativeMethods.SCardListReaders(myContext, null, buffer, ref len);
                readers = new ASCIIEncoding().GetString(buffer, 0, buffer.Length);
            }
            else
            {
                uint len = 0;

                byte[] groups = new ASCIIEncoding().GetBytes(readerGroup);

                // Get the buffer length
                NativeMethods.SCardListReaders(myContext, groups, null, ref len);

                // Get the reader string
                byte[] buffer = new byte[len];
                result = NativeMethods.SCardListReaders(myContext, groups, buffer, ref len);
                readers = new ASCIIEncoding().GetString(buffer, 0, buffer.Length);
            }

            if (result != PCSCResult.None)
            {
                if (result == PCSCResult.NoReadersAvailable)
                {
                    return new string[0];
                }
                else
                {
                    throw new PCSCException("ListReaders(): Error listing readers.");
                }
            }

            // Trim off the trailing \0 chars
            readers = readers.Substring(0, readers.Length - 2);

            return readers.Split(delimiter);
        }

        public PCSCReader this[string key]
        {
            get { return myReaders[key]; }
        }

        public PCSCReader this[int index]
        {
            get { return myReaders.ElementAt(index).Value; }
        }

        public bool Contains(string reader)
        {
            if (myReaders.ContainsKey(reader)) return true;
            return false;
        }

        #endregion

        #region "Members - Private / Protected"


        private void PollingProcedure()
        {
            PCSCResult result;
            SCardState pnpState = SCardState.Unaware;

            // Set all existing readers to the 'Unaware' state to force a re-detection
            foreach (var reader in myReaders.Values) reader.State = SCardState.Unaware;

            // Reader detection loop
            while (true)
            {
                // List readers
                string[] readers = ListReaders();

                // Check for added readers
                foreach (string r in readers)
                {
                    if (!myReaders.ContainsKey(r))
                    {
                        lock (myReaders)
                        {
                            myReaders.Add(r, new PCSCReader(r));
                        }
                        SpawnOnReaderInsertedEvent(r);
                    }
                }

                // Check for removed readers
                List<string> removed = new List<string>();
                foreach (string r in myReaders.Keys)
                {
                    if (!readers.Contains(r))
                    {
                        removed.Add(r);
                    }
                }
                foreach (string r in removed)
                {
                    SpawnOnReaderRemovedEvent(r);
                    lock (myReaders)
                    {
                        myReaders.Remove(r);
                    }
                }

                // Create our reader states, including 1 for the PnP notification reader
                SCARD_READERSTATE[] readerStates = new SCARD_READERSTATE[myReaders.Count + 1];
                readerStates[0].szReader = PnPDetectorReader;
                readerStates[0].dwCurrentState = pnpState;

                for (int i = 0; i < myReaders.Count; i++)
                {
                    PCSCReader r = myReaders.ElementAt(i).Value;
                    readerStates[i + 1].szReader = r.Name;
                    readerStates[i + 1].dwCurrentState = r.State;
                }

                // Reader state detection loop
                while (true)
                {
                    // Call the suspend wait event. If it is cleared, we will hold here
                    mySuspendEvent.WaitOne();

                    // First, check for a thread abort request
                    if (myThreadAbortRequested == true) return;

                    // Wait for a status change
                    result = NativeMethods.SCardGetStatusChange(myContext, PollingInterval, readerStates, readerStates.Length);

                    // Was it a timeout? If so, just continue to the next iteration of the loop
                    if (PCSCResult.Timeout == result) continue;

                    // Was an abort requested? If so return
                    if (PCSCResult.Canceled == result) return;

                    // Was there another error? If so restart the loop
                    if (PCSCResult.None != result)
                    {
                        Debug.WriteLine($"PCSC> Error: {result}");
                        continue;
                    };

                    // Loop through each reader (skipping the PnP)
                    for (int i = 1; i < readerStates.Length; i++)
                    {
                        // Mask off any changes
                        SCardState changes = (readerStates[i].dwEventState ^ readerStates[i].dwCurrentState);

                        // Was a card inserted?
                        if ((SCardState.Present & changes & readerStates[i].dwEventState) != 0x00)
                        {
                            // Ignore cards with the MUTE flag set
                            if ((readerStates[i].dwEventState & SCardState.Mute) == 0)
                            {
                                lock (myReaders)
                                {
                                    myReaders[readerStates[i].szReader].State |= SCardState.Present;
                                }

                                SpawnOnCardInsertedEvent(myReaders[readerStates[i].szReader]);
                            }
                        }

                        // Was a card removed?
                        if ((SCardState.Present & changes & ~readerStates[i].dwEventState) != 0x00)
                        {
                            lock (myReaders)
                            {
                                myReaders[readerStates[i].szReader].State &= ~SCardState.Present;
                            }

                            SpawnOnCardRemovedEvent(myReaders[readerStates[i].szReader]);
                        }

                        // Reset our reader polling state
                        readerStates[i].dwCurrentState = readerStates[i].dwEventState;
                    }

                    // Has a reader been inserted or removed? If so, break to the reader detection loop
                    pnpState = readerStates[0].dwEventState;
                    if ((readerStates[0].dwEventState & SCardState.Changed) != 0x00) break;
                    readerStates[0].dwCurrentState = readerStates[0].dwEventState;

                    // This is where we notify the Start() method that we have run at least once
                    myRunOnceEvent.Set();
                }
            } // reader detection while
        }

        #endregion

        #region "Events"

        public event EventHandler<PCSCReaderEventArgs> OnReaderInserted;
        public event EventHandler<PCSCReaderEventArgs> OnReaderRemoved;

        protected void RaiseOnReaderInserted(string reader)
        {
            OnReaderInserted?.Invoke(this, new PCSCReaderEventArgs(reader));
        }

        protected void RaiseOnReaderRemoved(string reader)
        {
            OnReaderRemoved?.Invoke(this, new PCSCReaderEventArgs(reader));
        }

        protected void SpawnOnCardInsertedEvent(PCSCReader reader)
        {
            // Create the card instance for our reader
            reader.ActiveCard = new PCSCCard(reader.Name);

            ThreadPool.QueueUserWorkItem(delegate
            {
                this.RaiseOnCardInserted(reader.Name, reader.ActiveCard);
            });
        }

        protected void SpawnOnCardRemovedEvent(PCSCReader reader)
        {
            if (reader.ActiveCard == null) return;

            ThreadPool.QueueUserWorkItem(delegate
            {
                this.RaiseOnCardRemoved(reader.Name);
            });
        }

        protected void SpawnOnReaderInsertedEvent(string reader)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                this.RaiseOnReaderInserted(reader);
            });
        }

        protected void SpawnOnReaderRemovedEvent(string reader)
        {
            // Disconnect from the card if any
            if (myReaders[reader].ActiveCard != null)
            {
                myReaders[reader].ActiveCard.Dispose();
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                this.RaiseOnReaderRemoved(reader);
            });
        }

        #endregion

        #region IDisposable Members

        public void Dispose()
        {
            Disconnect();
        }

        #endregion

        #region IEnumerable Members

        public IEnumerator GetEnumerator()
        {
            return myReaders.GetEnumerator();
        }

        #endregion

        #region "Constants / Private Declarations"

        private IntPtr myContext = IntPtr.Zero;
        private Thread myPollingThread = null;
        private const int PollingInterval = 1000;

        private ManualResetEvent mySuspendEvent = new ManualResetEvent(true);
        private ManualResetEvent myRunOnceEvent = new ManualResetEvent(false);

        private Dictionary<string, PCSCReader> myReaders = null;

        private const int ThreadAbortInterval = 5000;
        private volatile bool myThreadAbortRequested;

        private const string PnPDetectorReader = @"\\?PNP?\NOTIFICATION";
        #endregion
    }
}
