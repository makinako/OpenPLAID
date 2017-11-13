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

using CardFramework.Helpers;
#endregion

#region "Class definitions"
namespace CardFramework
{
  /// <summary>
  /// Describes basic functionality for a reader (or more generically, a 
  /// terminal device for communicating with identification devices)
  /// </summary>
  public abstract class Reader
	{
		#region "Members - Public"

    // Connectivity members
    public abstract void Connect();
    public abstract void Disconnect();
    public abstract bool IsConnected { get; }

    public abstract void Start();
    public abstract void Stop();
    public abstract void Suspend();
    public abstract void Resume();
    
    public abstract bool IsRunning { get; }
    public abstract bool IsSuspended { get; }

    // Versioning members
    //public abstract string MakeInfo { get; }
    //public abstract string ModelInfo { get; }
    //public abstract string VersionInfo { get; }

    // Activity events
    public event EventHandler<CardEventArgs> OnCardInserted;
    public event EventHandler<CardEventArgs> OnCardRemoved;

    public abstract bool SupportsCardRemoval { get; }

		#endregion

		#region "Members - Private / Protected"

    protected void RaiseOnCardInserted(string reader, Card card)
    {
      if (OnCardInserted != null) OnCardInserted(this, new CardEventArgs(reader, card));
    }

    protected void RaiseOnCardRemoved(string reader)
    {
      if (OnCardRemoved != null) OnCardRemoved(this, new CardEventArgs(reader));
    }

		#endregion
	
		#region "Constants / Private Declarations"
		#endregion
  }
}
#endregion