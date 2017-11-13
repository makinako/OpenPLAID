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
#endregion

#region "Class definitions"
namespace CardFramework
{
    /// <summary>
    /// A protocol implements a basic communications interface and is largely responsible for implementing
    /// communications standards.
    /// </summary>
    public abstract class Protocol : IDisposable
    {
        #region "Members - Public"

        /*
         * TODO: Move the Discovery protocols to an IDiscoverable interface, as not all protocols will need discovery information.
         */
        public abstract void LoadDiscoveryData();
        public abstract string DiscoverPlatform();

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"
        #endregion

        public virtual void Dispose()
        {
        }
    }
}
#endregion