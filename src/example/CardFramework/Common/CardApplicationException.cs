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
using System.Runtime.Serialization;
#endregion

#region "Class definitions"
namespace CardFramework
{
    [Serializable]
    public class CardApplicationException : InvalidOperationException
    {
        #region "Members - Public"

        public CardApplicationException()
          : base()
        {
        }

        public CardApplicationException(string message)
          : base(message)
        {
        }

        public CardApplicationException(string message, Exception innerException)
          : base(message, innerException)
        {
        }

        /*
         * Static helper methods
         */

        public static CardApplicationException ThrowUnsupportedProtocol()
        {
            return new CardApplicationException(ErrUnsupportedProtocol);
        }

        public static CardApplicationException ThrowUnsupportedPlatform()
        {
            return new CardApplicationException(ErrUnsupportedPlatform);
        }

        #endregion

        #region "Members - Private / Protected"

        protected CardApplicationException(SerializationInfo info, StreamingContext context)
          : base(info, context)
        {
        }

        #endregion

        #region "Constants / Private Declarations"
        private const string ErrUnsupportedPlatform = @"This application does not support this card platform.";
        private const string ErrUnsupportedProtocol = @"This card has no protocols supported by the application.";
        #endregion
    }
}
#endregion