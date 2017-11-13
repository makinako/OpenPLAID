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
    public abstract class CardApplication
    {
        #region "Members - Public"

        public event EventHandler<string> OnMessage;

        /// <summary>
        /// Tests whether the supplied card is supported by this application.
        /// </summary>
        /// <param name="card">The selected card.</param>
        /// <returns>true if the application supports this card; otherwise false.</returns>
        /// <remarks>
        /// It is completely up to the derived class to determine how it evaluates
        /// compatibility with the card, but as a general rule it should not 
        /// perform any operations which alter the state or contents of the card
        /// if it is at all avoidable. Additionally, this operation should be as
        /// fast as possible. Lengthy operations will slow the performance of the
        /// whole application.
        /// </remarks>
        public abstract bool Discover(Card card);

        public virtual void SetCard(Card card)
        {
            Card = card;
        }

        #endregion

        #region "Members - Private / Protected"

        protected Card Card { get; set; }

        protected void RaiseOnMessage(string message)
        {
            OnMessage?.Invoke(this, message);
        }

        #endregion

        #region "Constants / Private Declarations"
        #endregion
    }
}
#endregion