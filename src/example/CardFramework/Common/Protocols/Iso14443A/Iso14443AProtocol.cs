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
namespace CardFramework.Protocols.Iso14443A
{
    /// <summary>
    /// Describes the Type A parts of the contact-less smart card protocol 
    /// according to ISO 14443 Parts 3 and 4.
    /// </summary>
    public abstract class Iso14443AProtocol : Protocol
    {
        #region "Members - Public"

        /*
         * High-Level ISO-14443-A members
         */

        /// <summary>
        /// Unique Identifier, Type A
        /// </summary>
        public byte[] Uid { get; protected set; }

        /// <summary>
        /// Answer To reQuest, Type A
        /// </summary>
        public Atqa Atqa { get; protected set; }

        /// <summary>
        /// Select acKnowledgement, Type A
        /// </summary>
        public Sak Sak { get; protected set; }

        /// <summary>
        /// Answer To Select
        /// </summary>
        public Ats Ats { get; protected set; }

        /// <summary>
        /// Gets whether this implementation allows the execution of the low-level
        /// ISO-14443-A command set against a selected card.
        /// </summary>
        /// <remarks>
        /// This is a generic value applicable at the reader level and does not
        /// indicate whether the commands may be executed against a particular
        /// card.
        /// </remarks>
        public virtual bool SupportsLowLevelCommands
        {
            get { return false; }
        }

        /*
         * Low-level ISO-14443-A Part 3 members
         */

        /// <summary>
        /// Executes the ISO 14443-3 REQA command against the currently selected card.
        /// </summary>
        /// <returns>The Answer To reQest value.</returns>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual Atqa DoReqA()
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-3 WUPA command against the currently selected card.
        /// </summary>
        /// <returns>The Answer To reQuest value.</returns>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual Atqa DoWupA()
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-3 ANTICOLLISION command against the currently selected card.
        /// </summary>
        /// <returns></returns>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual byte[] DoAntiCollision(CascadeLevel level, byte nvb, byte[] uid)
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-3 SELECT command against the currently selected card.
        /// </summary>
        /// <returns>The Select AcKnowledge value.</returns>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual Sak DoSelect(CascadeLevel level, byte[] uid)
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-4 DESELECT command against the currently selected card.
        /// </summary>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual void DoDeselect()
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-3 HALTA command against the currently selected card.
        /// </summary>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual void DoHaltA()
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-4 ATS command against the currently selected card.
        /// </summary>
        /// <returns>The Answer To Select value.</returns>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual Ats DoRats(byte parameter)
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }

        /// <summary>
        /// Executes the ISO 14443-4 PPS command against the currently selected card.
        /// </summary>
        /// <remarks>
        /// This command requires that the SupportsLowLevelCommands value is true.
        /// </remarks>
        public virtual void DoPps(byte cid, byte param0, byte param1)
        {
            throw new ReaderException(@"Low-level ISO-14443-A command against the currently selected card not supported by this reader.");
        }


        /*
         * Base implementation of Protocol abstract methods
         */

        public override string DiscoverPlatform()
        {
            // TODO: To be implemented
            return @"Unknown type";
        }

        public override void LoadDiscoveryData()
        {
            // TODO: To be implemented
        }

        public override string ToString()
        {
            return @"ISO 14443 Type-A Protocol";
        }

        #endregion

        #region "Members - Private / Protected"
        #endregion

        #region "Constants / Private Declarations"
        #endregion
    }
}
#endregion