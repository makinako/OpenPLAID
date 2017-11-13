using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CardFramework
{
    public enum BulkEncoderStatus
    {
        Undefined = 0,
        Offline,
        Online,
        Connected,
        Error
    }

    public enum BulkEncoderCardStatus
    {
        Undefined = 0,
        NotPresent,
        Present,
        Error
    }

    public class EncoderEventArgs : EventArgs
    {
        public string Description;
    }

    /// <summary>
    /// Represents a bulk-encoding device (which may be a card printer or dedicated encoding hopper)
    /// </summary>
    public interface IBulkEncoder
    {
        /// <summary>
        /// Used to set any device-specific parameters (i.e. printer name) that this hardware requires
        /// </summary>
        /// <param name="parameters"></param>
        void SetParameters(Dictionary<string, string> parameters);

        void Connect();
        void Disconnect();

        BulkEncoderStatus EncoderStatus { get; }
        BulkEncoderCardStatus CardStatus { get; }

        void SetCardPowerState(bool enabled);

        void LoadCard(long timeoutMs = 0);
        void EjectCard();
        void RejectCard();

        //event EventHandler CardReady;
        //event EventHandler CardEjected;
        //event EventHandler<EncoderEventArgs> EncoderError;
        //event EventHandler<EncoderEventArgs> StatusChange;
    }
}