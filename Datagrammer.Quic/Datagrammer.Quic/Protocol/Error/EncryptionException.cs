using System;
using System.Runtime.Serialization;

namespace Datagrammer.Quic.Protocol.Error
{
    public class EncryptionException : ApplicationException
    {
        public EncryptionException()
        {
        }

        public EncryptionException(string message) : base(message)
        {
        }

        public EncryptionException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected EncryptionException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
