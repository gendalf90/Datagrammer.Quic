using System;
using System.Runtime.Serialization;

namespace Datagrammer.Quic.Protocol.Error
{
    public class EncodingException : ApplicationException
    {
        public EncodingException()
        {
        }

        public EncodingException(string message) : base(message)
        {
        }

        public EncodingException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected EncodingException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
