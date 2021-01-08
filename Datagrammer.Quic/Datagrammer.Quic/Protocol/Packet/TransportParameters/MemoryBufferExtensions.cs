using Datagrammer.Quic.Protocol.Error;

namespace Datagrammer.Quic.Protocol.Packet.TransportParameters
{
    public static class MemoryBufferExtensions
    {
        public static int ParseIntegerParameter(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            using (buffer.SetCursor(cursor))
            {
                var result = cursor.DecodeVariable32();

                if (!cursor.IsEnd())
                {
                    throw new EncodingException();
                }

                return result;
            }
        }
    }
}
