using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class ChangeCipherSpec
    {
        public static void WriteBytes(ref Span<byte> bytes)
        {
            if (bytes.Length < 6)
            {
                throw new EncodingException();
            }

            bytes[0] = 0x14;
            bytes[1] = 0x03;
            bytes[2] = 0x03;
            bytes[3] = 0x00;
            bytes[4] = 0x01;
            bytes[5] = 0x01;

            bytes = bytes.Slice(6);
        }
    }
}
