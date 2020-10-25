using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class ServerEncryptedExtension
    {
        public static void WriteBytes(ref Span<byte> bytes)
        {
            if (bytes.Length < 6)
            {
                throw new EncodingException();
            }

            bytes[0] = 0x08;
            bytes[1] = 0x00;
            bytes[2] = 0x00;
            bytes[3] = 0x02;
            bytes[4] = 0x00;
            bytes[5] = 0x00;

            bytes = bytes.Slice(6);
        }
    }
}
