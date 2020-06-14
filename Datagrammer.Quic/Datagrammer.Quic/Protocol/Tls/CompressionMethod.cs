using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class CompressionMethod
    {
        public static bool CheckForEmpty(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(2);

            return bytes.Span[0] == 1 && bytes.Span[1] == 0;
        }

        public static void WriteEmpty(ref Span<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            bytes[0] = 1;
            bytes[1] = 0;

            bytes = bytes.Slice(2);
        }
    }
}
