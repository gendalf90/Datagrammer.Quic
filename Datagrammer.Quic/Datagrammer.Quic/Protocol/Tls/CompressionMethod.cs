using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class CompressionMethod
    {
        public static bool CheckForEmptyList(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(2);

            return bytes.Span[0] == 1 && bytes.Span[1] == 0;
        }

        public static bool CheckForEmptyValue(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(1);

            return bytes.Span[0] == 0;
        }

        public static void WriteEmptyList(ref Span<byte> bytes)
        {
            if(bytes.Length < 2)
            {
                throw new EncodingException();
            }

            bytes[0] = 1;
            bytes[1] = 0;

            bytes = bytes.Slice(2);
        }

        public static void WriteEmptyValue(ref Span<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            bytes[0] = 0;

            bytes = bytes.Slice(1);
        }
    }
}
