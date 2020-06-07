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

        public static void WriteEmpty(ref WritingCursor cursor)
        {
            if(cursor.Destination.Length < 2)
            {
                throw new EncodingException();
            }

            cursor.Destination[0] = 1;
            cursor.Destination[1] = 0;

            cursor = cursor.Move(2);
        }
    }
}
