using System;

namespace Datagrammer.Quic.Protocol
{
    internal static class NetworkBitConverter
    {
        public static ulong ParseUnaligned(ReadOnlySpan<byte> bytes)
        {
            if(bytes.IsEmpty || bytes.Length > sizeof(ulong))
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            var result = 0UL;

            for (int i = bytes.Length - 1, j = 0; i >= 0; i--, j++)
            {
                result |= (ulong)bytes[BitConverter.IsLittleEndian ? j : i] << (8 * i);
            }

            return result;
        }
    }
}
