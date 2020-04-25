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
                result |= (ulong)bytes[j] << (8 * i);
            }

            return result;
        }

        public static int WriteUnaligned(Span<byte> destination, ulong value)
        {
            var length = GetByteLength(value);

            if(destination.Length < length)
            {
                throw new ArgumentOutOfRangeException(nameof(destination));
            }

            for(int i = 0, j = length - 1; i < length; i++, j--)
            {
                destination[i] = (byte)(value >> (j * 8) & byte.MaxValue);
            }

            return length;
        }

        public static int GetByteLength(ulong value)
        {
            var length = 0;

            for (ulong i = value; i > 0; i >>= 8)
            {
                length++;
            }

            return length == 0 ? 1 : length;
        }

        public static int GetBitLength(ulong value)
        {
            var length = 0;

            for (ulong i = value; i > 0; i >>= 1)
            {
                length++;
            }

            return length;
        }
    }
}
