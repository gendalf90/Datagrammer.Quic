using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    public static class NetworkBitConverter
    {
        public static ulong ParseUnaligned(ReadOnlySpan<byte> bytes)
        {
            if(bytes.IsEmpty || bytes.Length > sizeof(ulong))
            {
                throw new EncodingException();
            }

            var result = 0UL;

            for (int i = bytes.Length - 1, j = 0; i >= 0; i--, j++)
            {
                result |= (ulong)bytes[j] << (8 * i);
            }

            return result;
        }

        public static int WriteUnaligned(Span<byte> destination, ulong value, int? desiredLength = null)
        {
            var length = desiredLength ?? GetByteLength(value);

            if(length < 1 || destination.Length < length || length > sizeof(ulong))
            {
                throw new EncodingException();
            }

            for(int i = 0, j = length - 1; i < length; i++, j--)
            {
                destination[i] = (byte)(value >> (j * 8) & byte.MaxValue);
            }

            return length;
        }

        public static int GetByteLength(ulong value)
        {
            var length = 1;

            while ((value >>= 8) > 0)
            {
                length++;
            }

            return length;
        }

        public static int GetBitLength(ulong value)
        {
            var length = 0;

            while (value > 0)
            {
                length++;
                value >>= 1;
            }

            return length;
        }
    }
}
