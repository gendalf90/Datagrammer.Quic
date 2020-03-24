using System;

namespace Datagrammer.Quic.Protocol
{
    internal static class VariableLengthEncoding
    {
        public static bool TryDecode32(ReadOnlySpan<byte> bytes, out int value, out int decodedLength)
        {
            value = 0;

            if (!TryDecode(bytes, out var tokenLength, out decodedLength))
            {
                return false;
            }

            if (tokenLength > int.MaxValue)
            {
                return false;
            }

            value = (int)tokenLength;

            return true;
        }

        public static bool TryDecode(ReadOnlySpan<byte> bytes, out ulong value, out int decodedLength)
        {
            value = 0;
            decodedLength = 0;

            if(bytes.IsEmpty)
            {
                return false;
            }

            var length = (int)Math.Pow(2, bytes[0] >> 6);

            if(bytes.Length < length)
            {
                return false;
            }

            var bytesToDecode = bytes.Slice(0, length);

            long decodedValue = 0;

            switch(bytesToDecode.Length)
            {
                case 1: decodedValue = bytesToDecode[0] & (byte.MaxValue >> 2);
                    break;
                case 2: decodedValue = NetworkBitConverter.ToInt16(bytesToDecode) & (short.MaxValue >> 2);
                    break;
                case 4: decodedValue = NetworkBitConverter.ToInt32(bytesToDecode) & (int.MaxValue >> 2);
                    break;
                case 8: decodedValue = NetworkBitConverter.ToInt64(bytesToDecode) & (long.MaxValue >> 2);
                    break;
            }

            value = unchecked((ulong)decodedValue);
            decodedLength = bytesToDecode.Length;

            return true;
        }
    }
}
