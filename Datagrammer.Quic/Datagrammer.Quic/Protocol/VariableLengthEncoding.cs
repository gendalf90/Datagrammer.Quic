using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    internal static class VariableLengthEncoding
    {
        public static int Decode32(ReadOnlySpan<byte> bytes, out int decodedLength)
        {
            var value = Decode(bytes, out decodedLength);

            if (value > int.MaxValue)
            {
                throw new EncodingException();
            }

            return (int)value;
        }

        public static long Decode64(ReadOnlySpan<byte> bytes, out int decodedLength)
        {
            var value = Decode(bytes, out decodedLength);

            if (value > long.MaxValue)
            {
                throw new EncodingException();
            }

            return (long)value;
        }

        public static ulong Decode(ReadOnlySpan<byte> bytes, out int decodedLength)
        {
            decodedLength = 0;

            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var length = (int)Math.Pow(2, bytes[0] >> 6);

            if (bytes.Length < length)
            {
                throw new EncodingException();
            }

            var bytesToDecode = bytes.Slice(0, length);

            long decodedValue = 0;

            switch (length)
            {
                case 1:
                    decodedValue = bytesToDecode[0] & (byte.MaxValue >> 2);
                    break;
                case 2:
                    decodedValue = NetworkBitConverter.ToInt16(bytesToDecode) & (short.MaxValue >> 2);
                    break;
                case 4:
                    decodedValue = NetworkBitConverter.ToInt32(bytesToDecode) & (int.MaxValue >> 2);
                    break;
                case 8:
                    decodedValue = NetworkBitConverter.ToInt64(bytesToDecode) & (long.MaxValue >> 2);
                    break;
            }

            decodedLength = length;

            return unchecked((ulong)decodedValue);
        }
    }
}
