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
            var decodedValue = NetworkBitConverter.ParseUnaligned(bytesToDecode);

            switch (bytesToDecode.Length)
            {
                case 1:
                    decodedValue &= byte.MaxValue >> 2;
                    break;
                case 2:
                    decodedValue &= ushort.MaxValue >> 2;
                    break;
                case 4:
                    decodedValue &= uint.MaxValue >> 2;
                    break;
                case 8:
                    decodedValue &= ulong.MaxValue >> 2;
                    break;
            }

            decodedLength = bytesToDecode.Length;

            return decodedValue;
        }
    }
}
