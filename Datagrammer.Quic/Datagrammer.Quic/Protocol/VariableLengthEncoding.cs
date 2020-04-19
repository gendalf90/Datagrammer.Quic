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

            decodedValue &= ulong.MaxValue >> (64 - length * 8 + 2);
            decodedLength = length;

            return decodedValue;
        }

        public static void Encode(Span<byte> destination, ulong value, out int encodedLength)
        {
            if(value > ulong.MaxValue >> 2)
            {
                throw new EncodingException();
            }

            var length = 8;

            if(value <= byte.MaxValue >> 2)
            {
                length = 1;
            }
            else if(value <= ushort.MaxValue >> 2)
            {
                length = 2;
            }
            else if(value <= uint.MaxValue >> 2)
            {
                length = 4;
            }

            if(destination.Length < length)
            {
                throw new EncodingException();
            }

            var encodedLengthValue = (ulong)Math.Log(length, 2);
            var valueToEncode = value | encodedLengthValue << (length * 8 - 2);

            encodedLength = NetworkBitConverter.WriteUnaligned(destination, valueToEncode);
        }
    }
}
