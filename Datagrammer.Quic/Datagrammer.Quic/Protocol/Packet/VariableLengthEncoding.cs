using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public static class VariableLengthEncoding
    {
        private const byte MaxByte = 0x3f;
        private const ushort MaxUshort = 0x3fff;
        private const uint MaxUint = 0x3fffffff;
        private const ulong MaxUlong = 0x3fffffffffffffff;

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

            var first = bytes[0];
            var prefix = first >> 6;
            var length = 1 << prefix;

            if (bytes.Length < length)
            {
                throw new EncodingException();
            }

            long result = first & MaxByte;

            foreach (var toAddByte in bytes.Slice(1, length - 1))
            {
                result = (result << 8) + toAddByte;
            }

            decodedLength = length;

            return (ulong)result;
        }

        public static void Encode(Span<byte> destination, ulong value, out int encodedLength)
        {
            if (value > MaxUlong)
            {
                throw new EncodingException();
            }

            var length = value switch
            {
                <= MaxByte => 1,
                <= MaxUshort => 2,
                <= MaxUint => 4,
                _ => 8
            };

            if (destination.Length < length)
            {
                throw new EncodingException();
            }

            var lengthToEncode = (ulong)NetworkBitConverter.GetBitLength((ulong)length) - 1;
            var valueToEncode = value | lengthToEncode << (length * 8 - 2);

            encodedLength = NetworkBitConverter.WriteUnaligned(destination, valueToEncode, length);
        }
    }
}
