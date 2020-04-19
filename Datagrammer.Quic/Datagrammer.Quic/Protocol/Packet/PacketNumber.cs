using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber : IComparable<PacketNumber>, IEquatable<PacketNumber>
    {
        private readonly ulong value;

        private PacketNumber(ulong value)
        {
            this.value = value;
        }

        public static PacketNumber Parse32(ReadOnlyMemory<byte> bytes)
        {
            if (bytes.IsEmpty || bytes.Length > 4)
            {
                throw new EncodingException();
            }

            var value = NetworkBitConverter.ParseUnaligned(bytes.Span);

            return new PacketNumber(value);
        }

        public static PacketNumber ParseVariable(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var value = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new PacketNumber(value);
        }

        public int Write32(Span<byte> destination, out Span<byte> remainings)
        {
            var valueToWrite = value & uint.MaxValue;
            var writtenLength = NetworkBitConverter.WriteUnaligned(destination, valueToWrite);

            remainings = destination.Slice(writtenLength);

            return writtenLength;
        }

        public void WriteVariable(Span<byte> destination, out Span<byte> remainings)
        {
            VariableLengthEncoding.Encode(destination, value, out var encodedLength);

            remainings = destination.Slice(encodedLength);
        }

        public PacketNumber DecodeByLargestAcknowledged(PacketNumber largestAcknowledged)
        {
            var bits = NetworkBitConverter.GetBitLength(value);
            var expected = largestAcknowledged.value + 1;
            var win = 1UL << bits;
            var hwin = win / 2;
            var mask = win - 1;
            var candidate = (expected & ~mask) | value;

            if (candidate <= expected - hwin && candidate < (1 << 62) - win)
            {
                return new PacketNumber(candidate + win);
            }

            if (candidate > expected + hwin && candidate >= win)
            {
                return new PacketNumber(candidate - win);
            }

            return new PacketNumber(candidate);
        }

        public PacketNumber GetNext()
        {
            return new PacketNumber(value + 1);
        }

        public static PacketNumber Initial()
        {
            return new PacketNumber(0);
        }

        public bool Equals(PacketNumber other)
        {
            return value == other.value;
        }

        public int CompareTo(PacketNumber other)
        {
            return value.CompareTo(other.value);
        }

        public override bool Equals(object obj)
        {
            return obj is PacketNumber number && Equals(number);
        }

        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        public static bool operator ==(PacketNumber first, PacketNumber second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketNumber first, PacketNumber second)
        {
            return !first.Equals(second);
        }

        public override string ToString()
        {
            return value.ToString();
        }
    }
}
