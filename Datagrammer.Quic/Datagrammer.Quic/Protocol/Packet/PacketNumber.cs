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

        public static PacketNumber Parse(ReadOnlyMemory<byte> bytes)
        {
            var value = NetworkBitConverter.ParseUnaligned(bytes.Span);

            return new PacketNumber(value);
        }

        public static PacketNumber ParseVariable(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var value = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new PacketNumber(value);
        }

        public static PacketNumber ParseVariable(MemoryCursor cursor)
        {
            var value = cursor.DecodeVariable();

            return new PacketNumber(value);
        }

        public int Write(ref Span<byte> destination)
        {
            var valueToWrite = value & uint.MaxValue;
            var writtenLength = NetworkBitConverter.WriteUnaligned(destination, valueToWrite);

            destination = destination.Slice(writtenLength);

            return writtenLength;
        }

        public int Write(MemoryCursor cursor)
        {
            var bytes = cursor.PeekEnd();
            var length = NetworkBitConverter.WriteUnaligned(bytes.Span, value);

            cursor.Move(length);

            return length;
        }

        public void WriteVariable(Span<byte> destination, out Span<byte> remainings)
        {
            VariableLengthEncoding.Encode(destination, value, out var encodedLength);

            remainings = destination.Slice(encodedLength);
        }

        public void WriteVariable(MemoryCursor cursor)
        {
            cursor.EncodeVariable(value);
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

        public static PacketNumber Initial { get; } = new PacketNumber(0);

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
