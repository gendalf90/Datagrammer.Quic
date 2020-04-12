using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber : IComparable<PacketNumber>, IEquatable<PacketNumber>
    {
        private readonly ulong value;

        internal PacketNumber(ulong value)
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

        public static PacketNumber Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var value = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new PacketNumber(value);
        }

        public PacketNumber GetNext()
        {
            return new PacketNumber(value + 1);
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
