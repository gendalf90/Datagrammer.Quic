using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketVersion : IEquatable<PacketVersion>
    {
        private readonly byte first;
        private readonly byte second;
        private readonly byte third;
        private readonly byte fourth;

        private PacketVersion(byte first,
                              byte second,
                              byte third,
                              byte fourth)
        {
            this.first = first;
            this.second = second;
            this.third = third;
            this.fourth = fourth;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketVersion version && Equals(version);
        }

        public override int GetHashCode()
        {
            return ToInt().GetHashCode();
        }

        public bool Equals(PacketVersion other)
        {
            return ToInt() == other.ToInt();
        }

        public static bool operator ==(PacketVersion first, PacketVersion second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketVersion first, PacketVersion second)
        {
            return !first.Equals(second);
        }

        private int ToInt()
        {
            return (first << 24) | (second << 16) | (third << 8) | fourth;
        }

        public static PacketVersion Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 4)
            {
                throw new EncodingException();
            }

            var bytesSpan = bytes.Span;

            remainings = bytes.Slice(4);

            return new PacketVersion(bytesSpan[0], bytesSpan[1], bytesSpan[2], bytesSpan[3]);
        }

        public void WriteBytes(ref Span<byte> destination)
        {
            if(destination.Length < 4)
            {
                throw new EncodingException();
            }

            destination[0] = first;
            destination[1] = second;
            destination[2] = third;
            destination[3] = fourth;

            destination = destination.Slice(4);
        }

        public static PacketVersion CreateOne()
        {
            return new PacketVersion(0, 0, 0, 1);
        }

        public static PacketVersion CreateByDraft(byte draftNumber)
        {
            return new PacketVersion(byte.MaxValue, 0, 0, draftNumber);
        }

        public override string ToString()
        {
            return string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}", first, second, third, fourth);
        }
    }
}
