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
            return AsInt();
        }

        public bool Equals(PacketVersion other)
        {
            return AsInt() == other.AsInt();
        }

        public static bool operator ==(PacketVersion first, PacketVersion second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketVersion first, PacketVersion second)
        {
            return !first.Equals(second);
        }

        public static PacketVersion Parse(MemoryCursor cursor)
        {
            var bytes = cursor.Move(4).Span;

            return new PacketVersion(bytes[0], bytes[1], bytes[2], bytes[3]);
        }

        private int AsInt()
        {
            return (first << 24) | (second << 16) | (third << 8) | fourth;
        }

        [Obsolete]
        public static PacketVersion Parse(ReadOnlyMemory<byte> input, out ReadOnlyMemory<byte> output)
        {
            output = default;

            return default;
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var destination = cursor.Move(4).Span;

            destination[0] = first;
            destination[1] = second;
            destination[2] = third;
            destination[3] = fourth;
        }

        public static PacketVersion One { get; } = new PacketVersion(0, 0, 0, 1);

        public static PacketVersion CreateByDraft(byte draftNumber)
        {
            return new PacketVersion(byte.MaxValue, 0, 0, draftNumber);
        }

        public static PacketVersion Current { get; } = CreateByDraft(32);

        public override string ToString()
        {
            return string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}", first, second, third, fourth);
        }
    }
}
