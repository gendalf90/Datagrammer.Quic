using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketVersion : IEquatable<PacketVersion>
    {
        private readonly int value;

        private PacketVersion(byte first,
                              byte second,
                              byte third,
                              byte fourth)
        {
            value = (first << 24) | (second << 16) | (third << 8) | fourth;
        }

        private PacketVersion(int value)
        {
            this.value = value;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketVersion version && Equals(version);
        }

        public override int GetHashCode()
        {
            return value;
        }

        public bool Equals(PacketVersion other)
        {
            return value == other.value;
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
            var bytes = cursor.Move(4);
            var value = NetworkBitConverter.ParseUnaligned(bytes.Span);

            return new PacketVersion((int)value);
        }

        [Obsolete]
        public static PacketVersion Parse(ReadOnlyMemory<byte> input, out ReadOnlyMemory<byte> output)
        {
            output = default;

            return default;
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var destination = cursor.Move(4);

            NetworkBitConverter.WriteUnaligned(destination.Span, (ulong)value, 4);
        }

        public static PacketVersion One { get; } = new PacketVersion(0, 0, 0, 1);

        public static PacketVersion CreateByDraft(byte draftNumber)
        {
            return new PacketVersion(byte.MaxValue, 0, 0, draftNumber);
        }

        public override string ToString()
        {
            var bytes = BitConverter.GetBytes(value);

            return string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}", bytes[0], bytes[1], bytes[2], bytes[3]);
        }
    }
}
