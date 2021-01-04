using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketToken : IEquatable<PacketToken>
    {
        private readonly ReadOnlyMemory<byte> bytes;

        public PacketToken(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketToken version && Equals(version);
        }

        public override int GetHashCode()
        {
            return HashCodeCalculator.Calculate(bytes.Span);
        }

        public bool Equals(PacketToken other)
        {
            return bytes.Span.SequenceEqual(other.bytes.Span);
        }

        public static bool operator ==(PacketToken first, PacketToken second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketToken first, PacketToken second)
        {
            return !first.Equals(second);
        }

        public static PacketToken Empty { get; } = new PacketToken();

        public static PacketToken Parse(MemoryCursor cursor)
        {
            var length = cursor.DecodeVariable32();
            var bytes = cursor.Move(length);

            return new PacketToken(bytes);
        }

        [Obsolete]
        public static PacketToken Parse(ReadOnlyMemory<byte> input, out ReadOnlyMemory<byte> output)
        {
            output = default;

            return default;
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            cursor.EncodeVariable32(bytes.Length);
            bytes.CopyTo(cursor);
        }
    }
}
