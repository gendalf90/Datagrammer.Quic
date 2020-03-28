using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct StreamId : IEquatable<StreamId>
    {
        private readonly ulong value;

        private StreamId(ulong value)
        {
            this.value = value;
        }

        public override bool Equals(object obj)
        {
            return obj is StreamId version && Equals(version);
        }

        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        public bool Equals(StreamId other)
        {
            return value == other.value;
        }

        public static bool operator ==(StreamId first, StreamId second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(StreamId first, StreamId second)
        {
            return !first.Equals(second);
        }

        public static StreamId Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var id = VariableLengthEncoding.Decode(bytes.Span, out var decodedLength);

            remainings = bytes.Slice(decodedLength);

            return new StreamId(id);
        }
    }
}
