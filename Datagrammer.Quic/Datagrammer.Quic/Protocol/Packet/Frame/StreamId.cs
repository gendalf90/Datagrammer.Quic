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

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out StreamId streamId, out ReadOnlyMemory<byte> remainings)
        {
            streamId = new StreamId();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!VariableLengthEncoding.TryDecode(bytes.Span, out var id, out var decodedLength))
            {
                return false;
            }

            streamId = new StreamId(id);
            remainings = bytes.Slice(decodedLength);

            return true;
        }
    }
}
