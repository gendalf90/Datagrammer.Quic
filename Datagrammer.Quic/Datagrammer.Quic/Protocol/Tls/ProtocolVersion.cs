using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ProtocolVersion : IEquatable<ProtocolVersion>
    {
        private readonly short version;

        private ProtocolVersion(short version)
        {
            this.version = version;
        }

        public static ProtocolVersion Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var version = (short)(bytes.Span[0] << 8 | bytes.Span[1]);

            remainings = bytes.Slice(2);

            return new ProtocolVersion(version);
        }

        public void WriteBytes(ref WritingCursor cursor)
        {
            if (cursor.Destination.Length < 2)
            {
                throw new EncodingException();
            }

            cursor.Destination[0] = (byte)(version >> 8 & byte.MaxValue);
            cursor.Destination[1] = (byte)(version & byte.MaxValue);

            cursor = cursor.Move(2);
        }

        public static ProtocolVersion Tls12 { get; } = new ProtocolVersion(3 << 8 | 3);

        public static ProtocolVersion Tls13 { get; } = new ProtocolVersion(3 << 8 | 4);

        public bool Equals(ProtocolVersion other)
        {
            return version == other.version;
        }

        public override bool Equals(object obj)
        {
            return obj is ProtocolVersion version && Equals(version);
        }

        public override int GetHashCode()
        {
            return version;
        }

        public static bool operator ==(ProtocolVersion first, ProtocolVersion second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ProtocolVersion first, ProtocolVersion second)
        {
            return !first.Equals(second);
        }
    }
}
