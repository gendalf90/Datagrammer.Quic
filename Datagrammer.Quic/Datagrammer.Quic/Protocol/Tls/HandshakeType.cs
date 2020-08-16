using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct HandshakeType : IEquatable<HandshakeType>
    {
        private readonly byte code;

        private HandshakeType(byte code)
        {
            this.code = code;
        }

        public static HandshakeType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var code = bytes.Span[0];

            remainings = bytes.Slice(1);

            return new HandshakeType(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            bytes[0] = code;
            bytes = bytes.Slice(1);
        }

        public static HandshakeType ClientHello { get; } = new HandshakeType(1); //0x1

        public static HandshakeType ServerHello { get; } = new HandshakeType(2); //0x2

        public static HandshakeType Finished { get; } = new HandshakeType(20); //0x14

        public bool Equals(HandshakeType other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is HandshakeType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(HandshakeType first, HandshakeType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(HandshakeType first, HandshakeType second)
        {
            return !first.Equals(second);
        }
    }
}
