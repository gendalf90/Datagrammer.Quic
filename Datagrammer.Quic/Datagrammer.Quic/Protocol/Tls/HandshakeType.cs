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

        public static bool TrySlice(ref ReadOnlyMemory<byte> bytes, HandshakeType type)
        {
            if (bytes.IsEmpty)
            {
                return false;
            }

            var code = bytes.Span[0];

            if (code != type.code)
            {
                return false;
            }

            bytes = bytes.Slice(1);

            return true;
        }

        public static bool TrySlice(MemoryCursor cursor, HandshakeType type)
        {
            if(!cursor.TryPeek(1, out var bytes))
            {
                return false;
            }

            if(bytes.Span[0] != type.code)
            {
                return false;
            }

            cursor.Move(1);

            return true;
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

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(1).Span;

            bytes[0] = code;
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

        public static HandshakeType EncryptedExtensions { get; } = new HandshakeType(8); //0x8

        public static HandshakeType Certificate { get; } = new HandshakeType(11); //0x0B

        public static HandshakeType CertificateVerify { get; } = new HandshakeType(15); //0x0F

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
