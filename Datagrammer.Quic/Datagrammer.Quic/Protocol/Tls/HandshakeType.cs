﻿using Datagrammer.Quic.Protocol.Error;
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

        public void WriteBytes(Span<byte> bytes, out Span<byte> remainings)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            bytes[0] = code;

            remainings = bytes.Slice(1);
        }

        public static HandshakeType ClientHello { get; } = new HandshakeType(1);

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