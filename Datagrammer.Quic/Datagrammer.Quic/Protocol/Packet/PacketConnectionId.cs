﻿using Datagrammer.Quic.Protocol.Error;
using Datagrammer.Quic.Protocol.Tls;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketConnectionId : IEquatable<PacketConnectionId>
    {
        private const int MaxLength = 20;

        private readonly ValueBuffer buffer;

        private PacketConnectionId(ValueBuffer buffer)
        {
            this.buffer = buffer;
        }

        public override bool Equals(object obj)
        {
            return obj is PacketConnectionId version && Equals(version);
        }

        public override int GetHashCode()
        {
            return buffer.GetHashCode();
        }

        public bool Equals(PacketConnectionId other)
        {
            return buffer == other.buffer;
        }

        public static bool operator ==(PacketConnectionId first, PacketConnectionId second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketConnectionId first, PacketConnectionId second)
        {
            return !first.Equals(second);
        }

        public static PacketConnectionId Empty { get; } = new PacketConnectionId();

        public static PacketConnectionId Parse(MemoryCursor cursor)
        {
            var length = cursor.Move(1).Span[0];
            
            if (length > MaxLength)
            {
                throw new EncodingException();
            }

            var bytes = cursor.Move(length);

            return new PacketConnectionId(new ValueBuffer(bytes.Span));
        }

        [Obsolete]
        public static PacketConnectionId Parse(ReadOnlyMemory<byte> input, out ReadOnlyMemory<byte> output)
        {
            output = default;

            return default;
        }

        public static PacketConnectionId Parse(ReadOnlyMemory<byte> bytes)
        {
            var length = bytes.Span[0];

            if (bytes.Length != length + 1 || length > MaxLength)
            {
                throw new EncodingException();
            }

            var value = bytes.Slice(1, length).Span;

            return new PacketConnectionId(new ValueBuffer(value));
        }

        public static PacketConnectionId Generate()
        {
            Span<byte> bytes = stackalloc byte[16];

            Guid.NewGuid().TryWriteBytes(bytes);

            return new PacketConnectionId(new ValueBuffer(bytes));
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(buffer.Length + 1).Span;

            bytes[0] = (byte)buffer.Length;

            buffer.CopyTo(bytes.Slice(1));
        }

        public (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateClientInitialSecrets(IHash hash)
        {
            Span<byte> bytes = stackalloc byte[buffer.Length];

            buffer.CopyTo(bytes);

            return hash.CreateClientInitialSecrets(bytes);
        }

        public (ValueBuffer Key, ValueBuffer Iv, ValueBuffer Hp) CreateServerInitialSecrets(IHash hash)
        {
            Span<byte> bytes = stackalloc byte[buffer.Length];

            buffer.CopyTo(bytes);

            return hash.CreateServerInitialSecrets(bytes);
        }

        public override string ToString()
        {
            return buffer.ToString();
        }
    }
}
