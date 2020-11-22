﻿using Datagrammer.Quic.Protocol.Error;
using System;
using System.IO;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ProtocolVersion : IEquatable<ProtocolVersion>
    {
        private readonly short version;

        private ProtocolVersion(short version)
        {
            this.version = version;
        }

        public static ProtocolVersion Parse(ref ReadOnlyMemory<byte> bytes)
        {
            return Parse(bytes, out bytes);
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

        public static ProtocolVersion Parse(MemoryCursor cursor)
        {
            var versionBytes = cursor.Move(2).Span;
            var version = (short)(versionBytes[0] << 8 | versionBytes[1]);

            return new ProtocolVersion(version);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2).Span;

            bytes[0] = (byte)(version >> 8 & byte.MaxValue);
            bytes[1] = (byte)(version & byte.MaxValue);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            bytes[0] = (byte)(version >> 8 & byte.MaxValue);
            bytes[1] = (byte)(version & byte.MaxValue);

            bytes = bytes.Slice(2);
        }

        public void WriteBytes(Stream stream)
        {
            stream.WriteByte((byte)(version >> 8 & byte.MaxValue));
            stream.WriteByte((byte)(version & byte.MaxValue));
        }

        public static ProtocolVersion Tls12 { get; } = new ProtocolVersion(3 << 8 | 3);

        public static ProtocolVersion Tls13 { get; } = new ProtocolVersion(3 << 8 | 4);

        public static ProtocolVersion Current { get; } = Tls13;

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
