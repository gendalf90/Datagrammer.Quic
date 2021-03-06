﻿using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public readonly struct ExtensionType : IEquatable<ExtensionType>
    {
        private readonly ushort code;

        private ExtensionType(ushort code)
        {
            this.code = code;
        }

        public static ExtensionType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < 2)
            {
                throw new EncodingException();
            }

            var codeBytes = bytes.Slice(0, 2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            remainings = bytes.Slice(2);

            return new ExtensionType(code);
        }

        public static bool TrySlice(MemoryCursor cursor, ExtensionType type)
        {
            var bytes = cursor.Peek(2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(bytes.Span);

            if(type.code != code)
            {
                return false;
            }

            cursor.Move(2);

            return true;
        }

        public static ExtensionType Parse(MemoryCursor cursor)
        {
            var codeBytes = cursor.Move(2);
            var code = (ushort)NetworkBitConverter.ParseUnaligned(codeBytes.Span);

            return new ExtensionType(code);
        }

        public void WriteBytes(ref Span<byte> bytes)
        {
            var writtenLength = NetworkBitConverter.WriteUnaligned(bytes, code, 2);

            bytes = bytes.Slice(writtenLength);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var bytes = cursor.Move(2);

            NetworkBitConverter.WriteUnaligned(bytes.Span, code, 2);
        }

        public static ExtensionType ServerName { get; } = new ExtensionType(0);

        public static ExtensionType SupportedVersions { get; } = new ExtensionType(43); //0x2b

        public static ExtensionType SignatureAlgorithms { get; } = new ExtensionType(13); //0xd

        public static ExtensionType ApplicationLayerProtocolNegotiation { get; } = new ExtensionType(16);

        public static ExtensionType SupportedGroups { get; } = new ExtensionType(10); //0xa

        public static ExtensionType PskKeyExchangeModes { get; } = new ExtensionType(45); //0x2d

        public static ExtensionType KeyShare { get; } = new ExtensionType(51); //0x33

        public static ExtensionType TransportParameters { get; } = new ExtensionType(65445); //0xffa5

        public bool Equals(ExtensionType other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is ExtensionType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(ExtensionType first, ExtensionType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ExtensionType first, ExtensionType second)
        {
            return !first.Equals(second);
        }
    }
}
