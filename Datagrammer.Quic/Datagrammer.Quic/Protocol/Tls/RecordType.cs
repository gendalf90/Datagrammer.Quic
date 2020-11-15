using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct RecordType : IEquatable<RecordType>
    {
        private readonly byte code;

        private RecordType(byte code)
        {
            this.code = code;
        }

        public static bool TrySlice(ref ReadOnlyMemory<byte> bytes, RecordType type)
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

        public static RecordType ParseFinalBytes(ref ReadOnlyMemory<byte> bytes)
        {
            if (bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var code = bytes.Span[bytes.Length - 1];

            bytes = bytes.Slice(0, bytes.Length - 1);

            return new RecordType(code);
        }

        public static RecordType Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var code = bytes.Span[0];

            remainings = bytes.Slice(1);

            return new RecordType(code);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            var current = cursor.Move(1);

            current[0] = code;
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

        public static RecordType ApplicationData { get; } = new RecordType(0x17); //23

        public static RecordType Handshake { get; } = new RecordType(0x16); //22

        public bool Equals(RecordType other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is RecordType type && Equals(type);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(RecordType first, RecordType second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(RecordType first, RecordType second)
        {
            return !first.Equals(second);
        }
    }
}
