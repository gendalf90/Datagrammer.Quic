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

        public static bool TrySlice(MemoryCursor cursor, RecordType type)
        {
            if(cursor.Peek(1).Span[0] != type.code)
            {
                return false;
            }

            cursor.Move(1);

            return true;
        }

        public static RecordType Parse(MemoryCursor cursor)
        {
            return new RecordType(cursor.Move(1).Span[0]);
        }

        public static RecordType ParseReverse(MemoryCursor cursor)
        {
            return new RecordType(cursor.Move(-1).Span[0]);
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
            cursor.Move(1).Span[0] = code;
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
