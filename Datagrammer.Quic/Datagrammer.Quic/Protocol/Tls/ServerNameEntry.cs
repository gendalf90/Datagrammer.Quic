using System;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ServerNameEntry
    {
        private readonly byte type;
        private readonly ReadOnlyMemory<byte> bytes;

        private ServerNameEntry(byte type, ReadOnlyMemory<byte> bytes)
        {
            this.type = type;
            this.bytes = bytes;
        }

        public bool IsHostName()
        {
            return type == 0;
        }

        public static ServerNameEntry Parse(MemoryCursor cursor)
        {
            var type = cursor.Move(1).Span[0];
            var bytes = ByteVector.SliceVectorBytes(cursor, 0..ushort.MaxValue);

            return new ServerNameEntry(type, bytes.AsMemory(cursor));
        }

        public static void WriteHostName(MemoryCursor cursor, string hostName)
        {
            WriteHostNameType(cursor);
            WriteHostNameValue(cursor, hostName);
        }

        private static void WriteHostNameType(MemoryCursor cursor)
        {
            var bytes = cursor.Move(1);

            bytes.Span[0] = 0;
        }

        private static void WriteHostNameValue(MemoryCursor cursor, string hostName)
        {
            using var context = ByteVector.StartVectorWriting(cursor, 0..ushort.MaxValue);

            var length = Encoding.ASCII.GetByteCount(hostName);

            Span<byte> buffer = stackalloc byte[length];

            Encoding.ASCII.GetBytes(hostName, buffer);

            buffer.CopyTo(cursor);
        }

        public override string ToString()
        {
            return Encoding.ASCII.GetString(bytes.Span);
        }
    }
}
