using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct KeyExchange
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private KeyExchange(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static KeyExchange Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 1..ushort.MaxValue, out remainings);

            return new KeyExchange(data);
        }

        public void WriteBytes(ref WritingCursor cursor)
        {
            var context = ByteVector.StartVectorWriting(cursor.Destination, 1..ushort.MaxValue);

            context.Cursor = context.Cursor.Write(bytes.Span);

            cursor = cursor.Move(context.Complete());
        }
    }
}
