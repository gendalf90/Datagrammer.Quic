using System;
using System.Text;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct ProtocolName
    {
        private readonly ReadOnlyMemory<byte> bytes;

        private ProtocolName(ReadOnlyMemory<byte> bytes)
        {
            this.bytes = bytes;
        }

        public static ProtocolName Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            var data = ByteVector.SliceVectorBytes(bytes, 1..byte.MaxValue, out remainings);

            return new ProtocolName(data);
        }

        public static ProtocolName H3_20 { get; } = new ProtocolName(Encoding.UTF8.GetBytes("h3-20"));

        public void WriteBytes(ref WritingCursor cursor)
        {
            var context = ByteVector.StartVectorWriting(cursor.Destination, 1..byte.MaxValue);

            context.Cursor = context.Cursor.Write(bytes.Span);

            cursor = cursor.Move(context.Complete());
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(bytes.Span);
        }
    }
}
