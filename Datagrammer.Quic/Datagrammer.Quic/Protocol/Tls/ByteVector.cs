using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class ByteVector
    {
        public static ReadOnlyMemory<byte> SliceVectorBytes(ReadOnlyMemory<byte> data, Range range, out ReadOnlyMemory<byte> remainings)
        {
            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            if(data.Length < lengthSizeInBytes || lengthSizeInBytes > 4)
            {
                throw new EncodingException();
            }

            var lengthBytes = data.Slice(0, lengthSizeInBytes);
            var length = (int)NetworkBitConverter.ParseUnaligned(lengthBytes.Span);
            var afterLengthBytes = data.Slice(lengthSizeInBytes);

            if(afterLengthBytes.Length < length || length < range.Start.Value || length > range.End.Value)
            {
                throw new EncodingException();
            }

            remainings = afterLengthBytes.Slice(length);

            return afterLengthBytes.Slice(0, length);
        }

        public static WritingContext StartVectorWriting(Span<byte> bytes, Range range)
        {
            var context = new WritingContext(bytes, range);
            var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

            context.Cursor = context.Cursor.Move(lengthSizeInBytes);

            return context;
        }

        public ref struct WritingContext
        {
            private Span<byte> start;
            private Range range;

            public WritingContext(Span<byte> start, Range range)
            {
                this.start = start;
                this.range = range;

                Cursor = new WritingCursor(start, 0);
            }

            public WritingCursor Cursor { get; set; }

            public int Complete()
            {
                var lengthSizeInBytes = NetworkBitConverter.GetByteLength((ulong)range.End.Value);

                if (Cursor.Offset < lengthSizeInBytes)
                {
                    throw new EncodingException();
                }

                var payloadLength = Cursor.Offset - lengthSizeInBytes;

                if (payloadLength < range.Start.Value || payloadLength > range.End.Value)
                {
                    throw new EncodingException();
                }

                NetworkBitConverter.WriteUnaligned(start, (ulong)payloadLength, lengthSizeInBytes);

                return Cursor.Offset;
            }
        }
    }
}
