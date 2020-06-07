using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol
{
    public readonly ref struct WritingCursor
    {
        public WritingCursor(Span<byte> destination, int offset)
        {
            Destination = destination;
            Offset = offset;
        }

        public Span<byte> Destination { get; }

        public int Offset { get; }
    }

    public static class WritingCursorExtensions
    {
        public static WritingCursor Move(this WritingCursor cursor, int length)
        {
            if(length < cursor.Destination.Length)
            {
                throw new EncodingException();
            }

            return new WritingCursor(cursor.Destination.Slice(length), cursor.Offset + length);
        }

        public static WritingCursor Write(this WritingCursor cursor, ReadOnlySpan<byte> bytes)
        {
            if(!bytes.TryCopyTo(cursor.Destination))
            {
                throw new EncodingException();
            }

            return cursor.Move(bytes.Length);
        }
    }
}
