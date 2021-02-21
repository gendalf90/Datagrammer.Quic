using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class PaddingFrame
    {
        public static bool TryParse(MemoryCursor cursor)
        {
            return FrameType.TrySlice(cursor, FrameType.Padding);
        }

        public static void WriteBytes(MemoryCursor cursor)
        {
            FrameType.Padding.Write(cursor);
        }

        public static int SkipRange(MemoryCursor cursor)
        {
            var slicedCount = 0;

            while (!cursor.IsEnd() && TryParse(cursor))
            {
                slicedCount++;
            }

            return slicedCount;
        }

        public static FillContext EnsureLength(MemoryCursor cursor, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            return new FillContext(cursor, cursor.AsOffset(), length);
        }

        public readonly ref struct FillContext
        {
            private readonly MemoryCursor cursor;
            private readonly int startOffset;
            private readonly int length;

            public FillContext(MemoryCursor cursor, int startOffset, int length)
            {
                this.cursor = cursor;
                this.startOffset = startOffset;
                this.length = length;
            }

            public void Dispose()
            {
                while (cursor - startOffset < length)
                {
                    WriteBytes(cursor);
                }
            }
        }
    }
}
