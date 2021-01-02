namespace Datagrammer.Quic.Protocol
{
    public readonly struct MemoryBuffer
    {
        private readonly int offset;
        private readonly int length;

        public MemoryBuffer(int offset, int length)
        {
            this.offset = offset;
            this.length = length;
        }

        public CursorContext SetCursor(MemoryCursor cursor)
        {
            var previousCursorOffset = cursor.AsOffset();

            cursor.Set(offset);

            var cursorLimitContext = cursor.WithLimit(length);

            return new CursorContext(cursor, cursorLimitContext, previousCursorOffset);
        }

        public readonly ref struct CursorContext
        {
            private readonly MemoryCursor cursor;
            private readonly MemoryCursor.LimitContext limitContext;
            private readonly int cursorOffsetToSet;

            public CursorContext(
                MemoryCursor cursor,
                MemoryCursor.LimitContext limitContext,
                int cursorOffsetToSet)
            {
                this.cursor = cursor;
                this.limitContext = limitContext;
                this.cursorOffsetToSet = cursorOffsetToSet;
            }

            public void Dispose()
            {
                limitContext.Dispose();

                cursor.Set(cursorOffsetToSet);
            }
        }
    }
}
