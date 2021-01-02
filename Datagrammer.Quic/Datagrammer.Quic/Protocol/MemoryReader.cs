using System;

namespace Datagrammer.Quic.Protocol
{
    public readonly ref struct MemoryReader<T>
    {
        private readonly Func<MemoryCursor, T> parser;
        private readonly MemoryBuffer buffer;
        private readonly MemoryCursor cursor;

        public MemoryReader(Func<MemoryCursor, T> parser, MemoryBuffer buffer, MemoryCursor cursor)
        {
            this.parser = parser;
            this.buffer = buffer;
            this.cursor = cursor;
        }

        public Enumerator GetEnumerator()
        {
            var context = buffer.SetCursor(cursor);

            return new Enumerator(context, parser, cursor);
        }

        public ref struct Enumerator
        {
            private MemoryBuffer.CursorContext context;
            private MemoryCursor cursor;
            private Func<MemoryCursor, T> parser;
            private T current;
            private bool hasValue;

            public Enumerator(
                MemoryBuffer.CursorContext context, 
                Func<MemoryCursor, T> parser, 
                MemoryCursor cursor)
            {
                this.context = context;
                this.parser = parser;
                this.cursor = cursor;
                current = default;
                hasValue = false;
            }

            public T Current => hasValue ? current : throw new ArgumentOutOfRangeException(nameof(Current));

            public bool MoveNext()
            {
                hasValue = false;

                if (cursor.IsEnd())
                {
                    return false;
                }

                current = parser(cursor);
                hasValue = true;

                return true;
            }

            public void Dispose()
            {
                context.Dispose();
            }
        }
    }
}
