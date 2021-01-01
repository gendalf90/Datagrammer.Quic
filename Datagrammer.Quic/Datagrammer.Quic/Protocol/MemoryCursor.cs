using System;

namespace Datagrammer.Quic.Protocol
{
    public class MemoryCursor
    {
        private Memory<byte> buffer;
        private Index position;
        private Range limit;

        public MemoryCursor(Memory<byte> buffer)
        {
            this.buffer = buffer;

            position = Index.Start;
            limit = Range.All;
        }

        public Memory<byte> PeekStart()
        {
            return buffer[limit.Start..position];
        }

        public Memory<byte> PeekEnd()
        {
            return buffer[position..limit.End];
        }

        public Memory<byte> MoveStart()
        {
            var memory = PeekStart();

            position = limit.Start;

            return memory;
        }

        public Memory<byte> MoveEnd()
        {
            var memory = PeekEnd();

            position = limit.End;

            return memory;
        }

        public Memory<byte> Move(int length)
        {
            if (!TryMove(length, out var memory))
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            return memory;
        }

        public bool TryMove(int length, out Memory<byte> memory)
        {
            if (!TryMove(length, out var newPosition, out _, out memory))
            {
                return false;
            }

            position = newPosition;

            return true;
        }

        public Memory<byte> Peek(int length)
        {
            if(!TryPeek(length, out var memory))
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            return memory;
        }

        public bool TryPeek(int length, out Memory<byte> memory)
        {
            return TryMove(length, out _, out _, out memory);
        }

        public void Set(int offset)
        {
            if(!TrySet(offset, out var newPosition))
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            position = newPosition;
        }

        public LimitContext WithLimit(int length)
        {
            var previousLimit = limit;

            if(!TryMove(length, out _, out var newLimit, out _))
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            limit = newLimit;

            return new LimitContext(this, previousLimit);
        }

        private bool TryMove(int length, out Index newPosition, out Range offsetRange, out Memory<byte> offsetBytes)
        {
            offsetBytes = default;
            offsetRange = default;

            if(!TrySet(position.Value + length, out newPosition))
            {
                return false;
            }

            offsetRange = length > 0 ? position..newPosition : newPosition..position;
            offsetBytes = buffer[offsetRange];

            return true;
        }

        private bool TrySet(int offset, out Index newPosition)
        {
            newPosition = default;

            var limitInfo = limit.GetOffsetAndLength(buffer.Length);

            if (offset < limitInfo.Offset || offset > limitInfo.Offset + limitInfo.Length)
            {
                return false;
            }

            newPosition = offset;

            return true;
        }

        public int AsOffset()
        {
            return position.Value;
        }

        public static implicit operator int(MemoryCursor cursor)
        {
            return cursor.AsOffset();
        }

        public readonly ref struct LimitContext
        {
            private readonly MemoryCursor cursor;
            private readonly Range limitToSet;

            internal LimitContext(MemoryCursor cursor, Range limitToSet)
            {
                this.cursor = cursor;
                this.limitToSet = limitToSet;
            }

            public void Dispose()
            {
                cursor.limit = limitToSet;
            }
        }
    }
}
