using System;

namespace Datagrammer.Quic.Protocol
{
    public class MemoryCursor
    {
        private Memory<byte> buffer;
        private Index position;

        public MemoryCursor(Memory<byte> buffer)
        {
            this.buffer = buffer;
        }

        public Span<byte> Slice()
        {
            var result = buffer.Span[0..position];

            buffer = buffer[position..];
            position = 0;

            return result;
        }

        public Span<byte> Move(int length)
        {
            CheckLength(length);

            if(TryMove(length, out var newPosition, out var offsetBytes))
            {
                position = newPosition;
            }

            return offsetBytes;
        }

        public Span<byte> Peek(int length)
        {
            CheckLength(length);

            TryMove(length, out _, out var offsetBytes);

            return offsetBytes;
        }

        public void Reset()
        {
            position = 0;
        }

        private bool TryMove(int length, out Index newPosition, out Span<byte> offsetBytes)
        {
            newPosition = default;
            offsetBytes = default;

            if (length == 0)
            {
                return false;
            }

            newPosition = position.Value + length;

            var resultRange = length > 0 ? position..newPosition : newPosition..position;

            offsetBytes = buffer.Span[resultRange];

            return true;
        }

        private void CheckLength(int length)
        {
            var resultOffset = position.Value + length;

            if (resultOffset > buffer.Length || resultOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }
        }

        public int AsOffset()
        {
            return position.Value;
        }

        public static implicit operator int(MemoryCursor cursor)
        {
            return cursor.AsOffset();
        }
    }
}
