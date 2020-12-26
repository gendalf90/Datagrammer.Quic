using System;

namespace Datagrammer.Quic.Protocol
{
    public readonly struct ValueBuffer : IEquatable<ValueBuffer>
    {
        private readonly long part1;
        private readonly long part2;
        private readonly long part3;
        private readonly long part4;
        private readonly int length;

        public ValueBuffer(ReadOnlySpan<byte> bytes)
        {
            if(bytes.Length > MaxLength)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            length = bytes.Length;

            Span<byte> buffer = stackalloc byte[MaxLength];

            bytes.CopyTo(buffer);

            part1 = BitConverter.ToInt64(buffer.Slice(0, 8));
            part2 = BitConverter.ToInt64(buffer.Slice(8, 8));
            part3 = BitConverter.ToInt64(buffer.Slice(16, 8));
            part4 = BitConverter.ToInt64(buffer.Slice(24, 8));
        }

        public void CopyTo(Span<byte> bytes)
        {
            Span<byte> buffer = stackalloc byte[MaxLength];

            BitConverter.TryWriteBytes(buffer.Slice(0, 8), part1);
            BitConverter.TryWriteBytes(buffer.Slice(8, 8), part2);
            BitConverter.TryWriteBytes(buffer.Slice(16, 8), part3);
            BitConverter.TryWriteBytes(buffer.Slice(24, 8), part4);

            buffer.Slice(0, length).CopyTo(bytes);
        }

        public int Length => length;

        public bool Equals(ValueBuffer other)
        {
            return part1 == other.part1 &&
                part2 == other.part2 &&
                part3 == other.part3 &&
                part4 == other.part4 &&
                length == other.length;
        }

        public override bool Equals(object obj)
        {
            return obj is ValueBuffer version && Equals(version);
        }

        public override int GetHashCode()
        {
            return part1.GetHashCode() ^
                part2.GetHashCode() ^
                part3.GetHashCode() ^
                part4.GetHashCode() ^
                length.GetHashCode();
        }

        public static int MaxLength => 32;

        public static bool operator ==(ValueBuffer first, ValueBuffer second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ValueBuffer first, ValueBuffer second)
        {
            return !first.Equals(second);
        }

        public override string ToString()
        {
            var buffer = new byte[length];

            CopyTo(buffer);

            return BitConverter.ToString(buffer);
        }
    }
}
