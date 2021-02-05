using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Datagrammer.Quic.Protocol
{
    //rename to FixedBuffer
    public readonly struct ValueBuffer : IEquatable<ValueBuffer>
    {
        private readonly LayoutBuffer data;
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

            data = Unsafe.ReadUnaligned<LayoutBuffer>(ref MemoryMarshal.GetReference(buffer));
        }

        public void CopyTo(Span<byte> bytes)
        {
            Span<byte> buffer = stackalloc byte[MaxLength];

            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(buffer), data);

            buffer.Slice(0, length).CopyTo(bytes);
        }

        public byte this[int index]
        {
            get
            {
                if (index < 0 || index >= length)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                return Unsafe.Add(ref Unsafe.As<LayoutBuffer, byte>(ref Unsafe.AsRef(in data)), index);
            }
        }

        public int Length => length;

        public bool Equals(ValueBuffer other)
        {
            return 
                data.part_1 == other.data.part_1 &&
                data.part_2 == other.data.part_2 &&
                data.part_3 == other.data.part_3 &&
                data.part_4 == other.data.part_4 &&
                length == other.length;
        }

        public override bool Equals(object obj)
        {
            return obj is ValueBuffer buffer && Equals(buffer);
        }

        public override int GetHashCode()
        {
            return 
                data.part_1.GetHashCode() ^
                data.part_2.GetHashCode() ^
                data.part_3.GetHashCode() ^
                data.part_4.GetHashCode() ^
                length.GetHashCode();
        }

        public static int MaxLength => 32;

        public static ValueBuffer Empty { get; } = new ValueBuffer();

        public static implicit operator ValueBuffer(Span<byte> bytes)
        {
            return new ValueBuffer(bytes);
        }

        public static implicit operator ValueBuffer(byte[] bytes)
        {
            return new ValueBuffer(bytes);
        }

        public static bool operator ==(ValueBuffer first, ValueBuffer second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(ValueBuffer first, ValueBuffer second)
        {
            return !first.Equals(second);
        }

        public byte[] ToArray()
        {
            var buffer = new byte[length];

            CopyTo(buffer);

            return buffer;
        }

        public override string ToString()
        {
            return BitConverter.ToString(ToArray());
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct LayoutBuffer
        {
            [FieldOffset(0)]
            public long part_1;

            [FieldOffset(8)]
            public long part_2;

            [FieldOffset(16)]
            public long part_3;

            [FieldOffset(24)]
            public long part_4;
        }
    }
}
