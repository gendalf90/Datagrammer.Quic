using Datagrammer.Quic.Protocol.Tls;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber : IEquatable<PacketNumber>, IComparable<PacketNumber>
    {
        private readonly ulong value;

        private PacketNumber(ulong value)
        {
            this.value = value;
        }

        public static PacketNumber Parse(ReadOnlySpan<byte> bytes, ValueBuffer? mask = null)
        {
            if (!mask.HasValue)
            {
                return new PacketNumber(NetworkBitConverter.ParseUnaligned(bytes));
            }

            Span<byte> buffer = stackalloc byte[bytes.Length];

            bytes.CopyTo(buffer);

            Mask(buffer, mask.Value);

            return new PacketNumber(NetworkBitConverter.ParseUnaligned(buffer));
        }

        public static PacketNumber ParseVariable(MemoryCursor cursor)
        {
            return new PacketNumber(cursor.DecodeVariable());
        }

        public void Fill(Span<byte> bytes, ValueBuffer? mask = null)
        {
            NetworkBitConverter.WriteUnaligned(bytes, value, bytes.Length);

            if (mask.HasValue)
            {
                Mask(bytes, mask.Value);
            }
        }

        public int Write(MemoryCursor cursor, int? minLength = null, ValueBuffer? mask = null)
        {
            if (minLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(minLength));
            }

            var length = NetworkBitConverter.GetByteLength(value);

            if (minLength.HasValue)
            {
                length = Math.Max(length, minLength.Value);
            }

            var bytes = cursor.Move(length);

            NetworkBitConverter.WriteUnaligned(bytes.Span, value, length);

            if (mask.HasValue)
            {
                Mask(bytes.Span, mask.Value);
            }

            return length;
        }

        public void WriteVariable(MemoryCursor cursor)
        {
            cursor.EncodeVariable(value);
        }

        public PacketNumber DecodeByLargestAcknowledged(PacketNumber largestAcknowledged)
        {
            var bits = NetworkBitConverter.GetByteLength(value) * 8;
            var expected = largestAcknowledged.value + 1;
            var win = 1UL << bits;
            var hwin = win / 2;
            var mask = win - 1;
            var candidate = (expected & ~mask) | value;

            if (candidate <= expected - hwin && candidate < (1 << 62) - win)
            {
                return new PacketNumber(candidate + win);
            }

            if (candidate > expected + hwin && candidate >= win)
            {
                return new PacketNumber(candidate - win);
            }

            return new PacketNumber(candidate);
        }

        public PacketNumber EncodeByLargestAcknowledged(PacketNumber largestAcknowledged)
        {
            var range = 2 * (value - largestAcknowledged.value) + 1;

            var resultLength = range switch
            {
                > 0xffffff => 4,
                > 0xffff => 3,
                > 0xff => 2,
                _ => 1
            };

            var currentLength = NetworkBitConverter.GetByteLength(value);

            Span<byte> currentBytes = stackalloc byte[currentLength];

            NetworkBitConverter.WriteUnaligned(currentBytes, value, currentLength);

            var resultBytes = currentBytes.Slice(currentLength - resultLength);
            var resultValue = NetworkBitConverter.ParseUnaligned(resultBytes);

            return new PacketNumber(resultValue);
        }

        private static void Mask(Span<byte> bytes, ValueBuffer mask)
        {
            for (int i = 0, j = 1; i < bytes.Length && j < mask.Length; i++, j++)
            {
                bytes[i] ^= mask[j];
            }
        }

        public void Encrypt(IAead aead, Span<byte> data, Span<byte> tag, ReadOnlySpan<byte> associatedData)
        {
            aead.Encrypt(data, tag, value, associatedData);
        }

        public void Decrypt(IAead aead, Span<byte> data, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData)
        {
            aead.Decrypt(data, tag, value, associatedData);
        }

        public PacketNumber GetNext()
        {
            return new PacketNumber(value + 1);
        }

        public static PacketNumber Initial { get; } = new PacketNumber(0);

        public static bool operator ==(PacketNumber first, PacketNumber second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketNumber first, PacketNumber second)
        {
            return !first.Equals(second);
        }

        public override bool Equals(object obj)
        {
            return obj is PacketNumber other && Equals(other);
        }

        public bool Equals(PacketNumber other)
        {
            return value == other.value;
        }

        public int CompareTo(PacketNumber other)
        {
            return value.CompareTo(other.value);
        }

        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        public override string ToString()
        {
            return value.ToString();
        }
    }
}
