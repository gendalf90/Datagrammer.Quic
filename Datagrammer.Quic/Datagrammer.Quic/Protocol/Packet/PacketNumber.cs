﻿using Datagrammer.Quic.Protocol.Tls;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber : IComparable<PacketNumber>, IEquatable<PacketNumber>
    {
        private readonly ulong value;

        private PacketNumber(ulong value)
        {
            this.value = value;
        }

        public static PacketNumber Parse(ReadOnlySpan<byte> bytes)
        {
            var value = NetworkBitConverter.ParseUnaligned(bytes);

            return new PacketNumber(value);
        }

        public static PacketNumber ParseVariable(MemoryCursor cursor)
        {
            var value = cursor.DecodeVariable();

            return new PacketNumber(value);
        }

        public void Fill(Span<byte> bytes)
        {
            NetworkBitConverter.WriteUnaligned(bytes, value, bytes.Length);
        }

        public static void Mask(Span<byte> bytes, ValueBuffer mask)
        {
            for (int i = 0, j = 1; i < bytes.Length && j < mask.Length; i++, j++)
            {
                bytes[i] ^= mask[j];
            }
        }

        public void WriteVariable(MemoryCursor cursor)
        {
            cursor.EncodeVariable(value);
        }

        public PacketNumber DecodeByLargestAcknowledged(PacketNumber largestAcknowledged)
        {
            var bits = NetworkBitConverter.GetBitLength(value);
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

        public bool Equals(PacketNumber other)
        {
            return value == other.value;
        }

        public int CompareTo(PacketNumber other)
        {
            return value.CompareTo(other.value);
        }

        public override bool Equals(object obj)
        {
            return obj is PacketNumber number && Equals(number);
        }

        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        public static bool operator ==(PacketNumber first, PacketNumber second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PacketNumber first, PacketNumber second)
        {
            return !first.Equals(second);
        }

        public override string ToString()
        {
            return value.ToString();
        }
    }
}
