using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketFirstByte
    {
        private readonly int value;

        private PacketFirstByte(int value)
        {
            this.value = value;
        }

        public bool IsShortHeader() => !IsLongHeader;

        public bool IsInitialType() => IsLongHeader && PacketType == 0;

        public bool IsRttType() => IsLongHeader && PacketType == 1;

        public bool IsHandshakeType() => IsLongHeader && PacketType == 2;

        public bool IsRetryType() => IsLongHeader && PacketType == 3;

        public ReadOnlyMemory<byte> SlicePacketNumberBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < PacketNumberLength)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(PacketNumberLength);

            return bytes.Slice(0, PacketNumberLength);
        }

        public Memory<byte> SlicePacketNumberBytes(MemoryCursor cursor)
        {
            return cursor.Move(PacketNumberLength);
        }

        public static PacketFirstByte Parse(byte first)
        {
            var isFixedBitValid = Convert.ToBoolean((first >> 6) & 1);

            if(!isFixedBitValid)
            {
                throw new EncodingException();
            }

            return new PacketFirstByte(first);
        }

        public byte Build()
        {
            return (byte)(value | 0x40);
        }

        public PacketFirstByte Mask(ValueBuffer mask)
        {
            var result = Build();

            result ^= IsLongHeader
                ? (byte)(mask[0] & 0x0f)
                : (byte)(mask[0] & 0x1f);

            return new PacketFirstByte(result);
        }

        public void Write(MemoryCursor cursor)
        {
            cursor.Move(1).Span[0] = Build();
        }

        public PacketFirstByte SetPacketNumberLength(int length)
        {
            if(length < 1 || length > 4)
            {
                throw new EncodingException();
            }

            return new PacketFirstByte(value | (length - 1));
        }

        public PacketFirstByte SetMaxPacketNumberLength()
        {
            return new PacketFirstByte(value | 3);
        }

        public PacketFirstByte SetShort()
        {
            return new PacketFirstByte(value & 0x7f);
        }

        public PacketFirstByte SetInitial()
        {
            return new PacketFirstByte((value | 0x80) & 0xcf);
        }

        public PacketFirstByte SetRtt()
        {
            return new PacketFirstByte((value | 0x90) & 0xdf);
        }

        public PacketFirstByte SetHandshake()
        {
            return new PacketFirstByte((value | 0xa0) & 0xef);
        }

        public PacketFirstByte SetRetry()
        {
            return new PacketFirstByte(value | 0xb0);
        }

        private bool IsLongHeader => Convert.ToBoolean(value >> 7);

        private int PacketType => (value >> 4) & 3;

        private int PacketNumberLength => (value & 3) + 1;
    }
}
