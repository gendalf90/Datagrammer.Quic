using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketFirstByte
    {
        private readonly bool isLongHeader;
        private readonly bool isInitialType;
        private readonly bool isRttType;
        private readonly bool isHandshakeType;
        private readonly bool isRetryType;
        private readonly int numberLength;
        private readonly byte reserved;

        private PacketFirstByte(bool isLongHeader,
                                bool isInitialType,
                                bool isRttType,
                                bool isHandshakeType,
                                bool isRetryType,
                                int numberLength,
                                byte reserved)
        {
            this.isLongHeader = isLongHeader;
            this.isInitialType = isInitialType;
            this.isRttType = isRttType;
            this.isHandshakeType = isHandshakeType;
            this.isRetryType = isRetryType;
            this.numberLength = numberLength;
            this.reserved = reserved;
        }

        public bool IsShortHeader() => !isLongHeader;

        public bool IsInitialType() => isLongHeader && isInitialType;

        public bool IsRttType() => isLongHeader && isRttType;

        public bool IsHandshakeType() => isLongHeader && isHandshakeType;

        public bool IsRetryType() => isLongHeader && isRetryType;

        public ReadOnlyMemory<byte> SlicePacketNumberBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.Length < numberLength)
            {
                throw new EncodingException();
            }

            remainings = bytes.Slice(numberLength);

            return bytes.Slice(0, numberLength);
        }

        public Memory<byte> SlicePacketNumberBytes(MemoryCursor cursor)
        {
            return cursor.Move(numberLength);
        }

        public static PacketFirstByte Parse(byte first)
        {
            var isFixedBitValid = Convert.ToBoolean((first >> 6) & 1);

            if(!isFixedBitValid)
            {
                throw new EncodingException();
            }

            var isLongHeader = Convert.ToBoolean(first >> 7);
            var packetType = (first >> 4) & 3;
            var isInitialType = packetType == 0;
            var isRttType = packetType == 1;
            var isHandshakeType = packetType == 2;
            var isRetryType = packetType == 3;
            var numberLength = (first & 3) + 1;
            var reserved = (byte)(first & 12);

            return new PacketFirstByte(isLongHeader,
                                       isInitialType,
                                       isRttType,
                                       isHandshakeType,
                                       isRetryType,
                                       numberLength,
                                       reserved);
        }

        public byte Build()
        {
            var result = 1 << 6;

            result |= Convert.ToInt32(isLongHeader) << 7;

            if (isLongHeader && isRttType)
            {
                result |= 1 << 4;
            }

            if (isLongHeader && isHandshakeType)
            {
                result |= 2 << 4;
            }

            if (isLongHeader && isRetryType)
            {
                result |= 3 << 4;
            }

            result |= reserved;
            result |= numberLength - 1;
            
            return (byte)result;
        }

        public PacketFirstByte Mask(ValueBuffer mask)
        {
            var result = Build();

            result ^= (byte)(mask[0] & 0x0f);

            return Parse(result);
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

            return new PacketFirstByte(isLongHeader, isInitialType, isRttType, isHandshakeType, isRttType, length, reserved);
        }

        public PacketFirstByte SetMaxPacketNumberLength()
        {
            return new PacketFirstByte(isLongHeader, isInitialType, isRttType, isHandshakeType, isRttType, 4, reserved);
        }

        public PacketFirstByte SetShort()
        {
            return new PacketFirstByte(false, false, false, false, false, numberLength, reserved);
        }

        public PacketFirstByte SetInitial()
        {
            return new PacketFirstByte(true, true, false, false, false, numberLength, reserved);
        }

        public PacketFirstByte SetRtt()
        {
            return new PacketFirstByte(true, false, true, false, false, numberLength, reserved);
        }

        public PacketFirstByte SetHandshake()
        {
            return new PacketFirstByte(true, false, false, true, false, numberLength, reserved);
        }

        public PacketFirstByte SetRetry()
        {
            return new PacketFirstByte(true, false, false, false, true, numberLength, reserved);
        }
    }
}
