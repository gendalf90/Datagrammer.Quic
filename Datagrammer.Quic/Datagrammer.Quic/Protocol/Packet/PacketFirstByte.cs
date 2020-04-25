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

        private PacketFirstByte(bool isLongHeader,
                                bool isInitialType,
                                bool isRttType,
                                bool isHandshakeType,
                                bool isRetryType,
                                int numberLength)
        {
            this.isLongHeader = isLongHeader;
            this.isInitialType = isInitialType;
            this.isRttType = isRttType;
            this.isHandshakeType = isHandshakeType;
            this.isRetryType = isRetryType;
            this.numberLength = numberLength;
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

        public static PacketFirstByte Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if(bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var first = bytes.Span[0];
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

            remainings = bytes.Slice(1);

            return new PacketFirstByte(isLongHeader,
                                       isInitialType,
                                       isRttType,
                                       isHandshakeType,
                                       isRetryType,
                                       numberLength);
        }

        public void WriteBytes(Span<byte> bytes, out Span<byte> remainings)
        {
            if(bytes.IsEmpty)
            {
                throw new EncodingException();
            }

            var result = 1 << 6;

            result |= Convert.ToInt32(isLongHeader) << 7;

            if(isLongHeader && isRttType)
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

            result |= numberLength - 1;

            bytes[0] = (byte)result;
            remainings = bytes.Slice(1);
        }

        public PacketFirstByte SetPacketNumber(PacketNumber packetNumber)
        {
            var length = packetNumber.GetLength();

            if(length < 1 || length > 4)
            {
                throw new EncodingException();
            }

            return new PacketFirstByte(isLongHeader, isInitialType, isRttType, isHandshakeType, isRttType, length);
        }

        public PacketFirstByte SetShort()
        {
            return new PacketFirstByte(true, false, false, false, false, numberLength);
        }

        public PacketFirstByte SetInitial()
        {
            return new PacketFirstByte(false, true, false, false, false, numberLength);
        }

        public PacketFirstByte SetRtt()
        {
            return new PacketFirstByte(false, false, true, false, false, numberLength);
        }

        public PacketFirstByte SetHandshake()
        {
            return new PacketFirstByte(false, false, false, true, false, numberLength);
        }

        public PacketFirstByte SetRetry()
        {
            return new PacketFirstByte(false, false, false, false, true, numberLength);
        }
    }
}
