using Datagrammer.Quic.Protocol.Error;
using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketFirstByte
    {
        private readonly bool isShortHeader;
        private readonly bool isInitialType;
        private readonly bool isRttType;
        private readonly bool isHandshakeType;
        private readonly bool isRetryType;
        private readonly int numberLength;

        private PacketFirstByte(bool isShortHeader,
                                bool isInitialType,
                                bool isRttType,
                                bool isHandshakeType,
                                bool isRetryType,
                                int numberLength)
        {
            this.isShortHeader = isShortHeader;
            this.isInitialType = isInitialType;
            this.isRttType = isRttType;
            this.isHandshakeType = isHandshakeType;
            this.isRetryType = isRetryType;
            this.numberLength = numberLength;
        }

        public bool IsShortHeader() => isShortHeader;

        public bool IsInitialType() => isInitialType;

        public bool IsRttType() => isRttType;

        public bool IsHandshakeType() => isHandshakeType;

        public bool IsRetryType() => isRetryType;

        public PacketNumber ParseNumber(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            if (bytes.Length < numberLength)
            {
                throw new EncodingException();
            }

            var packetNumberBytes = bytes.Slice(0, numberLength);

            remainings = bytes.Slice(numberLength);

            return PacketNumber.Parse32(packetNumberBytes);
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

            var isShortHeader = !Convert.ToBoolean(first >> 7);
            var packetType = (first >> 4) & 3;
            var isInitialType = packetType == 0;
            var isRttType = packetType == 1;
            var isHandshakeType = packetType == 2;
            var isRetryType = packetType == 3;
            var numberLength = (first & 3) + 1;

            remainings = bytes.Slice(1);

            return new PacketFirstByte(isShortHeader,
                                       isInitialType,
                                       isRttType,
                                       isHandshakeType,
                                       isRetryType,
                                       numberLength);
        }
    }
}
