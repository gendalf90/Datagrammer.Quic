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

        public bool TryParseNumber(ReadOnlyMemory<byte> bytes, out PacketNumber packetNumber, out ReadOnlyMemory<byte> remainings)
        {
            packetNumber = new PacketNumber();
            remainings = bytes;

            if (bytes.Length < numberLength)
            {
                return false;
            }

            var packetNumberBytes = bytes.Slice(0, numberLength);
            var packetNumberValue = NetworkBitConverter.ToUInt32(packetNumberBytes.Span);

            packetNumber = new PacketNumber(packetNumberValue);
            remainings = bytes.Slice(numberLength);

            return true;
        }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out PacketFirstByte result, out ReadOnlyMemory<byte> remainings)
        {
            result = new PacketFirstByte();
            remainings = ReadOnlyMemory<byte>.Empty;

            if(bytes.IsEmpty)
            {
                return false;
            }

            var first = bytes.Span[0];
            var isFixedBitValid = Convert.ToBoolean((first >> 6) & 1);

            if(!isFixedBitValid)
            {
                return false;
            }

            var isShortHeader = !Convert.ToBoolean(first >> 7);
            var packetType = (first >> 4) & 3;
            var isInitialType = packetType == 0;
            var isRttType = packetType == 1;
            var isHandshakeType = packetType == 2;
            var isRetryType = packetType == 3;
            var numberLength = (first & 3) + 1;

            result = new PacketFirstByte(isShortHeader,
                                         isInitialType,
                                         isRttType,
                                         isHandshakeType,
                                         isRetryType,
                                         numberLength);
            remainings = bytes.Slice(1);

            return true;
        }
    }
}
