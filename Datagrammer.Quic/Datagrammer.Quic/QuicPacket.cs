using System;

namespace Datagrammer.Quic
{
    public readonly struct QuicPacket
    {
        private QuicPacket(bool isShort,
                           bool isInitial,
                           bool isRtt,
                           bool isHandshake,
                           bool isRetry,
                           int version,
                           ReadOnlyMemory<byte> destinationConnectionId,
                           ReadOnlyMemory<byte> sourceConnectionId,
                           uint packetNumber,
                           ReadOnlyMemory<byte> token,
                           ReadOnlyMemory<byte> tag,
                           ReadOnlyMemory<byte> payload)
        {
            IsShort = isShort;
            IsInitial = isInitial;
            IsRtt = isRtt;
            IsHandshake = isHandshake;
            IsRetry = isRetry;
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            PacketNumber = packetNumber;
            Token = token;
            Tag = tag;
            Payload = payload;
        }

        public bool IsShort { get; }

        public bool IsInitial { get; }

        public bool IsRtt { get; }

        public bool IsHandshake { get; }

        public bool IsRetry { get; }

        public int Version { get; }

        public ReadOnlyMemory<byte> DestinationConnectionId { get; }

        public ReadOnlyMemory<byte> SourceConnectionId { get; }

        public uint PacketNumber { get; }

        public ReadOnlyMemory<byte> Token { get; }

        public ReadOnlyMemory<byte> Tag { get; }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParseInitial(ReadOnlyMemory<byte> bytes, out QuicPacket packet)
        {
            packet = new QuicPacket();

            if (!TryGetFirstByte(bytes, out var firstByte, out var afterFirstByteRemainings))
            {
                return false;
            }

            if (IsShortHeader(firstByte))
            {
                return false;
            }

            if (!CheckFixedBit(firstByte))
            {
                return false;
            }

            if(!IsInitialType(firstByte))
            {
                return false;
            }

            if (!TryGetVersion(afterFirstByteRemainings, out var version, out var afterVersionRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterVersionRemainings, out var destinationConnectionId, out var afterDestinationConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterDestinationConnectionIdRemainings, out var sourceConnectionId, out var afterSourceConnectionIdRemainings))
            {
                return false;
            }

            if(!TryGetToken(afterSourceConnectionIdRemainings, out var token, out var afterTokenRemainings))
            {
                return false;
            }

            if(!TryGetSupportedVariableLength(afterTokenRemainings, out var length, out var afterLengthRemainings))
            {
                return false;
            }

            if (!TryGetPacketNumber(firstByte, afterLengthRemainings, out var packetNumber, out var afterPacketNumberRemainings))
            {
                return false;
            }

            packet = new QuicPacket(false,
                                    true,
                                    false,
                                    false,
                                    false,
                                    version,
                                    destinationConnectionId,
                                    sourceConnectionId,
                                    packetNumber,
                                    token,
                                    ReadOnlyMemory<byte>.Empty,
                                    afterPacketNumberRemainings);

            return true;
        }

        public static bool TryParseRtt(ReadOnlyMemory<byte> bytes, out QuicPacket packet)
        {
            packet = new QuicPacket();

            if (!TryGetFirstByte(bytes, out var firstByte, out var afterFirstByteRemainings))
            {
                return false;
            }

            if (IsShortHeader(firstByte))
            {
                return false;
            }

            if (!CheckFixedBit(firstByte))
            {
                return false;
            }

            if (!IsRttType(firstByte))
            {
                return false;
            }

            if (!TryGetVersion(afterFirstByteRemainings, out var version, out var afterVersionRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterVersionRemainings, out var destinationConnectionId, out var afterDestinationConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterDestinationConnectionIdRemainings, out var sourceConnectionId, out var afterSourceConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetSupportedVariableLength(afterSourceConnectionIdRemainings, out var length, out var afterLengthRemainings))
            {
                return false;
            }

            if (!TryGetPacketNumber(firstByte, afterLengthRemainings, out var packetNumber, out var afterPacketNumberRemainings))
            {
                return false;
            }

            packet = new QuicPacket(false,
                                    false,
                                    true,
                                    false,
                                    false,
                                    version,
                                    destinationConnectionId,
                                    sourceConnectionId,
                                    packetNumber,
                                    ReadOnlyMemory<byte>.Empty,
                                    ReadOnlyMemory<byte>.Empty,
                                    afterPacketNumberRemainings);

            return true;
        }

        public static bool TryParseHandshake(ReadOnlyMemory<byte> bytes, out QuicPacket packet)
        {
            packet = new QuicPacket();

            if (!TryGetFirstByte(bytes, out var firstByte, out var afterFirstByteRemainings))
            {
                return false;
            }

            if (IsShortHeader(firstByte))
            {
                return false;
            }

            if (!CheckFixedBit(firstByte))
            {
                return false;
            }

            if (!IsHandshakeType(firstByte))
            {
                return false;
            }

            if (!TryGetVersion(afterFirstByteRemainings, out var version, out var afterVersionRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterVersionRemainings, out var destinationConnectionId, out var afterDestinationConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterDestinationConnectionIdRemainings, out var sourceConnectionId, out var afterSourceConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetSupportedVariableLength(afterSourceConnectionIdRemainings, out var length, out var afterLengthRemainings))
            {
                return false;
            }

            if (!TryGetPacketNumber(firstByte, afterLengthRemainings, out var packetNumber, out var afterPacketNumberRemainings))
            {
                return false;
            }

            packet = new QuicPacket(false,
                                    false,
                                    false,
                                    true,
                                    false,
                                    version,
                                    destinationConnectionId,
                                    sourceConnectionId,
                                    packetNumber,
                                    ReadOnlyMemory<byte>.Empty,
                                    ReadOnlyMemory<byte>.Empty,
                                    afterPacketNumberRemainings);

            return true;
        }

        public static bool TryParseRetry(ReadOnlyMemory<byte> bytes, out QuicPacket packet)
        {
            packet = new QuicPacket();

            if (!TryGetFirstByte(bytes, out var firstByte, out var afterFirstByteRemainings))
            {
                return false;
            }

            if (IsShortHeader(firstByte))
            {
                return false;
            }

            if (!CheckFixedBit(firstByte))
            {
                return false;
            }

            if (!IsRetryType(firstByte))
            {
                return false;
            }

            if (!TryGetVersion(afterFirstByteRemainings, out var version, out var afterVersionRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterVersionRemainings, out var destinationConnectionId, out var afterDestinationConnectionIdRemainings))
            {
                return false;
            }

            if (!TryGetConnectionId(afterDestinationConnectionIdRemainings, out var sourceConnectionId, out var afterSourceConnectionIdRemainings))
            {
                return false;
            }

            if(!TryGetTag(afterSourceConnectionIdRemainings, out var tag))
            {
                return false;
            }

            var token = afterSourceConnectionIdRemainings.Slice(0, afterSourceConnectionIdRemainings.Length - tag.Length);

            packet = new QuicPacket(false,
                                    false,
                                    false,
                                    false,
                                    true,
                                    version,
                                    destinationConnectionId,
                                    sourceConnectionId,
                                    0,
                                    token,
                                    tag,
                                    ReadOnlyMemory<byte>.Empty);

            return true;
        }

        public static bool TryParseShort(ReadOnlyMemory<byte> bytes, ReadOnlyMemory<byte> destinationConnectionId, out QuicPacket packet)
        {
            packet = new QuicPacket();

            if(!TryGetFirstByte(bytes, out var firstByte, out var afterFirstByteRemainings))
            {
                return false;
            }

            if (!IsShortHeader(firstByte))
            {
                return false;
            }

            if (!CheckFixedBit(firstByte))
            {
                return false;
            }

            if(!CheckDestinationConnectionId(afterFirstByteRemainings, destinationConnectionId, out var afterDestinationConnectionIdRemainings))
            {
                return false;
            }

            if(!TryGetPacketNumber(firstByte, afterDestinationConnectionIdRemainings, out var packetNumber, out var afterPacketNumberRemainings))
            {
                return false;
            }
            
            packet = new QuicPacket(true,
                                    false,
                                    false,
                                    false,
                                    false,
                                    0,
                                    destinationConnectionId,
                                    ReadOnlyMemory<byte>.Empty,
                                    packetNumber,
                                    ReadOnlyMemory<byte>.Empty,
                                    ReadOnlyMemory<byte>.Empty,
                                    afterPacketNumberRemainings);

            return true;
        }

        private static bool TryGetFirstByte(ReadOnlyMemory<byte> bytes, out byte first, out ReadOnlyMemory<byte> remainingBytes)
        {
            first = 0;
            remainingBytes = bytes;

            if(bytes.IsEmpty)
            {
                return false;
            }

            first = bytes.Span[0];
            remainingBytes = bytes.Slice(1);

            return true;
        }

        private static bool CheckFixedBit(byte first)
        {
            return Convert.ToBoolean((first >> 6) & 1);
        }

        private static bool CheckDestinationConnectionId(ReadOnlyMemory<byte> bytes, ReadOnlyMemory<byte> destinationConnectionId, out ReadOnlyMemory<byte> remainingBytes)
        {
            remainingBytes = bytes;

            if(bytes.Length < destinationConnectionId.Length)
            {
                return false;
            }

            var bytesToCheck = bytes.Slice(0, destinationConnectionId.Length);

            remainingBytes = bytes.Slice(destinationConnectionId.Length);

            return bytesToCheck.Span.SequenceEqual(destinationConnectionId.Span);
        }

        private static bool IsShortHeader(byte first)
        {
            return !Convert.ToBoolean(first >> 7);
        }

        private static bool TryGetPacketNumber(byte firstByte, ReadOnlyMemory<byte> bytes, out uint packetNumber, out ReadOnlyMemory<byte> remainingBytes)
        {
            packetNumber = 0;
            remainingBytes = bytes;

            var packetNumberLength = (firstByte & 3) + 1;

            if(bytes.Length < packetNumberLength)
            {
                return false;
            }

            var packetNumberBytes = bytes.Slice(0, packetNumberLength);

            packetNumber = NetworkBitConverter.ToUInt32(packetNumberBytes.Span);
            remainingBytes = bytes.Slice(packetNumberLength);

            return true;
        }

        private static bool TryGetVersion(ReadOnlyMemory<byte> bytes, out int version, out ReadOnlyMemory<byte> remainingBytes)
        {
            version = 0;
            remainingBytes = bytes;

            if(bytes.Length < 4)
            {
                return false;
            }

            var versionBytes = bytes.Slice(0, 4);
            
            version = UnsafeBitConverter.ToInt32(versionBytes.Span);
            remainingBytes = bytes.Slice(4);

            return true;
        }

        private static bool TryGetConnectionId(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> connectionId, out ReadOnlyMemory<byte> remainingBytes)
        {
            connectionId = ReadOnlyMemory<byte>.Empty;
            remainingBytes = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var connectionIdLength = bytes.Span[0];
            var connectionIdBytes = bytes.Slice(1);

            if(connectionIdBytes.Length < connectionIdLength)
            {
                return false;
            }

            connectionId = connectionIdBytes.Slice(0, connectionIdLength);
            remainingBytes = bytes.Slice(0, connectionIdLength + 1);

            return true;
        }

        private static bool TryGetToken(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> token, out ReadOnlyMemory<byte> remainingBytes)
        {
            token = ReadOnlyMemory<byte>.Empty;
            remainingBytes = bytes;

            if(!TryGetSupportedVariableLength(bytes, out var tokenLength, out var afterLengthRemainings))
            {
                return false;
            }

            if(afterLengthRemainings.Length < tokenLength)
            {
                return false;
            }

            token = afterLengthRemainings.Slice(0, tokenLength);
            remainingBytes = afterLengthRemainings.Slice(tokenLength);

            return true;
        }

        private static bool TryGetTag(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> tag)
        {
            tag = ReadOnlyMemory<byte>.Empty;

            if(bytes.Length < 16)
            {
                return false;
            }

            tag = bytes.Slice(bytes.Length - 16, 16);

            return true;
        }

        private static bool TryGetSupportedVariableLength(ReadOnlyMemory<byte> bytes, out int length, out ReadOnlyMemory<byte> remainingBytes)
        {
            length = 0;
            remainingBytes = ReadOnlyMemory<byte>.Empty;

            if (!VariableLengthEncoding.TryDecodeValue(bytes.Span, out var tokenLength, out var decodedBytesLength))
            {
                return false;
            }

            if (tokenLength > int.MaxValue)
            {
                return false; //the length is too long, not supported
            }

            length = (int)tokenLength;
            remainingBytes = bytes.Slice(decodedBytesLength);

            return true;
        }

        private static bool IsInitialType(byte first)
        {
            return GetTypeCode(first) == 0;
        }

        private static bool IsRttType(byte first)
        {
            return GetTypeCode(first) == 1;
        }

        private static bool IsHandshakeType(byte first)
        {
            return GetTypeCode(first) == 2;
        }

        private static bool IsRetryType(byte first)
        {
            return GetTypeCode(first) == 3;
        }

        private static int GetTypeCode(byte first)
        {
            return (first >> 4) & 3;
        }
    }
}
