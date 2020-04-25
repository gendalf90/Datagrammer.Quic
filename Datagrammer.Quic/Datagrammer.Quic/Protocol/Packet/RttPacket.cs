﻿using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct RttPacket
    {
        private RttPacket(PacketVersion version,
                          PacketConnectionId destinationConnectionId,
                          PacketConnectionId sourceConnectionId,
                          PacketNumber number,
                          ReadOnlyMemory<byte> payload)
        {
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            Number = number;
            Payload = payload;
        }

        public PacketVersion Version { get; }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketConnectionId SourceConnectionId { get; }

        public PacketNumber Number { get; }

        public ReadOnlyMemory<byte> Payload { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out RttPacket result, out ReadOnlyMemory<byte> remainings)
        {
            result = new RttPacket();
            remainings = bytes;

            if (bytes.IsEmpty)
            {
                return false;
            }

            var firstByte = PacketFirstByte.Parse(bytes, out var afterFirstByteBytes);

            if (!firstByte.IsRttType())
            {
                return false;
            }

            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var packetBytes = PacketLength.SlicePacketBytes(afterSourceConnectionIdBytes, out var afterPacketBytes);
            var packetNumberBytes = firstByte.SlicePacketNumberBytes(packetBytes, out var afterPacketNumberBytes);
            var number = PacketNumber.Parse(packetNumberBytes);

            remainings = afterPacketBytes;
            result = new RttPacket(version,
                                   destinationConnectionId,
                                   sourceConnectionId,
                                   number,
                                   afterPacketNumberBytes);

            return true;
        }
    }
}
