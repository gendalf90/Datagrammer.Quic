using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct RetryPacket
    {
        private RetryPacket(PacketVersion version,
                            PacketConnectionId destinationConnectionId,
                            PacketConnectionId sourceConnectionId,
                            PacketToken retryToken,
                            PacketRetryIntegrityTag retryIntegrityTag)
        {
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            RetryToken = retryToken;
            RetryIntegrityTag = retryIntegrityTag;
        }

        public PacketVersion Version { get; }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketConnectionId SourceConnectionId { get; }

        public PacketToken RetryToken { get; }

        public PacketRetryIntegrityTag RetryIntegrityTag { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out RetryPacket result)
        {
            result = new RetryPacket();

            var firstByte = PacketFirstByte.Parse(bytes, out var afterFirstByteBytes);

            if (firstByte.IsShortHeader())
            {
                return false;
            }

            if (!firstByte.IsRetryType())
            {
                return false;
            }

            var version = PacketVersion.Parse(afterFirstByteBytes, out var afterVersionBytes);
            var destinationConnectionId = PacketConnectionId.Parse(afterVersionBytes, out var afterDestinationConnectionIdBytes);
            var sourceConnectionId = PacketConnectionId.Parse(afterDestinationConnectionIdBytes, out var afterSourceConnectionIdBytes);
            var tag = PacketRetryIntegrityTag.Parse(afterSourceConnectionIdBytes, out var beforeTagBytes);
            var token = new PacketToken(beforeTagBytes);

            result = new RetryPacket(version,
                                     destinationConnectionId,
                                     sourceConnectionId,
                                     token,
                                     tag);

            return true;
        }
    }
}
