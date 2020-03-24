using System;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct RetryPacket
    {
        private RetryPacket(PacketVersion version,
                            PacketConnectionId destinationConnectionId,
                            PacketConnectionId sourceConnectionId,
                            PacketRetryToken token,
                            PacketRetryIntegrityTag tag)
        {
            Version = version;
            DestinationConnectionId = destinationConnectionId;
            SourceConnectionId = sourceConnectionId;
            Token = token;
            Tag = tag;
        }

        public PacketVersion Version { get; }

        public PacketConnectionId DestinationConnectionId { get; }

        public PacketConnectionId SourceConnectionId { get; }

        public PacketRetryToken Token { get; }

        public PacketRetryIntegrityTag Tag { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out RetryPacket result)
        {
            result = new RetryPacket();

            if (!PacketFirstByte.TryParse(bytes, out var firstByte, out var afterFirstByteBytes))
            {
                return false;
            }

            if (firstByte.IsShortHeader())
            {
                return false;
            }

            if (!firstByte.IsRetryType())
            {
                return false;
            }

            if (!PacketVersion.TryParse(afterFirstByteBytes, out var version, out var afterVersionBytes))
            {
                return false;
            }

            if (!PacketConnectionId.TryParse(afterVersionBytes, out var destinationConnectionId, out var afterDestinationConnectionIdBytes))
            {
                return false;
            }

            if (!PacketConnectionId.TryParse(afterDestinationConnectionIdBytes, out var sourceConnectionId, out var afterSourceConnectionIdBytes))
            {
                return false;
            }

            if(!PacketRetryIntegrityTag.TryParse(afterSourceConnectionIdBytes, out var tag, out var beforeTagBytes))
            {
                return false;
            }

            var token = new PacketRetryToken(beforeTagBytes);

            result = new RetryPacket(version,
                                     destinationConnectionId,
                                     sourceConnectionId,
                                     token,
                                     tag);

            return true;
        }
    }
}
