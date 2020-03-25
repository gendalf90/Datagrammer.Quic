using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRanges
    {
        private readonly PacketNumber largestAcknowledged;
        private readonly ReadOnlyMemory<byte> bytes;

        internal AckRanges(PacketNumber largestAcknowledged, ReadOnlyMemory<byte> bytes)
        {
            this.largestAcknowledged = largestAcknowledged;
            this.bytes = bytes;
        }

        public AckRangeEnumerator GetEnumerator()
        {
            return new AckRangeEnumerator(largestAcknowledged, bytes);
        }
    }
}
