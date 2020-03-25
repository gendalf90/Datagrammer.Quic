using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public struct AckRangeEnumerator
    {
        private readonly PacketNumber largestAcknowledged;
        private readonly ReadOnlyMemory<byte> bytes;

        internal AckRangeEnumerator(PacketNumber largestAcknowledged, ReadOnlyMemory<byte> bytes)
        {
            this.largestAcknowledged = largestAcknowledged;
            this.bytes = bytes;
        }


    }
}
