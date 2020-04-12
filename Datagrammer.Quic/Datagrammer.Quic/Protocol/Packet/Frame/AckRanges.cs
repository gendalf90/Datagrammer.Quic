using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRanges
    {
        private readonly ReadOnlyMemory<byte> bytes;

        internal AckRanges(PacketNumber largestAcknowledged, ReadOnlyMemory<byte> bytes)
        {
            LargestAcknowledged = largestAcknowledged;

            this.bytes = bytes;
        }

        public PacketNumber LargestAcknowledged { get; }

        public AckRangeEnumerator GetEnumerator()
        {
            return new AckRangeEnumerator(bytes);
        }
    }
}
