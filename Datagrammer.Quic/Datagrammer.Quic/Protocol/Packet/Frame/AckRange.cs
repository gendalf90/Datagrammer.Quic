namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckRange
    {
        internal AckRange(PacketNumber start, PacketNumber end)
        {
            Start = start;
            End = end;
        }

        public PacketNumber Start { get; }

        public PacketNumber End { get; }
    }
}
