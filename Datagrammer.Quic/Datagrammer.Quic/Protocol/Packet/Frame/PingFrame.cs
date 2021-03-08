namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class PingFrame
    {
        public static bool TryParse(MemoryCursor cursor)
        {
            return FrameType.TrySlice(cursor, FrameType.Ping);
        }

        public static void Write(MemoryCursor cursor)
        {
            FrameType.Ping.Write(cursor);
        }
    }
}
