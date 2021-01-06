namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class PaddingFrame
    {
        public static bool TryParse(MemoryCursor cursor)
        {
            return FrameType.TrySlice(cursor, FrameType.Padding);
        }

        public static void WriteBytes(MemoryCursor cursor)
        {
            FrameType.Padding.Write(cursor);
        }
    }
}
