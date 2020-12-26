namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class PayloadExtension
    {
        public static bool TryParse(MemoryCursor cursor, ExtensionType type, out MemoryBuffer buffer)
        {
            buffer = new MemoryBuffer();

            if(!ExtensionType.TrySlice(cursor, type))
            {
                return false;
            }

            buffer = ExtensionLength.Slice(cursor);

            return true;
        }

        public static ExtensionLength.CursorWritingContext StartWriting(MemoryCursor cursor, ExtensionType type)
        {
            type.WriteBytes(cursor);

            return ExtensionLength.StartWriting(cursor);
        }
    }
}
