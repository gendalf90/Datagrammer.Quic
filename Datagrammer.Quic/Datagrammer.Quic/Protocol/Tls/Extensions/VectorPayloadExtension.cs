using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class VectorPayloadExtension
    {
        public static bool TryParse(MemoryCursor cursor, ExtensionType type, Range range, out MemoryBuffer buffer)
        {
            buffer = new MemoryBuffer();

            if(!ExtensionType.TrySlice(cursor, type))
            {
                return false;
            }

            buffer = ExtensionVectorLength.Slice(cursor, range);

            return true;
        }

        public static ExtensionVectorLength.CursorWritingContext StartWriting(MemoryCursor cursor, ExtensionType type, Range range)
        {
            type.WriteBytes(cursor);

            return ExtensionVectorLength.StartWriting(cursor, range);
        }
    }
}
