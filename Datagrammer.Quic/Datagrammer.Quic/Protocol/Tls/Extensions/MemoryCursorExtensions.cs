namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class MemoryCursorExtensions
    {
        public static bool TryParseSupportedGroups(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.SupportedGroups, 2..ushort.MaxValue, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartSupportedGroupsWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.SupportedGroups, 2..ushort.MaxValue);
        }

        public static bool TryParseSignatureAlgorithms(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.SignatureAlgorithms, 0..ushort.MaxValue, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartSignatureAlgorithmsWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.SignatureAlgorithms, 0..ushort.MaxValue);
        }

        public static bool TryParseKeyShares(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.KeyShare, 0..ushort.MaxValue, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartKeySharesWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.KeyShare, 0..ushort.MaxValue);
        }

        public static bool TryParseKeyShare(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return PayloadExtension.TryParse(cursor, ExtensionType.KeyShare, out buffer);
        }

        public static ExtensionLength.CursorWritingContext StartKeyShareWriting(this MemoryCursor cursor)
        {
            return PayloadExtension.StartWriting(cursor, ExtensionType.KeyShare);
        }

        public static bool TryParsePskKeyExchangeModes(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.PskKeyExchangeModes, 1..255, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartPskKeyExchangeModesWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.PskKeyExchangeModes, 1..255);
        }

        public static bool TryParseSupportedVersions(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.SupportedVersions, 2..254, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartSupportedVersionsWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.SupportedVersions, 2..254);
        }

        public static bool TryParseSupportedVersion(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return PayloadExtension.TryParse(cursor, ExtensionType.SupportedVersions, out buffer);
        }

        public static ExtensionLength.CursorWritingContext StartSupportedVersionWriting(this MemoryCursor cursor)
        {
            return PayloadExtension.StartWriting(cursor, ExtensionType.SupportedVersions);
        }

        public static bool TryParseServerNames(this MemoryCursor cursor, out MemoryBuffer buffer)
        {
            return VectorPayloadExtension.TryParse(cursor, ExtensionType.ServerName, 1..ushort.MaxValue, out buffer);
        }

        public static ExtensionVectorLength.CursorWritingContext StartServerNamesWriting(this MemoryCursor cursor)
        {
            return VectorPayloadExtension.StartWriting(cursor, ExtensionType.ServerName, 1..ushort.MaxValue);
        }
    }
}
