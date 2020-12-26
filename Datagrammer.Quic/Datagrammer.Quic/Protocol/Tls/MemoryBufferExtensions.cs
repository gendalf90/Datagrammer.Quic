using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public static class MemoryBufferExtensions
    {
        private static Func<MemoryCursor, CertificateEntry> certificateEntryParser = CertificateEntry.Parse;
        private static Func<MemoryCursor, PskKeyExchangeMode> pskKeyExchangeModeParser = PskKeyExchangeMode.Parse;
        private static Func<MemoryCursor, ServerNameEntry> serverNameEntryParser = ServerNameEntry.Parse;
        private static Func<MemoryCursor, NamedGroup> namedGroupParser = NamedGroup.Parse;
        private static Func<MemoryCursor, SignatureScheme> signatureSchemeParser = SignatureScheme.Parse;
        private static Func<MemoryCursor, KeyShareEntry> keyShareEntryParser = KeyShareEntry.Parse;
        private static Func<MemoryCursor, ProtocolVersion> protocolVersionParser = ProtocolVersion.Parse;

        public static MemoryReader<CertificateEntry> GetCertificateEntryReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<CertificateEntry>(certificateEntryParser, buffer, cursor);
        }

        public static MemoryReader<PskKeyExchangeMode> GetPskKeyExchangeModeReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<PskKeyExchangeMode>(pskKeyExchangeModeParser, buffer, cursor);
        }

        public static MemoryReader<ServerNameEntry> GetServerNameEntryReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<ServerNameEntry>(serverNameEntryParser, buffer, cursor);
        }

        public static MemoryReader<NamedGroup> GetNamedGroupReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<NamedGroup>(namedGroupParser, buffer, cursor);
        }

        public static MemoryReader<SignatureScheme> GetSignatureSchemeReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<SignatureScheme>(signatureSchemeParser, buffer, cursor);
        }
        public static MemoryReader<KeyShareEntry> GetKeyShareEntryReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<KeyShareEntry>(keyShareEntryParser, buffer, cursor);
        }

        public static MemoryReader<ProtocolVersion> GetProtocolVersionReader(this MemoryBuffer buffer, MemoryCursor cursor)
        {
            return new MemoryReader<ProtocolVersion>(protocolVersionParser, buffer, cursor);
        }
    }
}
