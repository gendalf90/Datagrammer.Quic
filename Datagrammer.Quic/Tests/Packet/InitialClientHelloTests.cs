using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using System;
using Xunit;

namespace Tests.Packet
{
    public class InitialClientHelloTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHex();
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var version = PacketVersion.CreateByDraft(29);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var clientHelloBytes = Utils.ParseHexString(GetClientHelloHex());

            //Act
            var cursor = new MemoryCursor(buffer);

            using (InitialPacket.StartWriting(cursor, version, destConnectionId, sourceConnectionId, packetNumber, token))
            {
                using (CryptoFrame.StartWriting(cursor, 0))
                {
                    clientHelloBytes.CopyTo(cursor);
                }

                for (int i = 0; i < 972; i++)
                {
                    PaddingFrame.WriteBytes(cursor);
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Read_ResultsAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetMessageHex());
            var version = PacketVersion.CreateByDraft(29);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var clientHelloBytes = GetClientHelloHex();
            var cryptoFrame = new CryptoFrame();

            //Act
            var cursor = new MemoryCursor(messageBytes);
            var result = InitialPacket.TryParse(cursor, out var packet);

            using (packet.Payload.SetCursor(cursor))
            {
                result &= CryptoFrame.TryParse(cursor, out cryptoFrame);

                for (int i = 0; i < 972; i++)
                {
                    result &= PaddingFrame.TryParse(cursor);
                }

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(version, packet.Version);
            Assert.Equal(sourceConnectionId, packet.SourceConnectionId);
            Assert.Equal(destConnectionId, packet.DestinationConnectionId);
            Assert.Equal(packetNumber, packet.Number);
            Assert.Equal(token, packet.Token);
            Assert.Equal(0, cryptoFrame.Offset);
            Assert.Equal(clientHelloBytes, Utils.ToHexString(cryptoFrame.Data.Read(cursor).ToArray()), true);
        }

        private string GetMessageHex()
        {
            return "c0ff00001d084981dc52fe5e141208b8923783d474a2570044ca00060040f9010000f503032b2f8e3fdd6898ceefa6ee8bb51ea11f32da7bb2bcc5cc04be93293ab87e9ee3000006130213011303010000c60033004700450017004104e317a93249974814b6908e7974323b4c5dcb9e648fa7e2c184d71c43becc3eb07cc98a5f787a117605196e51c7d09ade232c73590e07a6b190804cbd1075aab600000014001200000f717569632e7365656d616e6e2e696f0010000800060568332d3239002b0003020304000d000a00080804040304010201000a000600040017001dffa5002d050480004000070480004000040480008000080101090103010267100e0104030245c00f08b8923783d474a257002d0003020001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        }

        private (string DestConnectionIdHex, string SourceConnectionIdHex) GetConnectionIdsHex()
        {
            return ("084981dc52fe5e1412", "08b8923783d474a257");
        }

        private string GetPacketNumberHex()
        {
            return "00";
        }

        private string GetClientHelloHex()
        {
            return "010000f503032b2f8e3fdd6898ceefa6ee8bb51ea11f32da7bb2bcc5cc04be93293ab87e9ee3000006130213011303010000c60033004700450017004104e317a93249974814b6908e7974323b4c5dcb9e648fa7e2c184d71c43becc3eb07cc98a5f787a117605196e51c7d09ade232c73590e07a6b190804cbd1075aab600000014001200000f717569632e7365656d616e6e2e696f0010000800060568332d3239002b0003020304000d000a00080804040304010201000a000600040017001dffa5002d050480004000070480004000040480008000080101090103010267100e0104030245c00f08b8923783d474a257002d0003020001";
        }
    }
}
