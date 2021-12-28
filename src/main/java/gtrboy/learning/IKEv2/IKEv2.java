package gtrboy.learning.IKEv2;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import gtrboy.learning.IKEv2.parsers.IKEv2Parser;
import org.apache.commons.net.DatagramSocketClient;
import org.apache.commons.net.tftp.TFTPPacket;
import org.apache.commons.net.tftp.TFTPPacketException;

public class IKEv2 extends DatagramSocketClient {

    /**
     * The default number of milliseconds to wait to receive a datagram
     * before timing out.  The default is 500 milliseconds (0.5 seconds).
     */
    public static final int DEFAULT_TIMEOUT = 500;

    public static final int DEFAULT_PORT = 500;

    private static final int PACKET_SIZE = 1024;

    private byte[] receiveBuffer;

    /** A datagram used to minimize memory allocation in bufferedReceive() */
    private DatagramPacket receiveDatagram;

    /** A datagram used to minimize memory allocation in bufferedSend() */
    private DatagramPacket sendDatagram;

    /**
     * A buffer used to accelerate sends in bufferedSend().
     * It is left package visible so that TFTPClient may be slightly more
     * efficient during file sends.  It saves the creation of an
     * additional buffer and prevents a buffer copy in _newDataPcket().
     */
    byte[] sendBuffer;

    public IKEv2()
    {
        setDefaultTimeout(DEFAULT_TIMEOUT);
        receiveBuffer = null;
        receiveDatagram = null;
    }

    /**
     * Initializes the internal buffers. Buffers are used by
     * {@link #bufferedSend  bufferedSend() } and
     * {@link #bufferedReceive  bufferedReceive() }.  This
     * method must be called before calling either one of those two
     * methods.  When you finish using buffered operations, you must
     * call {@link #endBufferedOps  endBufferedOps() }.
     */
    public final void beginBufferedOps()
    {
        receiveBuffer = new byte[PACKET_SIZE];
        receiveDatagram =
                new DatagramPacket(receiveBuffer, receiveBuffer.length);
        sendBuffer = new byte[PACKET_SIZE];
        sendDatagram =
                new DatagramPacket(sendBuffer, sendBuffer.length);
    }

    public final IKEv2Parser bufferedReceive() throws IOException,
            InterruptedIOException, SocketException, TFTPPacketException
    {
        receiveDatagram.setData(receiveBuffer);
        receiveDatagram.setLength(receiveBuffer.length);
        _socket_.receive(receiveDatagram);

        final TFTPPacket newTFTPPacket = TFTPPacket.newTFTPPacket(receiveDatagram);
        return newTFTPPacket;
    }

    public final void bufferedSend(final byte[] pkt_bytes, String peerAddr, int port) throws IOException
    {
        InetSocketAddress peerSocketAddr = new InetSocketAddress(peerAddr, port);
        DatagramPacket packet = new DatagramPacket(pkt_bytes, pkt_bytes.length, peerSocketAddr);
        _socket_.send(packet);
    }

    public final void endBufferedOps()
    {
        receiveBuffer = null;
        receiveDatagram = null;
        sendBuffer = null;
        sendDatagram = null;
    }

}
