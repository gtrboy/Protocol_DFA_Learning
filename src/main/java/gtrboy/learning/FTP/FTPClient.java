package gtrboy.learning.FTP;

import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPConnectionClosedException;
import org.apache.commons.net.ftp.FTPReply;
// import org.apache.commons.net.ftp.FTPClient;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class FTPClient extends FTP {

    private final InetAddress internetAddress;
    private final int port;
    private final int timeout;
    private final FTPServerAdapterConfig config;
    //private Socket activeSocket;

    public FTPClient(FTPServerAdapterConfig config) throws UnknownHostException {

        this.config = config;
        this.internetAddress = InetAddress.getByName(config.getInternetAddress());
        this.port = config.getPort();
        this.timeout = config.getTimeout();

    }

    public void buildConnection() throws IOException {
        this.connect(internetAddress, port);
    }

    public void reset() throws IOException {
        this.disconnect();
    }

    public String ftp_user() {
        String username = config.getUsername();
        try{
            int ret = super.user(username);
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }

    }

    public String ftp_pass() {
        String password = config.getPassword();
        try{
            int ret = super.pass(password);
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }

    public String ftp_pwd() {
        try{
            int ret = super.pwd();
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }

    public String ftp_port() throws UnknownHostException {
        int data_port = config.getDataport();
        String localAddrStr = config.getLocalAddress();
        InetAddress localAddr = InetAddress.getByName(localAddrStr);
        try{
            int ret = super.port(localAddr, data_port);
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }
/*
    public String ftp_stor() throws IOException {
        int ret = super.user(username);
        return Integer.toString(ret);
    }

 */

    public String ftp_retr() {
        String retr_file = config.getDownfile();
        int data_port = config.getDataport();
        int timeout = this.timeout;
        ServerSocket server = null;
        Socket socket = null;

        try{
            // Open the port for active data transfer
            server = new ServerSocket(data_port);

            // send RETR cmd, the return code is 150 if success

            int ret1 = super.retr(retr_file);
            if(!FTPReply.isPositivePreliminary(ret1)){
                return FTPErrorCode.DATAERROR.toString();
            }

            // create client socket by using server.accept()

            if(timeout >= 0){
                server.setSoTimeout(timeout*1000);
            }
            socket = server.accept();
            if(timeout >= 0){
                socket.setSoTimeout(timeout*1000);
            }

            ReadSocket(socket);

            int ret2 = getReply();
            if(!FTPReply.isPositiveCompletion(ret2)){
                return FTPErrorCode.DATAERROR.toString();
            }
            return Integer.toString(ret2);
        }catch(SocketTimeoutException s)
        {
            //System.out.println("Socket timed out!");
            return FTPErrorCode.TIMEOUT.toString();
        }catch(IOException e)
        {
            //System.out.println(e.getMessage());
            //e.printStackTrace();
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }
            else{
                return FTPErrorCode.UNKERROR.toString();
            }
        } finally {
            try {
                if (server != null) {
                    server.close();
                }
                if (socket != null) {
                    socket.close();
                }
            }
            catch (IOException ignored){

            }
        }
    }

    public String ftp_list() {
        int data_port = config.getDataport();
        int timeout = this.timeout;
        ServerSocket server = null;
        Socket socket = null;

        try{
            // Open the port for active data transfer
            server = new ServerSocket(data_port);

            // send LIST cmd, the return code is 150 if success
            int ret1 = super.list();
            if(!FTPReply.isPositivePreliminary(ret1)){
                return FTPErrorCode.DATAERROR.toString();
            }

            // create client socket by using server.accept()
            if(timeout >= 0){
                server.setSoTimeout(timeout*1000);
            }
            socket = server.accept();
            if(timeout >= 0){
                socket.setSoTimeout(timeout*1000);
            }

            ReadSocket(socket);

            int ret2 = getReply();
            if(!FTPReply.isPositiveCompletion(ret2)){
                return FTPErrorCode.DATAERROR.toString();
            }
            return Integer.toString(ret2);
        }catch(SocketTimeoutException s)
        {
            //System.out.println("Socket timed out!");
            return FTPErrorCode.TIMEOUT.toString();
        }catch(IOException e)
        {
            //System.out.println(e.getMessage());
            //e.printStackTrace();
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }
            else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }finally {
            try {
                if (server != null) {
                    server.close();
                }
                if (socket != null) {
                    socket.close();
                }
            }
            catch (IOException ignored){

            }
        }
    }

    public String ftp_cwd() {
        try{
            String ch_dir = config.getChDir();
            int ret = super.cwd(ch_dir);
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }

    public String ftp_dele() {
        try {
            String del_file = config.getDelfile();
            int ret = super.dele(del_file);
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }

    public String ftp_quit() {
        try {
            int ret = super.quit();
            disconnect();
            return Integer.toString(ret);
        }catch (IOException e){
            if(e.getMessage().equals("Connection is not open")) {
                return FTPErrorCode.IOERROR.toString();
            }else{
                return FTPErrorCode.UNKERROR.toString();
            }
        }
    }


    protected void ReadSocket(Socket socket) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        String buf = reader.readLine();
        socket.close();
        //System.out.println("Retrieved data: "+buf);
    }

    public void arrangeServerDir() throws IOException {
        String homedir = config.getFtphomedir() + "/";
        File downfile = new File(homedir + config.getDownfile());
        File delfile = new File(homedir + config.getDelfile());
        // Before every learning round, create the file to be downloaded and the file to be deleted
        downfile.createNewFile();  // redundant, could be cut
        delfile.createNewFile();

        String childdir = homedir + config.getChDir() + "/";
        //System.out.println(childdir+config.getDownfile());
        //System.out.println(childdir+config.getDelfile());
        File childdownfile = new File(childdir + config.getDownfile());
        File childdelfile = new File(childdir + config.getDelfile());
        // Before every learning round, create the downloaded file and deleted file in the child dir
        childdownfile.createNewFile();
        childdelfile.createNewFile();
    }
}
