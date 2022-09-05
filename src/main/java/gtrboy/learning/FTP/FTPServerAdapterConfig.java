package gtrboy.learning.FTP;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class FTPServerAdapterConfig  {
    private InetAddress internetAddress;  // ip address of the ftp server
    private InetAddress localAddress;   // local address for active mode (PORT)
    private int port = 21;  // ftp control data port
    private int timeout = 10;  //timeout
    private String upfile;  // upload file name
    private String downfile;  // download file name
    private String delfile;  // delete file name
    private String username;  // ftp username
    private String password;  //ftp password
    private String chdir;  // change dir name
    private int dataport;  // data transform port for active mode (PORT)
    private String ftphomedir;  // ftp home dir, used to reset dir layout
    //private String ftpchilddir;

    public FTPServerAdapterConfig()  {
        //String f_content = readJSONFile("FTPServer.conf");
        //JSONObject j_obj = JSON.parseObject(f_content);

    }

    /*
    public FTPServerAdapterConfig(InetAddress internetAddress, InetAddress localAddress, int port, int timeout,
                                  String upfile, String downfile, String delfile,String username, String password,
                                  String chdir,String port_str, int dataport) {
        this.internetAddress = internetAddress;
        this.localAddress = localAddress;
        this.port = port;
        this.timeout = timeout;
        this.upfile = upfile;
        this.downfile = downfile;
        this.delfile = delfile;
        this.username = username;
        this.password = password;
        this.chdir = chdir;
        //this.port_str = port_str;
        this.dataport = dataport;
    }
     */

    public String getInternetAddress() {
        String addr_str =  internetAddress.toString();
        return addr_str.substring(addr_str.lastIndexOf("/") + 1 );
    }

    public void setInternetAddress(String address) throws UnknownHostException {
        this.internetAddress = InetAddress.getByName(address);
    }

    public String getLocalAddress() {
        String addr_str =  localAddress.toString();
        return addr_str.substring(addr_str.lastIndexOf("/") + 1 );
    }

    public void setLocalAddress(String address) throws UnknownHostException {
        this.localAddress = InetAddress.getByName(address);
    }


    public Integer getPort() { return port; }

    public void setPort(int port){ this.port =  port; }

    public Integer getTimeout() { return timeout; }

    public void setTimeout(int timeout){ this.timeout = timeout; }

    public String getUpfile(){return upfile;}

    public void setUpfile(String file){ this.upfile = file; }

    public String getDownfile(){return downfile;}

    public void setDownfile(String file){ this.downfile = file; }

    public String getDelfile(){return delfile;}

    public void setDelfile(String file){ this.delfile = file; }

    public String getUsername(){return username;}

    public void setUsername(String username){ this.username = username; }

    public String getPassword(){return password;}

    public void setPassword(String password){ this.password =  password; }

    public String getChDir(){return chdir;}

    public void setChdir(String chdir){this.chdir = chdir; }

    public String getFtphomedir(){return ftphomedir;}

    public void setFtphomedir(String ftphomedir){ this.ftphomedir = ftphomedir; }

    public Integer getDataport(){return dataport;}

    public void setDataport(int port){ this.dataport = port; }
}
