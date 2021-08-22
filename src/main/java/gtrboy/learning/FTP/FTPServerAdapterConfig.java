package gtrboy.learning.FTP;

import gtrboy.learning.learn.LearningConfig;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

public class FTPServerAdapterConfig  {
    private InetAddress internetAddress;
    private InetAddress localAddress;
    private int port = 21;
    private int timeout = 25;
    private String upfile;
    private String downfile;
    private String delfile;
    private String username;
    private String password;
    private String chdir;
    private int dataport;
    private String ftphomedir;
    private String ftpchilddir;

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
