package gtrboy.learning.FTP;

public enum FTPErrorCode {
    DATANOERROR,
    TIMEOUT,    // data transfer timeout
    IOERROR,    // control transfer timeout or disconnection
    DATAERROR,   // data transfer return invalid value in stage 2
    UNKERROR,   // unkown error
}
