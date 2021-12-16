package gtrboy.learning.utils;

public final class LogUtils {
    public static int LOG_LEVEL;
    private static final int DEBUG = 3;
    private static final int INFO = 2;
    private static final int FATAL = 1;

    private LogUtils(){
        LOG_LEVEL = 0;
    }

    public static void logErrExit(String curclass, String logstr){
        System.out.printf("[%s] %s\n", curclass, logstr);
        System.exit(-1);
        //e.printStackTrace();
    }

    public static void logException(Exception e, String curClass, String logStr){
        System.out.printf("[%s] %s\n", curClass, logStr);
        e.printStackTrace();
    }


    public static void logDebug(String curClass, String logStr){
        if(LOG_LEVEL>=DEBUG){
            System.out.printf("[DEBUG | %s] %s\n", curClass, logStr);
        }else{

        }
    }

    public static void logInfo(String curClass, String logStr){
        if(LOG_LEVEL>=INFO){
            System.out.printf("[INFO | %s] %s\n", curClass, logStr);
        }else{

        }
    }

    public static void logFatal(String curClass, String logStr){
        if(LOG_LEVEL>=FATAL){
            System.out.printf("[FATAL | %s] %s\n", curClass, logStr);
        }else{

        }
    }
}

