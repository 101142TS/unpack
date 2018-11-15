package z.unpack;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import z.unpack.util.RootUtil;
import z.unpack.util.FileUtil;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class MainActivity extends AppCompatActivity {
    public final static String hookSo = "/data/local/tmp/libunpack.so";
    public final static String hookFile = "/data/local/tmp/unpack.txt";
    //public final static String mTargetPackage = "zzz.jjni";       //一切正常
    //public final static String mTargetPackage = "com.eg.android.AlipayGphone"; //有點問題，會莫名崩潰
    public final static String mTargetPackage = "zzz.abjni";        //ok,1.txt
    public final static String mTargetApplication = "????";
    public final static String mTargetActivity = "?????";
    static {
        System.loadLibrary("unpack");
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("hello world");


        makeDirectoryAvaliable();
        moveSoFile();
        savehookFile();

    }
    boolean moveSoFile() {
        File dataPath = new File(getFilesDir().getParentFile(), "lib");
        File soPath = new File(dataPath, "libunpack.so");
        File hookPath = new File(hookSo);
        if (soPath.lastModified() <= hookPath.lastModified()) {
            return true;
        }

        if (soPath.exists() && soPath.isFile()) {
            if (FileUtil.FileCopy(soPath.getAbsolutePath(), hookSo)) {
                RootUtil rootUtil = RootUtil.getInstance();
                if (rootUtil.startShell()) {
                    rootUtil.execute("chmod 777 " + hookSo, null);
                    Log.d("101142ts", "release target so file into " + hookSo);
                }
            } else {
                Log.e("101142ts", "release target so file failed");
            }
        }
        return true;
    }

    boolean makeDirectoryAvaliable() {
        File tmpFolder = new File("data/local/tmp");
        if (!tmpFolder.exists()) {
            tmpFolder.mkdirs();
        }
        if (!tmpFolder.canWrite() || !tmpFolder.canRead() || !tmpFolder.canExecute()) {
            RootUtil rootUtil = RootUtil.getInstance();
            if (rootUtil.startShell()) {
                rootUtil.execute("chmod 777 " + tmpFolder.getAbsolutePath(), null);
            }
        }
        return true;
    }

    boolean savehookFile() {
        File file = new File(hookFile);
        if (!file.exists()) {
            RootUtil rootUtil = RootUtil.getInstance();
            if (rootUtil.startShell()) {
                rootUtil.execute("touch " + hookFile, null);
                rootUtil.execute("chmod 777 " + hookFile, null);
            }
        }

        try {
            FileWriter writer = new FileWriter(file);
            BufferedWriter wr = new BufferedWriter(writer);
            wr.write(mTargetPackage + "\n");
            wr.write(mTargetApplication + "\n");
            wr.write(mTargetActivity + "\n");
            wr.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
}
