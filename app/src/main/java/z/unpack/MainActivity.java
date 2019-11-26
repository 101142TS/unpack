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
    public final static int mWaitingTime = 1;
    public final static int mMode = 0;

    public MainActivity() {
        super();
    }

    //public final static String mTargetPackage = "com.example.simple";
    //public final static Strin/home/b/Desktop/unpackg mTargetPackage = "com.vjson.anime";  //legu 2.10.2.2
    //public final static String mTargetPackage = "com.jr.kingofglorysupport"; //legu 2.10.2.3
    //public final static String mTargetPackage = "com.nbvru.wepnb.bvfdfdc";  //legu 2.10.3.1
    //public final static String mTargetPackage = "com.billy.sdclean";        //legu 2.10.4.0
    //public final static String mTargetPackage = "org.fuyou.wly";    //libjiagu.so 12e8d2721ae9109b1332540311376344
    //public final static String mTargetPackage = "com.example.eisk.cn";    //libjiagu.so b6dd50c44eead298423d1853025cfe17
    //public final static String mTargetPackage = "com.majun.landlordtreasure";   //libjiagu.so   c777cc1017287f00d9cdd022b867d8ae

    //public final static String mTargetPackage = "cbp.game.chess"; //libjiagu.so    f880afeacaf320cd2eaf44a928aa9d91
    //public final static String mTargetPackage = "com.systoon.beijingtoon";  //libjiagu.so   91d2e05ac30d91afbf02a8e2d4448d14
    //public final static String mTargetPackage = "com.nanxi.a411"; //libjiagu.so b080d680f71862a4d7b4ccf9e41853e5
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so efe21d36f54114e1067b620071573265
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so f0fa7384273217a2431ab1c60ed21037
    //public final static String mTargetPackage = "com.huxiu";    //liabjiagu.so bdc6e7786076696da260d8bbbafe570e
    //public final static String mTargetPackage = "com.mytest.demo"; //Bangle Demo
    //public final static String mTargetPackage = "com.huxiu";    //lia.bjiagu.so da3fc3018e6bf81e6fb9e5e8f7e785cb
    //public final static String mTargetPackage = "com.pmp.ppmoney"; //libDexHelper.so
    //public final static String mTargetPackage = "zzz.jjni"; //360sample
    //public final static String mTargetPackage = "e.b.myapplication";
    //public final static String mTargetPackage = "github.jp1017.hellojni";
    //public final static String mTargetPackage = "com.sf.activity";   //assets/ijm_lib/
    //public final static String mTargetPackage = "aihuishou.aihuishouapp"; //dingxiang
    //public final static String mTargetPackage = "com.yanxin.eloanan";   //assets/main000/   20190321
    //public final static String mTargetPackage = "com.iss.qilubank";
    //public final static String mTargetPackage = "zzz.testnative";
    //public final static String mTargetPackage = "com.greenpoint.android.mc10086.activity";
    //public final static String mTargetPackage = "com.icbc";
    //public final static String mTargetPackage = "com.perflyst.twire";
    //public final static String mTargetPackage = "org.zirco";
    //public final static String mTargetPackage = "org.scoutant.blokish";
    //public final static String mTargetPackage = "com.xargsgrep.portknocker";
    //public final static String mTargetPackage = "github.vatsal.easyweatherdemo";
    //public final static String mTargetPackage = "edu.testapk.crackme";
    //public final static String mTargetPackage = "org.csploit.android";
    //public final static String mTargetPackage = "jp.forkhub";
    //public final static String mTargetPackage = "eu.depau.etchdroid";
    //public final static String mTargetPackage = "io.github.hopedia";
    //public final static String mTargetPackage = "org.schabi.newpipelegacy";
    //public final static String mTargetPackage = "com.iss.qilubank";
    //public final static String mTargetPackage = "com.gome.eshopnew";
    //public final static String mTargetPackage = "com.forever.browser";
    //public final static String mTargetPackage = "com.cmcc.cmvideo";
    //public final static String mTargetPackage = "com.qihoo360.mobilesafe.opti.powerctl";
    //public final static String mTargetPackage = "com.softbank.mbank.xy.qhjd";
    //public final static String mTargetPackage = "com.picc.aasipods";
    //public final static String mTargetPackage = "com.showself.ui";
    //public final static String mTargetPackage = "com.huaqian";
    //public final static String mTargetPackage = "com.zlqb.app";
    //public final static String mTargetPackage = "com.storm.smart";
    //public final static String mTargetPackage = "com.xwsd.app";
    //public final static String mTargetPackage = "cn.xxt.jxlxandroid";
    //public final static String mTargetPackage = "com.android.baiyimao";com.shcc.microcredit
    //public final static String mTargetPackage = "com.z.hhwk";
    //public final static String mTargetPackage = "com.esbook.reader";
    //public final static String mTargetPackage = "com.anysoft.tyyd";
    //public final static String mTargetPackage = "com.autohome.mycar";
    //public final static String mTargetPackage = "fm.jihua.kecheng";
    //public final static String mTargetPackage = "com.ludashi.benchmark";
    //public final static String mTargetPackage = "com.wenba.bangbang";
    //public final static String mTargetPackage = "com.qihoo.loan";
    //public final static String mTargetPackage = "com.greenpoint.android.mc10086.activity";
    //public final static String mTargetPackage = "com.mobike.mobikeapp";
    //public final static String mTargetPackage = "com.shcc.microcredit";
    //public final static String mTargetPackage = "com.ophone.reader.ui";
    //public final static String mTargetPackage = "com.pmp.ppmoney";
    //public final static String mTargetPackage = "com.mygolbs.mybus";
    //public final static String mTargetPackage = "com.bertadata.qxb";
    //public final static String mTargetPackage = "com.memezhibo.android";
    //public final static String mTargetPackage = "org.cocos2dx.VirusVsVirus2";
    //public final static String mTargetPackage = "com.mojang.minecraftpetool";
    //public final static String mTargetPackage = "com.tencent.qlauncher.lite";
    //public final static String mTargetPackage = "com.tencent.tgclub";
    //public final static String mTargetPackage = "com.black.unique";
    //public final static String mTargetPackage = "com.fqapp.zsh";
    //public final static String mTargetPackage = "com.shangfang.gylm";
    //public final static String mTargetPackage = "com.songguoyhqw";
    //public final static String mTargetPackage = "com.sf.activity";
    //public final static String mTargetPackage = "cn.dictcn.android.digitize.swg_xhzd_21003";
    //public final static String mTargetPackage = "com.hundsun.winner.pazq";
    public final static String mTargetPackage = "com.cqmc.client";
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
            wr.write("unpack" + "\n");
            wr.write(String.valueOf(mWaitingTime) + "\n");
            wr.write(String.valueOf(mMode) + "\n");
            //wr.write(mTargetActivity + "\n");
            wr.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
}
