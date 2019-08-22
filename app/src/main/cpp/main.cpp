//
// Created by b on 18-11-9.
//
#include <jni.h>
#include <AndroidDef.h>
#include "MinAndroidDef.h"
#include "utils/RWGuard.h"
#include "entry.cpp"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

# define mywrite(filename, ...) do {                                                        \
        FILE *fp = fopen(filename.c_str(), "w");                                            \
        fprintf(fp, __VA_ARGS__);                                                           \
        fflush(fp);                                                                         \
        fclose(fp);                                                                         \
    } while(false)
struct FupkInterface {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;
    void* reserved4;
    void* reserved5;        //data地址
    void* reserved6;        //procmaps_cnt
    void* reserved7;
};
struct procmaps {
    unsigned int l, r;
    char perms[4];
    unsigned int offest;
    char pathname[100];
}data[101000];
int procmaps_cnt;

FupkInterface* gUpkInterface;
HashTable* userDexFiles = nullptr;
Object* (*fdvmDecodeIndirectRef)(void* self, jobject jobj) = nullptr;
Thread* (*fdvmThreadSelf)() = nullptr;
void (*fupkInvokeMethod)(const Method* meth) = nullptr;
ClassObject* (*floadClassFromDex)(DvmDex* pDvmDex,
                                  const DexClassDef* pClassDef, Object* classLoader) = nullptr;
HashTable* (*GetloadedClasses)() = nullptr;
void (*fdvmClearException)(Thread* self) = nullptr;
ClassObject* (*fdvmDefineClass)(DvmDex* pDvmDex, const char* descriptor, Object* classLoader) = nullptr;
bool (*fdvmIsClassInitialized)(const ClassObject* clazz) = nullptr;
bool (*fdvmInitClass)(ClassObject* clazz) = nullptr;

jmethodID hookMethodID;
jclass dumpMethodclazz;

std::string str;
std::string recordFile, scheFile, logFile, dvmFile, tidFile, codedir;
int tot_dvm;
u4 DvmName[50];

void ReadClassDataHeader(const uint8_t **pData, DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

void ReadClassDataField(const uint8_t **pData, DexField *pField) {
    pField->fieldIdx = readUnsignedLeb128(pData);
    pField->accessFlags = readUnsignedLeb128(pData);
}

void ReadClassDataMethod(const uint8_t **pData, DexMethod *pMethod) {
    pMethod->methodIdx = readUnsignedLeb128(pData);
    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
}

//这部分代码基本是复用dexReadAndVerifyClassData中的代码
//dalvik/libdex/DexClass.cpp
DexClassData *ReadClassData(const uint8_t **pData) {
    DexClassDataHeader header;

    if (*pData == NULL) {
        return NULL;
    }

    //读取classHeader数据，主要是为了获取field个数和method个数
    ReadClassDataHeader(pData, &header);

    //分配空间用于保存DexClassData
    //注意此时DexClassData中将不再用指针的形式保存数据，而是使用数组保存
    size_t resultSize = sizeof(DexClassData) + (header.staticFieldsSize * sizeof(DexField)) + (header.instanceFieldsSize * sizeof(DexField)) + (header.directMethodsSize * sizeof(DexMethod)) + (header.virtualMethodsSize * sizeof(DexMethod));
    DexClassData *result = (DexClassData *)malloc(resultSize);
    if (result == NULL) {
        return NULL;
    }

    uint8_t *ptr = ((uint8_t *)result) + sizeof(DexClassData);
    result->header = header;
    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField *)ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    }
    else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField *)ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    }
    else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod *)ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    }
    else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod *)ptr;
    }
    else {
        result->virtualMethods = NULL;
    }

    for (uint32_t i = 0; i < header.staticFieldsSize; i++) {
        ReadClassDataField(pData, &result->staticFields[i]);
    }

    for (uint32_t i = 0; i < header.instanceFieldsSize; i++) {
        ReadClassDataField(pData, &result->instanceFields[i]);
    }

    for (uint32_t i = 0; i < header.directMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->directMethods[i]);
    }

    for (uint32_t i = 0; i < header.virtualMethodsSize; i++) {
        ReadClassDataMethod(pData, &result->virtualMethods[i]);
    }

    return result;
}
int userDexFilesSize() {
    return userDexFiles->tableSize;
}
DvmDex* getdvmDex(int idx, const char *&dexName) {
    if (idx >= userDexFilesSize())
        return nullptr;
    HashEntry *hashEntry = userDexFiles->pEntries + idx;
    // valid check
    if (hashEntry->data == nullptr)
        return nullptr;
    if (!RWGuard::getInstance()->isReadable(reinterpret_cast<unsigned int>(hashEntry->data))) {
        FLOGE("I Found an no empty hashEntry but it is not readable %d %08x", idx, hashEntry->data);
        return nullptr;
    }
    DvmDex *dvmDex = nullptr;
    DexOrJar *dexOrJar = (DexOrJar*) hashEntry->data;
    if (dexOrJar->isDex) {
        RawDexFile *rawDexFile = dexOrJar->pRawDexFile;
        dvmDex = rawDexFile->pDvmDex;
    } else {
        JarFile *jarFile = dexOrJar->pJarFile;
        dvmDex = jarFile->pDvmDex;
    }

    // right, just return
    dexName = dexOrJar->fileName;
    return dvmDex;
}
void mkdir_DexFile(DvmDex *pDvmDex, Object *loader, JNIEnv* env) {
    DexFile *pDexFile = pDvmDex->pDexFile;
    u4 num_class_defs = pDexFile->pHeader->classDefsSize;
    for (u4 i = 0; i < num_class_defs; i++) {
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        const char *header1 = "Landroid";
        const char *header2 = "Ldalvik";
        const char *header3 = "Ljava";
        const char *header4 = "Llibcore";
        const char *header5 = "Ljavax";
        const char *header6 = "Lbutterknife";
        //如果是系统类，或者classDataOff为0，则跳过
        if (!strncmp(header1, descriptor, strlen(header1)) ||
            !strncmp(header2, descriptor, strlen(header2)) ||
            !strncmp(header3, descriptor, strlen(header3)) ||
            !strncmp(header4, descriptor, strlen(header4)) ||
            !strncmp(header5, descriptor, strlen(header5)) ||
            !strncmp(header6, descriptor, strlen(header6)) ||
            !pClassDef->classDataOff) {
            FLOGE("DexDump %s Landroid or classDataOff 0", descriptor);
            continue;
        }

        std::string itdir = codedir;
        int ln = strlen(descriptor);
        for (int i = 0; i < ln - 1; i++) {
            if (descriptor[i] == '/') {
                mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            }
            itdir.push_back(descriptor[i]);
        }
        mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    }
}
void itoa(char *buf, u4 d) {
    memset(buf, 0, sizeof(buf));
    char *p = buf;
    char *p1, *p2;
    u4 ud = d;
    int divisor = 10;

    do {
        *p++ = (ud % divisor) + '0';
    }
    while (ud /= divisor);

    /* Terminate BUF.  */
    *p = 0;

    /* Reverse BUF.  */
    p1 = buf;
    p2 = p - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }
}
void GetMaps() {
    int pid = getpid();
    char tmp[50];
    itoa(tmp, pid);
    //  /proc/2207/maps
    std::string mapsfile = "/proc/" + std::string(tmp) + "/maps";
    FILE *fp = fopen(mapsfile.c_str(), "r");
    procmaps_cnt = 0;

    while (true) {
        if (fscanf(fp, "%x-%x %s %x %s %s", &data[procmaps_cnt].l, &data[procmaps_cnt].r,
                   data[procmaps_cnt].perms, &data[procmaps_cnt].offest, tmp, tmp) == EOF)
            break;
        char c;
        int i = 0;
        while (true) {
            c = getc(fp);
            if (c == ' ')
                continue;
            if (c == '\n' || c == '\r')
                break;
            data[procmaps_cnt].pathname[i++] = c;
        }
        procmaps_cnt++;

        //getchar();
    }
    fclose(fp);

    return;
}
void DumpClassbyInovke(DvmDex *pDvmDex, Object *loader, JNIEnv* env,
                       int stDvmDex, int stClass, int stMethod) {
    DexFile *pDexFile = pDvmDex->pDexFile;
    Thread *self = fdvmThreadSelf();

    u4 num_class_defs = pDexFile->pHeader->classDefsSize;
    for (u4 i = stClass; i < num_class_defs; i++) {
        /*
         * 有可能在定义类或者类初始化的时候崩掉，下次就不经过这个类了
         */
        mywrite(scheFile, "%d %d %d\n", stDvmDex, i, -1);

        ClassObject *clazz = NULL;
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        if (strcmp(descriptor, "Lcom/perflyst/twire/activities/SearchActivity$1;") != 0)
            continue;

        FLOGE("DexDump class: %d  %s", i, descriptor);
        //continue;
        const char *header1 = "Landroid";
        const char *header2 = "Ldalvik";
        const char *header3 = "Ljava";
        const char *header4 = "Llibcore";
        const char *header5 = "Ljavax";
        const char *header6 = "Lbutterknife";


        //如果是系统类，或者classDataOff为0，则跳过
        if (!strncmp(header1, descriptor, strlen(header1)) ||
            !strncmp(header2, descriptor, strlen(header2)) ||
            !strncmp(header3, descriptor, strlen(header3)) ||
            !strncmp(header4, descriptor, strlen(header4)) ||
            !strncmp(header5, descriptor, strlen(header5)) ||
            !strncmp(header6, descriptor, strlen(header6)) ||
            !pClassDef->classDataOff) {
            FLOGE("DexDump %s Landroid or classDataOff 0", descriptor);
            continue;
        }

        /*
         * 每个类下面新建一个log.txt，用来记录这个类下的所有方法调用时的信息
         */
        std::string itdir = codedir;
        int ln = strlen(descriptor);
        for (int i = 0; i < ln - 1; i++) {
            itdir.push_back(descriptor[i]);
        }
        itdir = itdir + "/" + "log.txt";
        gUpkInterface->reserved7 = (void *) (itdir.c_str());

        fdvmClearException(self);
        clazz = fdvmDefineClass(pDvmDex, descriptor, loader);
        // 当classLookUp抛出异常时，若没有进行处理就进入下一次lookUp，将导致dalvikAbort
        // 具体见defineClassNative中的注释
        // 这里选择直接清空exception
        fdvmClearException(self);

        if (!clazz) {
            FLOGE("DexDump defineClass %s failed", descriptor);
            continue;
        }

        if (!fdvmIsClassInitialized(clazz)) {
            if (fdvmInitClass(clazz)) {
                FLOGE("DexDump init: %s", descriptor);
            } else {
                FLOGE("DexDump init failed: %s", descriptor);
                continue;
            }
        }

        GetMaps();

        gUpkInterface->reserved2 = (void *) (clazz);
        gUpkInterface->reserved5 = (void *) (&data[0]);
        gUpkInterface->reserved6 = (void *) (&procmaps_cnt);


        jstring className = env->NewStringUTF(descriptor);
        jboolean flag;
        if (i == stClass)
            flag = env->CallStaticBooleanMethod(dumpMethodclazz,
                                                hookMethodID,
                                                className,
                                                (jint) stDvmDex,
                                                (jint) i,
                                                (jint) stMethod);
        else
            flag = env->CallStaticBooleanMethod(dumpMethodclazz,
                                                hookMethodID,
                                                className,
                                                (jint) stDvmDex,
                                                (jint) i,
                                                (jint) 0);
        env->DeleteLocalRef(className);

    }
}
Object* searchClassLoader(DvmDex *pDvmDex){
    dvmHashTableLock(GetloadedClasses());
    HashTable *pHashTable = GetloadedClasses();
    HashEntry *pEntry = pHashTable->pEntries;
    // int tableSize = pHashTable->tableSize;
    int numLiveEntries = pHashTable->numEntries;
    Object *result = NULL;

    if (numLiveEntries <= 0)
    {
        FLOGE("DexDump searchClassLoader : No live entry");
        result = 0;
        goto bail;
    }

    while (numLiveEntries > 0)
    {
        if (pEntry->data != NULL && pEntry->data != HASH_TOMBSTONE)
        {
            ClassObject *pClassObject = (ClassObject*)pEntry->data;
            if(pDvmDex == pClassObject->pDvmDex){
                result = pClassObject->classLoader;
                break;
            }
            numLiveEntries--;
        }
        pEntry++;
    }
    bail:
    dvmHashTableUnlock(GetloadedClasses());
    if(result == NULL){
        FLOGE("DexDump could not find appropriate class loader");
    }
    else{
        FLOGE("DexDump select classLoader : %#x", (unsigned int)result);
    }
    return result;
}
void InvokeEntry(JNIEnv* env, int stDvmDex, int stClass, int stMethod) {
    FLOGE("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ %d %d %d", stDvmDex, stClass, stMethod);
    //////
    for (int i = 0; i < tot_dvm; i++) {
        FLOGE("DvmName %d : %u", i, DvmName[i]);
    }
    //////
    DvmDex* pDvmDex;
    Object *loader;
    int dexSize = userDexFilesSize();

    bool ready = false;
    for (int i = 0; i < dexSize; i++) {
        const char *name;
        pDvmDex = getdvmDex(i, name);
        if (pDvmDex == nullptr) {
            continue;
        }

        loader = searchClassLoader(pDvmDex);

        if (loader == NULL)     continue;
        FLOGE("pDvmDex %d : %u", i, pDvmDex->pDexFile->pHeader->classDefsSize);
        if (pDvmDex->pDexFile->pHeader->classDefsSize == DvmName[stDvmDex]) {
            ready = true;
            break;
        }
    }

    if (ready) {
        FLOGE("dvmDex found");
        DumpClassbyInovke(pDvmDex, loader, env, stDvmDex, stClass, stMethod);
        mywrite(scheFile, "%d -1 -1", stDvmDex + 1);
        return;
    }
    else {
        FLOGE("ERROR : dvmDex not found!");
    }
    return;
}
void mkdir_DvmDex(JNIEnv* env) {
    mkdir(codedir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    for (int i = 0; i < userDexFilesSize(); i++) {
        const char *name;
        auto pDvmDex = getdvmDex(i, name);
        if (pDvmDex == nullptr) {
            continue;
        }

        Object *loader = searchClassLoader(pDvmDex);

        if (loader == NULL)     continue;

        FILE *fp = fopen(dvmFile.c_str(), "a");
        fprintf(fp, "%u\n", pDvmDex->pDexFile->pHeader->classDefsSize);
        fflush(fp);
        fclose(fp);

        gUpkInterface->reserved3 = (void *)(loader);

        mkdir_DexFile(pDvmDex, loader, env);
    }
}
void init1(JNIEnv* env, jstring folder) {
    /*  钩住系统中的java层,使得能在应用内部使用反射,
     *  TODO: 可能在应用内部也行？
     * */
    dumpMethodclazz = env->FindClass("android/app/fupk3/dumpMethod");
    hookMethodID = env->GetStaticMethodID(dumpMethodclazz,
                                          "hookMethod",
                                          "(Ljava/lang/String;III)Z");
    /*
     *  初始化各种文件和文件夹
     *  sche.txt用于记录强制反射调用到第几个dvmDex的第几个类的第几个方法
     *  logFile.txt用于记录强制反射调用过程中出现的调用逻辑
     *  record.txt用于记录强制反射调用过程中出现的所有方法
     */
    str = env->GetStringUTFChars(folder, nullptr);
    str = str + std::string("/101142ts");
    tidFile = str + std::string("/tid.txt");
    recordFile = str + std::string("/record.txt");
    scheFile = str + std::string("/sche.txt");
    logFile = str + std::string("/log.txt");
    dvmFile = str + std::string("/dvmName.txt");
    codedir = str + "/code/";

    gUpkInterface->reserved0 = (void *)(recordFile.c_str());
    gUpkInterface->reserved1 = (void *)(scheFile.c_str());
    gUpkInterface->reserved4 = (void *)(str.c_str());

}
void unpackAll(JNIEnv* env, jobject obj, jstring folder, jint millis) {
    FLOGE("in unpackAll");
    init1(env, folder);
    FLOGE("tid = %d",  gettid());
    FLOGE("tidFile = %s",  tidFile.c_str());
    mywrite(tidFile, "%d\n", gettid());

    sleep((int)millis);

    /*
     * 开始dump的流程，这个流程可能是第一次执行，也可能不是
     */

    if (access(scheFile.c_str(), W_OK) != 0) {
        FLOGE("ERROR: no sche");
        return;
    }
    std::string makeup = str + std::string("/makeup");
    if (access(makeup.c_str(), W_OK) != 0) {
        //第一次流程的时候要记录能dump的文件名
        sleep(10);
        mkdir_DvmDex(env);
        mywrite(makeup, "YES\n");
    }
    {
        FILE *fp = fopen(dvmFile.c_str(), "r");
        tot_dvm = 0;
        u4 classDefsSize;
        while (fscanf(fp, "%u", &classDefsSize) != EOF)
            DvmName[tot_dvm++] = classDefsSize;
        fclose(fp);
    }
    int stDvmDex, stClass, stMethod;
    /*
     * 下一次强制调用从stDvmDex, stClass, stMethod开始
     */

    FILE *fp = fopen(scheFile.c_str(), "r");
    fscanf(fp, "%d %d %d", &stDvmDex, &stClass, &stMethod);
    if (stMethod == -1) {
        //init失敗
        stClass++;
        stMethod = 0;
    }
    else
        stMethod++;
    fclose(fp);

    if (stDvmDex == tot_dvm) {
        //dump结束了
        std::string finishfile = str + std::string("/OK.txt");
        mywrite(finishfile, "\n");
    }
    else {
        InvokeEntry(env, stDvmDex, stClass, stMethod);
    }
    return;

}
bool init() {
    bool done = false;
    auto libdvm = dlopen("libdvm.so", RTLD_NOW);
    if (libdvm == nullptr)
        goto bail;
    gUpkInterface = (FupkInterface*)dlsym(libdvm, "gFupk");
    if (gUpkInterface == nullptr)
        goto bail;
    {
        auto fn = (HashTable* (*)())dlsym(libdvm, "dvmGetUserDexFiles");
        if (fn == nullptr) {
            goto bail;
        }
        userDexFiles = fn();
    }
    GetloadedClasses = (HashTable *(*)())(dlsym(libdvm, "dvmGetLoadedClasses"));
    if (GetloadedClasses == nullptr)
        goto bail;
    fdvmDefineClass = (ClassObject *(*)(DvmDex*, const char*, Object*))(dlsym(libdvm, "_Z14dvmDefineClassP6DvmDexPKcP6Object"));
    if (fdvmDefineClass == nullptr)
        goto bail;
    fdvmIsClassInitialized = (bool (*)(const ClassObject*))(dlsym(libdvm, "_Z21dvmIsClassInitializedPK11ClassObject"));
    if (fdvmIsClassInitialized == nullptr)
        goto bail;
    fdvmInitClass = (bool (*)(ClassObject*))(dlsym(libdvm, "dvmInitClass"));
    if (fdvmInitClass == nullptr)
        goto bail;
    fdvmDecodeIndirectRef = (Object *(*)(void *, jobject))
            (dlsym(libdvm, "_Z20dvmDecodeIndirectRefP6ThreadP8_jobject"));
    if (fdvmDecodeIndirectRef == nullptr)
        goto bail;
    fdvmClearException = (void (*)(Thread*))(dlsym(libdvm, "dvmClearException"));
    if (fdvmClearException == nullptr)
        goto bail;
    fdvmThreadSelf = (Thread *(*)())(dlsym(libdvm, "_Z13dvmThreadSelfv"));
    if (fdvmThreadSelf == nullptr)
        goto bail;
    floadClassFromDex = (ClassObject* (*)(DvmDex*, const DexClassDef*, Object*))dlsym(libdvm, "loadClassFromDex");
    if (floadClassFromDex == nullptr)
        goto bail;

    done = true;

    bail:
    if (!done) {
        FLOGE("Unable to initlize are you sure you are run in the correct machine");
    }
    return done;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    FLOGE("try to load unpack");
    JNIEnv *env = nullptr;
    jint result = -1;


    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        //FLOGE("This jni version is not supported");
        return JNI_VERSION_1_6;
    }

    auto clazz = env->FindClass("android/app/fupk3/Fupk");

    JNINativeMethod natives[] = {
            {"unpackAll", "(Ljava/lang/String;I)V", (void*)unpackAll}
    };
    if (env->RegisterNatives(clazz, natives,
                             sizeof(natives)/sizeof(JNINativeMethod)) != JNI_OK) {
        env->ExceptionClear();
    }
    FLOGE("unpack load success");

    if (init())
        FLOGE("init success");

    return JNI_VERSION_1_6;
}



