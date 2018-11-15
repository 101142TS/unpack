//
// Created by b on 18-11-9.
//
#include <jni.h>
#include <AndroidDef.h>
#include "MinAndroidDef.h"
#include "utils/RWGuard.h"
#include "entry.cpp"
#include <dlfcn.h>

struct FupkInterface {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;

    bool (*ExportMethod)(void* thread, Method* method);
};
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
        FLOGD("I Found an no empty hashEntry but it is not readable %d %08x", idx, hashEntry->data);
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
void DumpClass(DvmDex *pDvmDex, Object *loader, JNIEnv* env) {
    DexFile *pDexFile = pDvmDex->pDexFile;
    Thread* self = fdvmThreadSelf();

    unsigned int num_class_defs = pDexFile->pHeader->classDefsSize;
    for (size_t i = 0; i < num_class_defs; i++) {
        ClassObject *clazz = NULL;
        const u1 *data = NULL;
        DexClassData *pData = NULL;
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        DexClassDef temp = *pClassDef;

        const char *header = "Landroid";
        //如果是系统类，或者classDataOff为0，则跳过
        if (!strncmp(header, descriptor, 8) || !pClassDef->classDataOff) {
            FLOGD("DexDump %s Landroid or classDataOff 0", descriptor);
            continue;
        }

        fdvmClearException(self);
        clazz = fdvmDefineClass(pDvmDex, descriptor, loader);
        // 当classLookUp抛出异常时，若没有进行处理就进入下一次lookUp，将导致dalvikAbort
        // 具体见defineClassNative中的注释
        // 这里选择直接清空exception
        fdvmClearException(self);

        if (!clazz)
        {
            FLOGD("DexDump defineClass %s failed", descriptor);
            continue;
        }

        FLOGD("DexDump class: %s", descriptor);

        if (!fdvmIsClassInitialized(clazz))
        {
            if (fdvmInitClass(clazz))
            {
                FLOGD("DexDump init: %s", descriptor);
            }
        }

        data = dexGetClassData(pDexFile, pClassDef);

        //返回DexClassData结构
        pData = ReadClassData(&data);


        if (!pData)
        {
            FLOGD("DexDump ReadClassData %s failed", descriptor);
            continue;
        }

        if (pData->directMethods)
        {
            for (uint32_t i = 0; i < pData->header.directMethodsSize; i++) {
                //从clazz来获取method，这里获取到的应该是真实信息
                Method *method = &(clazz->directMethods[i]);
                uint32_t ac = (method->accessFlags) & 0x3ffff;

                FLOGD("DexDump direct method name %s.%s", descriptor, method->name);

                //method insns指针为空或者为native，但是dexMethod中codeOff不为0，则需要修正

                pData->directMethods[i].accessFlags = ac;
                if (!method->insns) {
                    //現在都是空了，反射調用的時候也會是空
                    pData->directMethods[i].codeOff = 0;
                }
                if (ac & ACC_NATIVE) {
                    FLOGD("NATIVE");
                    //需要在java層進行反射調用
                    jstring className = env->NewStringUTF(descriptor);
                    jstring methodName = env->NewStringUTF(method->name);
                    jboolean flag;
                    flag = env->CallStaticBooleanMethod(dumpMethodclazz,
                                                        hookMethodID,
                                                        className,
                                                        methodName
                                                        );
                    env->DeleteLocalRef(className);
                }
            }
        }

        if (pData->virtualMethods)
        {
            for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++) {
                //从clazz来获取method，这里获取到的应该是真实信息
                Method *method = &(clazz->virtualMethods[i]);
                uint32_t ac = (method->accessFlags) & 0x3ffff;

                FLOGD("DexDump virtual method name %s.%s", descriptor, method->name);

                pData->virtualMethods[i].accessFlags = ac;
                if (!method->insns) {
                    //現在都是空了，反射調用的時候也會是空
                    pData->virtualMethods[i].codeOff = 0;
                }
                if (ac & ACC_NATIVE) {
                    FLOGD("NATIVE");
                    //需要在java層進行反射調用
                    jstring className = env->NewStringUTF(descriptor);
                    jstring methodName = env->NewStringUTF(method->name);
                    jboolean flag;
                    flag = env->CallStaticBooleanMethod(dumpMethodclazz,
                                                        hookMethodID,
                                                        className,
                                                        methodName);
                    env->DeleteLocalRef(className);
                }
            }
        }
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
        FLOGD("DexDump searchClassLoader : No live entry");
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
        FLOGD("DexDump could not find appropriate class loader");
    }
    else{
        FLOGD("DexDump select classLoader : %#x", (unsigned int)result);
    }
    return result;
}
void unpackAll(JNIEnv* env, jobject obj, jstring folder) {
    dumpMethodclazz = env->FindClass("android/app/fupk3/dumpMethod");
    hookMethodID = env->GetStaticMethodID(dumpMethodclazz,
                                          "hookMethod",
                                          "(Ljava/lang/String;Ljava/lang/String;)Z");

    FLOGD("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

    for (int i = 0; i < userDexFilesSize(); i++) {
        const char *name;
        auto pDvmDex = getdvmDex(i, name);
        if (pDvmDex == nullptr) {
            FLOGD("dvmDex %d : nullptr", i);
            continue;
        }

        FLOGD("dvmDex %d : %s", i, name);

        Object *loader = searchClassLoader(pDvmDex);

        if (loader == NULL)     continue;
        gUpkInterface->reserved3 = (void *)(loader);
        DumpClass(pDvmDex, loader, env);
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
    fupkInvokeMethod = (void (*)(const Method*))dlsym(libdvm, "fupkInvokeMethod");
    if (fupkInvokeMethod == nullptr)
        goto bail;
    floadClassFromDex = (ClassObject* (*)(DvmDex*, const DexClassDef*, Object*)) dlsym(libdvm, "loadClassFromDex");
    if (floadClassFromDex == nullptr)
        goto bail;

    done = true;

    bail:
    if (!done) {
        FLOGD("Unable to initlize are you sure you are run in the correct machine");
    }
    return done;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{

    FLOGD("try to load unpack");
    JNIEnv *env = nullptr;
    jint result = -1;


    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        //FLOGE("This jni version is not supported");
        return JNI_VERSION_1_6;
    }

    bool regsuccess = false;

    auto clazz = env->FindClass("android/app/fupk3/Fupk");

    JNINativeMethod natives[] = {
            {"unpackAll", "(Ljava/lang/String;)V", (void*)unpackAll}
    };
    if (env->RegisterNatives(clazz, natives,
                             sizeof(natives)/sizeof(JNINativeMethod)) != JNI_OK) {
        env->ExceptionClear();
    }
    FLOGD("unpack load success");

    if (init())
        FLOGD("init success");

    return JNI_VERSION_1_6;
}



