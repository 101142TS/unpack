//
// Created by b on 18-11-9.
//
#include <jni.h>
#include <AndroidDef.h>
#include "MinAndroidDef.h"
#include "utils/RWGuard.h"
#include "entry.cpp"
#include <dlfcn.h>

HashTable* userDexFiles = nullptr;
Object* (*fdvmDecodeIndirectRef)(void* self, jobject jobj) = nullptr;
Thread* (*fdvmThreadSelf)() = nullptr;
void (*fupkInvokeMethod)(const Method* meth) = nullptr;
ClassObject* (*floadClassFromDex)(DvmDex* pDvmDex,
                                  const DexClassDef* pClassDef, Object* classLoader) = nullptr;

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
void DumpClass(DvmDex *pDvmDex) {
    DexFile *pDexFile = pDvmDex->pDexFile;

    unsigned int num_class_defs = pDexFile->pHeader->classDefsSize;
    for (size_t i = 0; i < num_class_defs; i++) {
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        FLOGD("    descriptor %d : %s", i, descriptor);
    }
}
void unpackAll(JNIEnv* env, jobject obj, jstring folder) {
    FLOGD("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

    for (int i = 0; i < userDexFilesSize(); i++) {
        const char *name;
        auto pDvmDex = getdvmDex(i, name);
        if (pDvmDex == nullptr) {
            FLOGD("dvmDex %d : nullptr", i);
            continue;
        }

        FLOGD("dvmDex %d : %s", i, name);

        DumpClass(pDvmDex);
    }
    return;
}
bool init() {
    bool done = false;
    auto libdvm = dlopen("libdvm.so", RTLD_NOW);
    if (libdvm == nullptr)
        goto bail;

    {
        auto fn = (HashTable* (*)())dlsym(libdvm, "dvmGetUserDexFiles");
        if (fn == nullptr) {
            goto bail;
        }
        userDexFiles = fn();
    }

    fdvmDecodeIndirectRef = (Object *(*)(void *, jobject))
            (dlsym(libdvm, "_Z20dvmDecodeIndirectRefP6ThreadP8_jobject"));
    if (fdvmDecodeIndirectRef == nullptr)
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
        FLOGE("Unable to initlize are you sure you are run in the correct machine");
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



