//
// Created by b on 18-11-9.
//
#include <jni.h>
#include "MinAndroidDef.h"
#include "entry.cpp"

void unpackAll(JNIEnv* env, jobject obj, jstring folder) {

    return;
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
    //FLOGD("current JNI Version %d", JNI_VERSION_1_6);

    return JNI_VERSION_1_6;
}

