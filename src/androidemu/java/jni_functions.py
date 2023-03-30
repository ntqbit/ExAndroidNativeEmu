JNI_FUNCTIONS = [
    {
        "id": 4,
        "ret": "jint",
        "name": "GetVersion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            }
        ]
    },
    {
        "id": 5,
        "ret": "jclass",
        "name": "DefineClass",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "name",
                "type": "char*"
            },
            {
                "name": "loader",
                "type": "jobject"
            },
            {
                "name": "buf",
                "type": "jbyte*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 6,
        "ret": "jclass",
        "name": "FindClass",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "name",
                "type": "char*"
            }
        ]
    },
    {
        "id": 7,
        "ret": "jmethodID",
        "name": "FromReflectedMethod",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "method",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 8,
        "ret": "jfieldID",
        "name": "FromReflectedField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "field",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 9,
        "ret": "jobject",
        "name": "ToReflectedMethod",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "cls",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "isStatic",
                "type": "jboolean"
            }
        ]
    },
    {
        "id": 10,
        "ret": "jclass",
        "name": "GetSuperclass",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "sub",
                "type": "jclass"
            }
        ]
    },
    {
        "id": 11,
        "ret": "jboolean",
        "name": "IsAssignableFrom",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "sub",
                "type": "jclass"
            },
            {
                "name": "sup",
                "type": "jclass"
            }
        ]
    },
    {
        "id": 12,
        "ret": "jobject",
        "name": "ToReflectedField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "cls",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "isStatic",
                "type": "jboolean"
            }
        ]
    },
    {
        "id": 13,
        "ret": "jint",
        "name": "Throw",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jthrowable"
            }
        ]
    },
    {
        "id": 14,
        "ret": "jint",
        "name": "ThrowNew",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "msg",
                "type": "char*"
            }
        ]
    },
    {
        "id": 15,
        "ret": "jthrowable",
        "name": "ExceptionOccurred",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            }
        ]
    },
    {
        "id": 16,
        "ret": "void",
        "name": "ExceptionDescribe",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            }
        ]
    },
    {
        "id": 17,
        "ret": "void",
        "name": "ExceptionClear",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            }
        ]
    },
    {
        "id": 18,
        "ret": "void",
        "name": "FatalError",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "msg",
                "type": "char*"
            }
        ]
    },
    {
        "id": 19,
        "ret": "jint",
        "name": "PushLocalFrame",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "capacity",
                "type": "jint"
            }
        ]
    },
    {
        "id": 20,
        "ret": "jobject",
        "name": "PopLocalFrame",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "result",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 21,
        "ret": "jobject",
        "name": "NewGlobalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "lobj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 22,
        "ret": "void",
        "name": "DeleteGlobalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "gref",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 23,
        "ret": "void",
        "name": "DeleteLocalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 24,
        "ret": "jboolean",
        "name": "IsSameObject",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj1",
                "type": "jobject"
            },
            {
                "name": "obj2",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 25,
        "ret": "jobject",
        "name": "NewLocalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "ref",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 26,
        "ret": "jint",
        "name": "EnsureLocalCapacity",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "capacity",
                "type": "jint"
            }
        ]
    },
    {
        "id": 27,
        "ret": "jobject",
        "name": "AllocObject",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            }
        ]
    },
    {
        "id": 28,
        "ret": "jobject",
        "name": "NewObject",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 29,
        "ret": "jobject",
        "name": "NewObjectV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 30,
        "ret": "jobject",
        "name": "NewObjectA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 31,
        "ret": "jclass",
        "name": "GetObjectClass",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 32,
        "ret": "jboolean",
        "name": "IsInstanceOf",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            }
        ]
    },
    {
        "id": 33,
        "ret": "jmethodID",
        "name": "GetMethodID",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "name",
                "type": "char*"
            },
            {
                "name": "sig",
                "type": "char*"
            }
        ]
    },
    {
        "id": 34,
        "ret": "jobject",
        "name": "CallObjectMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 35,
        "ret": "jobject",
        "name": "CallObjectMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 36,
        "ret": "jobject",
        "name": "CallObjectMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 37,
        "ret": "jboolean",
        "name": "CallBooleanMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 38,
        "ret": "jboolean",
        "name": "CallBooleanMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 39,
        "ret": "jboolean",
        "name": "CallBooleanMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 40,
        "ret": "jbyte",
        "name": "CallByteMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 41,
        "ret": "jbyte",
        "name": "CallByteMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 42,
        "ret": "jbyte",
        "name": "CallByteMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 43,
        "ret": "jchar",
        "name": "CallCharMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 44,
        "ret": "jchar",
        "name": "CallCharMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 45,
        "ret": "jchar",
        "name": "CallCharMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 46,
        "ret": "jshort",
        "name": "CallShortMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 47,
        "ret": "jshort",
        "name": "CallShortMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 48,
        "ret": "jshort",
        "name": "CallShortMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 49,
        "ret": "jint",
        "name": "CallIntMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 50,
        "ret": "jint",
        "name": "CallIntMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 51,
        "ret": "jint",
        "name": "CallIntMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 52,
        "ret": "jlong",
        "name": "CallLongMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 53,
        "ret": "jlong",
        "name": "CallLongMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 54,
        "ret": "jlong",
        "name": "CallLongMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 55,
        "ret": "jfloat",
        "name": "CallFloatMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 56,
        "ret": "jfloat",
        "name": "CallFloatMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 57,
        "ret": "jfloat",
        "name": "CallFloatMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 58,
        "ret": "jdouble",
        "name": "CallDoubleMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 59,
        "ret": "jdouble",
        "name": "CallDoubleMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 60,
        "ret": "jdouble",
        "name": "CallDoubleMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 61,
        "ret": "void",
        "name": "CallVoidMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 62,
        "ret": "void",
        "name": "CallVoidMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 63,
        "ret": "void",
        "name": "CallVoidMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 64,
        "ret": "jobject",
        "name": "CallNonvirtualObjectMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 65,
        "ret": "jobject",
        "name": "CallNonvirtualObjectMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 66,
        "ret": "jobject",
        "name": "CallNonvirtualObjectMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 67,
        "ret": "jboolean",
        "name": "CallNonvirtualBooleanMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 68,
        "ret": "jboolean",
        "name": "CallNonvirtualBooleanMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 69,
        "ret": "jboolean",
        "name": "CallNonvirtualBooleanMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 70,
        "ret": "jbyte",
        "name": "CallNonvirtualByteMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 71,
        "ret": "jbyte",
        "name": "CallNonvirtualByteMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 72,
        "ret": "jbyte",
        "name": "CallNonvirtualByteMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 73,
        "ret": "jchar",
        "name": "CallNonvirtualCharMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 74,
        "ret": "jchar",
        "name": "CallNonvirtualCharMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 75,
        "ret": "jchar",
        "name": "CallNonvirtualCharMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 76,
        "ret": "jshort",
        "name": "CallNonvirtualShortMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 77,
        "ret": "jshort",
        "name": "CallNonvirtualShortMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 78,
        "ret": "jshort",
        "name": "CallNonvirtualShortMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 79,
        "ret": "jint",
        "name": "CallNonvirtualIntMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 80,
        "ret": "jint",
        "name": "CallNonvirtualIntMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 81,
        "ret": "jint",
        "name": "CallNonvirtualIntMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 82,
        "ret": "jlong",
        "name": "CallNonvirtualLongMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 83,
        "ret": "jlong",
        "name": "CallNonvirtualLongMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 84,
        "ret": "jlong",
        "name": "CallNonvirtualLongMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 85,
        "ret": "jfloat",
        "name": "CallNonvirtualFloatMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 86,
        "ret": "jfloat",
        "name": "CallNonvirtualFloatMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 87,
        "ret": "jfloat",
        "name": "CallNonvirtualFloatMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 88,
        "ret": "jdouble",
        "name": "CallNonvirtualDoubleMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 89,
        "ret": "jdouble",
        "name": "CallNonvirtualDoubleMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 90,
        "ret": "jdouble",
        "name": "CallNonvirtualDoubleMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 91,
        "ret": "void",
        "name": "CallNonvirtualVoidMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 92,
        "ret": "void",
        "name": "CallNonvirtualVoidMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 93,
        "ret": "void",
        "name": "CallNonvirtualVoidMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 94,
        "ret": "jfieldID",
        "name": "GetFieldID",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "name",
                "type": "char*"
            },
            {
                "name": "sig",
                "type": "char*"
            }
        ]
    },
    {
        "id": 95,
        "ret": "jobject",
        "name": "GetObjectField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 96,
        "ret": "jboolean",
        "name": "GetBooleanField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 97,
        "ret": "jbyte",
        "name": "GetByteField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 98,
        "ret": "jchar",
        "name": "GetCharField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 99,
        "ret": "jshort",
        "name": "GetShortField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 100,
        "ret": "jint",
        "name": "GetIntField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 101,
        "ret": "jlong",
        "name": "GetLongField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 102,
        "ret": "jfloat",
        "name": "GetFloatField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 103,
        "ret": "jdouble",
        "name": "GetDoubleField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 104,
        "ret": "void",
        "name": "SetObjectField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 105,
        "ret": "void",
        "name": "SetBooleanField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jboolean"
            }
        ]
    },
    {
        "id": 106,
        "ret": "void",
        "name": "SetByteField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jbyte"
            }
        ]
    },
    {
        "id": 107,
        "ret": "void",
        "name": "SetCharField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jchar"
            }
        ]
    },
    {
        "id": 108,
        "ret": "void",
        "name": "SetShortField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jshort"
            }
        ]
    },
    {
        "id": 109,
        "ret": "void",
        "name": "SetIntField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jint"
            }
        ]
    },
    {
        "id": 110,
        "ret": "void",
        "name": "SetLongField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jlong"
            }
        ]
    },
    {
        "id": 111,
        "ret": "void",
        "name": "SetFloatField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jfloat"
            }
        ]
    },
    {
        "id": 112,
        "ret": "void",
        "name": "SetDoubleField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "val",
                "type": "jdouble"
            }
        ]
    },
    {
        "id": 113,
        "ret": "jmethodID",
        "name": "GetStaticMethodID",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "name",
                "type": "char*"
            },
            {
                "name": "sig",
                "type": "char*"
            }
        ]
    },
    {
        "id": 114,
        "ret": "jobject",
        "name": "CallStaticObjectMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 115,
        "ret": "jobject",
        "name": "CallStaticObjectMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 116,
        "ret": "jobject",
        "name": "CallStaticObjectMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 117,
        "ret": "jboolean",
        "name": "CallStaticBooleanMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 118,
        "ret": "jboolean",
        "name": "CallStaticBooleanMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 119,
        "ret": "jboolean",
        "name": "CallStaticBooleanMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 120,
        "ret": "jbyte",
        "name": "CallStaticByteMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 121,
        "ret": "jbyte",
        "name": "CallStaticByteMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 122,
        "ret": "jbyte",
        "name": "CallStaticByteMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 123,
        "ret": "jchar",
        "name": "CallStaticCharMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 124,
        "ret": "jchar",
        "name": "CallStaticCharMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 125,
        "ret": "jchar",
        "name": "CallStaticCharMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 126,
        "ret": "jshort",
        "name": "CallStaticShortMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 127,
        "ret": "jshort",
        "name": "CallStaticShortMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 128,
        "ret": "jshort",
        "name": "CallStaticShortMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 129,
        "ret": "jint",
        "name": "CallStaticIntMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 130,
        "ret": "jint",
        "name": "CallStaticIntMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 131,
        "ret": "jint",
        "name": "CallStaticIntMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 132,
        "ret": "jlong",
        "name": "CallStaticLongMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 133,
        "ret": "jlong",
        "name": "CallStaticLongMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 134,
        "ret": "jlong",
        "name": "CallStaticLongMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 135,
        "ret": "jfloat",
        "name": "CallStaticFloatMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 136,
        "ret": "jfloat",
        "name": "CallStaticFloatMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 137,
        "ret": "jfloat",
        "name": "CallStaticFloatMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 138,
        "ret": "jdouble",
        "name": "CallStaticDoubleMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 139,
        "ret": "jdouble",
        "name": "CallStaticDoubleMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 140,
        "ret": "jdouble",
        "name": "CallStaticDoubleMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 141,
        "ret": "void",
        "name": "CallStaticVoidMethod",
        "va": True,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "cls",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            }
        ]
    },
    {
        "id": 142,
        "ret": "void",
        "name": "CallStaticVoidMethodV",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "cls",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "va_list"
            }
        ]
    },
    {
        "id": 143,
        "ret": "void",
        "name": "CallStaticVoidMethodA",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "cls",
                "type": "jclass"
            },
            {
                "name": "methodID",
                "type": "jmethodID"
            },
            {
                "name": "args",
                "type": "jvalue*"
            }
        ]
    },
    {
        "id": 144,
        "ret": "jfieldID",
        "name": "GetStaticFieldID",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "name",
                "type": "char*"
            },
            {
                "name": "sig",
                "type": "char*"
            }
        ]
    },
    {
        "id": 145,
        "ret": "jobject",
        "name": "GetStaticObjectField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 146,
        "ret": "jboolean",
        "name": "GetStaticBooleanField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 147,
        "ret": "jbyte",
        "name": "GetStaticByteField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 148,
        "ret": "jchar",
        "name": "GetStaticCharField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 149,
        "ret": "jshort",
        "name": "GetStaticShortField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 150,
        "ret": "jint",
        "name": "GetStaticIntField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 151,
        "ret": "jlong",
        "name": "GetStaticLongField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 152,
        "ret": "jfloat",
        "name": "GetStaticFloatField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 153,
        "ret": "jdouble",
        "name": "GetStaticDoubleField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            }
        ]
    },
    {
        "id": 154,
        "ret": "void",
        "name": "SetStaticObjectField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 155,
        "ret": "void",
        "name": "SetStaticBooleanField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jboolean"
            }
        ]
    },
    {
        "id": 156,
        "ret": "void",
        "name": "SetStaticByteField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jbyte"
            }
        ]
    },
    {
        "id": 157,
        "ret": "void",
        "name": "SetStaticCharField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jchar"
            }
        ]
    },
    {
        "id": 158,
        "ret": "void",
        "name": "SetStaticShortField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jshort"
            }
        ]
    },
    {
        "id": 159,
        "ret": "void",
        "name": "SetStaticIntField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jint"
            }
        ]
    },
    {
        "id": 160,
        "ret": "void",
        "name": "SetStaticLongField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jlong"
            }
        ]
    },
    {
        "id": 161,
        "ret": "void",
        "name": "SetStaticFloatField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jfloat"
            }
        ]
    },
    {
        "id": 162,
        "ret": "void",
        "name": "SetStaticDoubleField",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "fieldID",
                "type": "jfieldID"
            },
            {
                "name": "value",
                "type": "jdouble"
            }
        ]
    },
    {
        "id": 163,
        "ret": "jstring",
        "name": "NewString",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "unicode",
                "type": "jchar*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 164,
        "ret": "jsize",
        "name": "GetStringLength",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            }
        ]
    },
    {
        "id": 165,
        "ret": "const jchar *",
        "name": "GetStringChars",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 166,
        "ret": "void",
        "name": "ReleaseStringChars",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "chars",
                "type": "jchar*"
            }
        ]
    },
    {
        "id": 167,
        "ret": "jstring",
        "name": "NewStringUTF",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "utf",
                "type": "char*"
            }
        ]
    },
    {
        "id": 168,
        "ret": "jsize",
        "name": "GetStringUTFLength",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            }
        ]
    },
    {
        "id": 169,
        "ret": "const char*",
        "name": "GetStringUTFChars",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 170,
        "ret": "void",
        "name": "ReleaseStringUTFChars",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "chars",
                "type": "char*"
            }
        ]
    },
    {
        "id": 171,
        "ret": "jsize",
        "name": "GetArrayLength",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jarray"
            }
        ]
    },
    {
        "id": 172,
        "ret": "jobjectArray",
        "name": "NewObjectArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "init",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 173,
        "ret": "jobject",
        "name": "GetObjectArrayElement",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jobjectArray"
            },
            {
                "name": "index",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 174,
        "ret": "void",
        "name": "SetObjectArrayElement",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jobjectArray"
            },
            {
                "name": "index",
                "type": "jsize"
            },
            {
                "name": "val",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 175,
        "ret": "jbooleanArray",
        "name": "NewBooleanArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 176,
        "ret": "jbyteArray",
        "name": "NewByteArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 177,
        "ret": "jcharArray",
        "name": "NewCharArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 178,
        "ret": "jshortArray",
        "name": "NewShortArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 179,
        "ret": "jintArray",
        "name": "NewIntArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 180,
        "ret": "jlongArray",
        "name": "NewLongArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 181,
        "ret": "jfloatArray",
        "name": "NewFloatArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 182,
        "ret": "jdoubleArray",
        "name": "NewDoubleArray",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "len",
                "type": "jsize"
            }
        ]
    },
    {
        "id": 183,
        "ret": "jboolean *",
        "name": "GetBooleanArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbooleanArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 184,
        "ret": "jbyte *",
        "name": "GetByteArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbyteArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 185,
        "ret": "jchar *",
        "name": "GetCharArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jcharArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 186,
        "ret": "jshort *",
        "name": "GetShortArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jshortArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 187,
        "ret": "jint *",
        "name": "GetIntArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jintArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 188,
        "ret": "jlong *",
        "name": "GetLongArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jlongArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 189,
        "ret": "jfloat *",
        "name": "GetFloatArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jfloatArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 190,
        "ret": "jdouble *",
        "name": "GetDoubleArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jdoubleArray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 191,
        "ret": "void",
        "name": "ReleaseBooleanArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbooleanArray"
            },
            {
                "name": "elems",
                "type": "jboolean*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 192,
        "ret": "void",
        "name": "ReleaseByteArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbyteArray"
            },
            {
                "name": "elems",
                "type": "jbyte*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 193,
        "ret": "void",
        "name": "ReleaseCharArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jcharArray"
            },
            {
                "name": "elems",
                "type": "jchar*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 194,
        "ret": "void",
        "name": "ReleaseShortArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jshortArray"
            },
            {
                "name": "elems",
                "type": "jshort*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 195,
        "ret": "void",
        "name": "ReleaseIntArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jintArray"
            },
            {
                "name": "elems",
                "type": "jint*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 196,
        "ret": "void",
        "name": "ReleaseLongArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jlongArray"
            },
            {
                "name": "elems",
                "type": "jlong*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 197,
        "ret": "void",
        "name": "ReleaseFloatArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jfloatArray"
            },
            {
                "name": "elems",
                "type": "jfloat*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 198,
        "ret": "void",
        "name": "ReleaseDoubleArrayElements",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jdoubleArray"
            },
            {
                "name": "elems",
                "type": "jdouble*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 199,
        "ret": "void",
        "name": "GetBooleanArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbooleanArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "l",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 200,
        "ret": "void",
        "name": "GetByteArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbyteArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jbyte*"
            }
        ]
    },
    {
        "id": 201,
        "ret": "void",
        "name": "GetCharArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jcharArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jchar*"
            }
        ]
    },
    {
        "id": 202,
        "ret": "void",
        "name": "GetShortArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jshortArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jshort*"
            }
        ]
    },
    {
        "id": 203,
        "ret": "void",
        "name": "GetIntArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jintArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jint*"
            }
        ]
    },
    {
        "id": 204,
        "ret": "void",
        "name": "GetLongArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jlongArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jlong*"
            }
        ]
    },
    {
        "id": 205,
        "ret": "void",
        "name": "GetFloatArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jfloatArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jfloat*"
            }
        ]
    },
    {
        "id": 206,
        "ret": "void",
        "name": "GetDoubleArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jdoubleArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jdouble*"
            }
        ]
    },
    {
        "id": 207,
        "ret": "void",
        "name": "SetBooleanArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbooleanArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "l",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 208,
        "ret": "void",
        "name": "SetByteArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jbyteArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jbyte*"
            }
        ]
    },
    {
        "id": 209,
        "ret": "void",
        "name": "SetCharArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jcharArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jchar*"
            }
        ]
    },
    {
        "id": 210,
        "ret": "void",
        "name": "SetShortArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jshortArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jshort*"
            }
        ]
    },
    {
        "id": 211,
        "ret": "void",
        "name": "SetIntArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jintArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jint*"
            }
        ]
    },
    {
        "id": 212,
        "ret": "void",
        "name": "SetLongArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jlongArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jlong*"
            }
        ]
    },
    {
        "id": 213,
        "ret": "void",
        "name": "SetFloatArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jfloatArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jfloat*"
            }
        ]
    },
    {
        "id": 214,
        "ret": "void",
        "name": "SetDoubleArrayRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jdoubleArray"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jdouble*"
            }
        ]
    },
    {
        "id": 215,
        "ret": "jint",
        "name": "RegisterNatives",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            },
            {
                "name": "methods",
                "type": "JNINativeMethod*"
            },
            {
                "name": "nMethods",
                "type": "jint"
            }
        ]
    },
    {
        "id": 216,
        "ret": "jint",
        "name": "UnregisterNatives",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "clazz",
                "type": "jclass"
            }
        ]
    },
    {
        "id": 217,
        "ret": "jint",
        "name": "MonitorEnter",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 218,
        "ret": "jint",
        "name": "MonitorExit",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 219,
        "ret": "jint",
        "name": "GetJavaVM",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "vm",
                "type": "JavaVM**"
            }
        ]
    },
    {
        "id": 220,
        "ret": "void",
        "name": "GetStringRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "jchar*"
            }
        ]
    },
    {
        "id": 221,
        "ret": "void",
        "name": "GetStringUTFRegion",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "str",
                "type": "jstring"
            },
            {
                "name": "start",
                "type": "jsize"
            },
            {
                "name": "len",
                "type": "jsize"
            },
            {
                "name": "buf",
                "type": "char*"
            }
        ]
    },
    {
        "id": 222,
        "ret": "void *",
        "name": "GetPrimitiveArrayCritical",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jarray"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 223,
        "ret": "void",
        "name": "ReleasePrimitiveArrayCritical",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "array",
                "type": "jarray"
            },
            {
                "name": "carray",
                "type": "void*"
            },
            {
                "name": "mode",
                "type": "jint"
            }
        ]
    },
    {
        "id": 224,
        "ret": "const jchar *",
        "name": "GetStringCritical",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "string",
                "type": "jstring"
            },
            {
                "name": "isCopy",
                "type": "jboolean*"
            }
        ]
    },
    {
        "id": 225,
        "ret": "void",
        "name": "ReleaseStringCritical",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "string",
                "type": "jstring"
            },
            {
                "name": "cstring",
                "type": "jchar*"
            }
        ]
    },
    {
        "id": 226,
        "ret": "jweak",
        "name": "NewWeakGlobalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 227,
        "ret": "void",
        "name": "DeleteWeakGlobalRef",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "ref",
                "type": "jweak"
            }
        ]
    },
    {
        "id": 228,
        "ret": "jboolean",
        "name": "ExceptionCheck",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            }
        ]
    },
    {
        "id": 229,
        "ret": "jobject",
        "name": "NewDirectByteBuffer",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "address",
                "type": "void*"
            },
            {
                "name": "capacity",
                "type": "jlong"
            }
        ]
    },
    {
        "id": 230,
        "ret": "void*",
        "name": "GetDirectBufferAddress",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "buf",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 231,
        "ret": "jlong",
        "name": "GetDirectBufferCapacity",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "buf",
                "type": "jobject"
            }
        ]
    },
    {
        "id": 232,
        "ret": "jobjectRefType",
        "name": "GetObjectRefType",
        "va": False,
        "args": [
            {
                "name": "env",
                "type": "JNIEnv*"
            },
            {
                "name": "obj",
                "type": "jobject"
            }
        ]
    }
]
