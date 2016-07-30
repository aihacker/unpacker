#include <android/log.h>
#include <substrate.h>
#include <stdio.h>

#define LOG_TAG "SUBhook"

#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

MSConfig (MSFilterExecutable, "/system/bin/app_process")


void (*original_getnewkey) (char* in, int len, char *out, char *key, int key_len, char *iv);
void replaced_getnewkey (char* in, int len, char *out, char *key, int key_len, char *iv) 
{
	LOGI ("ENC_KEY [%s]", key);
	LOGI ("IV [%s]", iv);
	LOGI ("PlainText [%s]", in);
	original_getnewkey (in, len, out, key, 128, iv);	
}

void* lookup_symbol (char* libraryname, char* symbolname)
{
	void *imagehandle = dlopen (libraryname, RTLD_GLOBAL | RTLD_NOW);
	if (imagehandle != NULL) {
		void * sym = dlsym (imagehandle, symbolname);
		if (sym != NULL) {
			return sym;
		}
		else{
			LOGI ("(lookup_symbol) dlsym didn't work");
			return NULL;
		}
	}
	else{
		LOGI("(lookup_symbol) dlerror: %s", dlerror ());
		return NULL;
	}
}

void cigi_hook (void *orig_fcn, void* new_fcn, void **orig_fcn_ptr)
{
	MSHookFunction (orig_fcn, new_fcn, orig_fcn_ptr);
}

MSInitialize {
	LOGI ("Cydia Init");
	void *getnewkey_t = lookup_symbol ("/data/app-lib/com.imohoo.shanpao-1/libshanpao_jni.so", "aes_encrypt_cbc");

	cigi_hook(getnewkey_t, (void*)&replaced_getnewkey, (void**)&original_getnewkey);
}
