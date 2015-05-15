#include "desbase64.h"
#include <stdio.h>
#include <windows.h>


int main(int argc, char *argv[])

{
	HINSTANCE hDll; //DLL¾ä±ú
	fn_type_get_des_base64_encrypt_need_buff_size  f_get_des_base64_encrypt_need_buff_size;
	fn_type_get_base64_des_decrypt_need_buff_size  f_get_base64_des_decrypt_need_buff_size;
	fn_type_des_base64_encrypt f_des_base64_encrypt;
	fn_type_base64_des_decrypt f_base64_des_decrypt;

	#ifdef _DEBUG
		hDll = LoadLibrary(L".\\lib\\Debug\\desbase64.dll");
	#elif
		hDll = LoadLibrary(L".\\lib\\Release\\desbase64.dll");
	#endif
	if (hDll != NULL)

	{

		f_get_des_base64_encrypt_need_buff_size = (fn_type_get_des_base64_encrypt_need_buff_size)GetProcAddress(hDll, "get_des_base64_encrypt_need_buff_size");
		f_get_base64_des_decrypt_need_buff_size = (fn_type_get_base64_des_decrypt_need_buff_size)GetProcAddress(hDll, "get_base64_des_decrypt_need_buff_size");
		f_des_base64_encrypt = (fn_type_des_base64_encrypt)GetProcAddress(hDll, "des_base64_encrypt");
		f_base64_des_decrypt = (fn_type_base64_des_decrypt)GetProcAddress(hDll, "base64_des_decrypt");
		if (f_get_des_base64_encrypt_need_buff_size != NULL)
		{

			uint64 key =  0x77616E6777616E61;//wangwana
			uint64 iv = 0xABCDEF12;
			char * data = "Man..";
			int32 Len = strlen(data);
			int32 need_buf = f_get_des_base64_encrypt_need_buff_size(Len);

			char *enc_data_buf = (char*)malloc(need_buf);

			int32 enc_Len = f_des_base64_encrypt(enc_data_buf,need_buf,data,Len,key,iv);

			//des½âÃÜ
			int32 dec_need_buf_len = f_get_base64_des_decrypt_need_buff_size(enc_Len);

			char* dec_data_buf = (char*)malloc(dec_need_buf_len);

			int32 dec_Len = f_base64_des_decrypt(dec_data_buf,dec_need_buf_len,enc_data_buf,enc_Len,key,iv);
			printf("%s",dec_data_buf);	
			free(enc_data_buf);
			free(dec_data_buf);
		}

		FreeLibrary(hDll);

	}
	system("pause");
	return 0;

}