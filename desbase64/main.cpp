/////////////main.cpp
#include "des.h"
#include "base64.h"
#include "desbase64.h"
#include <iostream>

int main()
{
	uint64 key =  0x77616E6777616E61;//wangwana
	uint64 iv = 0x00000000;
	char * data = "Well, the exact reason for an IV varies a bit between different modes that use IV.!";
	int32 Len = strlen(data);
	int32 need_buf = get_des_base64_encrypt_need_buff_size(Len);

	char *enc_data_buf = (char*)malloc(need_buf);

	int32 enc_Len = des_base64_encrypt(enc_data_buf,need_buf,data,Len,key,iv);


	//desΩ‚√‹
	int32 dec_need_buf_len = get_des_decrypt_need_buff_size(enc_Len);

	char* dec_data_buf = (char*)malloc(dec_need_buf_len);

	int32 dec_Len = base64_des_decrypt(dec_data_buf,dec_need_buf_len,enc_data_buf,enc_Len,key,iv);

 

	return 0;
}