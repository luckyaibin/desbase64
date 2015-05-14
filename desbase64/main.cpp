/////////////main.cpp
#include "des.h"
#include "base64.h"
#include "desbase64.h"
#include <iostream>

int main()
{
	uint64 key =  0x77616E6777616E61;//wangwana
	uint64 iv = 0x0f0f0f0f;
	char * data = "Well, the exact reason for an IV varies a bit between different modes that use IV.";
	int32 Len = strlen(data);
	int32 need_buf = get_des_encrypt_need_buff_size(Len);

	char *enc_data_buf = (char*)malloc(need_buf);

	int32 enc_Len = des_encrypt(enc_data_buf,need_buf,data,Len,key,iv);


	//desΩ‚√‹
	int32 dec_need_buf_len = get_des_decrypt_need_buff_size(enc_Len);

	char* dec_data_buf = (char*)malloc(dec_need_buf_len);

	int32 dec_Len = des_decrypt(dec_data_buf,dec_need_buf_len,enc_data_buf,enc_Len,key,iv);


	//uint64 data = 0x77616E6777616E77;//wangwanw;
	//uint64 key = 0x77616E6777616E61;//wangwana

	//uint64 res= Des(data,key,'e');// 0xC4DF68A1853AE96F

	//uint64 res2 = Des(res,key,'d');



	//char * str_error= "ZnVja3lvdS";
	//int32 decode_len = get_base64_decode_need_buf_len(strlen(str_error));
	//char *decoded_buf = (char*)malloc(decode_len+1);
	//decoded_buf[decode_len] = '\0';
	//int32 Len = decode64(decoded_buf,decode_len,str_error,strlen(str_error));

	return 0;
}