/////////////main.cpp
#include "des.h"
#include "base64.h"
#include "desbase64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
	long longBytes = 0;
	int32 fild_data;
	int32 need_size;
	int32 enc_size = 0;
	char *file_buf;
	char *enc_buf;
	char * encryped_data_buf;
	int32 dec_buf_size;
	char *decrpyted_data_buf;
	int32 data_size;
	FILE *p_data_file;
	FILE *p_encrypted_file;
	FILE *p_decrypted_file;

	uint64 key =  0x77616E6777616E61;//wangwana
	uint64 iv = 0xABCDEF12;
	char * data = "Man";
	int32 Len = strlen(data);
	int32 need_buf = get_des_base64_encrypt_need_buff_size(Len);

	char *enc_data_buf = (char*)malloc(need_buf);

	int32 enc_Len = des_base64_encrypt(enc_data_buf,need_buf,data,Len,key,iv);

	//des解密
	int32 dec_need_buf_len = get_des_decrypt_need_buff_size(enc_Len);

	char* dec_data_buf = (char*)malloc(dec_need_buf_len);

	int32 dec_Len = base64_des_decrypt(dec_data_buf,dec_need_buf_len,enc_data_buf,enc_Len,key,iv);


	//打开文件
	p_data_file = fopen("data.txt","rb");
	if (!p_data_file)
	{
		exit(1);
	}
	//读取数据
	fseek(p_data_file,0,SEEK_END);
	longBytes=ftell(p_data_file);// longBytes就是文件的长度
	file_buf = (char*)malloc(longBytes);
	fseek(p_data_file,0,SEEK_SET);
	fild_data = fread(file_buf,1,longBytes,p_data_file);
	fclose(p_data_file);
	//读取后加密
	need_size = get_des_base64_encrypt_need_buff_size(longBytes);
	enc_buf = (char*)malloc(need_size);
	enc_size = des_base64_encrypt(enc_buf,need_size,file_buf,longBytes,key,iv);

	//把加密后的写入另外一个文件
	p_encrypted_file = fopen("enc_des_base64.txt","wb");
	if (!p_encrypted_file)
	{
		exit(1);
	}
	//加密数据写入后关闭文件
	fwrite(enc_buf,1,enc_size,p_encrypted_file);
	fflush(p_encrypted_file);
	fclose(p_encrypted_file);


	//再重新打开文件
	p_encrypted_file = fopen("enc_des_base64.txt","rb");
	if (!p_encrypted_file)
	{
		exit(1);
	}
	//读取出来
	fseek(p_encrypted_file,0,SEEK_END);
	longBytes = ftell(p_encrypted_file);

	encryped_data_buf = (char*)malloc(longBytes);
	fseek(p_encrypted_file,0,SEEK_SET);
	fread(encryped_data_buf,1,longBytes,p_encrypted_file);

	//解密
	dec_buf_size = get_base64_des_decrypt_need_buff_size(longBytes);
	decrpyted_data_buf = (char*)malloc(dec_buf_size);
	data_size = base64_des_decrypt(decrpyted_data_buf,dec_buf_size,encryped_data_buf,longBytes,key,iv);

	p_decrypted_file = fopen("dec_des_base64.txt","wb");
	if (!p_decrypted_file)
	{
		exit(1);
	}
	//写入文件
	fwrite(decrpyted_data_buf,1,data_size,p_decrypted_file);
	fflush(p_decrypted_file);
	fclose(p_decrypted_file);
	
	return 0;
}