///////////////main.cpp
//#include "des.h"
//#include <iostream>
//
//int main()
//{
//	uint64 data = 0x77616E6777616E67;//wangwang;
//	uint64 key = 0x77616E6777616E67;
//
//	uint64 res= Des(data,key);// 0x511a5ef897d19dbf
//	system("pause");
//	return 0;
//}
#include <stdio.h>

#include <windows.h>

typedef int(*lpAddFun)(int, int); //�궨�庯��ָ������
int main(int argc, char *argv[])

{

	HINSTANCE hDll; //DLL���

	lpAddFun addFun; //����ָ��

	hDll = LoadLibrary("..\\Debug\\dllTest.dll");

	if (hDll != NULL)

	{

		addFun = (lpAddFun)GetProcAddress(hDll, "add");

		if (addFun != NULL)

		{

			int result = addFun(2, 3);

			printf("%d", result);

		}

		FreeLibrary(hDll);

	}

	return 0;

}