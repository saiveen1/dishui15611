#include "client.h"

using namespace std;

//不能用dll里面的修复IAT.....这样就必须先注入工具dll再启动..
VOID ClientThread(LPSTR host);

int main() {

	char szHost[] = "pe.exe";
	ClientThread(szHost); //主线程
	system("pause");
	return EXIT_SUCCESS;
}

VOID ClientThread(LPSTR host)
{
	//内存注入ServerDLL
	DWORD pid = 0;
	printf("输入PId.\n");
	cin >> dec >> pid;
	cout << endl;
	WCHAR moduleName[] = L"Server.dll";
	DWORD virtualSize = 0;
	DWORD remoteAddr = InjectDll(pid, moduleName);;
	printf("等待服务端开启管道\n");
	Sleep(3000);
	//连接管道
	HandleGatewayClient gatewayClient;
	gatewayClient.ConnectPipe();

	//发送请求
	int orderUser = 0;
	ResponseIAT rep = { 0 };
	do {
		printf("<<<输入请求:\n");
		printf("1 ] 弹出MessageBox\n");
		printf("2 ] IATHook-->GetKeyboardState\n");
		printf("3 ] 卸载IATHook\n");
		printf("4 ] InLieHook-->CreateProcessW\n");
		printf("5 ] 卸载InLineHook\n");
		printf("6 ] 退出.\n");
		cin >> dec >> orderUser;
		cout << endl;

		switch (orderUser)
		{
		case MSGBOX:
			gatewayClient.RemoteMsgBox();
			break;
		case IATHOOK_GCD:
			rep = gatewayClient.RemoteIATHookGCD();
			printf("接受到服务端数据: %d", rep.status);
			break;
		case UNIATHOOK:
			gatewayClient.Execute(UNIATHOOK);
			break;
		case INLINEHOOK_CREATEPROCESS:
			gatewayClient.Execute(INLINEHOOK_CREATEPROCESS);
			break;
		case UNINLIEHOOK:
			gatewayClient.Execute(UNINLIEHOOK);
			break;
		case DISCONNECT:
			gatewayClient.Execute(DISCONNECT);
			Process::VirtualFreeM(pid, (LPVOID)remoteAddr);
			break;
		default:
			printf(">>>>>未知命令, Order: %d\n", orderUser);
			break;
		}
		system("pause");
		system("cls");
	} while (orderUser != 6);

	//关闭管道并释放资源(注入里面会释放, 这里就不用管了)
	gatewayClient.DisconnectPipe();

}