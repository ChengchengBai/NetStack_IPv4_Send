
#include "Network_IPV4_send.h"
#include "Resource.h"

extern pcap_t *handle;

u_int8_t ip_buffer[MAX_SIZE];

int main()
{

	//open file
	FILE *fp;
	fp = fopen("data.txt", "rb");

	select_device();
	network_ipv4_send(ip_buffer, fp);

	fclose(fp);
	pcap_close(handle);
	system("pause");
	return 0;
}