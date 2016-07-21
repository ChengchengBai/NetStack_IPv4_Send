#include "Ethernet.h"
#include "Resource.h"

u_int32_t crc32_table[256] = { 0 };
extern u_int32_t size_of_packet = 0;

extern u_int32_t ip_size_of_packet;
extern u_int8_t ip_buffer[];

//open device
pcap_t *handle;
pcap_if_t *alldevs;
pcap_if_t *d;
char *device;
char error_buffer[PCAP_ERRBUF_SIZE];

int select_device()
{
	int i = 0;
	int inum;

	if (pcap_findalldevs(&alldevs, error_buffer) == -1)
	{
		printf("%s\n", error_buffer);
		return -1;
	}

	/* Print the list of all network adapter information */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; i++)
	{
		d = d->next;
	}
	device = d->name;
}

void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

u_int32_t calculate_crc(u_int8_t *buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}


void load_ethernet_header(u_int8_t *buffer)
{
	struct ethernet_header *hdr = (struct ethernet_header*)buffer;
	size_of_packet = 0;
	// add destination mac address
	hdr->destination_mac[0] = 0x11;
	hdr->destination_mac[1] = 0x11;
	hdr->destination_mac[2] = 0x11;
	hdr->destination_mac[3] = 0x11;
	hdr->destination_mac[4] = 0x11;
	hdr->destination_mac[5] = 0x11;

	//add source mac address
	hdr->source_mac[0] = 0x22;
	hdr->source_mac[1] = 0x22;
	hdr->source_mac[2] = 0x22;
	hdr->source_mac[3] = 0x22;
	hdr->source_mac[4] = 0x22;
	hdr->source_mac[5] = 0x22;

	// add source typy
	hdr->ethernet_type = htons(ETHERNET_IP);

	// caculate the size of packet now
	size_of_packet += sizeof(ethernet_header);
}

int load_ethernet_data(u_int8_t *buffer, u_int8_t *ip_buffer,int len)
{
	if (len > 1500)
	{
		printf("IP buffer is too large. So we stop the procedure.");
		return -1;
	}

	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(ip_buffer + i);
	}

	//add a serial 0 at the end
	while (len < 46)
	{
		*(buffer + len) = 0;
		len++;
	}

	u_int32_t crc = calculate_crc(buffer, len);

	*(u_int32_t *)(buffer + len) = crc;
	size_of_packet += len + 4;
	return 1;
}

int ethernet_send_packet(u_int8_t *buffer)
{
	//device = pcap_lookupdev(error_buffer);

	

	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);

	load_ethernet_header(buffer);
	load_ethernet_data(buffer + sizeof(ethernet_header), ip_buffer, ip_size_of_packet);

	//while (1)
	//{
		if (pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet) != 0)
		{
			printf("Sending failed..\n");
			return -1;
		}
		else
		{
			printf("Sending Succeed..\n");
			Sleep(6050);
		/*	return 1;*/
		}
	//}
	return 1;
}

