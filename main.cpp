#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

//setup btping parameters
static bdaddr_t bdaddr;
static int size    = 33;
static int ident   = 200;
static int delay   = 0;
static int count   = 1;
static int timeout = 10;
static int reverse = 0;
static int verify = 0;
//t lock status variables
static bool is_locked = 0;
static bool is_connected = 1;

// Stats
static int sent_pkt = 0;
static int recv_pkt = 0;

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

static void stat(int sig)
{
	int loss = sent_pkt ? (float)((sent_pkt-recv_pkt)/(sent_pkt/100.0)) : 0;
	printf("%d sent, %d received, %d%% loss\n", sent_pkt, recv_pkt, loss);

}

static void usage(void)
{
	printf("btlock\n");
	printf("Usage:\n");
	printf("\tbtlock <bdaddr>\n");

}

static void ping(char *svr)
{
	struct sigaction sa;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	unsigned char *send_buf;
	unsigned char *recv_buf;
	char str[18];
	int i, sk, lost;
	uint8_t id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stat;
	sigaction(SIGINT, &sa, NULL);

	send_buf = (unsigned char *) malloc(L2CAP_CMD_HDR_SIZE + size);
	recv_buf = (unsigned char *) malloc(L2CAP_CMD_HDR_SIZE + size);
	
	if (!send_buf || !recv_buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

// 	// Create sockets
	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		goto error;
	}

	// Bind to local address
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	// Connect to remote device
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		//perror("Can't connect");
		is_connected=0;
		printf("Device not connected\n");
		goto error;
	}

	// Get local address
	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	if (getsockname(sk, (struct sockaddr *) &addr, &optlen) < 0) {
		perror("Can't get local address");
		goto error;
	}

	ba2str(&addr.l2_bdaddr, str);
	//printf("Ping: %s from %s (data size %d) ...\n", svr, str, size);
        	
	/* Initialize send buffer */
	for (i = 0; i < size; i++)
		send_buf[L2CAP_CMD_HDR_SIZE + i] = (i % 40) + 'A';

	id = ident;

	while (count == -1 || count-- > 0) {
		struct timeval tv_send, tv_recv, tv_diff;
		l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
		l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;

		// Build command header
		send_cmd->ident = id;
		send_cmd->len   = htobs(size);

		if (reverse)
			send_cmd->code = L2CAP_ECHO_RSP;
		else
			send_cmd->code = L2CAP_ECHO_REQ;

		gettimeofday(&tv_send, NULL);

		// Send Echo Command
		if (send(sk, send_buf, L2CAP_CMD_HDR_SIZE + size, 0) <= 0) {
			perror("Send failed");
			goto error;
		}

		// Wait for Echo Response
		lost = 0;
		while (1) {
			struct pollfd pf[1];
			int err;

			pf[0].fd = sk;
			pf[0].events = POLLIN;

			if ((err = poll(pf, 1, timeout * 1000)) < 0) {
				perror("Poll failed");
				goto error;
			}

			if (!err) {
				lost = 1;
				break;
			}

			if ((err = recv(sk, recv_buf, L2CAP_CMD_HDR_SIZE + size, 0)) < 0) {
				perror("Recv failed");
				goto error;
			}

			if (!err){
				printf("Disconnected\n");
				goto error;
			}

			recv_cmd->len = btohs(recv_cmd->len);

			// Check for our id
			if (recv_cmd->ident != id)
				continue;

			// Check type
			if (!reverse && recv_cmd->code == L2CAP_ECHO_RSP)
				break;

			if (recv_cmd->code == L2CAP_COMMAND_REJ) {
				printf("Peer doesn't support Echo packets\n");
				goto error;
			}

		}
		sent_pkt++;

		if (!lost) {
			recv_pkt++;

			gettimeofday(&tv_recv, NULL);
			timersub(&tv_recv, &tv_send, &tv_diff);

			if (verify) {
				// Check payload length
				if (recv_cmd->len != size) {
					fprintf(stderr, "Received %d bytes, expected %d\n",
						   recv_cmd->len, size);
					goto error;
				}

				// Check payload
				if (memcmp(&send_buf[L2CAP_CMD_HDR_SIZE],
						   &recv_buf[L2CAP_CMD_HDR_SIZE], size)) {
					fprintf(stderr, "Response payload different.\n");
					goto error;
				}
			}

			//printf("%d bytes from %s id %d time %.2fms\n", recv_cmd->len, svr,id - ident, tv2fl(tv_diff));
			is_connected=1;
			printf("Device OK\n");

			if (delay)
				sleep(delay);
		} else {
			//printf("no response from %s: id %d\n", svr, id - ident);
		}

		if (++id > 254)
			id = ident;
	}
	//stat(0);
	free(send_buf);
	free(recv_buf);
	return;

error:
	close(sk);
	free(send_buf);
	free(recv_buf);
	return;
}

int main(int argc, char *argv[]) {

	// args
	int opt;

	/* Default options */
	bdaddr_t tmp = {0,0,0,0,0,0}; //BDADDR_ANY
	bacpy(&bdaddr, &tmp);

	if (!(argc - optind)) {
		usage();
		exit(1);
	}
  
        // Our process ID and Session ID 
        pid_t pid, sid;

        // Fork off the parent process 
        pid = fork();
        if (pid < 0) {
                exit(EXIT_FAILURE);
        }
        /* If we got a good PID, then
           we can exit the parent process. */
        if (pid > 0) {
                exit(EXIT_SUCCESS);
        }

        // Change the file mode mask
        umask(0);

        // Open any logs here

        // Create a new SID for the child process
        sid = setsid();
        if (sid < 0) {
                // Log the failure
                exit(EXIT_FAILURE);
        }



        // Change the current working directory
        if ((chdir("/")) < 0) {
                // Log the failure
                exit(EXIT_FAILURE);
        }

        // Close out the standard file descriptors (no console output)
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        // Daemon-specific initialization goes here

        // The Big Loop
	FILE *f=fopen("/var/run/btlock.pid","w+");
	fprintf(f,"%i",sid);
	fclose(f);
	
	FILE *log;
	time_t current_time;
        char* c_time_string;
	
        while (1) {
           ping(argv[optind]);
	   count=1; // reset ping count to 1
	   current_time = time(NULL);
	   c_time_string=strtok(ctime(&current_time), "\n");
	   log=fopen("/var/log/btlock.log","a+");
           if(!is_connected && !is_locked) {popen ("qdbus org.freedesktop.ScreenSaver /ScreenSaver Lock","r");is_locked=1;fprintf(log,"%s desktop locked.\n",c_time_string);};
	   if (is_connected && is_locked) {popen ("qdbus | grep kscreenlocker | sed 's/org.kde.//' | xargs kquitapp","r");is_locked=0;fprintf(log,"%s desktop unlocked.\n",c_time_string);};
	   fclose(log);
	   sleep(30); // wait 30 seconds  
        }


   exit(EXIT_SUCCESS);
}
