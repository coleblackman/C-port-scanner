#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h> 
#include <sys/signal.h>

// Cole Blackman programming assignment #1 Intro to Cybersecurity
// Option 1: port scanner
// Written in C, POSIX-intercompatible. Works on Linux and BSDs. Not windows.
// Reference used: Textbook Beej's Guide to Network Programming (https://beej.us/guide/bgnet/html/split/)
// Alarms reference: https://usna.edu/Users/cs/wikman/IC221/calendar.php?type=class&event=18 
void alarmed() {
    printf("Timed out.\n");
    exit(0);
}

int main (int argc, char* argv[]) {
    //create the alarm for later (to enable time out)
    signal(SIGALRM, alarmed);
    
    char ipv4[38];
    printf("Enter a target to scan: ");
    if (fgets(ipv4, sizeof(ipv4), stdin) ==NULL) {
        printf("Invalid input");
        return 0; 
    }



    uint32_t len = strlen(ipv4);
    ipv4[len - 1] = '\0'; //I hate the default beahvior of fgets() but we have to remove the \n that it includes and replace it
    
    char *ipv4_addr = ipv4;//assign the string

    uint32_t port_lower_bound; // we will read in the bounds next
    uint32_t port_upper_bound;

    printf("Please enter the range of ports you would like to scan on the target\n");
    printf("Enter a start port: ");
    scanf("%d", &port_lower_bound);
    printf("Enter an end port: ");
    scanf("%d", &port_upper_bound);

    //Print current time (the time the scan started)
    //Reference: https://en.cppreference.com/w/c/chrono/time and https://en.cppreference.com/w/c/chrono/localtime

    time_t t = time(NULL);
    printf("Port scanning started at (GMT): %s", asctime(gmtime(&t))); //print start time
    alarm(3);//start a timer for attempting to establish a connection
    struct addrinfo hints, *res;

    int sockt; //just some defintions
    int err;
    char port_str[10];

    //iterate through all the ports
    for (int port_number = port_lower_bound; port_number < port_upper_bound; port_number++) {
        res = NULL;
        sprintf(port_str, "%d", port_number); //convert the port num to a string for getaddrinfo (this is not a standard way to do this but I didn't think there was any point in adding another struct)

        //Reference: Beej's section 5.1
        memset(&hints, 0, sizeof hints); //IMPORTANT when creating a variable, not guaranteed to be empty. THis line just zeroes it
        hints.ai_family = AF_UNSPEC;//optional, more C-like to use the struct to derive these. Would be more portable if you ever wanted to add IPV6 support.
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(ipv4_addr, port_str, &hints, &res);
        if (status != 0) { //itll segfault on a nonexistent target without this
            //also from Beej's section 5.1
            fprintf(stderr, "%s\n", gai_strerror(status));
            continue; 
        }
        // assume ipv4 so pass PF_INET which is equivalent to AF_INET (internet protocol)
        // reference section 5.2 of Beej's.
        //TCP stream socket SOCK_STREAM
        sockt = socket(PF_INET, SOCK_STREAM, 0);
        err = connect(sockt, res->ai_addr, res->ai_addrlen);//Attempt to connect
        if (err == 0) { //print if the connection worked based on the return. 
            printf("Port %d is open\n", port_number);
        }
        else {
            printf("Port %d is closed\n", port_number);
        }
        
        freeaddrinfo(res); //free the linked list (beej's section 5.1)
    }
    printf("Port Scanning Complete\n");
    return 0; 
}
