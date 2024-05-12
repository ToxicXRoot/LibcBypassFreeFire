// hook libc created on 2023 May 12 Bypas Toxic @t.me/CacheTmp_DalVik
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>


typedef int( * SocketFunc)(int domain, int type, int protocol);
typedef int( * ConnectFunc)(int sockfd,
  const struct sockaddr * addr, socklen_t addrlen);
int( * originalSocket)(int domain, int type, int protocol);
int( * originalConnect)(int sockfd,
  const struct sockaddr * addr, socklen_t addrlen);
int( * originalInetPton)(int af,
  const char * src, void * dst);
int( * originalGetAddrInfo)(const char * node,
  const char * service,
    const struct addrinfo * hints, struct addrinfo ** res);
struct hostent * ( * originalGetHostByAddr)(const void * addr, socklen_t len, int type);
struct hostent * ( * originalGetHostByName)(const char * name);

int XXX = 0;

void hookedInetPton(int af,
  const char * src, void * dst) {
  char ip[INET6_ADDRSTRLEN]; // Assuming IPv6 address length

  if (af == AF_INET && strstr(src, "ff.dr.grtc.garenanow.com") ||

    strstr(src, "dl.tata.freefiremobile.com") ||
    strstr(src, "dl.dir.freefiremobile.com") ||
    strstr(src, "103.16.33.136") ||
    strstr(src, "103.16.33.") ||
    strstr(src, "dl.cdn.freefiremobile.com") ||

    strstr(src, "dl.listdl.com") ||

    strstr(src, "164.") ||
    strstr(src, "164.52.102.") ||
    strstr(src, "google") ||
    strstr(src, "dl.") ||
    strstr(src, "dl-") ||
    strstr(src, "dl-gmc.ggbluefox.com") ||

    strstr(src, "64.") ||
    strstr(src, "60.") ||
    strstr(src, "63.") ||
    strstr(src, "56.") ||

    strstr(src, "graph.facebook.com") ||

    strstr(src, "ffmmsdk.live.gop.garenanow.com") ||

    strstr(src, "tobapplog.ctobsnssdk.com") ||

    strstr(src, "conversions.appsflyer.com") ||

    strstr(src, "gsxnj.cn") ||

    strstr(src, "optimizationguide-pa.googleapis.com.") ||
    strstr(src, "dl.dir.freefiremobile.com") ||
    strstr(src, "ffmconnect.live.gop.garenanow.com") ||
    strstr(src, "csoversea.stronghold.freefiremobile.com") ||
    strstr(src, "gin.freefiremobile.com") ||
    strstr(src, "dl.cdn.freefiremobile.com") ||
    strstr(src, "dl-ind-production.freefiremobile.com") ||
    strstr(src, "dl.") ||
    strstr(src, "dl-") ||
    strstr(src, ".cn") ||

    strstr(src, "49.45.0.1") ||
    strstr(src, "202.81.117.88") ||
    strstr(src, "202.81.117.") ||
    strstr(src, "cdn-settings.appsflyersdk.com") ||
    strstr(src, "202.81.118.4") ||
    strstr(src, "202.81.118.") ||
    strstr(src, "103.219.201.93") ||
    strstr(src, "103.219.201.") ||
    strstr(src, "199.59.243.225") ||
    strstr(src, "199.") ||
    strstr(src, "app-measurement.com") ||
    strstr(src, "freefiremobile-a.akamaihd.net") ||
    strstr(src, "gcdsdk.appsflyer.com") ||

    strstr(src, ".akamaihd.net")

  )

  {
    // Log and save the blocked IP address to a file
    XXX = 0;
    //return -1;
    /*
     FILE *blockFile = fopen("/sdcard/Android/obb/blocked_ips.txt", "a");
     if (blockFile) {
         fprintf(blockFile, "Blocked IP: %s\n", src);
         fclose(blockFile);
         }
         */

    // return;
    // Do not perform the original inet_pton for blocked IPs

  } else {

    XXX = 1;
  }

  // Call the original inet_pton to convert the IP address for allowed IPs
  originalInetPton(af, src, dst);

  // Convert the IP address to string for logging
  if (af == AF_INET) {
    struct in_addr * ipv4 = (struct in_addr * ) dst;
    inet_ntop(af, ipv4, ip, INET6_ADDRSTRLEN);
  } else if (af == AF_INET6) {
    struct in6_addr * ipv6 = (struct in6_addr * ) dst;
    inet_ntop(af, ipv6, ip, INET6_ADDRSTRLEN);
  } else {
    return; // Handle other address families as needed
  }
  /*
      // Log and save the allowed IP address to a file
      FILE *allowFile = fopen("/sdcard/Android/obb/allowed_ips.txt", "a");
      if (allowFile) {
          fprintf(allowFile, "Allowed IP: %s\n", ip);
          fclose(allowFile);
          }

          */

}

int hookedGetAddrInfo(const char * node,
  const char * service,
    const struct addrinfo * hints, struct addrinfo ** res) {
  // Call the original getaddrinfo to perform the actual address resolution
  int result = originalGetAddrInfo(node, service, hints, res);

  // Log and save the URL address to a file
  if (result == 0 && * res != NULL) {
    char ip[INET6_ADDRSTRLEN]; // Assuming IPv6 address length
    struct sockaddr * addr = ( * res) -> ai_addr;

    if (addr -> sa_family == AF_INET) {
      struct sockaddr_in * ipv4 = (struct sockaddr_in * ) addr;
      inet_ntop(AF_INET, & (ipv4 -> sin_addr), ip, INET6_ADDRSTRLEN);
    } else if (addr -> sa_family == AF_INET6) {
      struct sockaddr_in6 * ipv6 = (struct sockaddr_in6 * ) addr;
      inet_ntop(AF_INET6, & (ipv6 -> sin6_addr), ip, INET6_ADDRSTRLEN);
    } else {
      return -2; // Handle other address families as needed
    }

    if (strstr(node, Yohoho("gin.freefiremobile.com")) || strstr(node, Yohoho("csoversea.stronghold.freefiremobile.com")) || strstr(node, "ff.sdk.grtc.garenanow.com") || strstr(node, "202.81.117.91") ||
      strstr(node, "google") ||
      // strstr(node, ".grtc.garenanow.com") ||
      strstr(node, "ff.dr.grtc.garenanow.com") ||
      strstr(node, "164.") ||
      strstr(node, "164.52.102.") ||
      strstr(node, "google") ||
      strstr(node, "dl-") ||
      strstr(node, "dl.") ||
      strstr(node, "dl-gmc.ggbluefox.com") ||
      strstr(node, "64.") ||
      strstr(node, "60.") ||
      strstr(node, "63.") ||
      strstr(node, "56.") ||

      strstr(node, "dl.tata.freefiremobile.com") ||
      strstr(node, "dl.dir.freefiremobile.com") ||
      strstr(node, "103.16.33.136") ||
      strstr(node, "103.16.33.") ||

      strstr(node, "dl.cdn.freefiremobile.com") ||

      strstr(node, "dl.listdl.com") ||
      //

      strstr(node, "49.45.0.1") ||
      strstr(node, "202.81.117.88") ||
      strstr(node, "202.81.117.") ||
      strstr(node, "cdn-settings.appsflyersdk.com") ||
      strstr(node, "202.81.118.4") ||
      strstr(node, "202.81.118.") ||
      strstr(node, "103.219.201.93") ||
      strstr(node, "103.219.201.") ||
      strstr(node, "199.59.243.225") ||
      strstr(node, "199.") ||
      strstr(node, "app-measurement.com") ||
      strstr(node, "freefiremobile-a.akamaihd.net") ||
      strstr(node, "gcdsdk.appsflyer.com") ||

      strstr(node, ".akamaihd.net")
    )

    {

      XXX = 0;
      return -1;
    } else {

      XXX = 1;
      return result;

      // Log and set XXX if needed

      /*
          FILE *file = fopen("/sdcard/Android/obb/url_logs.txt", "a");
          if (file) {
              fprintf(file, "getaddrinfo: %s for URL: %s, service: %s\n", ip, node, service);
              fclose(file);
          }
      */

      // Set XXX = 0 if needed
      // XXX = 0;

      // Return the original result

    }
  }
}

struct hostent * hookedGetHostByAddr(const void * addr, socklen_t len, int type) {
  // Call the original gethostbyaddr to perform the actual address resolution
  struct hostent * result = originalGetHostByAddr(addr, len, type);

  // Log and save the IP address to a file
  if (result != NULL) {
    char ip[INET6_ADDRSTRLEN]; // Assuming IPv6 address length
    inet_ntop(type, result -> h_addr_list[0], ip, INET6_ADDRSTRLEN);

    // Log and save the IP address to a file
    /*
            FILE *file = fopen("/sdcard/Android/obb/host_logs.txt", "a");
            if (file) {
                fprintf(file, "gethostbyaddr: %s\n", ip);
                fclose(file);
            }
            */
  }

  return result;
}

struct hostent * hookedGetHostByName(const char * name) {
  // Call the original gethostbyname to perform the actual address resolution
  struct hostent * result = originalGetHostByName(name);

  // Log and save the IP address to a file
  if (result != NULL) {
    char ip[INET6_ADDRSTRLEN]; // Assuming IPv6 address length
    inet_ntop(result -> h_addrtype, result -> h_addr_list[0], ip, INET6_ADDRSTRLEN);
    /*
            // Log and save the IP address to a file
            FILE *file = fopen("/sdcard/Android/obb/host_logs.txt", "a");
            if (file) {
                fprintf(file, "gethostbyname: %s\n", ip);
                fclose(file);
            }
            */
  }

  return result;
}

int hookedSocket(int domain, int type, int protocol) {
  // Log and save the IP address to a file
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

  // Call the original socket function
  int sockfd = originalSocket(domain, type, protocol);

  if (XXX == 0) {
    close(sockfd); // Close the socket to block the connection
    return -2; // Block the socket creation
  }

  return sockfd; // Allow the socket creation
}

int hookedConnect(int sockfd,
  const struct sockaddr * addr, socklen_t addrlen) {
  struct sockaddr_in * addr_in = (struct sockaddr_in * ) addr;

  if (XXX == 0) {
    return -2;
  }

  // Call the original connect function
  return originalConnect(sockfd, addr, addrlen);
}

#include <stdio.h>

#include <string.h>

#include <dlfcn.h>

void( * original_system_property_get)(const char * , char * );

// Hooked version of __system_property_get
void hooked_system_property_get(const char * name, char * value) {
  // Replace "ro.hardware" with the property you want to modify
  if (strcmp(name, "ro.hardware") == 0) {
    // Replace "NewHardwareName" with the desired hardware name
    strcpy(value, "qualcom");
    printf("Modified hardware name: %s\n", value);
    return;
  }

  // Call the original function for other properties
  original_system_property_get(name, value);
}

// Function pointer for the original strstr function
char * ( * originalStrstr)(const char * haystack,
  const char * needle);

// Hooked version of strstr
char * hookedStrstr(const char * haystack,
  const char * needle) {
  // Log or manipulate the strings as needed
  if (strstr(haystack, "vphonegaga") != nullptr) {
    // Block or log the occurrence of "hello"

    // For example, you can print a message, modify the string, or take any other action
    // In this case, we replace the occurrence of "hello" with "blocked"
    char * modifiedHaystack = strdup(haystack); // Duplicate the string for modification
    char * occurrence = strstr(modifiedHaystack, "crash6455");

    // Check if "hello" is found before attempting to replace
    if (occurrence != nullptr) {
      // Replace "hello" with "blocked"
      strncpy(occurrence, "blocked", strlen("blocked"));
    }

    // Log the modified string
    FILE * file = fopen("/sdcard/Android/obb/strings_Blocked.txt", "a");
    if (file) {
      fprintf(file, "Modified string: %s\n", modifiedHaystack);
      fclose(file);
    }

    //   free(modifiedHaystack);  // Free the duplicated string

    // You can also return the original haystack if you don't want to completely block it
    // return strdup(haystack);
    return originalStrstr(haystack, needle);
  }

  // Call the original strstr function
  return originalStrstr(haystack, needle);
}

pid_t my_pid = getpid();

// send_hook.c


ssize_t( * original_send)(int sockfd,
  const void * buf, size_t len, int flags);

// Define the hooked send function
#include <stdio.h>

// File pointer for the send log file
FILE * sendLogFile = fopen("/sdcard/Android/obb/send_log.txt", "a");

// ... Other parts of your code ...

// Define the hooked send function
ssize_t hooked_send(int sockfd,
  const void * buf, size_t len, int flags) {
  // Log information to the file
  if (sendLogFile) {
    fprintf(sendLogFile, "Socket: %d, Buffer: %s, Length: %zu, Flags: %d\n", sockfd, (char * ) buf, len, flags);

    fclose(sendLogFile);

  }
  // Call the original send function
  return original_send(sockfd, buf, len, flags);
}

// Declare pointers to the original functions
ssize_t( * original_recv)(int sockfd, void * buf, size_t len, int flags);
ssize_t( * original_recvfrom)(int sockfd, void * buf, size_t len, int flags, struct sockaddr * src_addr, socklen_t * addrlen);
ssize_t( * original_sendto)(int sockfd,
  const void * buf, size_t len, int flags,
    const struct sockaddr * dest_addr, socklen_t addrlen);

// File pointers for each log file
FILE * recvLogFile = fopen("/sdcard/Android/obb/recv_log.txt", "a");
FILE * recvfromLogFile = fopen("/sdcard/Android/obb/recvfrom_log.txt", "a");
FILE * sendtoLogFile = fopen("/sdcard/Android/obb/sendto_log.txt", "a");

// ... Other parts of your code ...

// Define the hooked recv function
ssize_t hooked_recv(int sockfd, void * buf, size_t len, int flags) {
  // Log information to the file
  if (recvLogFile) {
    fprintf(recvLogFile, "Socket: %d, Buffer: %s, Length: %zu, Flags: %d\n", sockfd, (char * ) buf, len, flags);

    fclose(recvLogFile);
  }

  // Log information to console
  //printf("Received data on socket %d: %s\n", sockfd, (char *)buf);

  // Call the original recv function
  return original_recv(sockfd, buf, len, flags);
}

// Define the hooked recvfrom function
ssize_t hooked_recvfrom(int sockfd, void * buf, size_t len, int flags, struct sockaddr * src_addr, socklen_t * addrlen) {
  // Log information to the file
  if (recvfromLogFile) {
    fprintf(recvfromLogFile, "Address: %s\n", inet_ntoa(((struct sockaddr_in * ) src_addr) -> sin_addr));
    fclose(recvfromLogFile);

  }

  // Call the original recvfrom function
  return original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

#include <stdio.h>

// File pointer for the UDP send log file
FILE * udpSendLogFile = fopen("/sdcard/Android/obb/udp_send_log.txt", "a");

// ... Other parts of your code ...

// Define the hooked sendto function
ssize_t hooked_sendto(int sockfd,
  const void * buf, size_t len, int flags,
    const struct sockaddr * dest_addr, socklen_t addrlen) {
  // Log information to the file
  if (udpSendLogFile) {
    fprintf(udpSendLogFile, "UDP Packet Sent - Socket: %d, Buffer: %s, Length: %zu, Flags: %d\n", sockfd, (char * ) buf, len, flags);
  }


  // Call the original sendto function
  return original_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

// ... Other parts of your code ...

void hookFunctions() {
  // Load the dynamic library containing the socket, connect, inet_pton, getaddrinfo, gethostbyaddr, and gethostbyname functions
  void * handle = dlopen("libc.so", RTLD_LAZY);
  if (handle == NULL) {
    // Handle the error
    return;
  }

  // Get the original socket, connect, inet_pton, getaddrinfo, gethostbyaddr, and gethostbyname functions
  originalSocket = (SocketFunc) dlsym(handle, "socket");

  originalConnect = (ConnectFunc) dlsym(handle, Yohoho("connect"));

  originalInetPton = (int( * )(int,
    const char * , void * )) dlsym(handle, Yohoho("inet_pton"));

  originalGetAddrInfo = (int( * )(const char * ,
    const char * ,
      const struct addrinfo * , struct addrinfo ** )) dlsym(handle, Yohoho("getaddrinfo"));
  originalGetHostByAddr = (struct hostent * ( * )(const void * , socklen_t, int)) dlsym(handle, "gethostbyaddr");
  originalGetHostByName = (struct hostent * ( * )(const char * )) dlsym(handle, "gethostbyname");

  original_system_property_get = (void( * )(const char * , char * )) dlsym(handle, "__system_property_get");

  // Get the original read function
  //originalRead = (void (*)(int, void *, size_t))dlsym(handle, "read");

  originalStrstr = (char * ( * )(const char * ,
    const char * )) dlsym(handle, "strstr");

  // Get the original send function
  original_send = (ssize_t( * )(int,
    const void * , size_t, int)) dlsym(handle, "send");

  // Get the original recv function
  original_recv = (ssize_t( * )(int, void * , size_t, int)) dlsym(handle, "recv");

  // Get the original recvfrom function
  original_recvfrom = (ssize_t( * )(int, void * , size_t, int, struct sockaddr * , socklen_t * )) dlsym(handle, "recvfrom");

  // Get the original sendto function
  original_sendto = (ssize_t( * )(int,
    const void * , size_t, int,
      const struct sockaddr * , socklen_t)) dlsym(handle, "sendto");

  // Replace the sendto function with our hooked version

  // Replace the socket and connect functions with our hooked versions using Dobby
  if (originalSocket != NULL) {
    DobbyHook((void * ) originalSocket, (void * ) hookedSocket, (void ** ) & originalSocket);
  }

  if (originalConnect != NULL) {
    DobbyHook((void * ) originalConnect, (void * ) hookedConnect, (void ** ) & originalConnect);
  }

  // Replace inet_pton with our hooked version
  if (originalInetPton != NULL) {
    DobbyHook((void * ) originalInetPton, (void * ) hookedInetPton, (void ** ) & originalInetPton);
  }

  // Replace getaddrinfo with our hooked version
  if (originalGetAddrInfo != NULL) {
    DobbyHook((void * ) originalGetAddrInfo, (void * ) hookedGetAddrInfo, (void ** ) & originalGetAddrInfo);
  }

  // Close the library handle
  dlclose(handle);

}
