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

void SSL_Certificates_cfgr_server(SSL_CTX *ctx) //This sets the certificate and the private key file to use
{
    if (SSL_CTX_use_certificate_file(ctx, "./Bob/Bob.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./Bob/Bob.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if(SSL_CTX_check_private_key(ctx)<=0){
        ERR_print_errors_fp(stderr);
     }

    if (SSL_CTX_load_verify_locations(ctx,"CAfile.pem",NULL)<1)
    {
    printf("Error setting the verify locations.\n");
    exit(0);
    }
}

void SSL_Certificates_cfgr_client(SSL_CTX *ctx) //This sets the certificate and the private key file to use
{
    if (SSL_CTX_use_certificate_file(ctx, "./Alice/Alice.crt", SSL_FILETYPE_PEM) <= 0) {

        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./Alice/Alice.pem", SSL_FILETYPE_PEM) <= 0 ) {

        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if(SSL_CTX_check_private_key(ctx)<=0){

        ERR_print_errors_fp(stderr);
    
    }

    if (SSL_CTX_load_verify_locations(ctx,"CAfile.pem",NULL)<1)
    {
    printf("Error setting the verify locations.\n");
    exit(0);
    }
}


SSL_CTX * create_cntx_server()
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(TLSv1_2_server_method()); //Specify to Create a Context for TLS1.2 only
    if (!ctx) {
        std::cout<<"Error Creating SSL Context"<<std::endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

SSL_CTX * create_cntx_client()
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(TLSv1_2_client_method()); //Specify to Create a Context for TLS1.2 only
    if (!ctx) {
        std::cout<<"Error Creating SSL Context"<<std::endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

void initialize_ssl(){ //Used to initialize ssl libraries
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void type_client(char *server_name){
    int port;
//std::cout<<std::endl;
std::cout<<"Please enter the Port on Which to connect to the Server..."<<std::endl;
std::cin>>port;

char buffer[1024] = {0};

    struct hostent* host = gethostbyname(server_name); //This resolves the domain name with the IP address..
    if (host == NULL) {
        std::cout << "Failed to find the hostname: " << std::endl;
        exit(1);
    }

    const char * hello_client="chat_hello";
    const char * hello_ssl_client="chat_START_SSL";
    //char * hello_ssl_client="chat_START_SSL_NOT_SUPPORTED";
    std::string ip_address="127.0.0.1";
    
    struct sockaddr_in address;

    address.sin_port=htons(port);
    address.sin_family=AF_INET;
    address.sin_addr= *((struct in_addr*)host->h_addr_list[0]);
    //inet_pton(AF_INET,ip_address.c_str(), &(address.sin_addr));
    memset(&(address.sin_zero),'\0',8);
    int client_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);


    int value_connect=connect(client_socket,(struct sockaddr *)&address,sizeof(address));
    if(value_connect < 0){
        std::cout<<"Connect Failed..Exiting.."<<std::endl;
        exit(1);
    }

    if(value_connect!=-1){
        std::cout<<"Connection Successfull on Port "<< port<< " and Address "<<address.sin_addr.s_addr<<std::endl;
    }
        //Start Chat Hello
        int val_sent=send(client_socket , hello_client , 1024, 0);
        std::cout<<"The number of bytes sent to the server:"<<val_sent<<"and the message sent is "<<hello_client<<std::endl;
        int valread = recv(client_socket ,buffer, 1024,0);
        std::cout<<"The Message received from Server: "<<buffer<<std::endl;

        //Start Chat SSL Hello
        memset(buffer, 0, sizeof(buffer));

        val_sent=send(client_socket , hello_ssl_client , 1024, 0);
        valread = recv(client_socket ,buffer, 1024,0);
        std::cout<<"The Message received from Server: "<<buffer<<std::endl;

        if(strcmp(buffer,"chat_START_SSL_NOT_SUPPORTED") == 0){
            std::cout<<"The Server Received chat_START_SSL_NOT_SUPPORTED. Hence, proceeding with TCP Transfer..."<<std::endl;
            char buff_cipher[1024]={0};

    struct pollfd fds[1];
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = client_socket;
    fds[1].events = POLLIN;
    
    int n_clients = 0;

        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
            if (len > 0) {
                     write(client_socket,buf,1024);
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = read(client_socket,buf,1024);
            if (len > 0) {
                printf("Server sent..: %d, %s", (int)len, buf);
                if(strcmp(buf,"chat_close\n")==0){
                    close(value_connect);
                    break;
                }
            } else {
                printf("Server disconnected.\n");
                break;
            }
        }
    }
}
else{
initialize_ssl();

SSL_CTX *ctx= create_cntx_client();

SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

/*Custom Settings*/
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2

/*Custom Settings*/

//Sending those Cipher Suites which offer PFS
int cipher_value=SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:TLS_CHACHA20_POLY1305_SHA256");
if(!cipher_value){
    std::cout<<"No Suitable Cipher Suite found...Exiting.."<<std::endl;
    exit(1);
}
SSL_CTX_set_ecdh_auto(ctx, 1);

SSL_Certificates_cfgr_client(ctx); // This loads the Certificates, Private Key of the Client and also verifies the CA's Certificates

SSL *ssl;
char buff_cipher[1024]={0};

    struct pollfd fds[1];
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = client_socket;
    fds[1].events = POLLIN;
    
    int n_clients = 0;

    ssl=SSL_new(ctx);
    SSL_set_verify_depth(ssl, 2);
    //SSL_set_tlsext_host_name(ssl,"Bob1.com");

    if(ssl == NULL){
        std::cout<<"Failed..."<<std::endl;
    }
    SSL_set_fd(ssl, client_socket);
    
    if (SSL_connect(ssl) <= 0) {
        std::cout<<"There is an error"<<std::endl;
        ERR_print_errors_fp(stderr);
    } 
    else
    {   std::cout<<"Sending data to Server Securely..."<<std::endl;
        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
            if (len > 0) {
                    SSL_write(ssl,buf,1024);
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = SSL_read(ssl,buf,1024);
            if (len > 0) {
                printf("Server sent..: %d, %s", (int)len, buf);
                if(strcmp(buf,"chat_close\n")==0){
                    std::cout << "yoyoyo";
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(value_connect);
                    break;
                }
            } else {
                
                printf("Server disconnected.\n");
                break;
            }
        }
    }
 }
close(client_socket);
SSL_CTX_free(ctx);
    }
}

void type_server(){

int port;
//std::cout<<std::endl;
std::cout<<"Please enter the Port on Which the Server Should listen..."<<std::endl;
std::cin>>port;
/*

*/ 
    char * hello_server= "chat_hello_ACK";
    char * hello_ssl_server="chat_START_SSL_ACK";
    //char * hello_ssl_server="chat_START_SSL_NOT_SUPPORTED";
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
    /*
    valsent = send(new_socket , hello_ssl_server , 1024, 0 );
    */
    if(strcmp(buffer,"chat_START_SSL_NOT_SUPPORTED") == 0){
        std::cout<<"The Server Received chat_START_SSL_NOT_SUPPORTED. Hence, proceeding with TCP Transfer..."<<std::endl;

    char buff_cipher[1024]={0};
    struct pollfd fds[1];
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = new_socket;
    fds[1].events = POLLIN;
    
    int n_clients = 0;
        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
            if (len > 0) {
                write(new_socket,buf,1024);
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = read(new_socket,buf,1024);
            if (len > 0) {
                printf("Client sent..: %d, %s", (int)len, buf);
                if(strcmp(buf,"chat_close\n")==0){
                    close(new_socket);
                    break;
                }
            } else {
                printf("Client disconnected.\n"); //Ctrl-C pressed and not "chat_close" message
                break;
                }
            }
        }

    }
    else{
    valsent = send(new_socket , hello_ssl_server , 1024, 0 );

initialize_ssl(); // This initializes the SSL libraries and algorithms to use for the SSL handshake.

SSL_CTX *ctx=create_cntx_server();

SSL_Certificates_cfgr_server(ctx); //Method to use appropraite Certificates and Private Keys

//Sending those Cipher Suites which offer PFS
/*Custom Settings*/
int cipher_value = SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:TLS_CHACHA20_POLY1305_SHA256");
//SSL_CTX_set_cipher_list(ctx, "TLS_CHACHA20_POLY1305_SHA256");
if(!cipher_value){
    std::cout<<"No Suitable Cipher Suite found...Exiting.."<<std::endl;
    exit(1);
}

SSL_CTX_set_ecdh_auto(ctx, 1);

SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); //This forces for Verification of Client/Server by asking for Certificates

SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2
/*Custom Settings*/

    char buff_cipher[1024]={0};
    SSL *ssl=SSL_new(ctx);
    //std::cout<<"These are the list of the available Cipher suites:"<<SSL_get_shared_ciphers(ssl,buff_cipher,1024)<<std::endl;
    SSL_set_fd(ssl, new_socket);

    struct pollfd fds[1];
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = new_socket;
    fds[1].events = POLLIN;
    
    int n_clients = 0;

    if (SSL_accept(ssl) <= 0) {
        std::cout<<"There is an error"<<std::endl;
        ERR_print_errors_fp(stderr);
    }
    /*
    Poll to do interactive chat between Bob and Client
    */
    else
    {   std::cout<<"Sending data to Client Securely..."<<std::endl;
        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
            if (len > 0) {
                SSL_write(ssl,buf,1024);
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = SSL_read(ssl,buf,1024);
            if (len > 0) {
                printf("Client sent..: %d, %s", (int)len, buf);
                if(strcmp(buf,"chat_close\n")==0){
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(new_socket);
                    break;
                }
            } else {
                printf("Client disconnected.\n"); //Ctrl-C pressed and not "chat_close" message
                break;
                }
            }
        }
    }

    close(sockid);
    SSL_CTX_free(ctx);
    }
}

int main(int argc, char *argv[]){
    if (argc == 1) {
        std::cout << "Please Pass an argument and try again" << std::endl;
        exit(1);
        }
    if((strcmp(argv[1],"-s")) == 0 ){
    type_server(); // This gets invoked when its a server
    }
    else if((strcmp(argv[1],"-c") == 0) && (strcmp(argv[2],"bob1") == 0)){
        type_client(argv[2]);
    }
    else{
        std::cout<<"There is an Error in which you are giving the arguments..Please check"<<std::endl;
        exit(1);
    }

    //type_server();
    
// int port;
// //std::cout<<std::endl;
// std::cout<<"Please enter the Port on Which the Server Should listen..."<<std::endl;
// std::cin>>port;

// // OpenSSL_add_all_algorithms(); // This is a synonym for SSL_library_init()
// // SSL_load_error_strings();
// // SSL_library_init();

// // //SSL_CTX *ctx= create_cntx();
// // SSL_CTX *ctx;
// //     // ctx = SSL_CTX_new(TLSv1_2_server_method()); //Specify to Create a Context for TLS1.2 only
// //     ctx = SSL_CTX_new(TLS_server_method()); //Specify to Create a Context for TLS1.2 only
// //     if (!ctx) {
// //         std::cout<<"Error Creating SSL Context"<<std::endl;
// //         ERR_print_errors_fp(stderr);
// //         exit(1);
// //     }

// /*

// */ 
//     char * hello_server= "chat_hello_ACK";
//     char * hello_ssl_server="chat_START_SSL_ACK";
//     std::string ip_address="127.0.0.1";
//     int flags,new_socket,valread;
//     char buffer[1024] = {0};

//     struct sockaddr_in address;
//     int addr_len = sizeof(address);
//     address.sin_addr.s_addr=INADDR_ANY;
//     address.sin_port=htons(port);
//     address.sin_family=AF_INET;
//     inet_pton(AF_INET,ip_address.c_str(), &(address.sin_addr));
//     memset(&(address.sin_zero), '\0', 8);

//     int sockid = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
//     if(sockid==-1){
//         std::cout<<"The socket could not be created"<<std::endl;
//         std::exit(1);
//     }
//     int opt=1;

//     if (setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
//                                                   &opt, sizeof(opt)))
//     {
//         perror("setsockopt");
//         exit(EXIT_FAILURE);
//     }

//     // int sockid = crt_socket(port);

//     if(bind(sockid,(struct sockaddr *)&address,sizeof(address))!=-1){
//         std::cout<<"Bind Successfull on Port "<< port<< " and Address "<<address.sin_addr.s_addr<<std::endl;
//     }
//     int status = listen(sockid,2);
//     if(status < 0){
//     std::cout<<"The Listen on Requested Port failed"<<std::endl;
//     std::exit(1);
//     }
//     new_socket = accept(sockid, (struct sockaddr *)&address,(socklen_t*)&addr_len);
//     if(!new_socket){   
//         std::cout<<"The Connection could not be accepted"<<std::endl;
//         std::exit(1);
//     }
//     std::cout<<"Connection Accepted of Client"<<std::endl;
    
//     //Start Chat Hello
//     valread = recv(new_socket ,buffer, 1024,0);
//     if(valread!=-1){
//     std::cout<<"The Message received from Client: "<<buffer<<std::endl;
//     }
//     // int valsent = send(new_socket , hello_server , strlen(hello_server) , 0 );
//     int valsent = send(new_socket , hello_server , 1024, 0 );

//     //Start SSL Chat Hello
//     memset(buffer, 0, sizeof(buffer));

//     valread = recv(new_socket ,buffer, 1024,0);
//     if(valread!=-1){
//     std::cout<<"The Message received from Client: "<<buffer<<std::endl;
//     }
//     // valsent = send(new_socket , hello_ssl_server , strlen(hello_ssl_server) , 0 );
//     valsent = send(new_socket , hello_ssl_server , 1024, 0 );

// //char reply[]="Hello from Server!";

// /*Custom Settings*/
// // SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
// // SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2

// /*Custom Settings*/

//     // int accept_rtn=accept(sockid,(struct sockaddr *)&address,(socklen_t *)&addr_len);
//     // std::cout<<"Accept Value"<<accept_rtn<<std::endl;

//     // if(accept_rtn < 0){
//     //     std::cout<<"Accept Failed..Exiting.."<<std::endl;
//     //     exit(1);
//     // }

// initialize_ssl(); // This initializes the SSL libraries and algorithms to use for the SSL handshake.

// // SSL_load_error_strings();
// // OpenSSL_add_all_algorithms(); // This is a synonym for SSL_library_init()

// //SSL_CTX *ctx= create_cntx();
// SSL_CTX *ctx;
//     // ctx = SSL_CTX_new(TLSv1_2_server_method()); //Specify to Create a Context for TLS1.2 only
//     ctx = SSL_CTX_new(TLSv1_2_server_method()); //Specify to Create a Context for TLS1.2 only
//     if (!ctx) {
//         std::cout<<"Error Creating SSL Context"<<std::endl;
//         ERR_print_errors_fp(stderr);
//         exit(1);
//     }

// SSL_Certificates_cfgr(ctx);

// //Sending those Cipher Suites which offer PFS
// SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:TLS_CHACHA20_POLY1305_SHA256");
// SSL_CTX_set_ecdh_auto(ctx, 1);

// SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

// /*Custom Settings*/
// SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
// SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2
// /*Custom Settings*/

//     char buff_cipher[1024]={0};
//     std::cout<<"Reached after accept..."<<std::endl;
//     SSL *ssl=SSL_new(ctx);
//     //std::cout<<"These are the list of the available Cipher suites:"<<SSL_get_shared_ciphers(ssl,buff_cipher,1024)<<std::endl;
//     SSL_set_fd(ssl, new_socket);

//     if (SSL_accept(ssl) <= 0) {
//         std::cout<<"There is an error"<<std::endl;
//         ERR_print_errors_fp(stderr);
//     } 
//     else
//     {   std::cout<<"Sending data to Client..."<<std::endl;
//         SSL_write(ssl, "Hi,from Server", strlen("Hi,from Server"));
//     }

//     SSL_shutdown(ssl);
//     SSL_free(ssl);
//     close(new_socket);

// close(sockid);
// SSL_CTX_free(ctx);

return 0;
}

