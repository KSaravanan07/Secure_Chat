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
    if (SSL_CTX_use_certificate_file(ctx, "./fake_certs/Bob/fakebob.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./fake_certs/Bob/Bob.key", SSL_FILETYPE_PEM) <= 0 ) {
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
    if (SSL_CTX_use_certificate_file(ctx, "./fake_certs/Alice/fakealice.crt", SSL_FILETYPE_PEM) <= 0) {

        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./fake_certs/Alice/Alice.key", SSL_FILETYPE_PEM) <= 0 ) {

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

void initialize_ssl(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void type_server_client(char *server_name){

int port;
std::cout<<"Please enter the Port on Which the Server Should listen..."<<std::endl;
std::cin>>port;
/*

*/
    /*### AS SERVER ###*/

    char * hello_server= "chat_hello_ACK";
    char * hello_ssl_server="chat_START_SSL_ACK";
    //char * trudy_hello_ssl="chat_START_SSL_NOT_SUPPORTED";
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
    //valsent = send(new_socket ,"chat_START_SSL_NOT_SUPPORTED", strlen("chat_START_SSL_NOT_SUPPORTED"), 0 );
    valsent = send(new_socket ,hello_ssl_server, 1024, 0 );


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

        val_sent=send(client_socket , hello_ssl_client , 1024, 0);
        valread = recv(client_socket ,buffer, 1024,0);
        std::cout<<"The Message received from Server: "<<buffer<<std::endl;

        /*
        ############################################################################# 
        Now proceeding with Sending the traffic to Alice and Bob via individual TLS pipes transfer...
        #############################################################################
        */
       // char buff_cipher[1024]={0};



    /*
    ##########################################################################
    This is for Secure Communication between Alice and Bob.
    ##########################################################################
    */

   /*
    Client SSL Setup
   */

initialize_ssl();

SSL_CTX *ctx_client= create_cntx_client();
SSL_CTX *ctx_server= create_cntx_server();

/*Client*/
SSL_CTX_set_mode(ctx_client, SSL_MODE_AUTO_RETRY);
SSL_CTX_set_verify(ctx_client, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
/*Client*/

/*Server*/
SSL_CTX_set_mode(ctx_server, SSL_MODE_AUTO_RETRY);
SSL_CTX_set_verify(ctx_server, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
/*Server*/

/*Client Settings*/
SSL_CTX_set_min_proto_version(ctx_client, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
SSL_CTX_set_max_proto_version(ctx_client, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2
/*Client Settings*/

/*Server Settings*/
SSL_CTX_set_min_proto_version(ctx_server, TLS1_2_VERSION); //Sets the minimum protocol version to TLS-1.2
SSL_CTX_set_max_proto_version(ctx_server, TLS1_3_VERSION); //Sets the maximum protocol version to TLS-1.2
/*Server Settings*/

//Sending those Cipher Suites which offer PFS
int cipher_value=SSL_CTX_set_cipher_list(ctx_client, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:TLS_CHACHA20_POLY1305_SHA256");
if(!cipher_value){
    std::cout<<"No Suitable Cipher Suite found...Exiting.."<<std::endl;
    exit(1);
}
SSL_CTX_set_ecdh_auto(ctx_client, 1);

//Sending those Cipher Suites which offer PFS
cipher_value=SSL_CTX_set_cipher_list(ctx_server, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:TLS_CHACHA20_POLY1305_SHA256");
if(!cipher_value){
    std::cout<<"No Suitable Cipher Suite found...Exiting.."<<std::endl;
    exit(1);
}
SSL_CTX_set_ecdh_auto(ctx_server, 1);


SSL_Certificates_cfgr_client(ctx_client); // This loads the Certificates, Private Key of the Client and also verifies the CA's Certificates
SSL_Certificates_cfgr_server(ctx_server); // This loads the Certificates, Private Key of the Server and also verifies the CA's Certificates

SSL *ssl_client,*ssl_server;
char buff_cipher[1024]={0},buff_server[1024]={0};

    ssl_client=SSL_new(ctx_client);
    ssl_server=SSL_new(ctx_server);

    SSL_set_verify_depth(ssl_client, 2);
    SSL_set_verify_depth(ssl_server, 2);

    if(ssl_client == NULL){
        std::cout<<"Failed Client Connection..."<<std::endl;
    }
    SSL_set_fd(ssl_client, client_socket);
    
    if(ssl_server == NULL){
        std::cout<<"Failed Server Connection..."<<std::endl;
    }
    SSL_set_fd(ssl_server, new_socket);
    
    std::cout<<SSL_connect(ssl_client)<<std::endl;
    std::cout<<SSL_accept(ssl_server)<<std::endl;

    if ((SSL_connect(ssl_client) <= 0) || (SSL_accept(ssl_server) <= 0)) {
        std::cout<<"There is an error in either the Client or the Server Connection...Exiting..."<<std::endl;
        ERR_print_errors_fp(stderr);
    } 
    else
    {
    struct pollfd fds[1];
    
    fds[0].fd = client_socket;  //Client Socket FD.
    fds[0].events = POLLIN;
    fds[1].fd = new_socket;     //Server Socket FD.
    fds[1].events = POLLIN;

        while(poll(fds, 2, -1)!=-1){
        char buf[1024];
        memset(buf,0,1024);
        if (fds[0].revents & POLLIN) {
            ssize_t len = SSL_read(ssl_client, buf, sizeof(buf));
            if (len > 0) {
                    printf("Client sent..: %d, %s", (int)len, buf);    
                    SSL_write(ssl_server,buf,1024);
                    if(strcmp(buf,"chat_close\n")==0){
                    SSL_shutdown(ssl_client);
                    SSL_free(ssl_server);
                    close(client_socket);
                    close(new_socket);
                    break;
                }
            }
        }
        if (fds[1].revents & POLLIN) {
            ssize_t len = SSL_read(ssl_server,buf,1024);
            if (len > 0) {
                printf("Server sent..: %d, %s", (int)len, buf);
                SSL_write(ssl_client,buf,1024);
                if(strcmp(buf,"chat_close\n")==0){
                    SSL_shutdown(ssl_client);
                    SSL_free(ssl_server);
                    close(new_socket);
                    close(client_socket);
                    break;
                }
            }
        }
    }
  }
  SSL_CTX_free(ctx_client);
  SSL_CTX_free(ctx_server);
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
